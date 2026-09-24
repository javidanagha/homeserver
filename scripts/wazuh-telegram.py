#!/usr/bin/env python3
"""Wazuh alerts -> Telegram (level >= MIN_LEVEL) + PostgreSQL archive (level >= ARCHIVE_LEVEL).
Also writes wazuh.json (lobby card + dashboard) and wazuh-full.json (full log view)."""
import hashlib, json, os, re, tempfile, time, urllib.parse, urllib.request
from collections import deque
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Asia/Baku")
except Exception:
    TZ = None
try:
    import psycopg2
except ImportError:
    psycopg2 = None

ALERTS = "/var/ossec/logs/alerts/alerts.json"
STATE_DIR = "/var/lib/wazuh-telegram"
SUMMARY_JSON = os.path.join(STATE_DIR, "wazuh.json")
FULL_JSON = os.path.join(STATE_DIR, "wazuh-full.json")
TOKEN = os.environ["TG_TOKEN"]
CHAT = os.environ["TG_CHAT"]
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "10"))
ARCHIVE_LEVEL = int(os.environ.get("ARCHIVE_LEVEL", "5"))
COOLDOWN = 60
SUMMARY_EVERY = 30
FULL_EVERY = 60
FULL_LIMIT = 20000
API = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SYSLOG_HDR = re.compile(r"^\w{3} +\d+ [\d:]+ \S+ ")
DYNAMIC = re.compile(r"\s+(?:from|for)\s+\S+")

INSERT_SQL = """INSERT INTO wazuh_alerts
    (alert_id, ts, rule_id, level, description, srcip, username, rule_groups, detail)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (alert_id) DO NOTHING"""
COUNTS_SQL = """SELECT
    count(*) FILTER (WHERE ts > now() - interval '24 hours'),
    count(*) FILTER (WHERE ts > now() - interval '24 hours' AND level >= %(min)s),
    count(*) FILTER (WHERE ts > now() - interval '24 hours' AND rule_groups LIKE '%%authentication_success%%'),
    count(*) FILTER (WHERE ts > now() - interval '24 hours' AND rule_groups LIKE '%%authentication_fail%%'),
    count(*) FILTER (WHERE ts > now() - interval '24 hours' AND rule_groups LIKE '%%waf%%'),
    count(*),
    count(*) FILTER (WHERE ts > now() - interval '7 days'),
    count(DISTINCT srcip) FILTER (WHERE ts > now() - interval '7 days')
    FROM wazuh_alerts"""
HOURLY_SQL = """SELECT h,
    count(a.id) FILTER (WHERE a.level >= %(min)s),
    count(a.id) FILTER (WHERE a.level < %(min)s)
    FROM generate_series(date_trunc('hour', now()) - interval '23 hours',
                         date_trunc('hour', now()), interval '1 hour') AS h
    LEFT JOIN wazuh_alerts a ON a.ts >= h AND a.ts < h + interval '1 hour'
    GROUP BY h ORDER BY h"""
TOP_RULES_SQL = """SELECT rule_id, count(*), (array_agg(description ORDER BY ts DESC))[1]
    FROM wazuh_alerts WHERE ts > now() - interval '7 days'
    GROUP BY rule_id ORDER BY 2 DESC LIMIT 8"""
TOP_IPS_SQL = """SELECT srcip, count(*) FROM wazuh_alerts
    WHERE ts > now() - interval '7 days' AND srcip IS NOT NULL
    GROUP BY 1 ORDER BY 2 DESC LIMIT 8"""
LEVELS_SQL = """SELECT level, count(*) FROM wazuh_alerts
    WHERE ts > now() - interval '7 days' GROUP BY 1 ORDER BY 1 DESC"""
ROWS_SQL = """SELECT ts, level, rule_id, description, srcip, username, detail, rule_groups
    FROM wazuh_alerts ORDER BY ts DESC LIMIT %s"""


def log(msg):
    print(msg, flush=True)


def send(text):
    data = urllib.parse.urlencode({"chat_id": CHAT, "text": text[:4000],
                                   "disable_web_page_preview": "true"}).encode()
    for attempt in range(3):
        try:
            with urllib.request.urlopen(API, data=data, timeout=10) as r:
                return r.status == 200
        except Exception as e:
            log(f"send failed ({attempt+1}/3): {e}")
            time.sleep(5)
    return False


def parse_ts(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    except Exception:
        return datetime.now(timezone.utc)


def local_time(ts):
    dt = parse_ts(ts)
    if TZ:
        dt = dt.astimezone(TZ)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def src_ip(a):
    d = a.get("data", {})
    req = d.get("request") if isinstance(d.get("request"), dict) else {}
    return d.get("srcip") or req.get("client_ip")


def detail(a):
    d = a.get("data", {})
    req = d.get("request")
    if isinstance(req, dict) and req.get("method"):
        return True, f"{req.get('method')} {req.get('uri', '')} → {d.get('status', '?')}"
    if a.get("full_log"):
        return False, SYSLOG_HDR.sub("", ANSI.sub("", a["full_log"]))[:300]
    return False, None


def fmt(a):
    r, d = a.get("rule", {}), a.get("data", {})
    out = [f"🚨 [{r.get('level')}] {ANSI.sub('', r.get('description', ''))}",
           f"🕒 {local_time(a.get('timestamp'))}",
           f"📋 rule {r.get('id')} · {a.get('agent', {}).get('name')}"]
    user = d.get("dstuser") or d.get("srcuser")
    if user:
        out.append(f"👤 {user}")
    ip = src_ip(a)
    if ip:
        out.append(f"🌐 {ip}")
    is_req, det = detail(a)
    if det:
        out.append(("↪ " if is_req else "📝 ") + det)
    return "\n".join(out)


def row_dict(r):
    ts, lvl, rid, desc, ip, user, det, groups = r
    return {"ts": ts.isoformat(), "level": lvl, "rule": rid, "desc": desc,
            "ip": ip, "user": user, "detail": det, "groups": groups or ""}


class Archive:
    def __init__(self):
        self.conn = None
        self.next_try = 0
        self.pending = deque(maxlen=5000)

    def _connect(self):
        if psycopg2 is None:
            return None
        if self.conn is not None and not self.conn.closed:
            return self.conn
        if time.time() < self.next_try:
            return None
        try:
            self.conn = psycopg2.connect(connect_timeout=3)
            self.conn.autocommit = True
        except Exception as e:
            log(f"db connect failed: {e}")
            self.conn, self.next_try = None, time.time() + 30
        return self.conn

    def _reset(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        self.conn, self.next_try = None, time.time() + 30

    def add(self, a):
        r, d = a.get("rule", {}), a.get("data", {})
        aid = a.get("id") or hashlib.sha1(json.dumps(a, sort_keys=True).encode()).hexdigest()
        self.pending.append((
            str(aid), parse_ts(a.get("timestamp")), int(r.get("id", 0)), int(r.get("level", 0)),
            ANSI.sub("", r.get("description", "")), src_ip(a),
            d.get("dstuser") or d.get("srcuser"), ",".join(r.get("groups", [])), detail(a)[1]))

    def flush(self):
        if not self.pending:
            return
        conn = self._connect()
        if conn is None:
            return
        rows = list(self.pending)
        try:
            with conn.cursor() as cur:
                cur.executemany(INSERT_SQL, rows)
            self.pending.clear()
        except Exception as e:
            log(f"db insert failed: {e}")
            self._reset()

    def summary(self):
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        if conn is None:
            return {"ok": False, "generated": now}
        p = {"min": MIN_LEVEL}
        try:
            with conn.cursor() as cur:
                cur.execute(COUNTS_SQL, p)
                c = cur.fetchone()
                cur.execute(HOURLY_SQL, p)
                hourly = [{"h": h.isoformat(), "hi": hi, "lo": lo} for h, hi, lo in cur.fetchall()]
                cur.execute(TOP_RULES_SQL)
                top_rules = [[f"{rid} · {DYNAMIC.sub('', desc)}", n] for rid, n, desc in cur.fetchall()]
                cur.execute(TOP_IPS_SQL)
                top_ips = [[ip, n] for ip, n in cur.fetchall()]
                cur.execute(LEVELS_SQL)
                levels = [[f"L{lvl}", n] for lvl, n in cur.fetchall()]
                cur.execute(ROWS_SQL, (100,))
                recent = [row_dict(r) for r in cur.fetchall()]
        except Exception as e:
            log(f"db summary failed: {e}")
            self._reset()
            return {"ok": False, "generated": now}
        return {"ok": True, "generated": now, "min_level": MIN_LEVEL, "archive_level": ARCHIVE_LEVEL,
                "counts": {"total_24h": c[0], "high_24h": c[1], "logins_24h": c[2],
                           "failed_logins_24h": c[3], "waf_24h": c[4], "all_time": c[5],
                           "total_7d": c[6], "uniq_ips_7d": c[7]},
                "hourly": hourly, "top_rules": top_rules, "top_ips": top_ips,
                "levels": levels, "recent": recent}

    def full(self):
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        if conn is None:
            return {"ok": False, "generated": now, "count": 0, "entries": []}
        try:
            with conn.cursor() as cur:
                cur.execute(ROWS_SQL, (FULL_LIMIT,))
                entries = [row_dict(r) for r in cur.fetchall()]
        except Exception as e:
            log(f"db full failed: {e}")
            self._reset()
            return {"ok": False, "generated": now, "count": 0, "entries": []}
        return {"ok": True, "generated": now, "count": len(entries), "entries": entries}


def write_json(path, obj):
    try:
        fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix=".tmp-", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except Exception as e:
        log(f"write_json {path} failed: {e}")


def follow(path):
    """Yields (line, live) tuples, or None when idle.
    On first open the existing file is replayed with live=False (archive only)."""
    f, ino, buf, live = None, None, "", False
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(2)
            yield None
            continue
        if f is None or st.st_ino != ino or st.st_size < f.tell():
            rotated = f is not None
            if f:
                f.close()
            f = open(path, "r", encoding="utf-8", errors="replace")
            ino, buf, live = st.st_ino, "", rotated
        chunk = f.readline()
        if not chunk:
            live = True
            time.sleep(1)
            yield None
            continue
        buf += chunk
        if buf.endswith("\n"):
            yield (buf, live)
            buf = ""


def main():
    seen, arch = {}, Archive()
    last_summary = last_full = 0
    send(f"✅ wazuh-telegram started on homeserver (telegram ≥{MIN_LEVEL}, archive ≥{ARCHIVE_LEVEL})")
    for item in follow(ALERTS):
        now = time.time()
        if item is not None:
            line, live = item
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                a = None
            if a:
                rule = a.get("rule", {})
                lvl = int(rule.get("level", 0))
                if lvl >= ARCHIVE_LEVEL:
                    arch.add(a)
                if live and lvl >= MIN_LEVEL:
                    key = (rule.get("id"), src_ip(a))
                    if now - seen.get(key, 0) >= COOLDOWN:
                        seen[key] = now
                        send(fmt(a))
                        time.sleep(1.1)
        if item is None or len(arch.pending) >= 200:
            arch.flush()
        if now - last_summary >= SUMMARY_EVERY:
            arch.flush()
            write_json(SUMMARY_JSON, arch.summary())
            last_summary = now
        if now - last_full >= FULL_EVERY:
            write_json(FULL_JSON, arch.full())
            last_full = now


if __name__ == "__main__":
    main()
