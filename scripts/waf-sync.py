#!/usr/bin/env python3
"""Summarise Coraza WAF blocks (from Caddy's JSON access log) into waf.json
for the lobby card + /waf/ dashboard.

A genuine WAF block is identified by status 403 + the X-Waf-Block: true
response header, which the Caddyfile's `handle_errors 403` block sets only
when coraza_waf itself raised the error (not a plain 403 from an upstream
app like Adminer/Filebrowser)."""
import glob, gzip, json, os, re, sys, tempfile, time
try:
    import psycopg2
except ImportError:
    psycopg2 = None
from collections import Counter
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote_plus

LOGDIR = os.environ.get("WAF_LOGDIR", "/var/log/caddy")
LOGBASENAME = "access.log"
OUT = os.environ.get("WAF_OUT", "/var/www/homeserver/waf.json")
OUT_FULL = os.environ.get("WAF_OUT_FULL", "/var/www/homeserver/waf-full.json")
CADDYFILE = "/etc/caddy/Caddyfile"

TYPES = [
    ("XSS", re.compile(r"<\s*script|onerror\s*=|onload\s*=|javascript:|<\s*svg|<\s*img|alert\s*\(")),
    ("SQLi", re.compile(r"union[\s/*]+select|'\s*or\s*'|'\s*or\s+\d|\bselect\b.+\bfrom\b|sleep\s*\(|benchmark\s*\(|;\s*drop\s|'\s*--")),
    ("Path traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|/proc/self")),
    ("Command injection", re.compile(r"[;|&]\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh)\b|\$\(|`")),
    ("Scanner probe", re.compile(r"\.env\b|wp-admin|wp-login|phpmyadmin|\.git/|xmlrpc|/cgi-bin/|\.php\b")),
]


def classify(path):
    p = unquote_plus(unquote_plus(path)).lower()
    for name, rx in TYPES:
        if rx.search(p):
            return name
    return "Other"


def mode():
    try:
        with open(CADDYFILE) as f:
            content = f.read()
        m = re.search(r"SecRuleEngine\s+(\S+)", content)
        return m.group(1) if m else "unknown"
    except OSError:
        return "unknown"


def is_block(entry):
    if entry.get("status") != 403:
        return False
    headers = entry.get("resp_headers", {}) or {}
    for k, v in headers.items():
        if k.lower() == "x-waf-block" and v and str(v[0]).lower() == "true":
            return True
    return False


def parse_file(path, opener=open, mode_str="r"):
    rows = []
    try:
        with opener(path, mode_str, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not is_block(entry):
                    continue
                req = entry.get("request", {})
                ts = entry.get("ts")
                if ts is None:
                    continue
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                ip = req.get("client_ip") or req.get("remote_ip") or "?"
                method = req.get("method", "?")
                uri = req.get("uri", "")
                rows.append((dt, ip, method, uri[:300]))
    except OSError:
        pass
    return rows


_gz_cache = {}  # path -> (mtime, rows); rotated files never change, parse once


def all_rows():
    rows = []
    rotated = sorted(glob.glob(os.path.join(LOGDIR, "access-*.log*")))
    for path in rotated:
        if path.endswith(".gz"):
            try:
                mt = os.path.getmtime(path)
                if _gz_cache.get(path, (None,))[0] != mt:
                    _gz_cache[path] = (mt, parse_file(path, gzip.open, "rt"))
                rows += _gz_cache[path][1]
            except OSError:
                continue
        else:
            rows += parse_file(path)
    rows += parse_file(os.path.join(LOGDIR, LOGBASENAME))
    rows.sort(key=lambda r: r[0])
    return rows


def build(now):
    rows = [r for r in all_rows() if r[0] >= now - timedelta(days=7)]
    day = [r for r in rows if r[0] >= now - timedelta(hours=24)]
    start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    hourly = Counter(int((r[0] - start).total_seconds() // 3600) for r in day)
    return {
        "mode": mode(),
        "engine": "Coraza (Caddy)",
        "updated": now.isoformat(),
        "count24h": len(day),
        "count7d": len(rows),
        "uniq7d": len({r[1] for r in rows}),
        "hourly": [{"h": (start + timedelta(hours=i)).isoformat(), "n": hourly.get(i, 0)} for i in range(24)],
        "topIps": Counter(r[1] for r in rows).most_common(8),
        "topPaths": Counter(r[3].split("?", 1)[0] for r in rows).most_common(8),
        "types": Counter(classify(r[3]) for r in rows).most_common(),
        "recent": [{"t": r[0].isoformat(), "ip": r[1], "m": r[2], "p": r[3], "c": classify(r[3])}
                   for r in reversed(rows[-100:])],
    }


def build_full(now):
    conn = pg_conn()
    if conn is not None:
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT ts, ip, method, path, type FROM waf_blocks "
                        "ORDER BY ts DESC LIMIT 20000"
                    )
                    db_rows = cur.fetchall()
            return {
                "updated": now.isoformat(),
                "source": "postgres",
                "count": len(db_rows),
                "entries": [
                    {"t": ts.isoformat(), "ip": ip, "m": method, "p": path, "c": ctype}
                    for (ts, ip, method, path, ctype) in db_rows
                ],
            }
        except Exception:
            pass
        finally:
            conn.close()
    # fallback if Postgres is unreachable: same as before, last 7 days from log files
    rows = [r for r in all_rows() if r[0] >= now - timedelta(days=7)]
    return {
        "updated": now.isoformat(),
        "source": "files-fallback",
        "count": len(rows),
        "entries": [{"t": r[0].isoformat(), "ip": r[1], "m": r[2], "p": r[3], "c": classify(r[3])}
                    for r in reversed(rows)],
    }


def pg_conn():
    if psycopg2 is None:
        return None
    try:
        return psycopg2.connect(
            host=os.environ.get("PGHOST", "127.0.0.1"),
            port=os.environ.get("PGPORT", "5432"),
            dbname=os.environ.get("PGDATABASE", "homedb"),
            user=os.environ.get("PGUSER"),
            password=os.environ.get("PGPASSWORD"),
            connect_timeout=3,
        )
    except Exception:
        return None


def archive_to_postgres(rows):
    conn = pg_conn()
    if conn is None:
        return
    try:
        with conn:
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO waf_blocks (ts, ip, method, path, type) "
                    "VALUES (%s, %s, %s, %s, %s) "
                    "ON CONFLICT (ts, ip, method, path) DO NOTHING",
                    [(r[0], r[1], r[2], r[3], classify(r[3])) for r in rows],
                )
    except Exception:
        pass
    finally:
        conn.close()


def write(data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(OUT))
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT)


def write_full(data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(OUT_FULL))
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT_FULL)


if __name__ == "__main__":
    once = "--once" in sys.argv
    while True:
        now = datetime.now(timezone.utc)
        rows_7d = [r for r in all_rows() if r[0] >= now - timedelta(days=7)]
        archive_to_postgres(rows_7d)
        write(build(now))
        write_full(build_full(now))
        if once:
            break
        time.sleep(30)
