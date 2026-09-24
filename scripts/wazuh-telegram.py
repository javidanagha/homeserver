#!/usr/bin/env python3
import json, os, re, time, urllib.parse, urllib.request
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Asia/Baku")
except Exception:
    TZ = None

ALERTS = "/var/ossec/logs/alerts/alerts.json"
TOKEN = os.environ["TG_TOKEN"]
CHAT = os.environ["TG_CHAT"]
MIN_LEVEL = int(os.environ.get("MIN_LEVEL", "10"))
COOLDOWN = 60
API = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SYSLOG_HDR = re.compile(r"^\w{3} +\d+ [\d:]+ \S+ ")

def send(text):
    data = urllib.parse.urlencode({"chat_id": CHAT, "text": text[:4000],
                                   "disable_web_page_preview": "true"}).encode()
    for attempt in range(3):
        try:
            with urllib.request.urlopen(API, data=data, timeout=10) as r:
                return r.status == 200
        except Exception as e:
            print(f"send failed ({attempt+1}/3): {e}", flush=True)
            time.sleep(5)
    return False

def local_time(ts):
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
        if TZ:
            dt = dt.astimezone(TZ)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts or "?"

def src_ip(a):
    d = a.get("data", {})
    req = d.get("request") if isinstance(d.get("request"), dict) else {}
    return d.get("srcip") or req.get("client_ip")

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
    req = d.get("request")
    if isinstance(req, dict) and req.get("method"):
        out.append(f"↪ {req.get('method')} {req.get('uri', '')} → {d.get('status', '?')}")
    elif a.get("full_log"):
        log = SYSLOG_HDR.sub("", ANSI.sub("", a["full_log"]))
        out.append(f"📝 {log[:300]}")
    return "\n".join(out)

def follow(path):
    f, ino, buf = None, None, ""
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(2); continue
        if f is None or st.st_ino != ino or st.st_size < f.tell():
            first = f is None
            if f: f.close()
            f = open(path, "r", encoding="utf-8", errors="replace")
            if first: f.seek(0, os.SEEK_END)
            ino, buf = st.st_ino, ""
        chunk = f.readline()
        if not chunk:
            time.sleep(1); continue
        buf += chunk
        if buf.endswith("\n"):
            yield buf; buf = ""

def main():
    seen = {}
    send(f"✅ wazuh-telegram started on homeserver (min level {MIN_LEVEL})")
    for line in follow(ALERTS):
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule = a.get("rule", {})
        if int(rule.get("level", 0)) < MIN_LEVEL:
            continue
        key = (rule.get("id"), src_ip(a))
        now = time.time()
        if now - seen.get(key, 0) < COOLDOWN:
            continue
        seen[key] = now
        send(fmt(a))
        time.sleep(1.1)

if __name__ == "__main__":
    main()
