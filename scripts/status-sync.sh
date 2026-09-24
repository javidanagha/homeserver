#!/bin/bash
DB=/home/homeserver/uptime-kuma/data/kuma.db
OUT=/var/www/homeserver/status.json
IDS="1 2 3 4 5 6"
while true; do
  tmp=$(mktemp)
  echo -n "{" > "$tmp"
  first=1
  for id in $IDS; do
    status=$(sqlite3 -readonly "$DB" "SELECT status FROM heartbeat WHERE monitor_id=$id ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$status" ] && status=null
    if [ $first -eq 1 ]; then first=0; else echo -n "," >> "$tmp"; fi
    echo -n "\"$id\":$status" >> "$tmp"
  done
  echo "}" >> "$tmp"
  mv "$tmp" "$OUT"
  chmod 644 "$OUT"
  sleep 15
done
