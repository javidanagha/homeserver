#!/bin/bash
set -e

mkdir -p "$HOME/.vnc"
echo "${VNC_PASSWORD:?VNC_PASSWORD is not set}" | vncpasswd -f > "$HOME/.vnc/passwd"
chmod 600 "$HOME/.vnc/passwd"

cat > "$HOME/.vnc/xstartup" <<'EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec dbus-launch --exit-with-session startxfce4
EOF
chmod +x "$HOME/.vnc/xstartup"

rm -f /tmp/.X1-lock /tmp/.X11-unix/X1

exec vncserver :1 \
    -geometry "${VNC_GEOMETRY:-1280x720}" \
    -depth 24 \
    -localhost no \
    -SecurityTypes VncAuth \
    -fg
