#!/usr/bin/env bash
# nginx-panel installer (Debian/Ubuntu and RHEL/Rocky/Alma).
# Usage: sudo ./install.sh [--bind 0.0.0.0] [--port 8181] [--allow 192.168.88.0/24,10.8.0.0/24]
#                         [--with-nginx] [--behind-proxy]
# By default the panel listens on all interfaces (0.0.0.0) and accepts any IP.
set -euo pipefail

BIND="0.0.0.0"; PORT="8181"; ALLOW=""; WITH_NGINX=0; BEHIND_PROXY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bind) BIND="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --allow) ALLOW="$2"; shift ;;
    --with-nginx) WITH_NGINX=1 ;;
    --behind-proxy) BEHIND_PROXY=1 ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac; shift
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/nginx-panel

echo "==> System dependencies"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q python3 python3-venv openssl logrotate
  [ $WITH_NGINX -eq 1 ] && apt-get install -y -q nginx libnginx-mod-stream certbot
  LOGGROUP=adm
elif command -v dnf >/dev/null; then
  dnf install -y python3 openssl logrotate
  if [ $WITH_NGINX -eq 1 ]; then dnf install -y epel-release || true; dnf install -y nginx nginx-mod-stream certbot; fi
  LOGGROUP=root
else
  echo "Only systems with apt or dnf are supported."; exit 1
fi

echo "==> Copying to $DEST"
mkdir -p "$DEST"
cp -r "$SRC/nginxpanel" "$SRC/requirements.txt" "$DEST/"
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

FIRST_INSTALL=0; [ -f /var/lib/nginx-panel/panel.db ] || FIRST_INSTALL=1
install -d -m 700 /var/lib/nginx-panel
install -d -m 750 /var/log/nginx/panel

cat > /usr/local/bin/nginx-panel <<WRAP
#!/bin/sh
set -a; [ -f /etc/nginx-panel.env ] && . /etc/nginx-panel.env; set +a
cd $DEST && exec $DEST/venv/bin/python -m nginxpanel "\$@"
WRAP
chmod 755 /usr/local/bin/nginx-panel

if [ ! -f /etc/nginx-panel.env ]; then
  cat > /etc/nginx-panel.env <<ENV
# nginx-panel configuration (read when the service starts)
NP_BIND=$BIND
NP_PANEL_PORT=$PORT
NP_BEHIND_PROXY=$BEHIND_PROXY
# Networks allowed to use the panel (comma-separated CIDRs). Empty = any.
NP_ALLOWED_NETS=$ALLOW
# Set to 1 if you access the panel over HTTPS (Secure cookies)
NP_SECURE_COOKIES=$BEHIND_PROXY
ENV
  chmod 600 /etc/nginx-panel.env
fi

echo "==> systemd service"
cat > /etc/systemd/system/nginx-panel.service <<UNIT
[Unit]
Description=nginx-panel (web administration for nginx)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/nginx-panel.env
WorkingDirectory=$DEST
ExecStart=$DEST/venv/bin/gunicorn --workers 1 --threads 8 --timeout 120 \\
  --no-control-socket --bind \${NP_BIND}:\${NP_PANEL_PORT} --access-logfile - nginxpanel.wsgi:app
Restart=on-failure
# Needs root: writes to /etc/nginx, reloads nginx, runs certbot and apt.
User=root
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
UNIT

echo "==> logrotate"
cat > /etc/logrotate.d/nginx-panel <<ROT
/var/log/nginx/panel/*.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    create 0640 root $LOGGROUP
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 \$(cat /run/nginx.pid) || true
    endscript
}
ROT

systemctl daemon-reload
systemctl enable --now nginx-panel

# The admin is only created on the first install: re-running the installer keeps existing users.
PW=""
if [ $FIRST_INSTALL -eq 1 ]; then
  OUT=$(/usr/local/bin/nginx-panel create-admin admin --random 2>/dev/null || true)
  PW=$(printf '%s\n' "$OUT" | sed -n 's/^Password: //p')
fi

echo
echo "================================================================"
if [ "$BIND" = "0.0.0.0" ]; then
  IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v -e ':' -e '^$' | head -3 | sed "s|.*|http://&:$PORT|" | tr '\n' ' ')
else
  IPS="http://$BIND:$PORT"
fi
echo " nginx-panel installed. Listening on $BIND:$PORT  →  ${IPS:-http://IP:$PORT}"
if [ -n "$PW" ]; then
  echo " User: admin   Password: $PW   (change it and enable 2FA)"
else
  echo " Existing users kept. Lost access? sudo nginx-panel create-admin admin --random"
fi
if [ "$BIND" = "0.0.0.0" ] && [ -z "$ALLOW" ]; then
  echo " WARNING: the panel (which runs as root) is reachable from any IP."
  echo "          Enable 2FA and restrict access with NP_ALLOWED_NETS in /etc/nginx-panel.env"
  echo "          or with the firewall (port $PORT)."
fi
echo " Next step in the panel: System → Take control of nginx"
echo "================================================================"
