#!/usr/bin/env bash
# Instalador de nginx-panel (Debian/Ubuntu y RHEL/Rocky/Alma).
# Uso:  sudo ./install.sh [--bind 0.0.0.0] [--port 8181] [--allow 192.168.88.0/24,10.8.0.0/24]
#                         [--with-nginx] [--behind-proxy]
# Por defecto el panel escucha en todas las interfaces (0.0.0.0) y acepta cualquier IP.
set -euo pipefail

BIND="0.0.0.0"; BIND_SET=0; PORT="8181"; ALLOW=""; WITH_NGINX=0; BEHIND_PROXY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bind) BIND="$2"; BIND_SET=1; shift ;;
    --port) PORT="$2"; shift ;;
    --allow) ALLOW="$2"; shift ;;
    --with-nginx) WITH_NGINX=1 ;;
    --behind-proxy) BEHIND_PROXY=1 ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1"; exit 1 ;;
  esac; shift
done
# Detrás de un proxy, el panel solo debe escuchar en localhost: si fuera accesible
# directamente, cualquiera podría falsear X-Forwarded-For.
if [ $BEHIND_PROXY -eq 1 ] && [ $BIND_SET -eq 0 ]; then BIND="127.0.0.1"; fi

[ "$(id -u)" -eq 0 ] || { echo "Ejecuta como root (sudo)."; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/nginx-panel

echo "==> Dependencias del sistema"
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
  echo "Solo se soportan sistemas con apt o dnf."; exit 1
fi

echo "==> Copiando a $DEST"
mkdir -p "$DEST"
cp -r "$SRC/nginxpanel" "$SRC/requirements.txt" "$DEST/"
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

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
# Configuración de nginx-panel (se lee al arrancar el servicio)
NP_BIND=$BIND
NP_PANEL_PORT=$PORT
NP_BEHIND_PROXY=$BEHIND_PROXY
# Proxies cuyo X-Forwarded-For se acepta (solo con NP_BEHIND_PROXY=1)
NP_TRUSTED_PROXIES=127.0.0.1,::1
# Redes que pueden usar el panel (CIDR separados por comas). Vacío = cualquiera.
NP_ALLOWED_NETS=$ALLOW
# Pon 1 si accedes al panel por HTTPS (cookies Secure)
NP_SECURE_COOKIES=$BEHIND_PROXY
ENV
  chmod 600 /etc/nginx-panel.env
elif ! grep -q '^NP_TRUSTED_PROXIES=' /etc/nginx-panel.env; then
  cat >> /etc/nginx-panel.env <<ENV
# Proxies cuyo X-Forwarded-For se acepta (solo con NP_BEHIND_PROXY=1). Si tu proxy está en
# otra máquina, añade aquí su IP.
NP_TRUSTED_PROXIES=127.0.0.1,::1
ENV
fi

echo "==> Servicio systemd"
cat > /etc/systemd/system/nginx-panel.service <<UNIT
[Unit]
Description=nginx-panel (administración web de nginx)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/nginx-panel.env
WorkingDirectory=$DEST
ExecStart=$DEST/venv/bin/gunicorn --workers 1 --threads 8 --timeout 120 \\
  --no-control-socket --bind \${NP_BIND}:\${NP_PANEL_PORT} --access-logfile - nginxpanel.wsgi:app
Restart=on-failure
# Necesita root: escribe en /etc/nginx, recarga nginx, ejecuta certbot y apt.
User=root
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
UNIT

# Si un backend usa nombres DNS que aún no resuelven al arrancar, nginx falla.
# systemd lo reintenta cada minuto, sin límite, hasta que arranca. (El panel también lo
# instala al aplicar la configuración; systemd lo ignora si nginx no está instalado.)
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/nginx-panel-restart.conf <<DROPIN
# Generado por nginx-panel: reintenta arrancar nginx cada minuto si falla (DNS de backends)
[Unit]
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=60
DROPIN

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

# Contraseña inicial: se genera aquí y se pasa por stdin (no aparece en ps ni en logs).
# Solo se crea el admin si aún no existe ningún usuario.
PW=""
if ! /usr/local/bin/nginx-panel has-users >/dev/null 2>&1; then
  PW=$(openssl rand -hex 12)
  printf '%s\n' "$PW" | /usr/local/bin/nginx-panel create-admin admin --password-stdin >/dev/null
fi

echo
echo "================================================================"
if [ "$BIND" = "0.0.0.0" ]; then
  IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v ':' | head -3 | sed "s|.*|http://&:$PORT|" | tr '\n' ' ')
else
  IPS="http://$BIND:$PORT"
fi
echo " nginx-panel instalado. Escucha en $BIND:$PORT  →  ${IPS:-http://IP:$PORT}"
if [ "$BIND" = "127.0.0.1" ]; then
  echo " Solo accesible desde este servidor. Desde tu equipo, con un túnel SSH:"
  echo "     ssh -L $PORT:127.0.0.1:$PORT usuario@servidor   y abre http://127.0.0.1:$PORT"
  echo " y publícalo como host con HTTPS desde el propio panel."
fi
[ -n "$PW" ] && echo " Usuario: admin   Contraseña: $PW   (cámbiala y activa 2FA)"
if [ "$BIND" = "0.0.0.0" ] && [ -z "$ALLOW" ]; then
  echo " AVISO: el panel (que corre como root) es accesible desde cualquier IP."
  echo "        Activa 2FA y limita el acceso con NP_ALLOWED_NETS en /etc/nginx-panel.env"
  echo "        o con el firewall (puerto $PORT)."
fi
echo " Siguiente paso en el panel: Sistema → Tomar el control de nginx"
echo "================================================================"
