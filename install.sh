#!/usr/bin/env bash
# nginx-panel · instalador y actualizador para Debian 13 (trixie)
#
#   sudo ./install.sh            instala, o actualiza si ya está instalado
#
# Sin opciones pregunta lo necesario (proxy inverso, puerto, redes permitidas, nginx).
# En una actualización muestra la configuración actual y vuelve a preguntar por el proxy
# inverso; Enter mantiene cada valor.
#
# Opciones (cada una evita su pregunta):
#   --port N                 puerto del panel (8181)
#   --bind IP                IP de escucha (0.0.0.0 = todas)
#   --allow CIDR,...         redes que pueden usar el panel ("" = cualquiera)
#   --behind-proxy           el panel se publica detrás de un proxy inverso
#   --no-proxy               acceso directo, sin proxy
#   --trusted-proxies IP,... IPs de proxies en otra máquina (implica --behind-proxy)
#   --https | --no-https     el proxy sirve el panel por HTTPS (cookies Secure)
#   --with-nginx | --no-nginx  instalar nginx + módulo stream + certbot
#   -y, --yes                no preguntar nada: opciones + configuración actual + valores por defecto
set -euo pipefail

ENV_FILE=/etc/nginx-panel.env
DEST=/opt/nginx-panel
SRC="$(cd "$(dirname "$0")" && pwd)"
LOOPBACK="127.0.0.1,::1"

# ---------------------------------------------------------------- estilo
if [ -t 1 ]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
else
  B=""; D=""; R=""; G=""; Y=""; C=""; N=""
fi
step() { printf '\n%s==>%s %s%s%s\n' "$C" "$N" "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
note() { printf '  %s%s%s\n' "$D" "$*" "$N"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

# ---------------------------------------------------------------- opciones
O_PORT=""; O_BIND=""; O_ALLOW=""; O_ALLOW_SET=0; O_PROXY=""; O_TRUSTED=""; O_HTTPS=""; O_NGINX=""
ASSUME_YES=0
need() { [ $# -ge 2 ] || die "Falta el valor de $1"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --port) need "$@"; O_PORT="$2"; shift ;;
    --bind) need "$@"; O_BIND="$2"; shift ;;
    --allow) need "$@"; O_ALLOW="$2"; O_ALLOW_SET=1; shift ;;
    --behind-proxy) O_PROXY=1 ;;
    --no-proxy) O_PROXY=0 ;;
    --trusted-proxies) need "$@"; O_TRUSTED="$2"; O_PROXY=1; shift ;;
    --https) O_HTTPS=1 ;;
    --no-https) O_HTTPS=0 ;;
    --with-nginx) O_NGINX=1 ;;
    --no-nginx) O_NGINX=0 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) die "Opción desconocida: $1 (usa --help)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root: sudo ./install.sh"

# Preguntas: desde la terminal aunque el script llegue por una tubería.
ASK=0
if [ $ASSUME_YES -eq 0 ] && { exec 3</dev/tty; } 2>/dev/null; then ASK=1; fi

# ask VAR "pregunta" "por defecto" [validador] [mensaje de error]
ask() {
  local __var=$1 prompt=$2 def=$3 check=${4:-} err=${5:-Valor no válido} ans
  while :; do
    ans=""
    if [ $ASK -eq 1 ]; then
      printf '  %s?%s %s %s[%s]%s: ' "$C" "$N" "$prompt" "$D" "${def:-vacío}" "$N" >&2
      IFS= read -r ans <&3 || ans=""
    fi
    ans="${ans:-$def}"
    [ "$ans" = "-" ] && ans=""
    if [ -z "$check" ] || "$check" "$ans"; then
      printf -v "$__var" '%s' "$ans"
      return
    fi
    [ $ASK -eq 1 ] || die "$err: '$ans'"
    warn "$err"
  done
}

# confirm "pregunta" s|n  →  0 = sí
confirm() {
  local prompt=$1 def=$2 ans hint="s/N"
  [ "$def" = s ] && hint="S/n"
  while :; do
    ans=""
    if [ $ASK -eq 1 ]; then
      printf '  %s?%s %s %s[%s]%s: ' "$C" "$N" "$prompt" "$D" "$hint" "$N" >&2
      IFS= read -r ans <&3 || ans=""
    fi
    ans="${ans:-$def}"
    case "${ans,,}" in
      s|si|sí|y|yes) return 0 ;;
      n|no) return 1 ;;
    esac
    warn "Responde s o n"
  done
}

# choose VAR "pregunta" defecto "opción 1" "opción 2"...  →  VAR = número elegido
choose() {
  local __cvar=$1 __cprompt=$2 __cdef=$3 i=1
  shift 3
  if [ $ASK -eq 1 ]; then
    printf '  %s?%s %s\n' "$C" "$N" "$__cprompt" >&2
    for o in "$@"; do printf '      %s%d)%s %s\n' "$B" "$i" "$N" "$o" >&2; i=$((i + 1)); done
  fi
  ask __pick "Elige" "$__cdef" "_in_range_$#" "Elige un número de la lista"
  printf -v "$__cvar" '%s' "$__pick"
}
_in_range_2() { [[ $1 =~ ^[12]$ ]]; }

# ---------------------------------------------------------------- validadores
_py_ok() { command -v python3 >/dev/null 2>&1; }
valid_port() { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_ip() {
  if _py_ok; then python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null
  else [[ $1 =~ ^[0-9A-Fa-f:.]+$ ]]; fi
}
valid_cidrs() {   # lista separada por comas; vacía = válida
  [ -z "$1" ] && return 0
  if _py_ok; then
    python3 -c 'import ipaddress,sys
for x in sys.argv[1].split(","):
    if x.strip(): ipaddress.ip_network(x.strip(), strict=False)' "$1" 2>/dev/null
  else [[ $1 =~ ^[0-9A-Fa-f:.,/\ ]+$ ]]; fi
}
valid_cidrs_req() { [ -n "$1" ] && valid_cidrs "$1"; }

# ---------------------------------------------------------------- sistema
step "Sistema"
OS_ID=""; OS_VER=""; OS_NAME="desconocido"
if [ -r /etc/os-release ]; then
  OS_ID=$(. /etc/os-release; echo "${ID:-}")
  OS_VER=$(. /etc/os-release; echo "${VERSION_ID:-}")
  OS_NAME=$(. /etc/os-release; echo "${PRETTY_NAME:-$OS_ID $OS_VER}")
fi
command -v apt-get >/dev/null || die "Este instalador es para Debian 13 (necesita apt). Detectado: $OS_NAME"
if [ "$OS_ID" = debian ] && [ "$OS_VER" = 13 ]; then
  ok "$OS_NAME"
else
  warn "$OS_NAME no está soportado oficialmente (solo Debian 13)."
  [ $ASK -eq 1 ] || die "Sistema no soportado. Ejecuta sin -y para confirmar que quieres continuar."
  confirm "¿Continuar igualmente?" n || exit 1
fi

# ---------------------------------------------------------------- configuración
getenv() { [ -f "$ENV_FILE" ] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 || true; }
UPDATE=0
if [ -f "$ENV_FILE" ]; then UPDATE=1; fi

CUR_PORT=$(getenv NP_PANEL_PORT);       CUR_PORT=${CUR_PORT:-8181}
CUR_BIND=$(getenv NP_BIND);             CUR_BIND=${CUR_BIND:-0.0.0.0}
CUR_ALLOW=$(getenv NP_ALLOWED_NETS)
CUR_PROXY=$(getenv NP_BEHIND_PROXY);    CUR_PROXY=${CUR_PROXY:-0}
CUR_TRUSTED=$(getenv NP_TRUSTED_PROXIES); CUR_TRUSTED=${CUR_TRUSTED:-$LOOPBACK}
CUR_HTTPS=$(getenv NP_SECURE_COOKIES);  CUR_HTTPS=${CUR_HTTPS:-$CUR_PROXY}
# Proxies remotos = los de confianza que no son localhost
CUR_REMOTE=$(printf '%s' "$CUR_TRUSTED" | tr ',' '\n' | sed 's/ //g' | grep -vxE '127\.0\.0\.1|::1|' | paste -sd, - || true)

yn() { [ "$1" = 1 ] && echo s || echo n; }

if [ $UPDATE -eq 1 ]; then
  step "Actualización · configuración actual ($ENV_FILE)"
  if [ "$CUR_PROXY" = 1 ]; then
    if [ -n "$CUR_REMOTE" ]; then note "Proxy inverso:  sí, en otra máquina ($CUR_REMOTE)"
    else note "Proxy inverso:  sí, en este servidor"; fi
    note "HTTPS:          $([ "$CUR_HTTPS" = 1 ] && echo sí || echo no)"
  else
    note "Proxy inverso:  no (acceso directo)"
  fi
  note "Escucha en:     $CUR_BIND:$CUR_PORT"
  note "Redes con acceso: ${CUR_ALLOW:-cualquiera}"
  echo
  note "Enter mantiene el valor entre corchetes; '-' lo deja vacío."
else
  step "Configuración"
  note "Enter acepta el valor entre corchetes; '-' lo deja vacío."
fi

# --- proxy inverso (se pregunta siempre, también al actualizar)
echo
note "Un proxy inverso publica el panel con tu dominio y HTTPS (https://panel.tudominio.com)."
note "Lo habitual es usar el nginx de este mismo servidor, gestionado desde el propio panel."
if [ -n "$O_PROXY" ]; then PROXY=$O_PROXY
elif confirm "¿Vas a publicar el panel detrás de un proxy inverso?" "$(yn "$CUR_PROXY")"; then PROXY=1
else PROXY=0; fi

TRUSTED=$LOOPBACK; REMOTE=""; WHERE=0
if [ "$PROXY" = 1 ]; then
  if [ -n "$O_TRUSTED" ]; then
    valid_cidrs_req "$O_TRUSTED" || die "--trusted-proxies no válido: $O_TRUSTED"
    WHERE=2; REMOTE=$O_TRUSTED
  else
    def_where=1; [ -n "$CUR_REMOTE" ] && def_where=2
    choose WHERE "¿Dónde está el proxy inverso?" "$def_where" \
      "En este servidor (el nginx que gestiona el panel) — recomendado" \
      "En otra máquina (otro nginx, HAProxy, Traefik, Cloudflare Tunnel…)"
    REMOTE=""
    if [ "$WHERE" = 2 ]; then
      ask REMOTE "IP(s) del proxy, separadas por comas" "$CUR_REMOTE" valid_cidrs_req \
        "Indica al menos una IP o CIDR válida (ej. 10.0.0.2)"
    fi
  fi
  [ -n "$REMOTE" ] && TRUSTED="$LOOPBACK,$REMOTE"

  if [ -n "$O_BIND" ]; then BIND=$O_BIND
  elif [ "$WHERE" = 1 ]; then
    BIND=127.0.0.1
    note "El panel escuchará solo en 127.0.0.1: nadie puede saltarse el proxy."
  else
    def_bind=$CUR_BIND; [ "$def_bind" = 127.0.0.1 ] && def_bind=0.0.0.0
    ask BIND "IP de este servidor por la que llega el proxy (0.0.0.0 = todas)" "$def_bind" valid_ip "IP no válida"
  fi

  if [ -n "$O_HTTPS" ]; then HTTPS=$O_HTTPS
  else
    def_https=s; [ "$CUR_PROXY" = 1 ] && def_https=$(yn "$CUR_HTTPS")
  fi
  if [ -n "$O_HTTPS" ]; then :
  elif confirm "¿El proxy sirve el panel por HTTPS? (activa cookies Secure)" "$def_https"; then HTTPS=1
  else HTTPS=0; fi
else
  if [ -n "$O_BIND" ]; then BIND=$O_BIND
  else
    def_bind=$CUR_BIND; [ "$CUR_PROXY" = 1 ] && def_bind=0.0.0.0
    ask BIND "IP de escucha del panel (0.0.0.0 = todas)" "$def_bind" valid_ip "IP no válida"
  fi
  HTTPS=${O_HTTPS:-0}
fi
valid_ip "$BIND" || die "IP de escucha no válida: $BIND"

# --- resto de ajustes
REVIEW=1
if [ $UPDATE -eq 1 ] && [ -z "$O_PORT$O_ALLOW" ] && [ $O_ALLOW_SET -eq 0 ]; then
  confirm "¿Revisar también puerto y redes con acceso?" n || REVIEW=0
fi
if [ -n "$O_PORT" ]; then PORT=$O_PORT
elif [ $REVIEW -eq 1 ]; then ask PORT "Puerto del panel" "$CUR_PORT" valid_port "Puerto entre 1 y 65535"
else PORT=$CUR_PORT; fi
valid_port "$PORT" || die "Puerto no válido: $PORT"

if [ $O_ALLOW_SET -eq 1 ]; then ALLOW=$O_ALLOW
elif [ $REVIEW -eq 1 ]; then
  [ "$PROXY" = 1 ] && note "Con proxy, se comprueba la IP real del cliente (la que reenvía el proxy)."
  ask ALLOW "Redes que pueden usar el panel (CIDR separadas por comas, vacío = cualquiera)" "$CUR_ALLOW" \
    valid_cidrs "Lista de IP/CIDR no válida (ej. 192.168.1.0/24,10.8.0.0/24)"
else ALLOW=$CUR_ALLOW; fi
valid_cidrs "$ALLOW" || die "Redes no válidas: $ALLOW"

# --- nginx
HAS_NGINX=0; command -v nginx >/dev/null 2>&1 && HAS_NGINX=1
if [ -n "$O_NGINX" ]; then WITH_NGINX=$O_NGINX
elif [ $HAS_NGINX -eq 1 ] || [ $UPDATE -eq 1 ]; then WITH_NGINX=0   # en el panel: Sistema → Instalar
elif confirm "nginx no está instalado. ¿Instalar ahora nginx + módulo stream + certbot?" s; then WITH_NGINX=1
else WITH_NGINX=0; fi

# ---------------------------------------------------------------- dependencias
step "Dependencias del sistema"
export DEBIAN_FRONTEND=noninteractive
PKGS=(python3 python3-venv openssl logrotate ca-certificates)
[ "$WITH_NGINX" = 1 ] && PKGS+=(nginx libnginx-mod-stream certbot)
apt-get update -q >/dev/null
apt-get install -y -q "${PKGS[@]}" >/dev/null
ok "${PKGS[*]}"

# ---------------------------------------------------------------- código
step "$([ $UPDATE -eq 1 ] && echo Actualizando || echo Instalando) en $DEST"
mkdir -p "$DEST"
rm -rf "$DEST/nginxpanel.new"
cp -r "$SRC/nginxpanel" "$DEST/nginxpanel.new"
find "$DEST/nginxpanel.new" -name __pycache__ -type d -prune -exec rm -rf {} +
rm -rf "$DEST/nginxpanel"
mv "$DEST/nginxpanel.new" "$DEST/nginxpanel"
cp "$SRC/requirements.txt" "$DEST/"
if ! "$DEST/venv/bin/python" -c 'import sys' >/dev/null 2>&1; then
  rm -rf "$DEST/venv"
  python3 -m venv "$DEST/venv"
fi
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q --upgrade -r "$DEST/requirements.txt"
ok "Código y entorno Python listos"

install -d -m 700 /var/lib/nginx-panel
install -d -m 750 /var/log/nginx/panel

cat > /usr/local/bin/nginx-panel <<WRAP
#!/bin/sh
set -a; [ -f $ENV_FILE ] && . $ENV_FILE; set +a
cd $DEST && exec $DEST/venv/bin/python -m nginxpanel "\$@"
WRAP
chmod 755 /usr/local/bin/nginx-panel

# ---------------------------------------------------------------- /etc/nginx-panel.env
step "Configuración ($ENV_FILE)"
KNOWN='^(NP_BIND|NP_PANEL_PORT|NP_BEHIND_PROXY|NP_TRUSTED_PROXIES|NP_ALLOWED_NETS|NP_SECURE_COOKIES)='
EXTRA=""
if [ -f "$ENV_FILE" ]; then
  cp -p "$ENV_FILE" "$ENV_FILE.bak"
  EXTRA=$(grep -E '^[A-Z_]+=' "$ENV_FILE" | grep -vE "$KNOWN" || true)
fi
umask 077
cat > "$ENV_FILE.new" <<ENV
# Configuración de nginx-panel. La reescribe el instalador (copia anterior: $ENV_FILE.bak).
# Tras editarla a mano: systemctl restart nginx-panel

# IP y puerto de escucha (127.0.0.1 = solo accesible a través del proxy o por túnel SSH)
NP_BIND=$BIND
NP_PANEL_PORT=$PORT

# 1 = el panel se publica detrás de un proxy inverso
NP_BEHIND_PROXY=$PROXY
# Proxies cuyo X-Forwarded-For se acepta (solo con NP_BEHIND_PROXY=1)
NP_TRUSTED_PROXIES=$TRUSTED
# 1 = el panel se sirve por HTTPS (cookies Secure)
NP_SECURE_COOKIES=$HTTPS

# Redes que pueden usar el panel (CIDR separadas por comas). Vacío = cualquiera.
NP_ALLOWED_NETS=$ALLOW
ENV
if [ -n "$EXTRA" ]; then printf '\n# Otros ajustes\n%s\n' "$EXTRA" >> "$ENV_FILE.new"; fi
umask 022

# Comprobación final con el propio código del panel antes de aplicar nada
if ! ( set -a; . "$ENV_FILE.new"; set +a
       "$DEST/venv/bin/python" -c 'import ipaddress
from nginxpanel import config
for n in config.ALLOWED_NETS + config.TRUSTED_PROXIES:
    ipaddress.ip_network(n, strict=False)' ) 2>/dev/null; then
  rm -f "$ENV_FILE.new"
  die "La configuración no es válida; no se ha cambiado nada en $ENV_FILE"
fi
mv "$ENV_FILE.new" "$ENV_FILE"
chmod 600 "$ENV_FILE"
ok "Guardada"

# ---------------------------------------------------------------- systemd
step "Servicio"
cat > /etc/systemd/system/nginx-panel.service <<UNIT
[Unit]
Description=nginx-panel (administración web de nginx)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ENV_FILE
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
# systemd lo reintenta cada minuto, sin límite, hasta que arranca.
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

cat > /etc/logrotate.d/nginx-panel <<ROT
/var/log/nginx/panel/*.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    create 0640 root adm
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 \$(cat /run/nginx.pid) || true
    endscript
}
ROT

systemctl daemon-reload
systemctl enable nginx-panel >/dev/null 2>&1
systemctl restart nginx-panel     # restart (no solo start): en una actualización carga el código nuevo

PROBE=$BIND; [ "$PROBE" = 0.0.0.0 ] && PROBE=127.0.0.1
[[ $PROBE == *:* ]] && PROBE="[$PROBE]"
UP=0
for _ in $(seq 1 15); do
  if "$DEST/venv/bin/python" - "http://$PROBE:$PORT/login" <<'PY' 2>/dev/null; then UP=1; break; fi
import sys, urllib.request, urllib.error
try:
    urllib.request.urlopen(sys.argv[1], timeout=2)
except urllib.error.HTTPError:
    pass            # responde (p. ej. 403 por NP_ALLOWED_NETS): está en marcha
PY
  sleep 1
done
if [ $UP -eq 1 ]; then ok "nginx-panel en marcha"
else warn "El servicio no responde todavía. Revisa: journalctl -u nginx-panel -n 50"; fi

# ---------------------------------------------------------------- admin inicial
# Se genera aquí y se pasa por stdin (no aparece en ps ni en logs).
# Solo si aún no existe ningún usuario: actualizar nunca toca las cuentas.
PW=""
if ! /usr/local/bin/nginx-panel has-users >/dev/null 2>&1; then
  PW=$(openssl rand -hex 12)
  printf '%s\n' "$PW" | /usr/local/bin/nginx-panel create-admin admin --password-stdin >/dev/null
fi

# ---------------------------------------------------------------- resumen
LINE="────────────────────────────────────────────────────────────────────"
echo
echo "$G$LINE$N"
if [ $UPDATE -eq 1 ]; then echo " ${B}nginx-panel actualizado${N}"; else echo " ${B}nginx-panel instalado${N}"; fi
echo "$G$LINE$N"
if [ "$BIND" = 0.0.0.0 ]; then
  URLS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v ':' | grep . | head -3 | sed "s|.*|http://&:$PORT|" | paste -sd' ' - || true)
else
  URLS="http://$BIND:$PORT"
fi
echo " Escucha en   $BIND:$PORT"
[ "$BIND" != 127.0.0.1 ] && echo " Abre         ${B}${URLS:-http://IP-del-servidor:$PORT}${N}"
[ -n "$PW" ] && echo " Usuario      ${B}admin${N}   Contraseña  ${B}$PW${N}   ${D}(cámbiala y activa 2FA)${N}"
echo

if [ "$PROXY" = 1 ] && [ "$WHERE" = 1 ]; then
  echo " ${B}Publicar el panel con tu dominio y HTTPS:${N}"
  echo "   1. Desde tu equipo abre un túnel:  ${C}ssh -L $PORT:127.0.0.1:$PORT root@este-servidor${N}"
  echo "      y entra en ${B}http://127.0.0.1:$PORT${N}"
  echo "   2. Sistema → Tomar el control de nginx"
  echo "   3. Certificados → Let's Encrypt para panel.tudominio.com"
  echo "   4. Hosts → nuevo host panel.tudominio.com → destino ${B}http://127.0.0.1:$PORT${N},"
  echo "      con el certificado, Forzar HTTPS y una lista de acceso."
elif [ "$PROXY" = 1 ]; then
  TARGET=$BIND
  if [ "$TARGET" = 0.0.0.0 ]; then
    TARGET=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v ':' | grep . | head -1 || true)
    TARGET=${TARGET:-IP-de-este-servidor}
  fi
  echo " ${B}Configura tu proxy${N} ($REMOTE) para reenviar a ${B}http://$TARGET:$PORT${N}"
  echo " con la cabecera X-Forwarded-For, y en el firewall abre el puerto $PORT solo a esa IP."
else
  echo " ${B}Siguiente paso:${N} Sistema → Tomar el control de nginx"
  if [ -z "$ALLOW" ] && [ "$BIND" != 127.0.0.1 ]; then
    echo
    warn "El panel (que corre como root) es accesible desde cualquier IP."
    note "Activa 2FA y limita el acceso: sudo ./install.sh (redes con acceso) o el firewall."
  fi
fi
echo "$G$LINE$N"
