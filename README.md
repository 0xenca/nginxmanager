# nginx-panel

Panel web en Python (Flask) para instalar y administrar nginx en un servidor Linux:
hosts, backends con balanceo, SSL, WebSocket, streams TCP/UDP, WAF básico, caché,
usuarios con permisos, analíticas y visor de logs.

Probado contra nginx 1.26 real: 115 comprobaciones de extremo a extremo (formularios →
config generada → `nginx -t` → tráfico real con curl).

## Instalación

```bash
unzip nginx-panel.zip && cd nginx-panel
sudo ./install.sh                                  # panel en todas las interfaces, puerto 8181
sudo ./install.sh --with-nginx                     # además instala nginx + módulo stream + certbot
sudo ./install.sh --allow 192.168.88.0/24,10.8.0.0/24   # solo esas redes pueden usar el panel
sudo ./install.sh --bind 127.0.0.1                 # solo local (acceso por túnel SSH)
```

El instalador crea `/opt/nginx-panel` (venv), el servicio `nginx-panel` (gunicorn),
`/etc/nginx-panel.env`, la rotación de logs y un usuario `admin` con contraseña aleatoria
que imprime al final.

Acceso: `http://IP-del-servidor:8181`. Las redes permitidas se cambian luego en
`/etc/nginx-panel.env` (`NP_ALLOWED_NETS`) + `systemctl restart nginx-panel`.

Primer uso: **Sistema → Instalar nginx** (si no lo está) → **Tomar el control de nginx**.

## Instalación manual (sin `install.sh`)

Mismos pasos que hace el instalador, para quien prefiera revisarlos o adaptarlos. Todo
como root (`sudo -i`), desde la carpeta del proyecto (descomprimida o clonada con
`git clone https://github.com/0xenca/nginxmanager.git && cd nginxmanager`).

**1. Dependencias del sistema**

```bash
# Debian / Ubuntu
apt-get update
apt-get install -y python3 python3-venv openssl logrotate
apt-get install -y nginx libnginx-mod-stream certbot     # opcional: nginx + stream + certbot

# RHEL / Rocky / Alma
dnf install -y python3 openssl logrotate
dnf install -y epel-release && dnf install -y nginx nginx-mod-stream certbot   # opcional
```

**2. Código y entorno virtual**

```bash
mkdir -p /opt/nginx-panel
cp -r nginxpanel requirements.txt /opt/nginx-panel/
python3 -m venv /opt/nginx-panel/venv
/opt/nginx-panel/venv/bin/pip install --upgrade pip
/opt/nginx-panel/venv/bin/pip install -r /opt/nginx-panel/requirements.txt

install -d -m 700 /var/lib/nginx-panel        # base de datos
install -d -m 750 /var/log/nginx/panel        # logs de los hosts
```

**3. Comando `nginx-panel`**

```bash
cat > /usr/local/bin/nginx-panel <<'EOF'
#!/bin/sh
set -a; [ -f /etc/nginx-panel.env ] && . /etc/nginx-panel.env; set +a
cd /opt/nginx-panel && exec /opt/nginx-panel/venv/bin/python -m nginxpanel "$@"
EOF
chmod 755 /usr/local/bin/nginx-panel
```

**4. Configuración** — `/etc/nginx-panel.env` (ajusta IP, puerto y redes):

```bash
cat > /etc/nginx-panel.env <<'EOF'
# Configuración de nginx-panel (se lee al arrancar el servicio)
NP_BIND=0.0.0.0
NP_PANEL_PORT=8181
NP_BEHIND_PROXY=0
# Redes que pueden usar el panel (CIDR separados por comas). Vacío = cualquiera.
NP_ALLOWED_NETS=
# Pon 1 si accedes al panel por HTTPS (cookies Secure)
NP_SECURE_COOKIES=0
EOF
chmod 600 /etc/nginx-panel.env
```

**5. Servicio systemd**

```bash
cat > /etc/systemd/system/nginx-panel.service <<'EOF'
[Unit]
Description=nginx-panel (administración web de nginx)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/nginx-panel.env
WorkingDirectory=/opt/nginx-panel
ExecStart=/opt/nginx-panel/venv/bin/gunicorn --workers 1 --threads 8 --timeout 120 \
  --no-control-socket --bind ${NP_BIND}:${NP_PANEL_PORT} --access-logfile - nginxpanel.wsgi:app
Restart=on-failure
# Necesita root: escribe en /etc/nginx, recarga nginx, ejecuta certbot y apt.
User=root
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
```

**6. Rotación de logs** (en RHEL/Rocky cambia `adm` por `root`):

```bash
cat > /etc/logrotate.d/nginx-panel <<'EOF'
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
        [ -s /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid) || true
    endscript
}
EOF
```

**7. Arrancar y crear el administrador**

```bash
systemctl daemon-reload
systemctl enable --now nginx-panel
nginx-panel create-admin admin --random      # imprime la contraseña generada
systemctl status nginx-panel
```

Entra en `http://IP-del-servidor:8181`, cambia la contraseña, activa 2FA y sigue con
**Sistema → Tomar el control de nginx**.

## Qué hace

| Área | Detalle |
|---|---|
| Hosts | Proxy inverso o redirección. Varios dominios y comodines. Destino directo o backend. |
| Grupos | Carpetas para organizar hosts (Internos, Públicos, Clientes…), con color. Lista agrupada y plegable (el estado se recuerda), buscador, selección múltiple para mover hosts entre grupos, «+ Host» directo en un grupo, activar/desactivar un grupo entero en un solo cambio de config, y filtro por grupo en analíticas, logs y exportaciones. Borrar un grupo nunca borra sus hosts. |
| Estado de hosts | Diagnóstico bajo demanda (botón ⟳: todos, por grupo o por host; nunca automático). Por capas: DNS (¿resuelve? ¿apunta aquí?), nginx en local (código, latencia, TLS), vía DNS como lo haría un cliente (detecta NAT loopback, firewall o que responda otra máquina), backend directo (cada servidor del balanceo), certificado (confiable, nombre, caducidad) y redirección HTTP→HTTPS. Resumen en una línea y detalle desplegable; el último resultado queda guardado. |
| Interfaz de escucha | Cada host y cada stream elige por qué IP del servidor se publica (desplegable con las IPs detectadas) o «Todas las interfaces» (por defecto). El panel añade un `default_server` por cada IP concreta y hace que los hosts en «todas» escuchen también en ella, para que ni se cuelen dominios ajenos ni desaparezcan hosts. |
| Dominios desconocidos | `default_server` devuelve 444 (cierra sin responder) y en HTTPS rechaza el handshake TLS si el SNI no coincide (`ssl_reject_handshake`). Ni la IP ni un dominio ajeno muestran nada. |
| Backends | Upstreams con round robin, least_conn, ip_hash o hash consistente; pesos, backup, down, max_fails, keepalive. |
| SSL | Let's Encrypt (HTTP-01 por webroot, renovación automática con recarga), subida de PEM con verificación clave↔certificado, autofirmados. Forzar HTTPS, HTTP/2, HSTS. |
| WebSocket | Upgrade/Connection y timeouts de 1 h por host. |
| Streams | TCP, UDP o ambos, varios destinos con balanceo y ACL por IP. |
| Protección | WAF básico (escáneres, sondeos `.env`/`.git`/phpMyAdmin, SQLi, XSS, traversal, Log4Shell, métodos TRACE), lista negra global, rate limit y límite de conexiones por IP, cabeceras de seguridad, `server_tokens off`, timeouts anti-slowloris. |
| Listas de acceso | Allow/deny por IP/CIDR + autenticación básica, combinables (`satisfy all/any`). |
| Caché | Por host: solo estáticos, o todo (respeta Cache-Control y nunca cachea peticiones con `Authorization` o cookie de sesión). Cabecera `X-Cache-Status`. |
| Analíticas | Peticiones por estado en el tiempo, ancho de banda, p95, % de 5xx, acierto de caché, top IPs/rutas/hosts/UA, ataques bloqueados. Bloqueo de IP con un clic. |
| Logs | Logs JSON. Filtros por fecha, IP o CIDR, host, estado (`404`, `5xx`, `>=400`, `!200`), método, ruta, UA, solo bloqueadas. Exportación CSV/JSONL del filtrado, descarga de ficheros (incluidos rotados `.gz`), visor de error.log. |
| Usuarios | Permisos por área (sin acceso / ver / gestionar), administradores, 2FA TOTP, bloqueo tras 5 fallos, auditoría de cada acción. |
| Sistema | Instalación de nginx, `nginx -t`, recarga, reinicio, copia antes de cada cambio y restauración. |

## Cómo aplica cambios

Cada cambio regenera **toda** la configuración desde la BD en `/etc/nginx/panel/`, guarda
copia de lo anterior, ejecuta `nginx -t` y solo entonces recarga. Si `nginx -t` falla:
restaura los ficheros, deshace el cambio en la BD y muestra el error. Nunca queda un nginx roto.

El panel reescribe `/etc/nginx/nginx.conf` (el original queda en `nginx.conf.panel-orig`) y,
por defecto, **deja de cargar `sites-enabled/` y `conf.d/`**. Si tienes sitios previos,
migra o actívalos en Seguridad → Avanzado (choca si alguno declara `default_server`).

## Seguridad del propio panel

El panel corre como **root** (escribe en `/etc/nginx`, ejecuta certbot y apt). Trátalo como un SSH:

- Por defecto escucha en todas las interfaces (0.0.0.0:8181). Limita quién entra con
  `NP_ALLOWED_NETS` (el panel responde 403 al resto) y/o con el firewall.
- Para usarlo por HTTPS, publícalo como un host del propio panel con certificado y lista de
  acceso; pon `NP_BEHIND_PROXY=1` y `NP_SECURE_COOKIES=1` en `/etc/nginx-panel.env`, reinicia,
  y cierra el 8181 en el firewall.
- Activa 2FA en Mi cuenta.
- Las directivas personalizadas (texto libre que llega a nginx) solo las ven los administradores.
  Todo lo demás pasa por validadores que impiden inyectar directivas.
- Sesiones: cookie HttpOnly + SameSite=Strict, CSRF en todos los POST, CSP estricta.

## Comandos

```bash
nginx-panel create-admin USUARIO [--random]   # crear o recuperar un admin (resetea su 2FA)
nginx-panel apply                             # regenerar config desde la BD
systemctl status nginx-panel
journalctl -u nginx-panel -f
```

## Límites conocidos

- **El estado se comprueba desde el propio servidor.** «Accesible» significa que nginx y el
  backend responden desde dentro; la prueba «Vía DNS» se acerca a lo que ve un cliente, pero
  no sustituye a una comprobación desde fuera de tu red (NAT loopback, CGNAT, firewall del ISP).

- **WAF básico, no ModSecurity/Coraza.** Corta escáneres y explotación automatizada con pocos
  falsos positivos; no sustituye a un WAF con reglas OWASP CRS.
- **Comodines `*.dominio`** necesitan DNS-01: súbelos como certificado propio.
- **Analíticas**: parsea los logs en cada consulta. Va bien hasta varios cientos de MB por
  rango; con más volumen la consulta se corta y lo indica.
- Sin GeoIP en esta versión.
- Probado en Ubuntu 24.04 con nginx 1.26. Contempla Debian (nginx 1.22, sintaxis `listen … http2`)
  y RHEL/Rocky (dnf + EPEL), pero no se ha probado en ellos.

## Estructura

```
nginxpanel/
  __init__.py   factoría Flask, cabeceras de seguridad
  views.py      rutas
  nginx.py      detección de entorno, generación, aplicación con rollback
  forms.py      formularios declarativos + validadores anti-inyección
  certs.py      Let's Encrypt / PEM / autofirmados
  logs.py       filtrado, exportación y analíticas
  auth.py       sesiones, permisos, CSRF, TOTP, bloqueo
  jobs.py       tareas en segundo plano (apt, certbot)
  templates/nginx/*.j2   plantillas de configuración nginx
```
