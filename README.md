<div align="center">

# 🚀 nginx-panel

### Todo el poder de nginx desde el navegador. Sin Docker. Sin ficheros a mano. Sin miedo.

**Proxy inverso · Balanceo de carga · SSL automático · WAF · Caché · Streams TCP/UDP · Analíticas · 2FA**

<br>

![Debian 13](https://img.shields.io/badge/Debian-13_trixie-A81D33?style=for-the-badge&logo=debian&logoColor=white)
![nginx](https://img.shields.io/badge/nginx-1.26-009639?style=for-the-badge&logo=nginx&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Gratis](https://img.shields.io/badge/precio-0_€-success?style=for-the-badge)
![Sin Docker](https://img.shields.io/badge/Docker-no_hace_falta-2496ED?style=for-the-badge&logo=docker&logoColor=white)

<br>

```bash
git clone https://github.com/0xenca/nginxmanager && cd nginxmanager && sudo ./install.sh
```

**Un comando. Un minuto. Un panel que nunca te deja nginx roto.**

</div>

---

## ✨ Por qué nginx-panel

<table>
<tr>
<td width="50%" valign="top">

### 🛡️ Imposible romper nginx
Cada cambio regenera la configuración completa, guarda una copia, pasa `nginx -t` y **solo entonces** recarga. ¿Falla? Restaura los ficheros y deshace el cambio en la base de datos. Tu nginx sigue sirviendo como si nada.

</td>
<td width="50%" valign="top">

### ⚡ nginx nativo, cero capas
Nada de contenedores ni proxies dentro de proxies: el panel escribe configuración nginx limpia y legible en `/etc/nginx/panel/`. El rendimiento es el de nginx, porque **es** nginx.

</td>
</tr>
<tr>
<td valign="top">

### 🔐 Seguro por diseño
WAF integrado, 2FA, permisos por área, auditoría de cada acción, CSP estricta, CSRF, validadores que impiden inyectar directivas. Los dominios desconocidos ni siquiera completan el handshake TLS.

</td>
<td valign="top">

### 🎯 Instalar es preguntar y listo
El instalador te guía: ¿proxy inverso?, ¿dónde?, ¿HTTPS?, ¿qué redes entran? Y para actualizar, el mismo comando: conserva tu configuración y vuelve a preguntar solo lo importante.

</td>
</tr>
</table>

---

## 📦 Instalación (Debian 13)

```bash
apt install -y git sudo                     # si tu Debian es mínimo
git clone https://github.com/0xenca/nginxmanager
cd nginxmanager
sudo ./install.sh
```

El instalador te pregunta:

| Pregunta | Para qué |
|---|---|
| 🌐 **¿Detrás de un proxy inverso?** | Publicar el panel como `https://panel.tudominio.com`. |
| 📍 **¿Dónde está el proxy?** | En este servidor (recomendado: el propio panel se publica a sí mismo) o en otra máquina (otro nginx, HAProxy, Traefik, Cloudflare Tunnel…). |
| 🔒 **¿HTTPS?** | Activa cookies `Secure`. |
| 🚪 **Puerto y redes con acceso** | Por ejemplo, solo tu LAN y tu VPN: `192.168.1.0/24,10.8.0.0/24`. |
| 🧩 **¿Instalar nginx?** | nginx + módulo stream + certbot, en el mismo paso. |

Al terminar te muestra la URL, el usuario `admin` con una contraseña aleatoria y los siguientes pasos.

Primer uso en el panel: **Sistema → Tomar el control de nginx**. Listo.

### 🔄 Actualizar

```bash
cd nginxmanager && git pull && sudo ./install.sh
```

Te enseña la configuración actual y vuelve a preguntar por el proxy inverso; **Enter mantiene cada valor**. Nunca toca usuarios, hosts ni certificados.

### 🤖 Sin preguntas (automatización)

```bash
sudo ./install.sh -y --with-nginx --allow 192.168.1.0/24          # acceso directo, solo LAN
sudo ./install.sh -y --behind-proxy --https                        # proxy en este servidor
sudo ./install.sh -y --trusted-proxies 10.0.0.2 --bind 10.0.0.5   # proxy en otra máquina
sudo ./install.sh --help                                           # todas las opciones
```

---

## 🧰 Todo lo que hace

<table>
<tr><td>🌍</td><td><b>Hosts</b></td><td>Proxy inverso o redirección. Varios dominios y comodines. Destino directo o backend balanceado.</td></tr>
<tr><td>🗂️</td><td><b>Grupos</b></td><td>Carpetas con color (Internos, Públicos, Clientes…). Lista agrupada y plegable, buscador, mover hosts entre grupos con selección múltiple y activar o desactivar un grupo entero en un solo cambio. Filtro por grupo en analíticas, logs y exportaciones.</td></tr>
<tr><td>🩺</td><td><b>Diagnóstico de hosts</b></td><td>Por capas y bajo demanda: DNS (¿resuelve? ¿apunta aquí?), nginx local, vía DNS como un cliente real (detecta NAT loopback, firewall o que responda otra máquina), cada servidor del backend, certificado (confianza, nombre, caducidad) y redirección HTTP→HTTPS.</td></tr>
<tr><td>⚖️</td><td><b>Backends</b></td><td>Round robin, least_conn, ip_hash o hash consistente. Pesos, backup, down, max_fails y keepalive.</td></tr>
<tr><td>🔒</td><td><b>SSL</b></td><td>Let's Encrypt con renovación automática, subida de PEM con verificación clave↔certificado, autofirmados. Forzar HTTPS, HTTP/2 y HSTS con un clic.</td></tr>
<tr><td>🔌</td><td><b>WebSocket</b></td><td>Cabeceras Upgrade/Connection y timeouts de 1 h por host.</td></tr>
<tr><td>📡</td><td><b>Streams TCP/UDP</b></td><td>Bases de datos, juegos, DNS, VPN… con varios destinos, balanceo y ACL por IP.</td></tr>
<tr><td>🛡️</td><td><b>WAF</b></td><td>Escáneres (sqlmap, nikto, nuclei…), sondeos (<code>.env</code>, <code>.git</code>, phpMyAdmin), SQLi, XSS, traversal, Log4Shell y métodos TRACE. Lista negra global, rate limit y límite de conexiones por IP, cabeceras de seguridad y timeouts anti-slowloris.</td></tr>
<tr><td>🚫</td><td><b>Dominios desconocidos</b></td><td>Cierre sin respuesta (444) y, en HTTPS, rechazo del handshake si el SNI no es tuyo. Ni tu IP ni un dominio ajeno muestran nada.</td></tr>
<tr><td>🧱</td><td><b>Listas de acceso</b></td><td>Allow/deny por IP/CIDR y usuarios con contraseña (SHA-512), combinables con <code>satisfy all/any</code>.</td></tr>
<tr><td>🚀</td><td><b>Caché</b></td><td>Solo estáticos o todo, respetando Cache-Control y sin cachear nunca peticiones con sesión o <code>Authorization</code>. Cabecera <code>X-Cache-Status</code>.</td></tr>
<tr><td>📊</td><td><b>Analíticas</b></td><td>Peticiones por estado, ancho de banda, p95, % de 5xx, aciertos de caché, top de IPs/rutas/hosts/UA y ataques bloqueados. <b>Bloquea una IP con un clic.</b></td></tr>
<tr><td>📜</td><td><b>Logs</b></td><td>JSON con filtros por fecha, IP/CIDR, host, estado (<code>5xx</code>, <code>>=400</code>, <code>!200</code>), método, ruta y UA. Exportación CSV/JSONL, descarga de rotados <code>.gz</code> y visor de error.log.</td></tr>
<tr><td>👥</td><td><b>Usuarios</b></td><td>Permisos por área (sin acceso / ver / gestionar), administradores, 2FA TOTP, bloqueo tras 5 fallos y auditoría de cada acción.</td></tr>
<tr><td>🖧</td><td><b>Interfaces</b></td><td>Cada host y cada stream elige por qué IP del servidor se publica, o todas.</td></tr>
<tr><td>⚙️</td><td><b>Sistema</b></td><td>Instalar nginx, <code>nginx -t</code>, recargar y reiniciar. Copia antes de cada cambio y restauración en un clic.</td></tr>
</table>

---

## 🧠 Cómo aplica los cambios

```
 tu cambio ─► BD ─► genera TODA la config ─► copia de seguridad ─► nginx -t ─┬─► ✅ recarga
                                                                            └─► ❌ restaura ficheros + deshace en BD + te enseña el error
```

- **Arranque a prueba de DNS:** si un backend usa un nombre que aún no resuelve al encender el servidor, systemd reintenta arrancar nginx cada minuto hasta lograrlo (`/etc/systemd/system/nginx.service.d/nginx-panel-restart.conf`).
- **Toma el control limpiamente:** reescribe `/etc/nginx/nginx.conf` (el original queda en `nginx.conf.panel-orig`) y por defecto deja de cargar `sites-enabled/` y `conf.d/`. Si tienes sitios previos, puedes reactivarlos en Seguridad → Avanzado.

---

## 🔐 Seguridad del propio panel

El panel corre como **root** (escribe en `/etc/nginx` y ejecuta certbot y apt). Trátalo como un SSH:

- 🌐 **Publícalo detrás de un proxy inverso con HTTPS.** Elige «proxy en este servidor» en el instalador: el panel escucha solo en `127.0.0.1` y nadie puede saltarse el proxy.
- 🎯 **Limita quién entra** con las redes permitidas (el panel responde 403 al resto) y/o con el firewall.
- 🔑 **Activa 2FA** en Mi cuenta. Cada código vale una sola vez.
- 🧾 **IP real del cliente:** `X-Forwarded-For` solo se acepta de `NP_TRUSTED_PROXIES`. El panel avisa en su log si recibe esa cabecera de alguien que no es de confianza.
- 🍪 **Sesiones:** cookie HttpOnly + SameSite=Strict, CSRF en todos los POST y CSP estricta con SRI. Cambiar la contraseña cierra las demás sesiones.
- ✍️ **Directivas personalizadas** (texto libre que llega a nginx) solo para administradores. Todo lo demás pasa por validadores que impiden inyectar directivas.

---

## ⌨️ Comandos

```bash
nginx-panel create-admin USUARIO                  # crear o recuperar un admin (pide la contraseña; resetea su 2FA)
nginx-panel create-admin USUARIO --password-stdin # lo mismo, para scripts
nginx-panel apply                                 # regenerar la config desde la BD
systemctl status nginx-panel
journalctl -u nginx-panel -f
```

### Configuración (`/etc/nginx-panel.env`)

La escribe el instalador; para cambiarla, vuelve a ejecutar `sudo ./install.sh` o edítala y haz `systemctl restart nginx-panel`.

| Variable | Por defecto | Qué hace |
|---|---|---|
| `NP_BIND` | `0.0.0.0` | IP de escucha (`127.0.0.1` con proxy en este servidor) |
| `NP_PANEL_PORT` | `8181` | Puerto del panel |
| `NP_BEHIND_PROXY` | `0` | `1` = publicado detrás de un proxy inverso |
| `NP_TRUSTED_PROXIES` | `127.0.0.1,::1` | Proxies cuyo `X-Forwarded-For` se acepta |
| `NP_SECURE_COOKIES` | `0` | `1` = panel servido por HTTPS |
| `NP_ALLOWED_NETS` | *(vacío = todas)* | Redes que pueden usar el panel |

---

## 📏 Límites conocidos

- **El diagnóstico se hace desde el propio servidor.** La prueba «vía DNS» se acerca a lo que ve un cliente, pero no sustituye a una comprobación desde fuera de tu red (NAT loopback, CGNAT, firewall del ISP).
- **WAF básico, no ModSecurity/Coraza.** Corta escáneres y explotación automatizada con pocos falsos positivos; no sustituye a un WAF con reglas OWASP CRS.
- **Comodines `*.dominio`** necesitan validación DNS-01: súbelos como certificado propio.
- **Analíticas:** se calculan leyendo los logs en cada consulta. Van bien hasta varios cientos de MB por rango; con más volumen la consulta se corta y lo indica.
- Sin GeoIP en esta versión.
- **Plataforma soportada: Debian 13.** Probado contra nginx 1.26 real (la versión de Debian 13) con 115 comprobaciones de extremo a extremo: formularios → config generada → `nginx -t` → tráfico real con curl.

---

## 🗺️ Estructura

```
install.sh              instalador / actualizador interactivo
nginxpanel/
  __init__.py           factoría Flask, cabeceras de seguridad, proxy de confianza
  views.py              rutas
  nginx.py              detección del entorno, generación y aplicación con rollback
  forms.py              formularios declarativos + validadores anti-inyección
  certs.py              Let's Encrypt / PEM / autofirmados
  checks.py             diagnóstico de hosts por capas
  logs.py               filtrado, exportación y analíticas
  auth.py               sesiones, permisos, CSRF, TOTP, bloqueo
  jobs.py               tareas en segundo plano (apt, certbot)
  templates/nginx/*.j2  plantillas de configuración nginx
```

<div align="center">

<br>

**Hecho para que gestionar nginx sea un placer, no un riesgo.** ⭐ Si te ahorra tiempo, dale una estrella.

</div>
