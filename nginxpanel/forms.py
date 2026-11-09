"""Definición declarativa de formularios + validación estricta.

Todo lo que acaba en la config de nginx pasa por un validador que impide
inyectar directivas (; { } comillas, espacios, $). Los únicos campos de texto
libre que llegan a nginx son los 'avanzados', reservados a administradores.
"""
import ipaddress
import re

# Admite "_" en las etiquetas (no es un hostname RFC 1123 válido, pero nginx y el DNS lo aceptan;
# p. ej. pve_internal.dominio.es). El TLD no puede llevarlo. Let's Encrypt lo rechaza (ver views).
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9][a-z0-9-]{0,62}$")
HOSTNAME_RE = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$")
DURATION_RE = re.compile(r"^\d{1,6}(ms|s|m|h|d)?$")
SIZE_RE = re.compile(r"^\d{1,6}[kKmMgG]?$")
URL_RE = re.compile(r"^https?://[^\s;{}\"'\\$`<>]+$")
AUTH_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


class V(Exception):
    pass


# ---------- validadores ----------

def v_domains(raw):
    items = [x.strip().lower().rstrip(".") for x in re.split(r"[\s,]+", raw or "") if x.strip()]
    if not items:
        raise V("Indica al menos un dominio")
    out = []
    for d in items:
        ok = DOMAIN_RE.match(d) is not None
        if not ok:
            try:
                ipaddress.ip_address(d)
                ok = True
            except ValueError:
                pass
        if not ok:
            raise V(f"Dominio no válido: {d}")
        if d not in out:
            out.append(d)
    return out


def v_host(raw):
    h = (raw or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ip = ipaddress.ip_address(h)
        return f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        pass
    if not h or not HOSTNAME_RE.match(h) or len(h) > 253:
        raise V(f"Host/IP no válido: {raw}")
    return h


def v_port(raw):
    try:
        p = int(raw)
    except (TypeError, ValueError):
        raise V("Puerto no válido")
    if not 1 <= p <= 65535:
        raise V("Puerto fuera de rango (1-65535)")
    return p


def v_int(lo, hi):
    def f(raw):
        try:
            n = int(raw)
        except (TypeError, ValueError):
            raise V("Número no válido")
        if not lo <= n <= hi:
            raise V(f"Debe estar entre {lo} y {hi}")
        return n
    return f


def v_duration(raw):
    raw = (raw or "").strip()
    if not DURATION_RE.match(raw):
        raise V("Duración no válida (ej. 30s, 10m, 1h)")
    return raw


def v_size(raw):
    raw = (raw or "").strip()
    if not SIZE_RE.match(raw):
        raise V("Tamaño no válido (ej. 64m, 1g)")
    return raw.lower()


def v_name(raw):
    raw = (raw or "").strip()
    if not NAME_RE.match(raw):
        raise V("Nombre no válido (letras, números, espacio . _ -)")
    return raw


def v_url(raw):
    raw = (raw or "").strip()
    if not URL_RE.match(raw):
        raise V("URL no válida (http:// o https://, sin espacios ni ; { } $ comillas)")
    return raw


def v_email(raw):
    raw = (raw or "").strip()
    if not EMAIL_RE.fullmatch(raw) or raw.startswith("-"):
        raise V("Email no válido")
    return raw


def parse_cidr(item):
    item = item.strip()
    if item.lower() == "all":
        return "all"
    return str(ipaddress.ip_network(item, strict=False))


def v_cidrs(raw):
    out = []
    for line in (raw or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            c = parse_cidr(line)
        except ValueError:
            raise V(f"IP/CIDR no válido: {line}")
        if c not in out:
            out.append(c)
    return out


def v_servers(raw):
    """Líneas 'host:puerto [weight=N] [backup] [down]'."""
    out = []
    for line in (raw or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        addr = parts[0]
        m = re.match(r"^(\[[0-9a-fA-F:]+\]|[^:\[\]]+):(\d+)$", addr)
        if not m:
            raise V(f"Servidor no válido (usa host:puerto): {line}")
        srv = {"host": v_host(m.group(1)), "port": v_port(m.group(2)), "weight": 1,
               "backup": False, "down": False}
        for p in parts[1:]:
            if p.startswith("weight="):
                srv["weight"] = v_int(1, 1000)(p[7:])
            elif p == "backup":
                srv["backup"] = True
            elif p == "down":
                srv["down"] = True
            else:
                raise V(f"Opción desconocida '{p}' en: {line}")
        out.append(srv)
    if not out:
        raise V("Añade al menos un servidor")
    return out


def servers_to_text(servers):
    lines = []
    for s in servers or []:
        t = f"{s['host']}:{s['port']}"
        if s.get("weight", 1) != 1:
            t += f" weight={s['weight']}"
        if s.get("backup"):
            t += " backup"
        if s.get("down"):
            t += " down"
        lines.append(t)
    return "\n".join(lines)


def v_snippet(raw):
    raw = (raw or "").replace("\r\n", "\n").strip()
    depth = 0
    for ch in raw:
        depth += ch == "{"
        depth -= ch == "}"
        if depth < 0:
            raise V("Llaves desbalanceadas en el bloque personalizado")
    if depth:
        raise V("Llaves desbalanceadas en el bloque personalizado")
    return raw


def v_auth_users(raw, existing):
    """'usuario:contraseña' por línea. 'usuario:' sin contraseña conserva la actual."""
    from .htpasswd import HashError, hash_password
    prev = {u["user"]: u["hash"] for u in existing or []}
    out = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        user, _, pw = line.partition(":")
        user = user.strip()
        if not AUTH_USER_RE.match(user):
            raise V(f"Usuario no válido: {user}")
        if pw:
            if len(pw) < 8:
                raise V(f"La contraseña de {user} debe tener 8+ caracteres")
            try:
                out.append({"user": user, "hash": hash_password(pw)})
            except HashError as e:
                raise V(str(e))
        elif user in prev:
            out.append({"user": user, "hash": prev[user]})
        else:
            raise V(f"Falta la contraseña de {user}")
    return out


# ---------- definición de campos ----------

def F(name, label, type="text", default="", **kw):
    d = {"name": name, "label": label, "type": type, "default": default}
    d.update(kw)
    return d


def S(title, **kw):
    d = {"type": "section", "label": title, "name": "_s_" + title}
    d.update(kw)
    return d


PROXY = {"type": ["proxy"]}
REDIR = {"type": ["redirect"]}


def v_listen_ip(allowed):
    def f(raw):
        raw = (raw or "").strip()
        if not raw:
            return ""
        try:
            ip = str(ipaddress.ip_address(raw.strip("[]")))
        except ValueError:
            raise V("IP no válida")
        if allowed is not None and ip not in allowed:
            raise V(f"{ip} no está configurada en ninguna interfaz de este servidor")
        return ip
    return f


def listen_field(local_ips, current=""):
    opts = [("", "Todas las interfaces (IPv4 + IPv6)")]
    opts += [(ip, f"{ip}  ·  {iface}") for ip, iface in local_ips]
    if current and current not in [o[0] for o in opts]:
        opts.append((current, f"{current}  ·  (ya no está en ninguna interfaz)"))
    return F("listen_ip", "Escuchar en", "select", "", options=opts,
             validate=v_listen_ip([ip for ip, _ in local_ips] + ([current] if current else [])),
             help="Interfaz/IP del servidor por la que se sirve. Por defecto, todas.")


GROUP_COLORS = [("slate", "Gris"), ("green", "Verde"), ("blue", "Azul"), ("amber", "Ámbar"),
                ("red", "Rojo"), ("violet", "Violeta"), ("teal", "Turquesa")]


GROUP_NAME_RE = re.compile(r"^[^\W_][\w .,()&+/-]{0,63}$")   # Unicode: admite tildes y ñ


def v_group(raw):
    """Los nombres de grupo solo se usan en el panel (nunca en nginx): se admiten acentos."""
    raw = " ".join((raw or "").split())
    if not GROUP_NAME_RE.match(raw):
        raise V("Nombre de grupo no válido (letras, números, espacios y . , ( ) & + / - _)")
    return raw


def host_fields(backends, certs, access_lists, local_ips=(), current_listen="", groups=()):
    return [
        S("General"),
        F("domains", "Dominios", "textarea", required=True, validate=v_domains, rows=3,
          help="Uno por línea. Admite comodín *.dominio.com. Peticiones a dominios no listados en ningún host se descartan."),
        F("group_id", "Grupo", "select", "", cast=int,
          options=[("", "— sin grupo —")] + [(str(gr["id"]), gr["name"]) for gr in groups]),
        F("type", "Tipo", "select", "proxy", options=[("proxy", "Proxy inverso"), ("redirect", "Redirección")]),
        F("enabled", "Activo", "bool", True),
        listen_field(local_ips, current_listen),
        S("Destino", show_if=PROXY),
        F("forward_mode", "Destino", "select", "direct", show_if=PROXY,
          options=[("direct", "Servidor directo"), ("backend", "Backend (balanceo)")]),
        F("forward_scheme", "Esquema", "select", "http", show_if=PROXY,
          options=[("http", "http"), ("https", "https")]),
        F("forward_host", "Host / IP", "text", "", show_if={**PROXY, "forward_mode": ["direct"]},
          validate=v_host, placeholder="192.168.1.10"),
        F("forward_port", "Puerto", "number", 80, show_if={**PROXY, "forward_mode": ["direct"]}, validate=v_port),
        F("backend_id", "Backend", "select", "", show_if={**PROXY, "forward_mode": ["backend"]},
          options=[("", "— elegir —")] + [(str(b["id"]), b["name"]) for b in backends], cast=int),
        F("upstream_ssl_verify", "Verificar certificado del destino (https)", "bool", False, show_if=PROXY),
        F("websocket", "Soporte WebSocket", "bool", False, show_if=PROXY,
          help="Cabeceras Upgrade/Connection y timeouts largos (1 h)."),
        F("read_timeout", "Timeout de lectura", "text", "60s", show_if=PROXY, validate=v_duration),
        S("Redirección", show_if=REDIR),
        F("redirect_url", "URL destino", "text", "", show_if=REDIR, validate=v_url,
          placeholder="https://otro-dominio.com"),
        F("redirect_code", "Código", "select", "301", show_if=REDIR, cast=int,
          options=[("301", "301 permanente"), ("302", "302 temporal"), ("307", "307"), ("308", "308")]),
        F("preserve_path", "Conservar ruta y query", "bool", True, show_if=REDIR),
        S("SSL"),
        F("cert_id", "Certificado", "select", "", cast=int,
          options=[("", "— sin SSL —")] + [(str(c["id"]), f"{c['name']} ({c['kind']})") for c in certs]),
        F("force_ssl", "Forzar HTTPS (redirigir 80 → 443)", "bool", True),
        F("http2", "HTTP/2", "bool", True),
        F("hsts", "HSTS (1 año)", "bool", False,
          help="Cuidado: los navegadores recordarán forzar HTTPS durante un año."),
        S("Seguridad"),
        F("waf", "Filtro de ataques (WAF básico)", "bool", True,
          help="Escáneres, sondeos (.env, .git…), inyecciones SQL/XSS, traversal, Log4Shell. Reglas en Seguridad."),
        F("sec_headers", "Cabeceras de seguridad", "bool", True),
        F("access_list_id", "Lista de acceso", "select", "", cast=int,
          options=[("", "— ninguna —")] + [(str(a["id"]), a["name"]) for a in access_lists]),
        F("rate_limit", "Limitar peticiones por IP", "bool", False,
          help="Usa la tasa global de Seguridad; exceso → 429."),
        F("rate_burst", "Ráfaga permitida", "number", 40, validate=v_int(1, 10000)),
        F("conn_limit", "Conexiones simultáneas por IP (0 = sin límite)", "number", 0, validate=v_int(0, 100000)),
        F("max_body", "Tamaño máx. de subida (vacío = global)", "text", "", validate=v_size, optional=True),
        S("Caché", show_if=PROXY),
        F("cache_mode", "Caché", "select", "off", show_if=PROXY,
          options=[("off", "Desactivada"), ("static", "Solo estáticos (css, js, imágenes, fuentes)"),
                   ("all", "Todo (respeta Cache-Control; omite peticiones con Authorization/cookie de sesión)")]),
        F("cache_ttl", "TTL por defecto", "text", "10m", show_if=PROXY, validate=v_duration),
        S("Avanzado (solo administradores)", admin_only=True),
        F("custom_server", "Directivas extra en server { }", "textarea", "", admin_only=True,
          validate=v_snippet, rows=4, mono=True),
        F("custom_location", "Directivas extra en location / { }", "textarea", "", admin_only=True,
          validate=v_snippet, rows=4, mono=True),
        F("notes", "Notas", "textarea", "", rows=2),
    ]


def backend_fields():
    return [
        F("name", "Nombre", required=True, validate=v_name),
        F("method", "Balanceo", "select", "round_robin", options=[
            ("round_robin", "Round robin"), ("least_conn", "Menos conexiones"),
            ("ip_hash", "IP hash (sesión pegajosa)"), ("hash_ip", "Hash consistente por IP")]),
        F("servers", "Servidores", "textarea", "", required=True, validate=v_servers, rows=5, mono=True,
          help="Uno por línea: host:puerto [weight=N] [backup] [down]", to_text=servers_to_text),
        F("max_fails", "Fallos antes de marcar caído", "number", 3, validate=v_int(0, 100)),
        F("fail_timeout", "Tiempo fuera tras fallos", "text", "30s", validate=v_duration),
        F("keepalive", "Conexiones keepalive al backend", "number", 32, validate=v_int(0, 10000)),
        F("notes", "Notas", "textarea", "", rows=2),
    ]


def stream_fields(access_lists, local_ips=(), current_listen=""):
    return [
        F("name", "Nombre", required=True, validate=v_name),
        F("enabled", "Activo", "bool", True),
        listen_field(local_ips, current_listen),
        F("listen_port", "Puerto de escucha", "number", "", required=True, validate=v_port),
        F("protocol", "Protocolo", "select", "tcp", options=[("tcp", "TCP"), ("udp", "UDP"), ("both", "TCP + UDP")]),
        F("targets", "Destinos", "textarea", "", required=True, validate=v_servers, rows=3, mono=True,
          help="Uno por línea: host:puerto [weight=N] [backup]", to_text=servers_to_text),
        F("method", "Balanceo", "select", "round_robin", options=[
            ("round_robin", "Round robin"), ("least_conn", "Menos conexiones"), ("hash_ip", "Hash por IP")]),
        F("connect_timeout", "Timeout de conexión", "text", "10s", validate=v_duration),
        F("proxy_timeout", "Timeout de inactividad", "text", "10m", validate=v_duration),
        F("access_list_id", "Lista de acceso (solo reglas IP)", "select", "", cast=int,
          options=[("", "— ninguna —")] + [(str(a["id"]), a["name"]) for a in access_lists]),
        F("notes", "Notas", "textarea", "", rows=2),
    ]


def access_fields():
    return [
        F("name", "Nombre", required=True, validate=v_name),
        F("allow", "Permitir (IP/CIDR)", "textarea", "", validate=v_cidrs, rows=4, mono=True,
          help="Uno por línea. Ej: 192.168.88.0/24", to_text=lambda v: "\n".join(v or [])),
        F("deny", "Denegar (IP/CIDR)", "textarea", "", validate=v_cidrs, rows=3, mono=True,
          to_text=lambda v: "\n".join(v or [])),
        F("default_action", "Si no coincide ninguna regla", "select", "deny",
          options=[("deny", "Denegar"), ("allow", "Permitir")]),
        F("auth_users", "Autenticación básica", "textarea", "", rows=3, mono=True, special="auth_users",
          help="usuario:contraseña por línea. Para conservar una contraseña existente deja 'usuario:' sin nada detrás.",
          to_text=lambda v: "\n".join(f"{u['user']}:" for u in v or [])),
        F("satisfy", "Combinar IP y usuario", "select", "all",
          options=[("all", "Debe cumplir ambas (IP Y usuario)"), ("any", "Basta una (IP O usuario)")]),
    ]


def settings_fields():
    return [
        S("Comportamiento"),
        F("default_behavior", "Peticiones a dominios desconocidos / por IP", "select", "drop", options=[
            ("drop", "Cerrar la conexión sin responder (444) — recomendado"),
            ("404", "Responder 404")],
          help="En HTTPS se rechaza el handshake TLS si el SNI no coincide con ningún host."),
        F("ipv6", "Escuchar también en IPv6", "bool", True),
        F("client_max_body_size", "Tamaño máx. de subida global", "text", "64m", validate=v_size),
        F("gzip", "Compresión gzip", "bool", True),
        F("trusted_proxies", "Proxies de confianza (real_ip)", "textarea", "", validate=v_cidrs, rows=2, mono=True,
          help="Si delante hay Cloudflare/otro proxy, sus rangos aquí para registrar la IP real del cliente.",
          to_text=lambda v: "\n".join(v or [])),
        S("Protección"),
        F("waf_scanners", "Bloquear escáneres conocidos (sqlmap, nikto, nuclei…)", "bool", True),
        F("waf_probes", "Bloquear sondeos (.env, .git, phpMyAdmin, backups…)", "bool", True),
        F("waf_injection", "Bloquear patrones de inyección (SQLi, XSS, traversal, Log4Shell)", "bool", True),
        F("waf_bad_methods", "Bloquear métodos TRACE/TRACK/DEBUG", "bool", True),
        F("waf_empty_ua", "Bloquear peticiones sin User-Agent", "bool", False,
          help="Puede romper clientes de API y health-checks."),
        F("rate_limit_rps", "Tasa por IP para hosts con límite (peticiones/s)", "number", 20, validate=v_int(1, 10000)),
        F("blocklist", "Lista negra global (IP/CIDR)", "textarea", "", validate=v_cidrs, rows=6, mono=True,
          help="Se aplica a todos los hosts HTTP y streams.", to_text=lambda v: "\n".join(v or [])),
        S("Caché"),
        F("cache_keys_zone_mb", "Zona de claves (MB)", "number", 50, validate=v_int(1, 4096)),
        F("cache_max_size", "Tamaño máximo en disco", "text", "2g", validate=v_size),
        S("Let's Encrypt"),
        F("le_email", "Email de contacto", "text", "", placeholder="admin@dominio.com", validate=v_email,
          optional=True),
        F("le_staging", "Usar entorno staging (pruebas)", "bool", False),
        S("Avanzado (solo administradores)", admin_only=True),
        F("include_legacy", "Incluir también conf.d/ y sites-enabled/ existentes", "bool", False, admin_only=True,
          help="Desactivado por defecto: un 'default_server' antiguo chocaría con el del panel."),
        F("http_custom", "Directivas extra en http { }", "textarea", "", admin_only=True,
          validate=v_snippet, rows=4, mono=True),
    ]


# ---------- parseo genérico ----------

def _visible(field, values):
    cond = field.get("show_if")
    if not cond:
        return True
    return all(str(values.get(k)) in [str(x) for x in vs] for k, vs in cond.items())


def parse_form(fields, form, existing=None, is_admin=False):
    existing = existing or {}
    data, errors = {}, []
    # primero selects/bools para evaluar show_if
    raw_vals = {}
    for f in fields:
        if f["type"] == "section":
            continue
        if f["type"] == "bool":
            raw_vals[f["name"]] = form.get(f["name"]) in ("on", "1", "true")
        else:
            raw_vals[f["name"]] = form.get(f["name"], "")
    for f in fields:
        if f["type"] == "section":
            continue
        name = f["name"]
        if f.get("admin_only") and not is_admin:
            data[name] = existing.get(name, f["default"])
            continue
        val = raw_vals[name]
        if f["type"] == "bool":
            data[name] = val
            continue
        if not _visible(f, raw_vals):
            data[name] = existing.get(name, f["default"]) if name in existing else f["default"]
            continue
        sval = val.strip() if isinstance(val, str) else val
        try:
            if f.get("special") == "auth_users":
                data[name] = v_auth_users(val, existing.get(name))
                continue
            if sval == "" and f.get("optional"):
                data[name] = ""
                continue
            if sval == "" and f["type"] == "select" and f.get("cast"):
                data[name] = None
                continue
            if f["type"] == "select":
                allowed = [str(o[0]) for o in f["options"]]
                if str(sval) not in allowed:
                    raise V("Opción no válida")
            if f.get("required") and sval == "":
                raise V("Obligatorio")
            if f.get("validate"):
                data[name] = f["validate"](val if f["type"] == "textarea" else sval)
            elif f.get("cast"):
                data[name] = f["cast"](sval)
            else:
                data[name] = sval
        except V as e:
            errors.append(f"{f['label']}: {e}")
            data[name] = val
    return data, errors


def form_values(fields, entity):
    """Valores para pintar el formulario (convierte listas a texto)."""
    out = {}
    for f in fields:
        if f["type"] == "section":
            continue
        v = entity.get(f["name"], f["default"]) if entity else f["default"]
        if f.get("to_text") and not isinstance(v, str):
            v = f["to_text"](v)
        elif f["name"] == "domains" and isinstance(v, list):
            v = "\n".join(v)
        out[f["name"]] = "" if v is None else v
    return out
