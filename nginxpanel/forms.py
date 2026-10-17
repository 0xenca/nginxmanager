"""Declarative form definitions + strict validation.

Everything that ends up in the nginx config goes through a validator that
prevents directive injection (; { } quotes, spaces, $). The only free-text
fields that reach nginx are the 'advanced' ones, reserved for administrators.
"""
import ipaddress
import re

# Allows "_" in labels (not a valid RFC 1123 hostname, but nginx and DNS accept it;
# e.g. pve_internal.example.com). The TLD cannot contain it. Let's Encrypt rejects it (see views).
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9][a-z0-9-]{0,62}$")
HOSTNAME_RE = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$")
DURATION_RE = re.compile(r"^\d{1,6}(ms|s|m|h|d)?$")
SIZE_RE = re.compile(r"^\d{1,6}[kKmMgG]?$")
URL_RE = re.compile(r"^https?://[^\s;{}\"'\\$`<>]+$")
AUTH_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class V(Exception):
    pass


# ---------- validators ----------

def v_domains(raw):
    items = [x.strip().lower().rstrip(".") for x in re.split(r"[\s,]+", raw or "") if x.strip()]
    if not items:
        raise V("Enter at least one domain")
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
            raise V(f"Invalid domain: {d}")
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
        raise V(f"Invalid host/IP: {raw}")
    return h


def v_port(raw):
    try:
        p = int(raw)
    except (TypeError, ValueError):
        raise V("Invalid port")
    if not 1 <= p <= 65535:
        raise V("Port out of range (1-65535)")
    return p


def v_int(lo, hi):
    def f(raw):
        try:
            n = int(raw)
        except (TypeError, ValueError):
            raise V("Invalid number")
        if not lo <= n <= hi:
            raise V(f"Must be between {lo} and {hi}")
        return n
    return f


def v_duration(raw):
    raw = (raw or "").strip()
    if not DURATION_RE.match(raw):
        raise V("Invalid duration (e.g. 30s, 10m, 1h)")
    return raw


def v_size(raw):
    raw = (raw or "").strip()
    if not SIZE_RE.match(raw):
        raise V("Invalid size (e.g. 64m, 1g)")
    return raw.lower()


def v_name(raw):
    raw = (raw or "").strip()
    if not NAME_RE.match(raw):
        raise V("Invalid name (letters, digits, space . _ -)")
    return raw


def v_url(raw):
    raw = (raw or "").strip()
    if not URL_RE.match(raw):
        raise V("Invalid URL (http:// or https://, no spaces, ; { } $ or quotes)")
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
            raise V(f"Invalid IP/CIDR: {line}")
        if c not in out:
            out.append(c)
    return out


def v_servers(raw):
    """Lines 'host:port [weight=N] [backup] [down]'."""
    out = []
    for line in (raw or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        addr = parts[0]
        m = re.match(r"^(\[[0-9a-fA-F:]+\]|[^:\[\]]+):(\d+)$", addr)
        if not m:
            raise V(f"Invalid server (use host:port): {line}")
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
                raise V(f"Unknown option '{p}' in: {line}")
        out.append(srv)
    if not out:
        raise V("Add at least one server")
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
            raise V("Unbalanced braces in the custom block")
    if depth:
        raise V("Unbalanced braces in the custom block")
    return raw


def v_auth_users(raw, existing):
    """'user:password' per line. 'user:' without a password keeps the current one."""
    from .htpasswd import ssha
    prev = {u["user"]: u["hash"] for u in existing or []}
    out = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        user, _, pw = line.partition(":")
        user = user.strip()
        if not AUTH_USER_RE.match(user):
            raise V(f"Invalid user: {user}")
        if pw:
            if len(pw) < 8:
                raise V(f"The password for {user} must be 8+ characters")
            out.append({"user": user, "hash": ssha(pw)})
        elif user in prev:
            out.append({"user": user, "hash": prev[user]})
        else:
            raise V(f"Missing password for {user}")
    return out


# ---------- field definitions ----------

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
            raise V("Invalid IP")
        if allowed is not None and ip not in allowed:
            raise V(f"{ip} is not configured on any interface of this server")
        return ip
    return f


def listen_field(local_ips, current=""):
    opts = [("", "All interfaces (IPv4 + IPv6)")]
    opts += [(ip, f"{ip}  ·  {iface}") for ip, iface in local_ips]
    if current and current not in [o[0] for o in opts]:
        opts.append((current, f"{current}  ·  (no longer on any interface)"))
    return F("listen_ip", "Listen on", "select", "", options=opts,
             validate=v_listen_ip([ip for ip, _ in local_ips] + ([current] if current else [])),
             help="Server interface/IP to serve on. All of them by default.")


GROUP_COLORS = [("slate", "Grey"), ("green", "Green"), ("blue", "Blue"), ("amber", "Amber"),
                ("red", "Red"), ("violet", "Violet"), ("teal", "Teal")]


GROUP_NAME_RE = re.compile(r"^[^\W_][\w .,()&+/-]{0,63}$")   # Unicode: allows accented letters


def v_group(raw):
    """Group names are only used in the panel (never in nginx): accented letters are allowed."""
    raw = " ".join((raw or "").split())
    if not GROUP_NAME_RE.match(raw):
        raise V("Invalid group name (letters, digits, spaces and . , ( ) & + / - _)")
    return raw


def host_fields(backends, certs, access_lists, local_ips=(), current_listen="", groups=()):
    return [
        S("General"),
        F("domains", "Domains", "textarea", required=True, validate=v_domains, rows=3,
          help="One per line. Wildcards like *.example.com are allowed. Requests for domains not listed on any host are dropped."),
        F("group_id", "Group", "select", "", cast=int,
          options=[("", "— no group —")] + [(str(gr["id"]), gr["name"]) for gr in groups]),
        F("type", "Type", "select", "proxy", options=[("proxy", "Reverse proxy"), ("redirect", "Redirect")]),
        F("enabled", "Enabled", "bool", True),
        listen_field(local_ips, current_listen),
        S("Target", show_if=PROXY),
        F("forward_mode", "Target", "select", "direct", show_if=PROXY,
          options=[("direct", "Direct server"), ("backend", "Backend (load balancing)")]),
        F("forward_scheme", "Scheme", "select", "http", show_if=PROXY,
          options=[("http", "http"), ("https", "https")]),
        F("forward_host", "Host / IP", "text", "", show_if={**PROXY, "forward_mode": ["direct"]},
          validate=v_host, placeholder="192.168.1.10"),
        F("forward_port", "Port", "number", 80, show_if={**PROXY, "forward_mode": ["direct"]}, validate=v_port),
        F("backend_id", "Backend", "select", "", show_if={**PROXY, "forward_mode": ["backend"]},
          options=[("", "— choose —")] + [(str(b["id"]), b["name"]) for b in backends], cast=int),
        F("upstream_ssl_verify", "Verify the target's certificate (https)", "bool", False, show_if=PROXY),
        F("websocket", "WebSocket support", "bool", False, show_if=PROXY,
          help="Upgrade/Connection headers and long timeouts (1 h)."),
        F("read_timeout", "Read timeout", "text", "60s", show_if=PROXY, validate=v_duration),
        S("Redirect", show_if=REDIR),
        F("redirect_url", "Target URL", "text", "", show_if=REDIR, validate=v_url,
          placeholder="https://other-domain.com"),
        F("redirect_code", "Code", "select", "301", show_if=REDIR, cast=int,
          options=[("301", "301 permanent"), ("302", "302 temporary"), ("307", "307"), ("308", "308")]),
        F("preserve_path", "Preserve path and query", "bool", True, show_if=REDIR),
        S("SSL"),
        F("cert_id", "Certificate", "select", "", cast=int,
          options=[("", "— no SSL —")] + [(str(c["id"]), f"{c['name']} ({c['kind']})") for c in certs]),
        F("force_ssl", "Force HTTPS (redirect 80 → 443)", "bool", True),
        F("http2", "HTTP/2", "bool", True),
        F("hsts", "HSTS (1 year)", "bool", False,
          help="Careful: browsers will remember to force HTTPS for a year."),
        S("Security"),
        F("waf", "Attack filter (basic WAF)", "bool", True,
          help="Scanners, probes (.env, .git…), SQL/XSS injection, traversal, Log4Shell. Rules under Security."),
        F("sec_headers", "Security headers", "bool", True),
        F("access_list_id", "Access list", "select", "", cast=int,
          options=[("", "— none —")] + [(str(a["id"]), a["name"]) for a in access_lists]),
        F("rate_limit", "Rate-limit requests per IP", "bool", False,
          help="Uses the global rate from Security; excess → 429."),
        F("rate_burst", "Allowed burst", "number", 40, validate=v_int(1, 10000)),
        F("conn_limit", "Concurrent connections per IP (0 = unlimited)", "number", 0, validate=v_int(0, 100000)),
        F("max_body", "Max upload size (empty = global)", "text", "", validate=v_size, optional=True),
        S("Cache", show_if=PROXY),
        F("cache_mode", "Cache", "select", "off", show_if=PROXY,
          options=[("off", "Off"), ("static", "Static files only (css, js, images, fonts)"),
                   ("all", "Everything (honors Cache-Control; skips requests with Authorization/session cookie)")]),
        F("cache_ttl", "Default TTL", "text", "10m", show_if=PROXY, validate=v_duration),
        S("Advanced (administrators only)", admin_only=True),
        F("custom_server", "Extra directives in server { }", "textarea", "", admin_only=True,
          validate=v_snippet, rows=4, mono=True),
        F("custom_location", "Extra directives in location / { }", "textarea", "", admin_only=True,
          validate=v_snippet, rows=4, mono=True),
        F("notes", "Notes", "textarea", "", rows=2),
    ]


def backend_fields():
    return [
        F("name", "Name", required=True, validate=v_name),
        F("method", "Load balancing", "select", "round_robin", options=[
            ("round_robin", "Round robin"), ("least_conn", "Least connections"),
            ("ip_hash", "IP hash (sticky sessions)"), ("hash_ip", "Consistent hash by IP")]),
        F("servers", "Servers", "textarea", "", required=True, validate=v_servers, rows=5, mono=True,
          help="One per line: host:port [weight=N] [backup] [down]", to_text=servers_to_text),
        F("max_fails", "Failures before marking down", "number", 3, validate=v_int(0, 100)),
        F("fail_timeout", "Time out after failures", "text", "30s", validate=v_duration),
        F("keepalive", "Keepalive connections to the backend", "number", 32, validate=v_int(0, 10000)),
        F("notes", "Notes", "textarea", "", rows=2),
    ]


def stream_fields(access_lists, local_ips=(), current_listen=""):
    return [
        F("name", "Name", required=True, validate=v_name),
        F("enabled", "Enabled", "bool", True),
        listen_field(local_ips, current_listen),
        F("listen_port", "Listen port", "number", "", required=True, validate=v_port),
        F("protocol", "Protocol", "select", "tcp", options=[("tcp", "TCP"), ("udp", "UDP"), ("both", "TCP + UDP")]),
        F("targets", "Targets", "textarea", "", required=True, validate=v_servers, rows=3, mono=True,
          help="One per line: host:port [weight=N] [backup]", to_text=servers_to_text),
        F("method", "Load balancing", "select", "round_robin", options=[
            ("round_robin", "Round robin"), ("least_conn", "Least connections"), ("hash_ip", "Hash by IP")]),
        F("connect_timeout", "Connect timeout", "text", "10s", validate=v_duration),
        F("proxy_timeout", "Idle timeout", "text", "10m", validate=v_duration),
        F("access_list_id", "Access list (IP rules only)", "select", "", cast=int,
          options=[("", "— none —")] + [(str(a["id"]), a["name"]) for a in access_lists]),
        F("notes", "Notes", "textarea", "", rows=2),
    ]


def access_fields():
    return [
        F("name", "Name", required=True, validate=v_name),
        F("allow", "Allow (IP/CIDR)", "textarea", "", validate=v_cidrs, rows=4, mono=True,
          help="One per line. E.g. 192.168.88.0/24", to_text=lambda v: "\n".join(v or [])),
        F("deny", "Deny (IP/CIDR)", "textarea", "", validate=v_cidrs, rows=3, mono=True,
          to_text=lambda v: "\n".join(v or [])),
        F("default_action", "If no rule matches", "select", "deny",
          options=[("deny", "Deny"), ("allow", "Allow")]),
        F("auth_users", "Basic authentication", "textarea", "", rows=3, mono=True, special="auth_users",
          help="user:password per line. To keep an existing password, leave 'user:' with nothing after it.",
          to_text=lambda v: "\n".join(f"{u['user']}:" for u in v or [])),
        F("satisfy", "Combine IP and user", "select", "all",
          options=[("all", "Must satisfy both (IP AND user)"), ("any", "Either is enough (IP OR user)")]),
    ]


def settings_fields():
    return [
        S("Behavior"),
        F("default_behavior", "Requests for unknown domains / by IP", "select", "drop", options=[
            ("drop", "Close the connection without responding (444) — recommended"),
            ("404", "Respond 404")],
          help="On HTTPS the TLS handshake is rejected if the SNI matches no host."),
        F("ipv6", "Also listen on IPv6", "bool", True),
        F("client_max_body_size", "Global max upload size", "text", "64m", validate=v_size),
        F("gzip", "Gzip compression", "bool", True),
        F("trusted_proxies", "Trusted proxies (real_ip)", "textarea", "", validate=v_cidrs, rows=2, mono=True,
          help="If Cloudflare/another proxy sits in front, put its ranges here to log the real client IP.",
          to_text=lambda v: "\n".join(v or [])),
        S("Protection"),
        F("waf_scanners", "Block known scanners (sqlmap, nikto, nuclei…)", "bool", True),
        F("waf_probes", "Block probes (.env, .git, phpMyAdmin, backups…)", "bool", True),
        F("waf_injection", "Block injection patterns (SQLi, XSS, traversal, Log4Shell)", "bool", True),
        F("waf_bad_methods", "Block TRACE/TRACK/DEBUG methods", "bool", True),
        F("waf_empty_ua", "Block requests without a User-Agent", "bool", False,
          help="May break API clients and health checks."),
        F("rate_limit_rps", "Per-IP rate for rate-limited hosts (requests/s)", "number", 20, validate=v_int(1, 10000)),
        F("blocklist", "Global blocklist (IP/CIDR)", "textarea", "", validate=v_cidrs, rows=6, mono=True,
          help="Applies to all HTTP hosts and streams.", to_text=lambda v: "\n".join(v or [])),
        S("Cache"),
        F("cache_keys_zone_mb", "Keys zone (MB)", "number", 50, validate=v_int(1, 4096)),
        F("cache_max_size", "Max size on disk", "text", "2g", validate=v_size),
        S("Let's Encrypt"),
        F("le_email", "Contact email", "text", "", placeholder="admin@example.com"),
        F("le_staging", "Use the staging environment (testing)", "bool", False),
        S("Advanced (administrators only)", admin_only=True),
        F("include_legacy", "Also include existing conf.d/ and sites-enabled/", "bool", False, admin_only=True,
          help="Off by default: an old 'default_server' would clash with the panel's."),
        F("http_custom", "Extra directives in http { }", "textarea", "", admin_only=True,
          validate=v_snippet, rows=4, mono=True),
    ]


# ---------- generic parsing ----------

def _visible(field, values):
    cond = field.get("show_if")
    if not cond:
        return True
    return all(str(values.get(k)) in [str(x) for x in vs] for k, vs in cond.items())


def parse_form(fields, form, existing=None, is_admin=False):
    existing = existing or {}
    data, errors = {}, []
    # selects/bools first, to evaluate show_if
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
                    raise V("Invalid option")
            if f.get("required") and sval == "":
                raise V("Required")
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
    """Values to render the form (converts lists to text)."""
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
