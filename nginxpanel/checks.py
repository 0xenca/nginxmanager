"""On-demand, layered reachability diagnostics for hosts.

For each host:
  DNS          does it resolve? does it point to an IP of this server?
  nginx        request to the local nginx (listen IP) with the domain's Host/SNI
  Via DNS      the same request to the IP the domain resolves to (like a client)
  Backend      direct TCP + HTTP connection to the target (or to each backend server)
  Certificate  trusted, correct name, expiry?
  HTTP→HTTPS   if HTTPS is forced, port 80 must redirect

All with short timeouts and in parallel across hosts.
"""
import http.client
import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

UA = "nginx-panel-check/1.0"
TIMEOUT = 4.0
LEVELS = {"ok": 0, "info": 0, "warn": 1, "error": 2}


def _probe_name(domain):
    """For wildcards, an arbitrary subdomain is probed."""
    return "panel-check." + domain[2:] if domain.startswith("*.") else domain


def _ms(t0):
    return int((time.monotonic() - t0) * 1000)


def http_probe(ip, port, scheme, host_header, sni=None, path="/", verify=False, front=False):
    """Connects to ip:port (optional TLS with SNI) and sends a GET. Never raises."""
    t0 = time.monotonic()
    res = {"ok": False, "ip": ip, "port": port}
    try:
        sock = socket.create_connection((ip.strip("[]"), port), timeout=TIMEOUT)
    except OSError as e:
        res["error"] = _neterr(e)
        res["stage"] = "tcp"
        return res
    res["tcp_ms"] = _ms(t0)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=sni or host_header)
            except ssl.SSLCertVerificationError as e:
                res["error"] = e.verify_message or str(e)
                res["stage"] = "cert"
                return res
            except (ssl.SSLError, OSError) as e:
                res["error"] = _tlserr(e)
                res["stage"] = "tls"
                return res
            res["tls"] = sock.version()
        conn = http.client.HTTPConnection(host_header, port, timeout=TIMEOUT)
        conn.sock = sock
        conn.request("GET", path, headers={"Host": host_header, "User-Agent": UA, "Accept": "*/*",
                                           "Connection": "close"})
        r = conn.getresponse()
        res.update(ok=True, status=r.status, location=r.getheader("Location") or "",
                   server=r.getheader("Server") or "", ms=_ms(t0))
        conn.close()
    except (OSError, http.client.HTTPException) as e:
        if front and isinstance(e, (http.client.RemoteDisconnected, ConnectionResetError)):
            res["error"] = ("nginx closed the connection without responding (444): no published host matches "
                            "this domain. Pending reload, disabled host or a different listen IP?")
        elif isinstance(e, http.client.RemoteDisconnected):
            res["error"] = "the server closed the connection without responding"
        else:
            res["error"] = _neterr(e) if isinstance(e, OSError) else f"invalid HTTP response ({type(e).__name__})"
        res["stage"] = "http"
        try:
            sock.close()
        except OSError:
            pass
    return res


def _neterr(e):
    if isinstance(e, socket.timeout) or "timed out" in str(e):
        return "no response (timeout)"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused (port closed)"
    if isinstance(e, ConnectionResetError):
        return "connection reset by peer"
    if isinstance(e, socket.gaierror):
        return "does not resolve"
    if getattr(e, "errno", None) in (101, 113):
        return "network or host unreachable"
    return str(e)


def _tlserr(e):
    msg = str(e)
    if "UNRECOGNIZED_NAME" in msg or "unrecognized name" in msg:
        return "nginx rejects the SNI (the domain is not published over HTTPS)"
    if "EOF" in msg or "reset" in msg.lower():
        return "nginx closed the TLS connection"
    return msg


def resolve(name):
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    out = []
    for fam, *_rest, sa in infos:
        ip = sa[0]
        if ip not in out:
            out.append(ip)
    return out


def _fmt(ip):
    return f"[{ip}]" if ":" in ip else ip


def check_host(h, ctx):
    """ctx: local_ips (set), cert_paths(host)->paths|None, backend (dict|None), acl (bool),
    cert (dict|None), days_left(cert)->int|None"""
    checks = []

    def add(name, level, detail):
        checks.append({"name": name, "level": level, "detail": detail})

    if not h.get("enabled", True):
        return {"ts": time.time(), "level": "off", "summary": "Disabled", "checks": []}

    domain = h["domains"][0]
    name = _probe_name(domain)
    has_ssl = ctx["cert_paths"] is not None
    scheme, port = ("https", 443) if has_ssl else ("http", 80)
    is_proxy = h.get("type", "proxy") == "proxy"
    local_ips = ctx["local_ips"]

    # 1. DNS
    ips = resolve(name)
    dns_ok = bool(ips)
    if not ips:
        add("DNS", "warn", f"{name} does not resolve from this server")
    else:
        mine = [ip for ip in ips if ip in local_ips]
        if mine:
            add("DNS", "ok", f"{', '.join(ips)} — points to this server")
        else:
            add("DNS", "info", f"{', '.join(ips)} — not a local IP (fine if there is NAT or a proxy in front)")

    # 2. local nginx
    listen = h.get("listen_ip") or "127.0.0.1"
    front = http_probe(listen, port, scheme, name, sni=name, front=True)
    front_level = "error"
    if not front["ok"]:
        add(f"nginx {scheme.upper()} local", "error", f"{_fmt(listen)}:{port} — {front['error']}")
    else:
        st = front["status"]
        acl_expected = ctx["acl"] and st in (401, 403)
        if h.get("type") == "redirect":
            front_level = "ok" if 300 <= st < 400 else "warn"
            detail = f"{st} → {front['location'] or '(no Location)'}"
        elif st in (502, 503, 504):
            front_level = "error"
            detail = f"{st}: nginx responds but gets no response from the backend"
        elif st >= 500:
            front_level = "error"
            detail = f"{st}: backend error"
        elif acl_expected:
            front_level = "ok"
            detail = f"{st}: protected by an access list (expected)"
        elif st == 403 and h.get("waf"):
            front_level = "warn"
            detail = "403: blocked (WAF or blocklist?)"
        elif st == 429:
            front_level = "warn"
            detail = "429: rate limit reached"
        elif st >= 400:
            front_level = "warn"
            detail = f"{st}: nginx and the backend respond, but / returns an error"
        else:
            front_level = "ok"
            detail = f"{st}"
        tls = f" · {front['tls']}" if front.get("tls") else ""
        add(f"nginx {scheme.upper()} local", front_level, f"{detail} · {front['ms']} ms{tls}")

    # 3. via DNS (like a client)
    via_level = None
    ext_ips = [ip for ip in ips if ip not in local_ips and not ipaddress.ip_address(ip).is_loopback]
    if ext_ips and front["ok"]:
        via = http_probe(ext_ips[0], port, scheme, name, sni=name, front=True)
        same = via["ok"] and via["status"] == front["status"] and via["server"].lower().startswith("nginx")
        if same:
            via_level = "ok"
            add("Via DNS", "ok", f"{_fmt(ext_ips[0])}:{port} responds {via['status']} in {via['ms']} ms")
        elif via["ok"]:
            via_level = "warn"
            who = via["server"] or "no Server header"
            add("Via DNS", "warn", f"{_fmt(ext_ips[0])}:{port} responds {via['status']} ({who}) but locally "
                                   f"it is {front['status']}: looks like another server. Does DNS point to another machine, "
                                   "or is there a CDN/proxy/router in front?")
        else:
            via_level = "warn"
            add("Via DNS", "warn", f"{_fmt(ext_ips[0])}:{port} — {via['error']}. It may work from outside: "
                                   "check NAT loopback (hairpin), firewall or port forwarding")

    # 4. certificate
    if has_ssl and front.get("stage") not in ("tcp", "tls"):
        strict = http_probe(listen, port, "https", name, sni=name, verify=True)
        days = ctx["days_left"]
        exp = f" · expires in {days} days" if days is not None else ""
        if strict["ok"] or strict.get("stage") == "http":
            lvl = "warn" if days is not None and days < 14 else "ok"
            add("Certificate", lvl, f"trusted and valid for {name}{exp}")
        elif strict.get("stage") == "cert":
            msg = strict["error"]
            lvl = "info" if ctx["cert"] and ctx["cert"].get("kind") == "selfsigned" else "error"
            if "self" in msg.lower():
                msg = "self-signed (browsers will warn)"
            elif "expired" in msg.lower():
                msg, lvl = "EXPIRED", "error"
            elif "hostname" in msg.lower() or "match" in msg.lower():
                msg, lvl = f"does not cover {name}", "error"
            elif "local issuer" in msg.lower():
                msg = "missing intermediate chain (fullchain) or untrusted CA"
            add("Certificate", lvl, msg + exp)
    elif h.get("cert_id") and not has_ssl:
        add("Certificate", "error", "assigned but has no files: the host is published over HTTP only")

    # 5. HTTP → HTTPS
    if has_ssl and h.get("force_ssl"):
        r80 = http_probe(listen, 80, "http", name, front=True)
        if r80["ok"] and r80["status"] in (301, 302, 307, 308) and r80["location"].startswith("https://"):
            add("HTTP→HTTPS", "ok", f"{r80['status']} → {r80['location'][:60]}")
        elif r80["ok"]:
            add("HTTP→HTTPS", "warn", f"port 80 responds {r80['status']} without redirecting")
        else:
            add("HTTP→HTTPS", "warn", f"port 80: {r80['error']}")

    # 6. direct backend
    backend_down = False
    if is_proxy:
        targets = []
        if ctx["backend"]:
            targets = [(s["host"], s["port"], s.get("backup"), s.get("down")) for s in ctx["backend"]["servers"]]
        elif h.get("forward_host"):
            targets = [(h["forward_host"], h["forward_port"], False, False)]
        up = 0
        multi = len([t for t in targets if not t[3]]) > 1
        fail_lvl = "warn" if multi else "error"   # with several servers, one down does not take the host down
        for host, port_, backup, down in targets:
            label = f"Backend {host}:{port_}" + (" (backup)" if backup else "")
            if down:
                add(label, "info", "marked as 'down' in the backend")
                continue
            target_ip = host
            if not _is_ip(host.strip("[]")):
                r = resolve(host)
                if not r:
                    add(label, fail_lvl, f"{host} does not resolve from this server")
                    continue
                target_ip = r[0]
            b = http_probe(target_ip, port_, h.get("forward_scheme", "http"), name)
            if b["ok"]:
                up += 1
                lvl = "warn" if b["status"] >= 500 else "ok"
                add(label, lvl, f"{b['status']} in {b['ms']} ms")
            elif b.get("stage") in ("http", "tls"):
                up += 1
                add(label, "warn", f"port open, but: {b['error']}"
                    + (" (is it HTTPS while the host says http, or vice versa?)" if b.get("stage") in ("http", "tls") else ""))
            else:
                add(label, fail_lvl, b["error"] + (" — load balancing uses the rest" if multi else ""))
        backend_down = bool(targets) and up == 0

    # summary
    worst = max((LEVELS[c["level"]] for c in checks), default=0)
    level = {0: "ok", 1: "warn", 2: "error"}[worst]
    if not front["ok"]:
        summary = ("Not published in nginx (444)" if "444" in front["error"]
                   else f"nginx not responding ({front['error']})")
    elif backend_down:
        summary = "Backend down"
        level = "error"
    elif front_level == "error":
        summary = f"Error {front.get('status')}"
    elif front_level == "warn":
        summary = f"Responds {front.get('status')} (check)"
    else:
        summary = f"Reachable · {front['status']} · {front['ms']} ms"
        if via_level == "warn":
            summary += " · fails via DNS"
    if front["ok"] and not dns_ok:
        summary += " · no DNS"
    return {"ts": time.time(), "level": level, "summary": summary, "checks": checks}


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def run_checks(items, max_workers=12):
    """items: list of (host, ctx). Returns {host_id: result}."""
    out = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(check_host, h, ctx): h["id"] for h, ctx in items}
        for f, hid in futs.items():
            try:
                out[hid] = f.result(timeout=60)
            except Exception as e:  # noqa: BLE001
                out[hid] = {"ts": time.time(), "level": "error", "summary": f"Checker failure: {e}",
                            "checks": []}
    return out
