"""Detección del entorno, generación de la config y aplicación con rollback."""
import fcntl
import os
import pwd
import re
import shutil
import subprocess
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import config
from .db import get_settings, list_entities

TPL = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates" / "nginx")),
    trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True, undefined=StrictUndefined,
)


def run(cmd, timeout=60, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, f"No encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "Tiempo de espera agotado"


# ---------------- entorno ----------------

def nginx_installed():
    return shutil.which(config.NGINX_BIN) is not None or Path(config.NGINX_BIN).is_file()


def _ver_tuple(v):
    return tuple(int(x) for x in v.split("."))


def detect_env():
    env = {"installed": nginx_installed(), "version": None, "build": "", "user": "nobody"}
    for u in ("www-data", "nginx", "http"):
        try:
            pwd.getpwnam(u)
            env["user"] = u
            break
        except KeyError:
            pass
    if env["installed"]:
        _, out = run([config.NGINX_BIN, "-V"])
        env["build"] = out
        m = re.search(r"nginx/(\d+\.\d+\.\d+)", out)
        env["version"] = m.group(1) if m else "0.0.0"
    ver = _ver_tuple(env["version"] or "0.0.0")
    b = env["build"]
    env["http2_directive"] = ver >= (1, 25, 1)
    env["reject_handshake"] = ver >= (1, 19, 4)
    env["has_http2"] = "--with-http_v2_module" in b
    env["has_stub_status"] = "--with-http_stub_status_module" in b
    env["has_realip"] = "--with-http_realip_module" in b
    env["ipv6"] = Path("/proc/net/if_inet6").exists()

    includes = []
    for pattern_dir, pattern in ((config.NGINX_DIR / "modules-enabled", "*.conf"),
                                 (Path("/usr/share/nginx/modules"), "*.conf")):
        if pattern_dir.is_dir() and list(pattern_dir.glob(pattern)):
            includes.append(f"{pattern_dir}/{pattern}")
    env["module_includes"] = includes

    env["stream"] = False
    env["stream_load"] = None
    if "--with-stream=dynamic" in b:
        loaded = False
        for inc in includes:
            d, pat = inc.rsplit("/", 1)
            for f in Path(d).glob(pat):
                try:
                    if "stream" in f.read_text():
                        loaded = True
                except OSError:
                    pass
        if loaded:
            env["stream"] = True
        else:
            for d in (config.NGINX_DIR / "modules", Path("/usr/lib/nginx/modules"),
                      Path("/usr/lib64/nginx/modules"), Path("/usr/share/nginx/modules")):
                so = d / "ngx_stream_module.so"
                if so.exists():
                    env["stream"] = True
                    env["stream_load"] = str(so)
                    break
    elif "--with-stream" in b:
        env["stream"] = True

    env["ca_bundle"] = next((p for p in ("/etc/ssl/certs/ca-certificates.crt",
                                         "/etc/pki/tls/certs/ca-bundle.crt") if Path(p).exists()),
                            "/etc/ssl/certs/ca-certificates.crt")
    return env


def local_ips():
    """IPs configuradas en las interfaces del servidor (sin link-local)."""
    ips = []
    code, out = run(["ip", "-o", "addr", "show"])
    if code == 0:
        for m in re.finditer(r"^\d+:\s+(\S+)\s+inet6?\s+([0-9a-fA-F.:]+)/\d+", out, re.M):
            iface, ip = m.group(1), m.group(2)
            if ip.lower().startswith("fe80"):
                continue
            ips.append((ip, iface))
    else:
        ips = _ips_from_kernel()
    seen, out_ips = set(), []
    for ip, iface in ips:
        if ip not in seen:
            seen.add(ip)
            out_ips.append((ip, iface))
    return out_ips


def _ips_from_kernel():
    """Respaldo sin iproute2: IPv4 vía ioctl por interfaz, IPv6 vía /proc/net/if_inet6."""
    import fcntl as _f
    import ipaddress as _ip
    import socket
    import struct
    out = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for iface in sorted(os.listdir("/sys/class/net")):
            try:
                res = _f.ioctl(sock.fileno(), 0x8915, struct.pack("256s", iface[:15].encode()))
                out.append((socket.inet_ntoa(res[20:24]), iface))
            except OSError:
                pass
    except OSError:
        pass
    finally:
        sock.close()
    try:
        for line in Path("/proc/net/if_inet6").read_text().splitlines():
            parts = line.split()
            addr = str(_ip.IPv6Address(bytes.fromhex(parts[0])))
            if not addr.startswith("fe80"):
                out.append((addr, parts[-1]))
    except (OSError, ValueError, IndexError):
        pass
    return out or [("127.0.0.1", "lo")]


def listen_addr(ip):
    """'' -> '' ; IPv4 tal cual ; IPv6 entre corchetes (para 'listen')."""
    if not ip:
        return ""
    return f"[{ip}]" if ":" in ip else ip


def nginx_running():
    try:
        pid = int(Path(config.PID_FILE).read_text().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def stub_status():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{config.STATUS_PORT}/nginx_status", timeout=2) as r:
            txt = r.read().decode()
        nums = list(map(int, re.findall(r"\d+", txt)))
        # Active connections: N / server accepts handled requests / A H R / Reading Writing Waiting
        return {"active": nums[0], "accepts": nums[1], "handled": nums[2], "requests": nums[3],
                "reading": nums[4], "writing": nums[5], "waiting": nums[6]}
    except Exception:
        return None


# ---------------- certificados (rutas) ----------------

def cert_paths(cert):
    if not cert:
        return None
    if cert["kind"] == "letsencrypt":
        base = config.LE_DIR / "live" / cert["certname"]
    else:
        base = config.DATA_DIR / "certs" / str(cert["id"])
    fc, key = base / "fullchain.pem", base / "privkey.pem"
    if fc.exists() and key.exists():
        return {"fullchain": str(fc), "key": str(key)}
    return None


def ensure_default_cert():
    """Certificado autofirmado para el default_server en nginx < 1.19.4."""
    d = config.DATA_DIR / "certs" / "default"
    fc, key = d / "fullchain.pem", d / "privkey.pem"
    if not fc.exists():
        d.mkdir(parents=True, exist_ok=True)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
             "-subj", "/CN=invalid", "-keyout", str(key), "-out", str(fc)])
        os.chmod(key, 0o600)
    return {"fullchain": str(fc), "key": str(key)}


# ---------------- render ----------------

def render_all(db=None):
    """Devuelve (nginx_conf, {ruta_relativa: contenido}, avisos)."""
    env = detect_env()
    s = get_settings(db)
    hosts = list_entities("hosts", db)
    backends = {b["id"]: b for b in list_entities("backends", db)}
    streams = list_entities("streams", db)
    certs = {c["id"]: c for c in list_entities("certs", db)}
    acls = {a["id"]: a for a in list_entities("access_lists", db)}
    warnings = []
    files = {}
    managed = str(config.MANAGED_DIR)
    ipv6 = bool(s["ipv6"] and env["ipv6"])

    common = dict(env=env, s=s, managed=managed, ipv6=ipv6, acme_root=str(config.ACME_ROOT),
                  log_dir=str(config.LOG_DIR), cache_dir=str(config.CACHE_DIR))

    files["snippets/proxy.conf"] = TPL.get_template("proxy.conf.j2").render(**common)
    files["snippets/security_headers.conf"] = TPL.get_template("security_headers.conf.j2").render(**common)
    files["snippets/waf_maps.conf"] = TPL.get_template("waf_maps.conf.j2").render(**common)

    for b in backends.values():
        files[f"upstreams/backend_{b['id']}.conf"] = TPL.get_template("upstream.conf.j2").render(b=b, **common)

    for a in acls.values():
        if a.get("auth_users"):
            files[f"htpasswd/access_{a['id']}"] = "".join(f"{u['user']}:{u['hash']}\n" for u in a["auth_users"])

    # IPs concretas usadas por algún host: nginx solo ofrece en IP:puerto los servers
    # que escuchan exactamente ahí, así que los hosts "en todas" también deben declararlas.
    extra_addrs = {listen_addr(h["listen_ip"]) for h in hosts
                   if h.get("enabled", True) and h.get("listen_ip")}
    for h in hosts:
        if not h.get("enabled", True):
            continue
        cert = certs.get(h.get("cert_id")) if h.get("cert_id") else None
        paths = cert_paths(cert) if cert else None
        if cert and not paths:
            warnings.append(f"Host {', '.join(h['domains'])}: el certificado '{cert['name']}' aún no tiene "
                            f"ficheros; se publica sin SSL.")
        backend = None
        if h.get("type", "proxy") == "proxy" and h.get("forward_mode") == "backend":
            backend = backends.get(h.get("backend_id"))
            if not backend:
                warnings.append(f"Host {', '.join(h['domains'])}: backend inexistente, omitido.")
                continue
        acl = acls.get(h.get("access_list_id")) if h.get("access_list_id") else None
        laddr = listen_addr(h.get("listen_ip") or "")
        files[f"hosts/host_{h['id']}.conf"] = TPL.get_template("host.conf.j2").render(
            h=h, cert=paths, backend=backend, acl=acl, laddr=laddr,
            also_addrs=sorted(extra_addrs), **common)

    if streams and not env["stream"]:
        warnings.append("Este nginx no tiene el módulo stream: los streams no se publican. "
                        "En Debian/Ubuntu: apt install libnginx-mod-stream.")
    active_streams = [st for st in streams if st.get("enabled", True)] if env["stream"] else []
    for st in active_streams:
        acl = acls.get(st.get("access_list_id")) if st.get("access_list_id") else None
        files[f"streams/stream_{st['id']}.conf"] = TPL.get_template("stream.conf.j2").render(
            st=st, acl=acl, laddr=listen_addr(st.get("listen_ip") or ""), **common)

    default_cert = None if env["reject_handshake"] else ensure_default_cert()
    nginx_conf = TPL.get_template("nginx.conf.j2").render(
        pid_file=config.PID_FILE, nginx_dir=str(config.NGINX_DIR), status_port=config.STATUS_PORT,
        has_streams=bool(active_streams), default_cert=default_cert,
        extra_addrs=sorted(extra_addrs), **common)
    return nginx_conf, files, warnings


def render_host_preview(hid, db=None):
    _, files, _ = render_all(db)
    return files.get(f"hosts/host_{hid}.conf", "# Host desactivado o sin generar")


# ---------------- aplicar ----------------

@contextmanager
def apply_lock():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.DATA_DIR / "apply.lock", "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def test_config():
    return run([config.NGINX_BIN, "-t", "-c", str(config.NGINX_CONF)])


def _write_tree(root, files, env):
    root.mkdir(parents=True)
    for sub in ("hosts", "upstreams", "streams", "snippets", "htpasswd"):
        (root / sub).mkdir()
    for rel, content in files.items():
        p = root / rel
        p.write_text(content)
        if rel.startswith("htpasswd/"):
            os.chmod(p, 0o640)
            try:
                shutil.chown(p, group=pwd.getpwnam(env["user"]).pw_gid)
            except (KeyError, PermissionError, LookupError):
                os.chmod(p, 0o644)


def backup_current(label="auto"):
    ts = time.strftime("%Y%m%d-%H%M%S") + f".{int(time.time() * 1000) % 1000:03d}"
    label = re.sub(r"[^A-Za-z0-9_-]", "_", label)[:40]
    dest = config.BACKUP_DIR / f"{ts}-{label}"
    n = 1
    while dest.exists():
        n += 1
        dest = config.BACKUP_DIR / f"{ts}-{label}-{n}"
    dest.mkdir(parents=True, exist_ok=True)
    if config.NGINX_CONF.exists():
        shutil.copy2(config.NGINX_CONF, dest / "nginx.conf")
    if config.MANAGED_DIR.exists():
        shutil.copytree(config.MANAGED_DIR, dest / "panel")
    backups = sorted(config.BACKUP_DIR.iterdir())
    for old in backups[:-40]:
        shutil.rmtree(old, ignore_errors=True)
    return dest


def list_backups():
    if not config.BACKUP_DIR.exists():
        return []
    return sorted((p.name for p in config.BACKUP_DIR.iterdir() if p.is_dir()), reverse=True)


def has_systemd():
    return Path("/run/systemd/system").exists() and shutil.which("systemctl") is not None


# Si un backend usa nombres DNS y aún no resuelven (p. ej. justo al arrancar el servidor),
# nginx no arranca. Con esto systemd lo reintenta cada minuto, sin límite, hasta que lo logra.
SYSTEMD_DROPIN = Path("/etc/systemd/system/nginx.service.d/nginx-panel-restart.conf")
SYSTEMD_DROPIN_TEXT = """# Generado por nginx-panel: reintenta arrancar nginx cada minuto si falla (DNS de backends)
[Unit]
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=60
"""


def ensure_systemd_restart():
    """Instala el drop-in de reintento de nginx si falta o ha cambiado."""
    if config.DRY_RUN or not has_systemd():
        return
    try:
        if SYSTEMD_DROPIN.exists() and SYSTEMD_DROPIN.read_text() == SYSTEMD_DROPIN_TEXT:
            return
        SYSTEMD_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        SYSTEMD_DROPIN.write_text(SYSTEMD_DROPIN_TEXT)
    except OSError:
        return
    run(["systemctl", "daemon-reload"])


def reload_nginx():
    if config.DRY_RUN:
        return True, "DRY_RUN: recarga omitida"
    if nginx_running():
        code, out = run([config.NGINX_BIN, "-s", "reload", "-c", str(config.NGINX_CONF)])
    elif has_systemd():
        code, out = run(["systemctl", "start", "nginx"])
    else:
        code, out = run([config.NGINX_BIN, "-c", str(config.NGINX_CONF)])
    return code == 0, out


def ensure_dirs(env):
    for d in (config.LOG_DIR, config.ACME_ROOT / ".well-known" / "acme-challenge", config.CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(config.LOG_DIR, 0o750)
    for d in (config.ACME_ROOT, config.ACME_ROOT / ".well-known", config.ACME_ROOT / ".well-known" / "acme-challenge"):
        os.chmod(d, 0o755)
    try:
        uid = pwd.getpwnam(env["user"]).pw_uid
        os.chown(config.CACHE_DIR, uid, -1)
    except (KeyError, PermissionError):
        pass


def apply(db=None, label="auto"):
    """Genera, valida con nginx -t y recarga. Si falla, restaura lo anterior."""
    if not nginx_installed():
        return False, "nginx no está instalado.", []
    nginx_conf, files, warnings = render_all(db)
    env = detect_env()
    with apply_lock():
        ensure_dirs(env)
        ensure_systemd_restart()
        orig = config.NGINX_DIR / "nginx.conf.panel-orig"
        if config.NGINX_CONF.exists() and not orig.exists():
            shutil.copy2(config.NGINX_CONF, orig)
        backup_current(label)
        new = config.MANAGED_DIR.with_name("panel.new")
        old = config.MANAGED_DIR.with_name("panel.old")
        for p in (new, old):
            shutil.rmtree(p, ignore_errors=True)
        _write_tree(new, files, env)
        prev_conf = config.NGINX_CONF.read_text() if config.NGINX_CONF.exists() else None
        had_managed = config.MANAGED_DIR.exists()
        if had_managed:
            config.MANAGED_DIR.rename(old)
        new.rename(config.MANAGED_DIR)
        config.NGINX_CONF.write_text(nginx_conf)

        code, out = test_config()
        if code != 0:
            shutil.rmtree(config.MANAGED_DIR, ignore_errors=True)
            if had_managed:
                old.rename(config.MANAGED_DIR)
            if prev_conf is not None:
                config.NGINX_CONF.write_text(prev_conf)
            return False, "nginx -t ha fallado; se ha restaurado la configuración anterior.\n\n" + out, warnings
        shutil.rmtree(old, ignore_errors=True)
        ok, rout = reload_nginx()
        if not ok:
            return False, "La configuración es válida pero la recarga falló:\n" + rout, warnings
        return True, out, warnings


def restore_backup(name, db=None):
    src = config.BACKUP_DIR / name
    if not src.is_dir() or "/" in name or name.startswith("."):
        return False, "Backup no encontrado"
    with apply_lock():
        backup_current("pre-restore")
        prev_conf = config.NGINX_CONF.read_text() if config.NGINX_CONF.exists() else None
        old = config.MANAGED_DIR.with_name("panel.old")
        shutil.rmtree(old, ignore_errors=True)
        if config.MANAGED_DIR.exists():
            config.MANAGED_DIR.rename(old)
        if (src / "panel").exists():
            shutil.copytree(src / "panel", config.MANAGED_DIR)
        if (src / "nginx.conf").exists():
            shutil.copy2(src / "nginx.conf", config.NGINX_CONF)
        code, out = test_config()
        if code != 0:
            shutil.rmtree(config.MANAGED_DIR, ignore_errors=True)
            if old.exists():
                old.rename(config.MANAGED_DIR)
            if prev_conf is not None:
                config.NGINX_CONF.write_text(prev_conf)
            return False, out
        shutil.rmtree(old, ignore_errors=True)
        ok, rout = reload_nginx()
        return ok, out if ok else rout


def service_action(action):
    if config.DRY_RUN:
        return True, f"DRY_RUN: {action} omitido"
    if action == "reload":
        code, out = test_config()
        if code != 0:
            return False, out
        return reload_nginx()
    if action in ("restart", "stop", "start") and has_systemd():
        if action != "stop":
            code, out = test_config()
            if code != 0:
                return False, out
        code, out = run(["systemctl", action, "nginx"])
        return code == 0, out or f"{action} OK"
    return False, "Acción no soportada en este sistema"


# ---------------- instalación ----------------

def install_commands():
    if shutil.which("apt-get"):
        envp = "DEBIAN_FRONTEND=noninteractive"
        return [
            f"{envp} apt-get update",
            f"{envp} apt-get install -y nginx libnginx-mod-stream certbot openssl",
            "systemctl enable --now nginx",
        ]
    if shutil.which("dnf"):
        return [
            "dnf install -y epel-release || true",
            "dnf install -y nginx nginx-mod-stream certbot openssl",
            "systemctl enable --now nginx",
        ]
    return None
