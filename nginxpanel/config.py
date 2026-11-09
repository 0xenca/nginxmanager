"""Rutas y parámetros del panel. Todo se puede sobreescribir con variables NP_*."""
import os
import secrets
from pathlib import Path


def _env(name, default):
    return os.environ.get(name, default)


DATA_DIR = Path(_env("NP_DATA_DIR", "/var/lib/nginx-panel"))
NGINX_BIN = _env("NP_NGINX_BIN", "nginx")
NGINX_DIR = Path(_env("NP_NGINX_DIR", "/etc/nginx"))
NGINX_CONF = NGINX_DIR / "nginx.conf"
MANAGED_DIR = NGINX_DIR / "panel"                  # todo lo generado vive aquí
LOG_DIR = Path(_env("NP_LOG_DIR", "/var/log/nginx/panel"))
ACME_ROOT = Path(_env("NP_ACME_ROOT", "/var/www/panel-acme"))
CACHE_DIR = Path(_env("NP_CACHE_DIR", "/var/cache/nginx/panel"))
LE_DIR = Path(_env("NP_LE_DIR", "/etc/letsencrypt"))
PID_FILE = _env("NP_PID_FILE", "/run/nginx.pid")
STATUS_PORT = int(_env("NP_STATUS_PORT", "8099"))   # stub_status, solo 127.0.0.1
PANEL_PORT = int(_env("NP_PANEL_PORT", "8181"))
DRY_RUN = _env("NP_DRY_RUN", "0") == "1"           # no recarga/instala nada (tests)
BEHIND_PROXY = _env("NP_BEHIND_PROXY", "0") == "1"   # el panel se publica a través de nginx
# Redes desde las que se permite usar el panel (CIDR separados por comas). Vacío = cualquiera.
ALLOWED_NETS = [x.strip() for x in _env("NP_ALLOWED_NETS", "").split(",") if x.strip()]
# Proxies cuyo X-Forwarded-For se acepta cuando NP_BEHIND_PROXY=1 (por defecto solo localhost).
TRUSTED_PROXIES = [x.strip() for x in _env("NP_TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if x.strip()]
SECURE_COOKIES = _env("NP_SECURE_COOKIES", "0") == "1"

DB_PATH = DATA_DIR / "panel.db"
BACKUP_DIR = DATA_DIR / "backups"
JOBS_DIR = DATA_DIR / "jobs"
SECRET_FILE = DATA_DIR / "secret.key"


def secret_key():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRET_FILE.exists():
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32))
    return SECRET_FILE.read_text().strip()
