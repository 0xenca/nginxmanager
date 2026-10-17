"""Panel paths and parameters. Everything can be overridden with NP_* variables."""
import os
import secrets
from pathlib import Path


def _env(name, default):
    return os.environ.get(name, default)


DATA_DIR = Path(_env("NP_DATA_DIR", "/var/lib/nginx-panel"))
NGINX_BIN = _env("NP_NGINX_BIN", "nginx")
NGINX_DIR = Path(_env("NP_NGINX_DIR", "/etc/nginx"))
NGINX_CONF = NGINX_DIR / "nginx.conf"
MANAGED_DIR = NGINX_DIR / "panel"                  # everything generated lives here
LOG_DIR = Path(_env("NP_LOG_DIR", "/var/log/nginx/panel"))
ACME_ROOT = Path(_env("NP_ACME_ROOT", "/var/www/panel-acme"))
CACHE_DIR = Path(_env("NP_CACHE_DIR", "/var/cache/nginx/panel"))
LE_DIR = Path(_env("NP_LE_DIR", "/etc/letsencrypt"))
PID_FILE = _env("NP_PID_FILE", "/run/nginx.pid")
STATUS_PORT = int(_env("NP_STATUS_PORT", "8099"))   # stub_status, 127.0.0.1 only
PANEL_PORT = int(_env("NP_PANEL_PORT", "8181"))
DRY_RUN = _env("NP_DRY_RUN", "0") == "1"           # never reloads/installs anything (tests)
BEHIND_PROXY = _env("NP_BEHIND_PROXY", "0") == "1"   # the panel is published through nginx
# Networks allowed to use the panel (comma-separated CIDRs). Empty = any.
ALLOWED_NETS = [x.strip() for x in _env("NP_ALLOWED_NETS", "").split(",") if x.strip()]
SECURE_COOKIES = _env("NP_SECURE_COOKIES", "0") == "1"

DB_PATH = DATA_DIR / "panel.db"
BACKUP_DIR = DATA_DIR / "backups"
JOBS_DIR = DATA_DIR / "jobs"
SECRET_FILE = DATA_DIR / "secret.key"


def secret_key():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRET_FILE.exists():
        SECRET_FILE.write_text(secrets.token_hex(32))
        os.chmod(SECRET_FILE, 0o600)
    return SECRET_FILE.read_text().strip()
