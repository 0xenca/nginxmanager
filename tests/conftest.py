"""Test setup: every NP_* path points to a throwaway directory.

nginxpanel.config reads the environment at import time, so this runs before
the package is imported. If a real nginx binary is available (or NP_NGINX_BIN
points to one), applying the config runs a real `nginx -t` against the
generated files; reloads are always skipped (NP_DRY_RUN=1). Set
NP_REQUIRE_NGINX=1 to fail instead of skipping when nginx is missing.

`nginx -t` opens the listening sockets, so as a non-root user nginx needs
cap_net_bind_service (see .github/workflows/tests.yml).
"""
import html
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BASE = Path(tempfile.mkdtemp(prefix="nginxpanel-tests-"))
NGINX_DIR = BASE / "etc-nginx"
NGINX_DIR.mkdir()

_real_nginx = os.environ.get("NP_NGINX_BIN") or shutil.which("nginx") or "nginx-not-installed"
os.environ.update({
    "NP_DATA_DIR": str(BASE / "data"),
    "NP_LOG_DIR": str(BASE / "log"),
    "NP_NGINX_DIR": str(NGINX_DIR),
    "NP_ACME_ROOT": str(BASE / "acme"),
    "NP_CACHE_DIR": str(BASE / "cache"),
    "NP_LE_DIR": str(BASE / "letsencrypt"),
    "NP_PID_FILE": str(BASE / "nginx.pid"),
    "NP_NGINX_BIN": _real_nginx,
    "NP_DRY_RUN": "1",
})
for candidate in ("/etc/nginx/mime.types", "/usr/local/nginx/conf/mime.types"):
    if Path(candidate).exists():
        shutil.copy(candidate, NGINX_DIR / "mime.types")
        break
else:
    (NGINX_DIR / "mime.types").write_text("types { text/html html; }\n")

from nginxpanel import auth, create_app, db, nginx  # noqa: E402

HAS_NGINX = nginx.nginx_installed()
if os.environ.get("NP_REQUIRE_NGINX") == "1" and not HAS_NGINX:
    raise RuntimeError("NP_REQUIRE_NGINX=1 but no nginx binary was found")
ADMIN_PW = "admin-password-1"
needs_nginx = pytest.mark.skipif(not HAS_NGINX, reason="nginx binary not available")


def pytest_report_header(config):
    return f"nginx: {os.environ['NP_NGINX_BIN'] if HAS_NGINX else 'not available (nginx -t tests skipped)'}"


@pytest.fixture(scope="session")
def app():
    application = create_app()
    application.testing = True
    # response.page: body with HTML entities decoded, so assertions can use plain quotes
    application.response_class.page = property(lambda r: html.unescape(r.get_data(as_text=True)))
    return application


@pytest.fixture(autouse=True)
def clean_db():
    """Empty database and generated files before every test."""
    db.init_db()
    conn = db.connect()
    for table in db.ENTITY_TABLES + ("users", "settings", "audit", "host_status", "login_attempts"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
    shutil.rmtree(BASE / "data" / "certs", ignore_errors=True)
    yield


def make_user(username="admin", password=ADMIN_PW, is_admin=True, perms=None):
    import json
    conn = db.connect()
    conn.execute("INSERT INTO users(username, password_hash, is_admin, perms, active, created_at) VALUES (?,?,?,?,1,?)",
                 (username, auth.hash_password(password), int(is_admin), json.dumps(perms or {}), time.time()))
    conn.commit()
    conn.close()


class Client:
    """Flask test client that logs in and sends the CSRF token on every POST."""

    def __init__(self, app):
        self.c = app.test_client()

    def token(self):
        with self.c.session_transaction() as s:
            if "_csrf" not in s:
                s["_csrf"] = "test-token"
            return s["_csrf"]

    def login(self, username="admin", password=ADMIN_PW):
        return self.post("/login", {"username": username, "password": password}, follow=False)

    def get(self, path, **kw):
        return self.c.get(path, **kw)

    def post(self, path, data=None, follow=True, **kw):
        return self.c.post(path, data={"_csrf": self.token(), **(data or {})}, follow_redirects=follow, **kw)


@pytest.fixture
def client(app):
    make_user()
    cl = Client(app)
    assert cl.login().status_code == 302
    return cl


HOST_FORM = {
    "domains": "app.example.com", "type": "proxy", "enabled": "on", "listen_ip": "",
    "forward_mode": "direct", "forward_scheme": "http", "forward_host": "127.0.0.1", "forward_port": "8080",
    "read_timeout": "60s", "redirect_code": "301", "waf": "on", "sec_headers": "on",
    "rate_burst": "40", "conn_limit": "0", "max_body": "", "cache_mode": "off", "cache_ttl": "10m",
}
