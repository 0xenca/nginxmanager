"""Host diagnostics against a local HTTP server."""
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nginxpanel import checks


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "nginx"

    def do_GET(self):
        status = 503 if self.path == "/down" else 200
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_http_probe_ok(server):
    r = checks.http_probe("127.0.0.1", server, "http", "app.example.com")
    assert r["ok"] and r["status"] == 200 and r["server"] == "nginx"


def test_http_probe_refused():
    r = checks.http_probe("127.0.0.1", free_port(), "http", "app.example.com")
    assert not r["ok"] and r["stage"] == "tcp" and r["error"] == "connection refused (port closed)"


def test_http_probe_tls_against_plain_http(server):
    r = checks.http_probe("127.0.0.1", server, "https", "app.example.com")
    assert not r["ok"] and r["stage"] == "tls"


def test_disabled_host():
    res = checks.check_host({"enabled": False}, {})
    assert res["level"] == "off" and res["summary"] == "Disabled"


def test_backend_checks(server):
    host = {"id": 1, "enabled": True, "domains": ["localhost"], "type": "proxy", "forward_scheme": "http"}
    ctx = {"local_ips": {"127.0.0.1"}, "cert_paths": None, "cert": None, "days_left": None, "acl": False,
           "backend": {"servers": [{"host": "127.0.0.1", "port": server}, {"host": "127.0.0.1", "port": free_port()},
                                   {"host": "127.0.0.1", "port": 1, "down": True}]}}
    res = checks.check_host(host, ctx)
    by_name = {c["name"]: c for c in res["checks"]}
    assert by_name[f"Backend 127.0.0.1:{server}"]["level"] == "ok"
    assert by_name["Backend 127.0.0.1:1"]["detail"] == "marked as 'down' in the backend"
    refused = [c for c in res["checks"] if c["detail"].startswith("connection refused")]
    assert refused and refused[0]["level"] == "warn"            # one of two servers down is only a warning
    assert res["level"] in ("warn", "error")


def test_run_checks_never_raises():
    res = checks.run_checks([({"id": 7, "enabled": True, "domains": None}, {})])
    assert res[7]["level"] == "error" and res[7]["summary"].startswith("Checker failure")
