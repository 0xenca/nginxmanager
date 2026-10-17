"""End-to-end through the web UI: forms → DB → generated config."""
import pytest
from conftest import ADMIN_PW, HOST_FORM, Client, make_user

from nginxpanel import db, nginx

PAGES = ["/", "/hosts", "/backends", "/streams", "/access", "/certs", "/certs/new", "/security", "/analytics",
         "/logs", "/logs?kind=stream", "/logs/errors", "/logs/files", "/users", "/users/new", "/profile", "/audit",
         "/system", "/system/nginx.conf", "/hosts/new", "/backends/new", "/streams/new", "/access/new"]


def actions():
    return [r["action"] for r in db.connect().execute("SELECT action FROM audit ORDER BY id")]


def test_login_required(app):
    r = app.test_client().get("/hosts")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_login_page_without_users(app):
    body = app.test_client().get("/login").page
    assert "There are no users" in body


def test_wrong_password_and_lockout(app):
    make_user()
    c = Client(app)
    for _ in range(5):
        r = c.post("/login", {"username": "admin", "password": "wrong-password"}, follow=False)
        assert r.status_code == 401
    r = c.post("/login", {"username": "admin", "password": ADMIN_PW}, follow=False)
    assert r.status_code == 429 and "Too many failed attempts" in r.page
    assert actions().count("login_failed") == 5


def test_csrf_is_enforced(client):
    r = client.c.post("/groups/new", data={"name": "x"})
    assert r.status_code == 400 and "Invalid CSRF token" in r.page


@pytest.mark.parametrize("path", PAGES)
def test_pages_render(client, path):
    r = client.get(path)
    assert r.status_code == 200, r.page[:500]
    assert '<html lang="en">' in r.page


def test_full_crud_flow(client):
    client.post("/groups/new", {"name": "Internal", "color": "blue"})
    gid = db.list_entities("groups", db.connect())[0]["id"]

    client.post("/backends/new", {"name": "web", "method": "round_robin", "servers": "127.0.0.1:9001\n127.0.0.1:9002",
                                  "max_fails": "3", "fail_timeout": "30s", "keepalive": "32"})
    bid = db.list_entities("backends", db.connect())[0]["id"]

    client.post("/access/new", {"name": "office", "allow": "10.0.0.0/8", "deny": "", "default_action": "deny",
                                "auth_users": "bob:password123", "satisfy": "any"})
    aid = db.list_entities("access_lists", db.connect())[0]["id"]

    r = client.post("/certs/new", {"kind": "selfsigned", "name": "self", "domains": "app.example.com"})
    assert "Self-signed certificate created." in r.page
    cid = db.list_entities("certs", db.connect())[0]["id"]

    r = client.post("/hosts/new", {**HOST_FORM, "domains": "app.example.com\nwww.example.com", "group_id": str(gid),
                                   "forward_mode": "backend", "backend_id": str(bid), "cert_id": str(cid),
                                   "force_ssl": "on", "access_list_id": str(aid), "cache_mode": "static"})
    body = r.page
    assert r.status_code == 200, body[:1000]
    hosts = db.list_entities("hosts", db.connect())
    assert len(hosts) == 1 and hosts[0]["group_id"] == gid
    hid = hosts[0]["id"]

    preview = client.get(f"/hosts/{hid}/config").page
    assert f"proxy_pass http://panel_up_{bid};" in preview and "listen 443 ssl" in preview

    client.post("/streams/new", {"name": "ssh", "enabled": "on", "listen_ip": "", "listen_port": "2222",
                                 "protocol": "tcp", "targets": "127.0.0.1:22", "method": "round_robin",
                                 "connect_timeout": "10s", "proxy_timeout": "10m"})
    assert len(db.list_entities("streams", db.connect())) == 1

    for p in (f"/hosts/{hid}/edit", f"/backends/{bid}/edit", f"/access/{aid}/edit", "/hosts/new?group=1"):
        assert client.get(p).status_code == 200

    # resources in use cannot be deleted
    r = client.post(f"/backends/{bid}/delete")
    assert "Cannot delete: in use by app.example.com, www.example.com" in r.page
    r = client.post(f"/certs/{cid}/delete")
    assert "Cannot delete: in use by" in r.page

    client.post(f"/hosts/{hid}/toggle")
    assert db.get_entity("hosts", hid, db.connect())["enabled"] is False
    client.post(f"/groups/{gid}/toggle", {"enable": "1"})
    assert db.get_entity("hosts", hid, db.connect())["enabled"] is True

    client.post(f"/groups/{gid}/delete")
    assert db.get_entity("hosts", hid, db.connect())["group_id"] is None      # hosts survive their group

    client.post(f"/hosts/{hid}/delete")
    client.post(f"/backends/{bid}/delete")
    assert db.list_entities("hosts", db.connect()) == [] and db.list_entities("backends", db.connect()) == []

    assert actions()[1:] == [
        "group_create", "backends_create", "access_lists_create", "cert_selfsigned", "hosts_create",
        "streams_create", "hosts_disable", "group_enable", "group_delete", "hosts_delete", "backends_delete"]


def test_host_validation_errors(client):
    r = client.post("/hosts/new", {**HOST_FORM, "domains": "bad domain;"})
    assert r.status_code == 400 and "Domains: Invalid domain: bad" in r.page
    client.post("/hosts/new", HOST_FORM)
    r = client.post("/hosts/new", HOST_FORM)
    assert r.status_code == 400 and "Domain already used by another host: app.example.com" in r.page
    r = client.post("/hosts/new", {**HOST_FORM, "domains": "x.example.com", "forward_mode": "backend", "backend_id": ""})
    assert "Choose a backend" in r.page


def test_stream_port_conflicts(client):
    form = {"name": "a", "enabled": "on", "listen_ip": "", "listen_port": "5000", "protocol": "tcp",
            "targets": "127.0.0.1:22", "method": "round_robin", "connect_timeout": "10s", "proxy_timeout": "10m"}
    client.post("/streams/new", form)
    r = client.post("/streams/new", {**form, "name": "b", "protocol": "both"})
    assert "Port 5000 is already used by stream 'a'" in r.page
    r = client.post("/streams/new", {**form, "name": "c", "listen_port": "443"})
    assert "Port 443 is reserved" in r.page


def test_hosts_move_and_json_check(client):
    client.post("/groups/new", {"name": "Público", "color": "green"})
    gid = db.list_entities("groups", db.connect())[0]["id"]
    client.post("/hosts/new", HOST_FORM)
    hid = db.list_entities("hosts", db.connect())[0]["id"]
    r = client.post("/hosts/move", {"group_id": str(gid), "ids": str(hid)})
    assert '1 host(s) moved to "Público".' in r.page
    r = client.post("/hosts/check", {"scope": f"host:{hid}"}, headers={"Accept": "application/json"})
    data = r.get_json()
    assert set(data["levels"]) == {str(hid)} and str(hid) in data["html"]
    assert db.get_statuses(db.connect())[hid]["checks"]


def test_block_ip_from_analytics(client):
    r = client.post("/security/block", {"ip": "203.0.113.7"})
    assert "203.0.113.7/32 added to the blocklist." in r.page
    assert db.get_settings(db.connect())["blocklist"] == ["203.0.113.7/32"]


def test_permissions(app, client):
    client.post("/users/new", {"username": "viewer", "password": "viewer-pass-1", "active": "on", "perm_hosts": "1"})
    v = Client(app)
    assert v.login("viewer", "viewer-pass-1").status_code == 302
    assert v.get("/hosts").status_code == 200
    assert v.get("/hosts/new").status_code == 403
    assert v.get("/system").status_code == 403
    assert v.post("/groups/new", {"name": "x"}).status_code == 403
    body = v.get("/").page
    assert "Backends</a>" not in body and "Hosts</a>" in body
    # a non-admin user manager cannot grant more than they have
    client.post("/users/new", {"username": "manager", "password": "manager-pass-1", "active": "on",
                               "perm_users": "2", "perm_hosts": "1"})
    m = Client(app)
    m.login("manager", "manager-pass-1")
    r = m.post("/users/new", {"username": "sneaky", "password": "sneaky-pass-1", "active": "on", "perm_system": "2"})
    assert "You cannot grant more permissions than you have" in r.page
    r = m.post("/users/new", {"username": "sneaky", "password": "sneaky-pass-1", "active": "on", "is_admin": "on"})
    assert "Only an administrator can create administrators" in r.page


def test_admin_cannot_delete_self(client):
    r = client.post("/users/1/delete")
    uid = db.connect().execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]
    r = client.post(f"/users/{uid}/delete")
    assert "You cannot delete yourself." in r.page


def test_change_password_and_2fa_setup(client):
    r = client.post("/profile", {"action": "password", "current": "nope", "new": "x" * 12, "confirm": "x" * 12})
    assert "The current password is incorrect." in r.page
    r = client.post("/profile", {"action": "password", "current": ADMIN_PW, "new": "new-password-1",
                                 "confirm": "new-password-1"})
    assert "Password changed." in r.page
    r = client.post("/profile", {"action": "2fa_start"})
    assert "otpauth://totp/NginxPanel:admin" in r.page
    r = client.post("/profile", {"action": "2fa_confirm", "code": "000000"})
    assert "Wrong code." in r.page


def test_saved_without_nginx_message(client, monkeypatch):
    monkeypatch.setattr(nginx, "nginx_installed", lambda: False)
    r = client.post("/hosts/new", HOST_FORM)
    assert "Saved. nginx is not installed" in r.page


def test_error_pages(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404 and "Not found." in r.page
