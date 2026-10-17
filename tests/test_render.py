"""Config generation (no nginx binary needed)."""
from nginxpanel import certs, db, nginx

BASE_HOST = {"domains": ["app.example.com"], "type": "proxy", "enabled": True, "listen_ip": "",
             "forward_mode": "direct", "forward_scheme": "http", "forward_host": "127.0.0.1", "forward_port": 8080,
             "read_timeout": "60s", "waf": True, "sec_headers": True, "rate_limit": False, "rate_burst": 40,
             "conn_limit": 0, "max_body": "", "cache_mode": "off", "cache_ttl": "10m", "force_ssl": True,
             "http2": True, "hsts": False, "websocket": False, "upstream_ssl_verify": False,
             "custom_server": "", "custom_location": ""}


def host(**kw):
    return db.save_entity("hosts", {**BASE_HOST, **kw}, db=db.connect())


def render():
    return nginx.render_all(db.connect())


def test_direct_proxy_host():
    hid = host()
    conf, files, warnings = render()
    h = files[f"hosts/host_{hid}.conf"]
    assert warnings == []
    assert "server_name app.example.com;" in h
    assert "proxy_pass http://127.0.0.1:8080;" in h
    assert "if ($waf_block != \"\")" in h
    assert "security_headers.conf" in h
    assert "listen 443" not in h                           # no certificate assigned
    assert "include " + str(nginx.config.MANAGED_DIR) + "/hosts/*.conf;" in conf
    assert "default_server" in conf and "return 444;" in conf


def test_backend_upstream_and_disabled_host():
    conn = db.connect()
    bid = db.save_entity("backends", {"name": "web", "method": "least_conn", "max_fails": 3, "fail_timeout": "30s",
                                      "keepalive": 16, "servers": [
                                          {"host": "10.0.0.1", "port": 80, "weight": 2, "backup": False, "down": False},
                                          {"host": "10.0.0.2", "port": 80, "weight": 1, "backup": True, "down": False}]},
                         db=conn)
    hid = host(forward_mode="backend", backend_id=bid)
    off = host(domains=["off.example.com"], enabled=False)
    _, files, _ = render()
    up = files[f"upstreams/backend_{bid}.conf"]
    assert "least_conn;" in up
    assert "server 10.0.0.1:80 weight=2 max_fails=3 fail_timeout=30s;" in up
    assert "server 10.0.0.2:80 max_fails=3 fail_timeout=30s backup;" in up
    assert "keepalive 16;" in up
    assert f"proxy_pass http://panel_up_{bid};" in files[f"hosts/host_{hid}.conf"]
    assert f"hosts/host_{off}.conf" not in files


def test_missing_backend_is_skipped_with_warning():
    hid = host(forward_mode="backend", backend_id=999)
    _, files, warnings = render()
    assert f"hosts/host_{hid}.conf" not in files
    assert any("backend does not exist" in w for w in warnings)


def test_ssl_redirect_hsts_and_http2():
    cid = db.save_entity("certs", {"name": "self", "kind": "selfsigned", "domains": ["app.example.com"]},
                         db=db.connect())
    ok, out = certs.make_selfsigned(cid, ["app.example.com"])
    assert ok, out
    hid = host(cert_id=cid, hsts=True)
    _, files, warnings = render()
    h = files[f"hosts/host_{hid}.conf"]
    assert warnings == []
    assert "return 301 https://$host$request_uri;" in h
    assert "listen 443 ssl" in h
    assert "ssl_certificate " in h and "fullchain.pem" in h
    assert 'Strict-Transport-Security "max-age=31536000"' in h


def test_cert_without_files_publishes_http_only():
    cid = db.save_entity("certs", {"name": "pending", "kind": "letsencrypt", "certname": "x",
                                   "domains": ["app.example.com"]}, db=db.connect())
    hid = host(cert_id=cid)
    _, files, warnings = render()
    assert "listen 443" not in files[f"hosts/host_{hid}.conf"]
    assert any("has no files yet" in w for w in warnings)


def test_redirect_host_preserves_path():
    hid = host(type="redirect", redirect_url="https://new.example.com/", redirect_code=308, preserve_path=True)
    _, files, _ = render()
    assert "return 308 https://new.example.com$request_uri;" in files[f"hosts/host_{hid}.conf"]


def test_access_list_and_htpasswd():
    from nginxpanel.forms import v_auth_users
    aid = db.save_entity("access_lists", {"name": "office", "allow": ["10.0.0.0/8"], "deny": ["10.6.6.6/32"],
                                          "default_action": "deny", "satisfy": "any",
                                          "auth_users": v_auth_users("bob:password123", [])}, db=db.connect())
    hid = host(access_list_id=aid)
    _, files, _ = render()
    h = files[f"hosts/host_{hid}.conf"]
    assert h.index("deny 10.6.6.6/32;") < h.index("allow 10.0.0.0/8;") < h.index("deny all;")
    assert "satisfy any;" in h and 'auth_basic "Restricted access";' in h
    assert files[f"htpasswd/access_{aid}"].startswith("bob:{SSHA}")


def test_cache_websocket_and_limits():
    hid = host(cache_mode="all", websocket=True, rate_limit=True, rate_burst=10, conn_limit=5, max_body="10m")
    _, files, _ = render()
    h = files[f"hosts/host_{hid}.conf"]
    for directive in ("proxy_cache panel_cache;", "proxy_no_cache $http_authorization $panel_has_session;",
                      "proxy_read_timeout 3600s;", "limit_req zone=panel_rl burst=10 nodelay;",
                      "limit_conn panel_conn 5;", "client_max_body_size 10m;"):
        assert directive in h


def test_specific_listen_ip_adds_default_server_and_shared_listen():
    a = host(listen_ip="192.0.2.10")
    b = host(domains=["other.example.com"])
    conf, files, _ = render()
    assert "listen 192.0.2.10:80;" in files[f"hosts/host_{a}.conf"]
    assert "listen 192.0.2.10:80;" in files[f"hosts/host_{b}.conf"]   # "all interfaces" host also listens there
    assert "listen 192.0.2.10:80 default_server;" in conf


def test_blocklist_and_settings():
    db.set_settings({"blocklist": ["203.0.113.0/24"], "default_behavior": "404", "gzip": False,
                     "http_custom": "# custom marker"}, db=db.connect())
    conf, _, _ = render()
    assert "203.0.113.0/24 1;" in conf
    assert "return 404;" in conf
    assert "gzip on;" not in conf
    assert "# custom marker" in conf


def test_stream_rendering_or_warning():
    sid = db.save_entity("streams", {"name": "ssh", "enabled": True, "listen_ip": "", "listen_port": 2222,
                                     "protocol": "both", "method": "hash_ip", "connect_timeout": "10s",
                                     "proxy_timeout": "10m", "targets": [
                                         {"host": "10.0.0.5", "port": 22, "weight": 1, "backup": False,
                                          "down": False}]}, db=db.connect())
    conf, files, warnings = render()
    if nginx.detect_env()["stream"]:
        s = files[f"streams/stream_{sid}.conf"]
        assert "listen 2222;" in s and "listen 2222 udp;" in s and "hash $remote_addr consistent;" in s
        assert "stream {" in conf
    else:
        assert any("stream module" in w for w in warnings)
        assert "stream {" not in conf


def test_preview_of_disabled_host():
    hid = host(enabled=False)
    assert nginx.render_host_preview(hid, db.connect()) == "# Host disabled or not generated"
