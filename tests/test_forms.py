"""Validators: everything that reaches the nginx config must be injection-proof."""
import pytest

from nginxpanel import forms
from nginxpanel.forms import V


@pytest.mark.parametrize("raw, expected", [
    ("Example.COM", ["example.com"]),
    ("a.example.com, b.example.com\na.example.com", ["a.example.com", "b.example.com"]),
    ("*.example.com", ["*.example.com"]),
    ("pve_internal.example.com", ["pve_internal.example.com"]),
    ("10.0.0.1", ["10.0.0.1"]),
    ("example.com.", ["example.com"]),
])
def test_domains_valid(raw, expected):
    assert forms.v_domains(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "exa mple.com;", "example.com;return", "evil.com{", "$host", "a..b.com", "example.c_m", "-bad.example.com",
])
def test_domains_rejected(raw):
    with pytest.raises(V):
        forms.v_domains(raw)


@pytest.mark.parametrize("raw, expected", [
    ("192.168.1.10", "192.168.1.10"), ("::1", "[::1]"), ("[2001:db8::1]", "[2001:db8::1]"), ("backend.lan", "backend.lan"),
])
def test_host_valid(raw, expected):
    assert forms.v_host(raw) == expected


@pytest.mark.parametrize("raw", ["", "host;", "a b", "x" * 300, "host:80", "$upstream"])
def test_host_rejected(raw):
    with pytest.raises(V):
        forms.v_host(raw)


@pytest.mark.parametrize("raw", ["0", "65536", "abc", None, "-1"])
def test_port_rejected(raw):
    with pytest.raises(V):
        forms.v_port(raw)


def test_servers_parsing_round_trip():
    text = "10.0.0.1:80 weight=3\n10.0.0.2:80 backup\n[::1]:8080 down  # comment\n\n"
    servers = forms.v_servers(text)
    assert servers == [
        {"host": "10.0.0.1", "port": 80, "weight": 3, "backup": False, "down": False},
        {"host": "10.0.0.2", "port": 80, "weight": 1, "backup": True, "down": False},
        {"host": "[::1]", "port": 8080, "weight": 1, "backup": False, "down": True},
    ]
    assert forms.v_servers(forms.servers_to_text(servers)) == servers


@pytest.mark.parametrize("raw", ["", "10.0.0.1", "10.0.0.1:80 max_fails=1", "10.0.0.1:80;", "10.0.0.1:80 weight=0"])
def test_servers_rejected(raw):
    with pytest.raises(V):
        forms.v_servers(raw)


def test_cidrs():
    assert forms.v_cidrs("10.1.2.3/8\n192.168.1.1\n# comment\nall\n10.0.0.0/8") == \
        ["10.0.0.0/8", "192.168.1.1/32", "all"]
    with pytest.raises(V):
        forms.v_cidrs("10.0.0.0/8; allow all")


@pytest.mark.parametrize("raw, ok", [
    ("30s", True), ("10m", True), ("1h", True), ("500ms", True), ("30 s", False), ("30s;", False), ("", False),
])
def test_duration(raw, ok):
    if ok:
        assert forms.v_duration(raw) == raw
    else:
        with pytest.raises(V):
            forms.v_duration(raw)


@pytest.mark.parametrize("raw", ["https://example.com/x?y=1", "http://10.0.0.1:8080"])
def test_url_valid(raw):
    assert forms.v_url(raw) == raw


@pytest.mark.parametrize("raw", ["ftp://example.com", "https://example.com; return 200", "https://a.com/$host",
                                 "https://a.com/{x}", "https://a.com/\"x"])
def test_url_rejected(raw):
    with pytest.raises(V):
        forms.v_url(raw)


def test_snippet_braces():
    assert forms.v_snippet("location /x {\r\n  return 204;\r\n}") == "location /x {\n  return 204;\n}"
    for bad in ("}", "location / {", "} {"):
        with pytest.raises(V):
            forms.v_snippet(bad)


def test_auth_users_keep_existing_hash():
    first = forms.v_auth_users("alice:password123\nbob:password456", [])
    assert [u["user"] for u in first] == ["alice", "bob"]
    assert all(u["hash"].startswith("{SSHA}") for u in first)
    kept = forms.v_auth_users("alice:\nbob:newpassword1", first)
    assert kept[0]["hash"] == first[0]["hash"]
    assert kept[1]["hash"] != first[1]["hash"]
    for bad in ("carol:", "al ice:password123", "dave:short"):
        with pytest.raises(V):
            forms.v_auth_users(bad, first)


def test_group_names_allow_unicode_but_not_garbage():
    assert forms.v_group("  Clientes   España ") == "Clientes España"
    for bad in ("", "_hidden", "<script>", "x" * 70):
        with pytest.raises(V):
            forms.v_group(bad)


def test_listen_ip_must_be_local():
    f = forms.v_listen_ip(["192.168.1.5"])
    assert f("") == ""
    assert f("192.168.1.5") == "192.168.1.5"
    with pytest.raises(V):
        f("192.168.1.6")


def test_parse_form_respects_show_if_and_admin_only():
    fields = forms.host_fields([], [], [])
    form = {"domains": "r.example.com", "type": "redirect", "enabled": "on", "redirect_url": "https://x.example.com",
            "redirect_code": "302", "preserve_path": "on", "forward_host": "not validated; because hidden",
            "rate_burst": "40", "conn_limit": "0", "custom_server": "return 200;"}
    data, errors = forms.parse_form(fields, form, existing={"custom_server": "keep me"}, is_admin=False)
    assert errors == []
    assert data["redirect_code"] == 302
    assert data["forward_host"] == ""                 # hidden field falls back to its default
    assert data["custom_server"] == "keep me"         # non-admins cannot change advanced fields


def test_parse_form_reports_errors_with_labels():
    fields = forms.backend_fields()
    _, errors = forms.parse_form(fields, {"name": "web", "method": "evil", "servers": "", "max_fails": "x",
                                          "fail_timeout": "30s", "keepalive": "32"})
    assert "Load balancing: Invalid option" in errors
    assert "Servers: Required" in errors
    assert any(e.startswith("Failures before marking down:") for e in errors)
