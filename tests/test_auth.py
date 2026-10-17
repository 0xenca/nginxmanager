import base64
import hashlib

from nginxpanel import auth, htpasswd

# RFC 6238 appendix B, SHA-1 seed "12345678901234567890"
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


def test_totp_rfc6238_vectors():
    # 8-digit reference values truncated to the 6 digits used by authenticator apps
    assert auth._totp_at(RFC_SECRET, 59 // 30) == "287082"
    assert auth._totp_at(RFC_SECRET, 1111111109 // 30) == "081804"
    assert auth._totp_at(RFC_SECRET, 2000000000 // 30) == "279037"


def test_totp_verify_window(monkeypatch):
    monkeypatch.setattr(auth.time, "time", lambda: 59)
    assert auth.totp_verify(RFC_SECRET, "287 082")
    assert auth.totp_verify(RFC_SECRET, auth._totp_at(RFC_SECRET, 0))       # one step back is accepted
    assert not auth.totp_verify(RFC_SECRET, auth._totp_at(RFC_SECRET, 5))
    assert not auth.totp_verify(RFC_SECRET, "abcdef")
    assert not auth.totp_verify(None, "287082")


def test_totp_new_secret_and_uri():
    secret = auth.totp_new_secret()
    assert len(secret) == 32 and base64.b32decode(secret)
    uri = auth.totp_uri(secret, "ana maria")
    assert uri.startswith("otpauth://totp/NginxPanel:ana%20maria?secret=" + secret)


def test_password_policy():
    assert auth.password_ok("0123456789")
    assert not auth.password_ok("short")
    assert not auth.password_ok(None)


def test_ssha_is_nginx_compatible():
    h = htpasswd.ssha("secret-pass")
    raw = base64.b64decode(h[len("{SSHA}"):])
    digest, salt = raw[:20], raw[20:]
    assert h.startswith("{SSHA}") and len(salt) == 8
    assert hashlib.sha1(b"secret-pass" + salt).digest() == digest
    assert htpasswd.ssha("secret-pass") != h          # random salt


def test_levels():
    admin = {"is_admin": 1, "perms": {}}
    viewer = {"is_admin": 0, "perms": {"hosts": 1, "logs": 2}}
    assert auth.level(admin, "users") == 2
    assert auth.level(viewer, "hosts") == 1
    assert auth.level(viewer, "logs") == 2
    assert auth.level(viewer, "system") == 0
    assert auth.level(None, "hosts") == 0
