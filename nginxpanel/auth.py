"""Authentication, per-area permissions, CSRF, TOTP and login throttling."""
import base64
import functools
import hashlib
import hmac
import json
import secrets
import struct
import time

from flask import abort, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import audit, get_db

# area -> description. Levels: 0 no access, 1 view, 2 manage
AREAS = {
    "hosts": "Hosts and redirects",
    "backends": "Backends (upstreams)",
    "streams": "TCP/UDP streams",
    "certs": "SSL certificates",
    "access": "Access lists",
    "security": "Security / global settings",
    "logs": "Logs and analytics",
    "system": "System (install, reload, backups)",
    "users": "Users and audit",
}
LEVELS = {0: "No access", 1: "View", 2: "Manage"}

MAX_FAILS = 5
FAIL_WINDOW = 15 * 60


def hash_password(pw):
    return generate_password_hash(pw)


def password_ok(pw):
    return isinstance(pw, str) and len(pw) >= 10


def load_user(uid):
    row = get_db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
    if not row:
        return None
    u = dict(row)
    u["perms"] = json.loads(u["perms"] or "{}")
    return u


def level(user, area):
    if not user:
        return 0
    if user["is_admin"]:
        return 2
    return int(user["perms"].get(area, 0))


def can(area, lvl=1):
    return level(g.get("user"), area) >= lvl


def client_ip():
    return request.remote_addr or "?"


def log(action, detail=""):
    u = g.get("user")
    audit(u["username"] if u else None, client_ip(), action, detail)


# ---------- decorators ----------

def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not g.get("user"):
            return redirect(url_for("main.login", next=request.path))
        return fn(*a, **kw)
    return wrapper


def require(area, lvl=1):
    def deco(fn):
        @functools.wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if level(g.user, area) < lvl:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


def admin_required(fn):
    @functools.wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not g.user["is_admin"]:
            abort(403)
        return fn(*a, **kw)
    return wrapper


# ---------- CSRF ----------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def check_csrf():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid CSRF token. Reload the page.")


# ---------- lockout after failed attempts ----------

def is_locked(ip):
    db = get_db()
    since = time.time() - FAIL_WINDOW
    db.execute("DELETE FROM login_attempts WHERE ts < ?", (time.time() - 86400,))
    n = db.execute("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND ts>?", (ip, since)).fetchone()[0]
    return n >= MAX_FAILS


def register_fail(ip, username):
    db = get_db()
    db.execute("INSERT INTO login_attempts(ip, ts, username) VALUES (?,?,?)", (ip, time.time(), username))
    db.commit()
    audit(username, ip, "login_failed")


def clear_fails(ip):
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
    db.commit()


def authenticate(username, password):
    row = get_db().execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        return dict(row)
    # similar cost if the user does not exist (prevents timing-based enumeration)
    check_password_hash(_DUMMY, password or "x")
    return None


_DUMMY = generate_password_hash("dummy-password-for-timing")


# ---------- TOTP (RFC 6238) without dependencies ----------

def totp_new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_verify(secret, code, window=1):
    code = (code or "").strip().replace(" ", "")
    if not secret or len(code) != 6 or not code.isdigit():
        return False
    now = int(time.time() // 30)
    return any(hmac.compare_digest(_totp_at(secret, now + d), code) for d in range(-window, window + 1))


def totp_uri(secret, username, issuer="NginxPanel"):
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}"


def do_login(user):
    session.clear()
    session["uid"] = user["id"]
    session["login_at"] = time.time()
    session.permanent = True
    db = get_db()
    db.execute("UPDATE users SET last_login=? WHERE id=?", (time.time(), user["id"]))
    db.commit()
    audit(user["username"], client_ip(), "login")


def flash_errors(errors):
    for e in errors:
        flash(e, "error")
