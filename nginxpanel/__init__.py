"""Flask app factory."""
import ipaddress
import time
from datetime import timedelta

from flask import Flask, abort, g, request, session

from . import auth, config, logs
from .db import close_db, init_db


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.secret_key(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=config.SECURE_COOKIES,
        SESSION_COOKIE_NAME="np_session",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    if config.BEHIND_PROXY:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    init_db()
    app.teardown_appcontext(close_db)
    allowed = [ipaddress.ip_network(n, strict=False) for n in config.ALLOWED_NETS]

    @app.before_request
    def restrict_networks():
        if not allowed:
            return None
        try:
            ip = ipaddress.ip_address(request.remote_addr or "")
        except ValueError:
            abort(403)
        if not any(ip in n for n in allowed):
            return "Access to the panel is not allowed from this network.", 403
        return None

    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid and time.time() - session.get("login_at", 0) < 12 * 3600:
            g.user = auth.load_user(uid)
            if not g.user:
                session.clear()
        auth.check_csrf()

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'none'")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.context_processor
    def helpers():
        return {
            "can": auth.can, "csrf_token": auth.csrf_token, "AREAS": auth.AREAS,
            "LEVELS": auth.LEVELS, "human_bytes": logs.human_bytes,
        }

    @app.template_filter("dt")
    def fmt_dt(ts, fmt="%Y-%m-%d %H:%M"):
        if not ts:
            return "—"
        return time.strftime(fmt, time.localtime(ts))

    from .views import bp
    app.register_blueprint(bp)
    return app
