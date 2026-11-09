"""Factoría de la app Flask."""
import ipaddress
import logging
import time
from datetime import timedelta

from flask import Flask, abort, g, request, session

from . import auth, config, logs
from .db import close_db, init_db


def _trusted_proxy_fix(wsgi_app, trusted):
    """ProxyFix, pero solo si la conexión llega desde un proxy de confianza.

    Sin esto, quien llegue directamente al puerto del panel podría falsear X-Forwarded-For
    y saltarse NP_ALLOWED_NETS y el bloqueo por intentos fallidos.
    """
    from werkzeug.middleware.proxy_fix import ProxyFix
    nets = [ipaddress.ip_network(n, strict=False) for n in trusted]
    fixed = ProxyFix(wsgi_app, x_for=1, x_proto=1, x_host=1)

    warned = set()

    def middleware(environ, start_response):
        addr = environ.get("REMOTE_ADDR", "")
        try:
            peer = ipaddress.ip_address(addr)
        except ValueError:
            peer = None
        if peer is not None and any(peer in n for n in nets):
            return fixed(environ, start_response)
        if environ.get("HTTP_X_FORWARDED_FOR") and addr not in warned and len(warned) < 50:
            warned.add(addr)
            logging.getLogger("nginxpanel").warning(
                "X-Forwarded-For ignorado: %s no está en NP_TRUSTED_PROXIES. Si es tu proxy, "
                "añádelo en /etc/nginx-panel.env.", addr)
        return wsgi_app(environ, start_response)
    return middleware


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
        app.wsgi_app = _trusted_proxy_fix(app.wsgi_app, config.TRUSTED_PROXIES)
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
            return "Acceso al panel no permitido desde esta red.", 403
        return None

    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid and time.time() - session.get("login_at", 0) < 12 * 3600:
            g.user = auth.load_user(uid)
            if not g.user or session.get("epoch", 0) != g.user.get("session_epoch", 0):
                g.user = None
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
    def fmt_dt(ts, fmt="%d/%m/%Y %H:%M"):
        if not ts:
            return "—"
        return time.strftime(fmt, time.localtime(ts))

    from .views import bp
    app.register_blueprint(bp)
    return app
