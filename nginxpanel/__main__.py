"""CLI: python -m nginxpanel <comando>

  create-admin USUARIO [--password X]   crea/restablece un administrador
  apply                                 regenera la config de nginx desde la BD
  serve [--host H] [--port P]           servidor de desarrollo (en producción: gunicorn)
"""
import argparse
import getpass
import json
import secrets
import sys
import time


def main():
    from . import auth, config, db, nginx
    p = argparse.ArgumentParser(prog="nginx-panel")
    sub = p.add_subparsers(dest="cmd", required=True)
    ca = sub.add_parser("create-admin")
    ca.add_argument("username")
    ca.add_argument("--password")
    ca.add_argument("--random", action="store_true", help="genera una contraseña aleatoria")
    sub.add_parser("apply")
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=config.PANEL_PORT)
    a = p.parse_args()

    db.init_db()
    conn = db.connect()
    if a.cmd == "create-admin":
        pw = a.password
        if a.random:
            pw = secrets.token_urlsafe(14)
        if not pw:
            pw = getpass.getpass("Contraseña (10+ caracteres): ")
        if not auth.password_ok(pw):
            sys.exit("La contraseña debe tener al menos 10 caracteres")
        h = auth.hash_password(pw)
        row = conn.execute("SELECT id FROM users WHERE username=?", (a.username,)).fetchone()
        if row:
            conn.execute("UPDATE users SET password_hash=?, is_admin=1, active=1, totp_enabled=0, totp_secret=NULL "
                         "WHERE id=?", (h, row["id"]))
            print(f"Administrador '{a.username}' restablecido (2FA desactivado).")
        else:
            conn.execute("INSERT INTO users(username, password_hash, is_admin, perms, active, created_at) "
                         "VALUES (?,?,1,?,1,?)", (a.username, h, json.dumps({}), time.time()))
            print(f"Administrador '{a.username}' creado.")
        conn.commit()
        db.audit("cli", "localhost", "create-admin", a.username, db=conn)
        if a.random:
            print(f"Contraseña: {pw}")
    elif a.cmd == "apply":
        ok, out, warnings = nginx.apply(conn, label="cli")
        for w in warnings:
            print("AVISO:", w)
        print(out)
        if ok:
            db.set_settings({"bootstrapped": True}, db=conn)
        sys.exit(0 if ok else 1)
    elif a.cmd == "serve":
        from . import create_app
        create_app().run(host=a.host, port=a.port, threaded=True)


if __name__ == "__main__":
    main()
