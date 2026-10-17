"""Panel routes."""
import json
import re
import shutil
import time

from flask import (Blueprint, Response, abort, current_app, flash, g, jsonify, redirect, render_template,
                   request, send_file, session, stream_with_context, url_for)

from . import auth, certs as certmod, checks, config, db, forms, jobs, logs, nginx
from .auth import admin_required, can, log, login_required, require

bp = Blueprint("main", __name__)


# ======================================================================
# utilities
# ======================================================================

def apply_and_report(label):
    """Applies the config. Returns True if it was applied (or if nginx is not installed)."""
    if not nginx.nginx_installed():
        flash("Saved. nginx is not installed: it will be applied once installed (System).", "warn")
        return True
    ok, out, warnings = nginx.apply(db.get_db(), label=label)
    for w in warnings:
        flash(w, "warn")
    if ok:
        flash("Configuration applied and nginx reloaded.", "ok")
    else:
        flash(out, "error")
    return ok


def save_with_rollback(table, data, eid, label):
    """Saves and applies; if nginx rejects the config, reverts the change in the DB."""
    before = db.get_entity(table, eid) if eid else None
    new_id = db.save_entity(table, data, eid)
    if apply_and_report(label):
        return new_id
    if before:
        db.save_entity(table, before, eid)
    else:
        db.delete_entity(table, new_id)
    return None


def delete_with_apply(table, eid, label):
    before = db.get_entity(table, eid)
    db.delete_entity(table, eid)
    if not apply_and_report(label) and before:
        db.save_entity(table, before)


def page_args():
    try:
        return max(1, int(request.args.get("page", 1)))
    except ValueError:
        return 1


# ======================================================================
# session
# ======================================================================

@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))
    no_users = db.get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    if request.method == "POST":
        ip = auth.client_ip()
        if auth.is_locked(ip):
            flash("Too many failed attempts. Wait 15 minutes.", "error")
            return render_template("login.html", no_users=no_users), 429
        user = auth.authenticate(request.form.get("username", "").strip(), request.form.get("password", ""))
        if not user:
            auth.register_fail(ip, request.form.get("username", "")[:64])
            time.sleep(0.5)
            flash("Wrong username or password.", "error")
            return render_template("login.html", no_users=no_users), 401
        nxt = request.args.get("next", "")
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = url_for("main.dashboard")
        if user["totp_enabled"]:
            keep = session.get("_csrf")
            session.clear()
            session["_csrf"] = keep
            session["pending_2fa"] = user["id"]
            session["pending_at"] = time.time()
            session["next"] = nxt
            return redirect(url_for("main.login_2fa"))
        auth.clear_fails(ip)
        auth.do_login(user)
        return redirect(nxt)
    return render_template("login.html", no_users=no_users)


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    uid = session.get("pending_2fa")
    if not uid or time.time() - session.get("pending_at", 0) > 300:
        session.clear()
        return redirect(url_for("main.login"))
    if request.method == "POST":
        ip = auth.client_ip()
        if auth.is_locked(ip):
            flash("Too many failed attempts. Wait 15 minutes.", "error")
            return render_template("login_2fa.html"), 429
        row = db.get_db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
        if row and auth.totp_verify(row["totp_secret"], request.form.get("code")):
            nxt = session.get("next") or url_for("main.dashboard")
            auth.clear_fails(ip)
            auth.do_login(dict(row))
            return redirect(nxt)
        auth.register_fail(ip, row["username"] if row else "?")
        flash("Wrong code.", "error")
    return render_template("login_2fa.html")


@bp.route("/logout", methods=["POST"])
def logout():
    if g.user:
        log("logout")
    session.clear()
    return redirect(url_for("main.login"))


# ======================================================================
# dashboard
# ======================================================================

@bp.route("/")
@login_required
def dashboard():
    env = nginx.detect_env()
    hosts = db.list_entities("hosts")
    cert_list = db.list_entities("certs")
    expiring = [c for c in cert_list if certmod.days_left(c) is not None and certmod.days_left(c) < 21]
    stats = logs.analytics("24h") if can("logs") else None
    return render_template(
        "dashboard.html", env=env, running=nginx.nginx_running(), stub=nginx.stub_status(),
        counts={"hosts": len(hosts), "enabled": sum(1 for h in hosts if h.get("enabled", True)),
                "backends": len(db.list_entities("backends")), "streams": len(db.list_entities("streams")),
                "certs": len(cert_list)},
        expiring=expiring, days_left=certmod.days_left, stats=stats,
        settings=db.get_settings())


# ======================================================================
# generic CRUD (hosts, backends, streams, access lists)
# ======================================================================

def _fields(table, existing=None):
    cur = (existing or {}).get("listen_ip") or ""
    if table == "hosts":
        return forms.host_fields(db.list_entities("backends"), db.list_entities("certs"),
                                 db.list_entities("access_lists"), nginx.local_ips(), cur, sorted_groups())
    if table == "backends":
        return forms.backend_fields()
    if table == "streams":
        return forms.stream_fields(db.list_entities("access_lists"), nginx.local_ips(), cur)
    return forms.access_fields()


META = {
    "hosts": {"area": "hosts", "title": "host", "list": "main.hosts"},
    "backends": {"area": "backends", "title": "backend", "list": "main.backends"},
    "streams": {"area": "streams", "title": "stream", "list": "main.streams"},
    "access_lists": {"area": "access", "title": "access list", "list": "main.access_lists"},
}


def _cross_validate(table, data, eid):
    errs = []
    if table == "hosts" and data.get("group_id") and not db.get_entity("groups", data["group_id"]):
        errs.append("The selected group no longer exists")
    if table == "hosts":
        mine = set(data.get("domains") or [])
        for h in db.list_entities("hosts"):
            if h["id"] != eid:
                dup = mine & set(h["domains"])
                if dup:
                    errs.append(f"Domain already used by another host: {', '.join(sorted(dup))}")
        if data.get("type") == "proxy" and data.get("forward_mode") == "backend" and not data.get("backend_id"):
            errs.append("Choose a backend")
        if data.get("type") == "proxy" and data.get("forward_mode") == "direct" and not data.get("forward_host"):
            errs.append("Enter the target host or IP")
        if data.get("type") == "redirect" and not data.get("redirect_url"):
            errs.append("Enter the redirect URL")
    elif table in ("backends", "streams"):
        key = "servers" if table == "backends" else "targets"
        if data.get("method") in ("ip_hash", "hash_ip") and any(s.get("backup") for s in data.get(key) or []
                                                                 if isinstance(s, dict)):
            errs.append("nginx does not support 'backup' servers with hash load balancing")
    if table == "streams" and isinstance(data.get("listen_port"), int):
        p = data["listen_port"]
        if p in (80, 443, config.STATUS_PORT, config.PANEL_PORT):
            errs.append(f"Port {p} is reserved (HTTP/HTTPS/panel)")
        protos = {"tcp": {"tcp"}, "udp": {"udp"}, "both": {"tcp", "udp"}}
        mine_ip = data.get("listen_ip") or ""
        for st in db.list_entities("streams"):
            other_ip = st.get("listen_ip") or ""
            same_addr = mine_ip == other_ip   # nginx accepts *:p and IP:p at the same time
            if st["id"] != eid and st["listen_port"] == p and same_addr and \
                    protos[st["protocol"]] & protos[data.get("protocol", "tcp")]:
                errs.append(f"Port {p} is already used by stream '{st['name']}'")
    if table in ("backends", "access_lists") and data.get("name"):
        for e in db.list_entities(table):
            if e["id"] != eid and e.get("name", "").lower() == data["name"].lower():
                errs.append("One with that name already exists")
    return errs


def crud_form(table, eid=None):
    meta = META[table]
    if not can(meta["area"], 2):
        abort(403)
    existing = db.get_entity(table, eid) if eid else None
    if eid and not existing:
        abort(404)
    fields = _fields(table, existing)
    if request.method == "POST":
        data, errors = forms.parse_form(fields, request.form, existing, g.user["is_admin"])
        if not errors:
            errors = _cross_validate(table, data, eid)
        if errors:
            auth.flash_errors(errors)
            values = dict(forms.form_values(fields, existing), **{k: request.form.get(k, "") for k in request.form})
            for f in fields:
                if f["type"] == "bool":
                    values[f["name"]] = f["name"] in request.form
            return render_template("form.html", fields=fields, values=values, meta=meta, eid=eid, table=table), 400
        new_id = save_with_rollback(table, data, eid, f"{table}-{eid or 'new'}")
        if new_id:
            log(f"{table}_{'edit' if eid else 'create'}", json.dumps(
                {k: v for k, v in data.items() if k != "auth_users"}, ensure_ascii=False, default=str)[:1500])
            return redirect(url_for(meta["list"]))
        values = dict(forms.form_values(fields, existing), **{k: request.form.get(k, "") for k in request.form})
        for f in fields:
            if f["type"] == "bool":
                values[f["name"]] = f["name"] in request.form
        return render_template("form.html", fields=fields, values=values, meta=meta, eid=eid, table=table), 400
    values = forms.form_values(fields, existing)
    if not eid and table == "hosts" and request.args.get("group", "").isdigit():
        values["group_id"] = request.args["group"]      # "+ host" from a group header
    return render_template("form.html", fields=fields, values=values, meta=meta, eid=eid, table=table)


def _in_use(table, eid):
    users = []
    if table == "backends":
        users = [h for h in db.list_entities("hosts") if h.get("backend_id") == eid and h.get("forward_mode") == "backend"]
    elif table == "access_lists":
        users = [h for h in db.list_entities("hosts") if h.get("access_list_id") == eid] + \
                [s for s in db.list_entities("streams") if s.get("access_list_id") == eid]
    elif table == "certs":
        users = [h for h in db.list_entities("hosts") if h.get("cert_id") == eid]
    return [", ".join(u["domains"]) if "domains" in u else u.get("name", "?") for u in users]


def crud_delete(table, eid):
    meta = META.get(table, {"area": "certs", "list": "main.certs"})
    if not can(meta["area"], 2):
        abort(403)
    used = _in_use(table, eid)
    if used:
        flash(f"Cannot delete: in use by {'; '.join(used)}", "error")
        return redirect(url_for(meta["list"]))
    ent = db.get_entity(table, eid)
    if not ent:
        abort(404)
    delete_with_apply(table, eid, f"{table}-del-{eid}")
    if table == "hosts" and not db.get_entity("hosts", eid):
        db.delete_status(eid)
    log(f"{table}_delete", json.dumps(ent.get("domains") or ent.get("name"), ensure_ascii=False))
    return redirect(url_for(meta["list"]))


def crud_toggle(table, eid):
    meta = META[table]
    if not can(meta["area"], 2):
        abort(403)
    ent = db.get_entity(table, eid)
    if not ent:
        abort(404)
    ent["enabled"] = not ent.get("enabled", True)
    save_with_rollback(table, ent, eid, f"{table}-toggle-{eid}")
    log(f"{table}_{'enable' if ent['enabled'] else 'disable'}", str(eid))
    return redirect(url_for(meta["list"]))


# ---- hosts ----

def sorted_groups():
    return sorted(db.list_entities("groups"), key=lambda gr: gr["name"].lower())


def group_hids(group_arg):
    """'' -> None (no filter); '0' -> hosts without a group; id -> hosts in that group."""
    if not group_arg or not str(group_arg).isdigit():
        return None
    gid = int(group_arg)
    return {str(h["id"]) for h in db.list_entities("hosts") if (h.get("group_id") or 0) == gid}


@bp.route("/hosts")
@require("hosts")
def hosts():
    backends = {b["id"]: b for b in db.list_entities("backends")}
    certs = {c["id"]: c for c in db.list_entities("certs")}
    acls = {a["id"]: a for a in db.list_entities("access_lists")}
    groups = sorted_groups()
    gids = {gr["id"] for gr in groups}
    all_hosts = sorted(db.list_entities("hosts"), key=lambda h: h["domains"][0])
    by_group = {gr["id"]: [] for gr in groups}
    loose = []
    for h in all_hosts:
        gid = h.get("group_id")
        (by_group[gid] if gid in gids else loose).append(h)
    statuses = db.get_statuses()
    last = max((st["ts"] for st in statuses.values()), default=None)
    return render_template("hosts.html", hosts=all_hosts, groups=groups, by_group=by_group, loose=loose,
                           backends=backends, certs=certs, acls=acls, colors=forms.GROUP_COLORS,
                           statuses=statuses, last_check=last)


@bp.route("/hosts/check", methods=["POST"])
@require("hosts")
def hosts_check():
    """Manual reachability check. scope: all | group:<id> | host:<id>."""
    scope = request.form.get("scope", "all")
    all_hosts = db.list_entities("hosts")
    if scope.startswith("host:") and scope[5:].isdigit():
        targets = [h for h in all_hosts if h["id"] == int(scope[5:])]
    elif scope.startswith("group:") and scope[6:].isdigit():
        gid = int(scope[6:])
        targets = [h for h in all_hosts if (h.get("group_id") or 0) == gid]
    else:
        targets = all_hosts
    backends = {b["id"]: b for b in db.list_entities("backends")}
    certs_ = {c["id"]: c for c in db.list_entities("certs")}
    acls = {a["id"] for a in db.list_entities("access_lists")}
    local = {ip for ip, _ in nginx.local_ips()} | {"127.0.0.1", "::1"}
    items = []
    for h in targets:
        cert = certs_.get(h.get("cert_id")) if h.get("cert_id") else None
        items.append((h, {
            "local_ips": local,
            "cert": cert,
            "cert_paths": nginx.cert_paths(cert) if cert else None,
            "days_left": certmod.days_left(cert) if cert else None,
            "backend": backends.get(h.get("backend_id")) if h.get("forward_mode") == "backend" else None,
            "acl": h.get("access_list_id") in acls,
        }))
    t0 = time.time()
    results = checks.run_checks(items)
    db.save_statuses(results)
    log("hosts_check", f"{scope}: {len(results)} hosts in {time.time() - t0:.1f} s")
    if request.headers.get("Accept", "").startswith("application/json"):
        tpl = current_app.jinja_env.get_template("_hoststatus.html")
        cell = tpl.module.status_cell
        return jsonify({"html": {str(hid): str(cell(st)) for hid, st in results.items()},
                        "levels": {str(hid): st["level"] for hid, st in results.items()},
                        "elapsed": round(time.time() - t0, 1)})
    bad = sum(1 for r in results.values() if r["level"] == "error")
    flash(f"Checked {len(results)} hosts: {bad} with errors.", "error" if bad else "ok")
    return redirect(url_for("main.hosts"))


# ---- groups (folders) ----

@bp.route("/groups/new", methods=["POST"])
@require("hosts", 2)
def group_new():
    return _group_save(None)


@bp.route("/groups/<int:gid>/edit", methods=["POST"])
@require("hosts", 2)
def group_edit(gid):
    db.get_entity("groups", gid) or abort(404)
    return _group_save(gid)


def _group_save(gid):
    try:
        name = forms.v_group(request.form.get("name"))
    except forms.V as e:
        flash(str(e), "error")
        return redirect(url_for("main.hosts"))
    color = request.form.get("color", "slate")
    if color not in dict(forms.GROUP_COLORS):
        color = "slate"
    if any(gr["name"].lower() == name.lower() and gr["id"] != gid for gr in db.list_entities("groups")):
        flash(f"A group named \"{name}\" already exists.", "error")
        return redirect(url_for("main.hosts"))
    prev = db.get_entity("groups", gid) if gid else {}
    db.save_entity("groups", {**(prev or {}), "name": name, "color": color}, gid)
    log("group_" + ("edit" if gid else "create"), name)
    flash(f"Group \"{name}\" saved.", "ok")
    return redirect(url_for("main.hosts"))


@bp.route("/groups/<int:gid>/delete", methods=["POST"])
@require("hosts", 2)
def group_delete(gid):
    gr = db.get_entity("groups", gid) or abort(404)
    moved = 0
    for h in db.list_entities("hosts"):
        if h.get("group_id") == gid:
            h["group_id"] = None
            db.save_entity("hosts", h, h["id"])
            moved += 1
    db.delete_entity("groups", gid)
    log("group_delete", f"{gr['name']} ({moved} hosts moved to no group)")
    flash(f"Group \"{gr['name']}\" deleted. Its {moved} hosts are now ungrouped (none were deleted).", "ok")
    return redirect(url_for("main.hosts"))


@bp.route("/groups/<int:gid>/toggle", methods=["POST"])
@require("hosts", 2)
def group_toggle(gid):
    """Enables or disables all hosts in the group in a single config change."""
    gr = db.get_entity("groups", gid) or abort(404)
    enable = request.form.get("enable") == "1"
    members = [h for h in db.list_entities("hosts") if h.get("group_id") == gid]
    before = {h["id"]: h.get("enabled", True) for h in members}
    for h in members:
        h["enabled"] = enable
        db.save_entity("hosts", h, h["id"])
    if not apply_and_report(f"group-{gid}-{'on' if enable else 'off'}"):
        for h in members:
            h["enabled"] = before[h["id"]]
            db.save_entity("hosts", h, h["id"])
    else:
        log("group_" + ("enable" if enable else "disable"), f"{gr['name']} ({len(members)} hosts)")
    return redirect(url_for("main.hosts"))


@bp.route("/hosts/move", methods=["POST"])
@require("hosts", 2)
def hosts_move():
    """Moves several hosts to a group. Does not change the nginx config, only the organization."""
    target = request.form.get("group_id", "")
    gid = int(target) if target.isdigit() and int(target) > 0 else None
    if gid and not db.get_entity("groups", gid):
        abort(404)
    ids = {int(x) for x in request.form.getlist("ids") if x.isdigit()}
    if not ids:
        flash("Select at least one host.", "warn")
        return redirect(url_for("main.hosts"))
    n = 0
    for h in db.list_entities("hosts"):
        if h["id"] in ids:
            h["group_id"] = gid
            db.save_entity("hosts", h, h["id"])
            n += 1
    name = db.get_entity("groups", gid)["name"] if gid else "no group"
    log("hosts_move", f"{n} hosts → {name}")
    flash(f"{n} host(s) moved to \"{name}\".", "ok")
    return redirect(url_for("main.hosts"))


@bp.route("/hosts/new", methods=["GET", "POST"])
@login_required
def host_new():
    return crud_form("hosts")


@bp.route("/hosts/<int:eid>/edit", methods=["GET", "POST"])
@login_required
def host_edit(eid):
    return crud_form("hosts", eid)


@bp.route("/hosts/<int:eid>/delete", methods=["POST"])
@login_required
def host_delete(eid):
    return crud_delete("hosts", eid)


@bp.route("/hosts/<int:eid>/toggle", methods=["POST"])
@login_required
def host_toggle(eid):
    return crud_toggle("hosts", eid)


@bp.route("/hosts/<int:eid>/config")
@require("hosts")
def host_config(eid):
    h = db.get_entity("hosts", eid) or abort(404)
    return render_template("preview.html", title=", ".join(h["domains"]),
                           content=nginx.render_host_preview(eid, db.get_db()), back=url_for("main.hosts"))


# ---- backends ----

@bp.route("/backends")
@require("backends")
def backends():
    hosts_by_backend = {}
    for h in db.list_entities("hosts"):
        if h.get("forward_mode") == "backend" and h.get("backend_id"):
            hosts_by_backend.setdefault(h["backend_id"], []).append(h)
    return render_template("backends.html", backends=db.list_entities("backends"), used=hosts_by_backend)


@bp.route("/backends/new", methods=["GET", "POST"])
@login_required
def backend_new():
    return crud_form("backends")


@bp.route("/backends/<int:eid>/edit", methods=["GET", "POST"])
@login_required
def backend_edit(eid):
    return crud_form("backends", eid)


@bp.route("/backends/<int:eid>/delete", methods=["POST"])
@login_required
def backend_delete(eid):
    return crud_delete("backends", eid)


# ---- streams ----

@bp.route("/streams")
@require("streams")
def streams():
    return render_template("streams.html", streams=db.list_entities("streams"),
                           env=nginx.detect_env(), acls={a["id"]: a for a in db.list_entities("access_lists")})


@bp.route("/streams/new", methods=["GET", "POST"])
@login_required
def stream_new():
    return crud_form("streams")


@bp.route("/streams/<int:eid>/edit", methods=["GET", "POST"])
@login_required
def stream_edit(eid):
    return crud_form("streams", eid)


@bp.route("/streams/<int:eid>/delete", methods=["POST"])
@login_required
def stream_delete(eid):
    return crud_delete("streams", eid)


@bp.route("/streams/<int:eid>/toggle", methods=["POST"])
@login_required
def stream_toggle(eid):
    return crud_toggle("streams", eid)


# ---- access lists ----

@bp.route("/access")
@require("access")
def access_lists():
    return render_template("access.html", items=db.list_entities("access_lists"),
                           used={a["id"]: _in_use("access_lists", a["id"]) for a in db.list_entities("access_lists")})


@bp.route("/access/new", methods=["GET", "POST"])
@login_required
def access_new():
    return crud_form("access_lists")


@bp.route("/access/<int:eid>/edit", methods=["GET", "POST"])
@login_required
def access_edit(eid):
    return crud_form("access_lists", eid)


@bp.route("/access/<int:eid>/delete", methods=["POST"])
@login_required
def access_delete(eid):
    return crud_delete("access_lists", eid)


# ======================================================================
# certificates
# ======================================================================

@bp.route("/certs")
@require("certs")
def certs():
    items = []
    for c in db.list_entities("certs"):
        c["days"] = certmod.days_left(c)
        c["used"] = _in_use("certs", c["id"])
        items.append(c)
    return render_template("certs.html", items=items, certbot=shutil.which("certbot") is not None,
                           settings=db.get_settings())


def _le_done(cid):
    def done(ok, _text):
        conn = db.connect()
        try:
            c = db.get_entity("certs", cid, conn)
            if not c:
                return ""
            if ok:
                certmod.refresh(c)
                c["status"] = "ok"
                c["last_error"] = ""
            else:
                c["status"] = "error"
                c["last_error"] = "certbot failed; check the job log"
            db.save_entity("certs", c, cid, conn)
            if ok and nginx.nginx_installed():
                aok, out, _ = nginx.apply(conn, label=f"cert-{cid}")
                return "Config applied." if aok else "WARNING while applying: " + out
            return ""
        finally:
            conn.close()
    return done


@bp.route("/certs/new", methods=["GET", "POST"])
@require("certs", 2)
def cert_new():
    settings = db.get_settings()
    if request.method == "POST":
        kind = request.form.get("kind")
        name = request.form.get("name", "").strip()
        errors = []
        try:
            name = forms.v_name(name)
        except forms.V as e:
            errors.append(f"Name: {e}")
        domains = []
        if kind in ("letsencrypt", "selfsigned"):
            try:
                domains = forms.v_domains(request.form.get("domains"))
            except forms.V as e:
                errors.append(str(e))
            if kind == "letsencrypt" and any("_" in d for d in domains):
                errors.append("Let's Encrypt (and any public CA) does not issue certificates for names "
                              "with an underscore. Use a self-signed one, your internal CA, or rename (e.g. pve-internal).")
            if kind == "letsencrypt" and any(d.startswith("*.") for d in domains):
                errors.append("Wildcards (*.domain) require DNS-01 validation; "
                              "upload it as a custom certificate.")
            if kind == "letsencrypt" and not shutil.which("certbot") and not config.DRY_RUN:
                errors.append("certbot is not installed (System → Install).")
        elif kind != "custom":
            errors.append("Invalid type")
        if errors:
            auth.flash_errors(errors)
            return render_template("cert_new.html", settings=settings, form=request.form), 400

        cid = db.save_entity("certs", {"name": name, "kind": kind, "domains": domains, "status": "pending"})
        c = db.get_entity("certs", cid)
        if kind == "custom":
            cert_pem = request.form.get("cert_pem") or (request.files.get("cert_file").read().decode(errors="replace")
                                                        if request.files.get("cert_file") else "")
            key_pem = request.form.get("key_pem") or (request.files.get("key_file").read().decode(errors="replace")
                                                      if request.files.get("key_file") else "")
            ok, msg = certmod.store_custom(cid, cert_pem, key_pem, request.form.get("chain_pem", ""))
            if not ok:
                db.delete_entity("certs", cid)
                flash(msg, "error")
                return render_template("cert_new.html", settings=settings, form=request.form), 400
            certmod.refresh(c)
            db.save_entity("certs", c, cid)
            log("cert_upload", f"{name} {c['domains']}")
            flash("Certificate imported.", "ok")
        elif kind == "selfsigned":
            ok, out = certmod.make_selfsigned(cid, domains)
            if not ok:
                db.delete_entity("certs", cid)
                flash(out, "error")
                return redirect(url_for("main.certs"))
            certmod.refresh(c)
            db.save_entity("certs", c, cid)
            log("cert_selfsigned", f"{name} {domains}")
            flash("Self-signed certificate created.", "ok")
        else:
            if not nginx.nginx_running() and not config.DRY_RUN:
                db.delete_entity("certs", cid)
                flash("nginx must be running and managed by the panel to validate the domain.", "error")
                return redirect(url_for("main.certs"))
            c["certname"] = certmod.certname_for(cid, domains)
            db.save_entity("certs", c, cid)
            jid = jobs.start(f"Let's Encrypt: {', '.join(domains)}",
                             [certmod.certbot_issue_cmd(c, settings)], on_done=_le_done(cid))
            c["job"] = jid
            db.save_entity("certs", c, cid)
            log("cert_letsencrypt", f"{name} {domains}")
            return redirect(url_for("main.job", jid=jid))
        return redirect(url_for("main.certs"))
    return render_template("cert_new.html", settings=settings, form={})


@bp.route("/certs/<int:eid>/renew", methods=["POST"])
@require("certs", 2)
def cert_renew(eid):
    c = db.get_entity("certs", eid) or abort(404)
    if c["kind"] == "letsencrypt":
        cmd = certmod.certbot_renew_cmd(c) if certmod.cert_paths(c) else \
            certmod.certbot_issue_cmd(c, db.get_settings())
        jid = jobs.start(f"Renew {c['name']}", [cmd], on_done=_le_done(eid))
        log("cert_renew", c["name"])
        return redirect(url_for("main.job", jid=jid))
    if c["kind"] == "selfsigned":
        certmod.make_selfsigned(eid, c["domains"])
        certmod.refresh(c)
        db.save_entity("certs", c, eid)
        apply_and_report(f"cert-{eid}")
        log("cert_renew", c["name"])
    else:
        flash("Custom certificates are renewed by uploading a new one.", "warn")
    return redirect(url_for("main.certs"))


@bp.route("/certs/<int:eid>/delete", methods=["POST"])
@require("certs", 2)
def cert_delete(eid):
    c = db.get_entity("certs", eid) or abort(404)
    used = _in_use("certs", eid)
    if used:
        flash(f"Cannot delete: in use by {'; '.join(used)}", "error")
        return redirect(url_for("main.certs"))
    certmod.remove_files(c)
    db.delete_entity("certs", eid)
    log("cert_delete", c["name"])
    flash("Certificate deleted.", "ok")
    return redirect(url_for("main.certs"))


# ======================================================================
# security / global settings
# ======================================================================

@bp.route("/security", methods=["GET", "POST"])
@require("security")
def security():
    fields = forms.settings_fields()
    current = db.get_settings()
    meta = {"area": "security", "title": "security settings", "list": "main.security"}
    if request.method == "POST":
        if not can("security", 2):
            abort(403)
        data, errors = forms.parse_form(fields, request.form, current, g.user["is_admin"])
        if errors:
            auth.flash_errors(errors)
            return render_template("form.html", fields=fields, values=forms.form_values(fields, current),
                                   meta=meta, eid=None, table="settings", settings_mode=True), 400
        db.set_settings(data)
        if apply_and_report("settings"):
            log("settings", json.dumps(data, ensure_ascii=False, default=str)[:1500])
        else:
            db.set_settings({k: current[k] for k in data})
        return redirect(url_for("main.security"))
    return render_template("form.html", fields=fields, values=forms.form_values(fields, current),
                           meta=meta, eid=None, table="settings", settings_mode=True)


@bp.route("/security/block", methods=["POST"])
@require("security", 2)
def block_ip():
    """Adds an IP to the blocklist from the logs/analytics."""
    ip = request.form.get("ip", "")
    try:
        cidr = forms.parse_cidr(ip)
    except ValueError:
        flash("Invalid IP", "error")
        return redirect(request.referrer or url_for("main.security"))
    s = db.get_settings()
    if cidr not in s["blocklist"]:
        db.set_settings({"blocklist": s["blocklist"] + [cidr]})
        if apply_and_report("block-ip"):
            log("block_ip", cidr)
            flash(f"{cidr} added to the blocklist.", "ok")
    return redirect(request.referrer or url_for("main.security"))


# ======================================================================
# logs and analytics
# ======================================================================

@bp.route("/analytics")
@require("logs")
def analytics():
    rng = request.args.get("range", "24h")
    data = logs.analytics(rng, request.args.get("host", "").strip(),
                          request.args.get("from"), request.args.get("to"),
                          hids=group_hids(request.args.get("group")))
    hosts = sorted({d for h in db.list_entities("hosts") for d in h["domains"]})
    return render_template("analytics.html", a=data, hosts=hosts, args=request.args, groups=sorted_groups(),
                           chart_json=json.dumps({"labels": data["labels"], "series": data["series"],
                                                  "bytes": data["bytes_series"],
                                                  "status": data["top_status"]}).replace("</", "<\\/"))


@bp.route("/logs")
@require("logs")
def logs_view():
    kind = request.args.get("kind", "access")
    if kind not in logs.KINDS:
        kind = "access"
    flt = logs.Filter(request.args)
    if kind == "access":
        flt.hids = group_hids(request.args.get("group"))
    res = logs.search(kind, flt, page_args(), 100)
    qs = request.query_string.decode()
    qs_nopage = "&".join(p for p in qs.split("&") if p and not p.startswith("page="))
    return render_template("logs.html", kind=kind, res=res, args=request.args, page=page_args(), groups=sorted_groups(),
                           qs=qs_nopage, cols=logs.KINDS[kind])


@bp.route("/logs/export")
@require("logs")
def logs_export():
    kind = request.args.get("kind", "access")
    if kind not in logs.KINDS:
        abort(400)
    fmt = "jsonl" if request.args.get("fmt") == "jsonl" else "csv"
    flt = logs.Filter(request.args)
    if kind == "access":
        flt.hids = group_hids(request.args.get("group"))
    log("logs_export", f"{kind} {fmt} {json.dumps(flt.as_dict(), default=str)}")
    fname = f"{kind}-{time.strftime('%Y%m%d-%H%M%S')}.{fmt}"
    return Response(stream_with_context(logs.export(kind, flt, fmt)),
                    mimetype="text/csv" if fmt == "csv" else "application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@bp.route("/logs/errors")
@require("logs")
def logs_errors():
    files = [f["name"] for f in logs.all_files() if "error" in f["name"] and not f["name"].endswith(".gz")]
    name = request.args.get("file", "error.log")
    if name not in files:
        name = files[0] if files else "error.log"
    lines = logs.error_lines(name, request.args.get("q", ""), logs.parse_dt(request.args.get("from")),
                             logs.parse_dt(request.args.get("to")), int(request.args.get("limit", 500) or 500),
                             request.args.get("level", ""))
    return render_template("errors.html", lines=lines, files=files, name=name, args=request.args)


@bp.route("/logs/files")
@require("logs")
def logs_files():
    return render_template("logfiles.html", files=logs.all_files())


@bp.route("/logs/download/<path:name>")
@require("logs")
def logs_download(name):
    p = logs.safe_file(name)
    if not p:
        abort(404)
    log("logs_download", name)
    return send_file(p, as_attachment=True, download_name=p.name)


# ======================================================================
# users
# ======================================================================

@bp.route("/users")
@require("users")
def users():
    rows = [dict(r) for r in db.get_db().execute("SELECT * FROM users ORDER BY username")]
    for r in rows:
        r["perms"] = json.loads(r["perms"] or "{}")
    return render_template("users.html", users=rows)


def _user_form_save(uid=None):
    f = request.form
    username = f.get("username", "").strip()
    errors = []
    if not re.fullmatch(r"[A-Za-z0-9._@-]{3,64}", username):
        errors.append("Username: 3-64 characters (letters, digits . _ @ -)")
    pw = f.get("password", "")
    if not uid and not auth.password_ok(pw):
        errors.append("The password must be at least 10 characters long")
    if uid and pw and not auth.password_ok(pw):
        errors.append("The password must be at least 10 characters long")
    is_admin = 1 if f.get("is_admin") else 0
    if is_admin and not g.user["is_admin"]:
        errors.append("Only an administrator can create administrators")
    perms = {}
    for area in auth.AREAS:
        try:
            lv = int(f.get(f"perm_{area}", 0))
        except ValueError:
            lv = 0
        lv = max(0, min(2, lv))
        if lv > auth.level(g.user, area):
            errors.append(f"You cannot grant more permissions than you have ({auth.AREAS[area]})")
        perms[area] = lv
    active = 1 if f.get("active") else 0
    conn = db.get_db()
    dup = conn.execute("SELECT id FROM users WHERE username=? AND id IS NOT ?", (username, uid)).fetchone()
    if dup:
        errors.append("That user already exists")
    if uid:
        target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if target["is_admin"] and not g.user["is_admin"]:
            errors.append("You cannot modify an administrator")
        if uid == g.user["id"] and (not is_admin and g.user["is_admin"] or not active):
            errors.append("You cannot remove your own administrator role or deactivate yourself")
    if errors:
        return errors
    if uid:
        conn.execute("UPDATE users SET username=?, is_admin=?, perms=?, active=? WHERE id=?",
                     (username, is_admin, json.dumps(perms), active, uid))
        if pw:
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (auth.hash_password(pw), uid))
        if f.get("reset_2fa"):
            conn.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?", (uid,))
    else:
        conn.execute("INSERT INTO users(username, password_hash, is_admin, perms, active, created_at) "
                     "VALUES (?,?,?,?,?,?)", (username, auth.hash_password(pw), is_admin, json.dumps(perms),
                                               active, time.time()))
    conn.commit()
    log("user_" + ("edit" if uid else "create"), f"{username} admin={is_admin} perms={perms} active={active}")
    return []


@bp.route("/users/new", methods=["GET", "POST"])
@require("users", 2)
def user_new():
    if request.method == "POST":
        errors = _user_form_save()
        if not errors:
            flash("User created.", "ok")
            return redirect(url_for("main.users"))
        auth.flash_errors(errors)
    return render_template("user_form.html", u=None, form=request.form)


@bp.route("/users/<int:uid>/edit", methods=["GET", "POST"])
@require("users", 2)
def user_edit(uid):
    row = db.get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or abort(404)
    u = dict(row)
    u["perms"] = json.loads(u["perms"] or "{}")
    if request.method == "POST":
        errors = _user_form_save(uid)
        if not errors:
            flash("User updated.", "ok")
            return redirect(url_for("main.users"))
        auth.flash_errors(errors)
    return render_template("user_form.html", u=u, form=request.form)


@bp.route("/users/<int:uid>/delete", methods=["POST"])
@require("users", 2)
def user_delete(uid):
    conn = db.get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or abort(404)
    if uid == g.user["id"]:
        flash("You cannot delete yourself.", "error")
    elif row["is_admin"] and not g.user["is_admin"]:
        abort(403)
    elif row["is_admin"] and conn.execute("SELECT COUNT(*) FROM users WHERE is_admin=1 AND active=1").fetchone()[0] <= 1:
        flash("You cannot delete the last administrator.", "error")
    else:
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        log("user_delete", row["username"])
        flash("User deleted.", "ok")
    return redirect(url_for("main.users"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    conn = db.get_db()
    if request.method == "POST":
        action = request.form.get("action")
        row = conn.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
        if action == "password":
            from werkzeug.security import check_password_hash
            if not check_password_hash(row["password_hash"], request.form.get("current", "")):
                flash("The current password is incorrect.", "error")
            elif not auth.password_ok(request.form.get("new", "")):
                flash("The new password must be at least 10 characters long.", "error")
            elif request.form.get("new") != request.form.get("confirm"):
                flash("The passwords do not match.", "error")
            else:
                conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                             (auth.hash_password(request.form["new"]), g.user["id"]))
                conn.commit()
                log("change_password")
                flash("Password changed.", "ok")
        elif action == "2fa_start":
            session["totp_setup"] = auth.totp_new_secret()
        elif action == "2fa_confirm":
            secret = session.get("totp_setup")
            if secret and auth.totp_verify(secret, request.form.get("code")):
                conn.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (secret, g.user["id"]))
                conn.commit()
                session.pop("totp_setup", None)
                log("2fa_enable")
                flash("Two-step verification enabled.", "ok")
            else:
                flash("Wrong code. Check the time on your phone.", "error")
        elif action == "2fa_disable":
            if auth.totp_verify(row["totp_secret"], request.form.get("code")):
                conn.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?", (g.user["id"],))
                conn.commit()
                log("2fa_disable")
                flash("Two-step verification disabled.", "ok")
            else:
                flash("Wrong code.", "error")
        return redirect(url_for("main.profile"))
    secret = session.get("totp_setup")
    return render_template("profile.html", setup_secret=secret,
                           setup_uri=auth.totp_uri(secret, g.user["username"]) if secret else None)


@bp.route("/audit")
@require("users")
def audit():
    q = request.args.get("q", "").strip()
    sql, params = "SELECT * FROM audit", []
    if q:
        sql += " WHERE username LIKE ? OR action LIKE ? OR detail LIKE ? OR ip LIKE ?"
        params = [f"%{q}%"] * 4
    page = page_args()
    rows = db.get_db().execute(sql + " ORDER BY id DESC LIMIT 100 OFFSET ?", params + [(page - 1) * 100]).fetchall()
    return render_template("audit.html", rows=rows, q=q, page=page)


# ======================================================================
# system
# ======================================================================

@bp.route("/system")
@require("system")
def system():
    env = nginx.detect_env()
    managed = config.NGINX_CONF.exists() and "nginx-panel" in config.NGINX_CONF.read_text(errors="ignore")[:200]
    return render_template("system.html", env=env, running=nginx.nginx_running(), managed=managed,
                           backups=nginx.list_backups()[:25], jobs=jobs.recent(),
                           install_cmds=nginx.install_commands(), settings=db.get_settings(),
                           certbot=shutil.which("certbot"), dry=config.DRY_RUN)


@bp.route("/system/install", methods=["POST"])
@require("system", 2)
def system_install():
    cmds = nginx.install_commands()
    if not cmds:
        flash("Unsupported package manager (apt or dnf is required).", "error")
        return redirect(url_for("main.system"))
    jid = jobs.start("Install nginx + certbot", cmds)
    log("install_nginx")
    return redirect(url_for("main.job", jid=jid))


@bp.route("/system/apply", methods=["POST"])
@require("system", 2)
def system_apply():
    if apply_and_report("manual"):
        db.set_settings({"bootstrapped": True})
    log("apply_config")
    return redirect(url_for("main.system"))


@bp.route("/system/service/<action>", methods=["POST"])
@require("system", 2)
def system_service(action):
    if action == "test":
        code, out = nginx.test_config()
        flash(out, "ok" if code == 0 else "error")
    elif action in ("reload", "restart", "start", "stop"):
        ok, out = nginx.service_action(action)
        flash(out or f"{action}: OK", "ok" if ok else "error")
        log(f"nginx_{action}", out[:500])
    else:
        abort(404)
    return redirect(request.referrer or url_for("main.system"))


@bp.route("/system/restore", methods=["POST"])
@require("system", 2)
def system_restore():
    name = request.form.get("name", "")
    if name not in nginx.list_backups():
        abort(404)
    ok, out = nginx.restore_backup(name)
    flash(("Backup restored. " if ok else "Could not restore: ") + out, "ok" if ok else "error")
    if ok:
        flash("Note: the panel database does not change. The next change in the panel will regenerate "
              "the configuration from the DB.", "warn")
    log("restore_backup", name)
    return redirect(url_for("main.system"))


@bp.route("/system/nginx.conf")
@require("system")
def system_conf():
    content = config.NGINX_CONF.read_text(errors="replace") if config.NGINX_CONF.exists() else "(does not exist)"
    return render_template("preview.html", title=str(config.NGINX_CONF), content=content,
                           back=url_for("main.system"))


@bp.route("/jobs/<jid>")
@login_required
def job(jid):
    if not (can("system") or can("certs")):
        abort(403)
    j = jobs.get(jid) or abort(404)
    if request.args.get("format") == "json":
        return jsonify({"status": j["status"], "log": j["log"]})
    return render_template("job.html", j=j)


@bp.app_errorhandler(403)
def e403(_e):
    return render_template("error.html", code=403, msg="You do not have permission for this."), 403


@bp.app_errorhandler(404)
def e404(_e):
    return render_template("error.html", code=404, msg="Not found."), 404


@bp.app_errorhandler(400)
def e400(e):
    return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request")), 400
