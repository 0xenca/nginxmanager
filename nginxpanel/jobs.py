"""Tareas en segundo plano (instalar nginx, pedir certificados) con log en disco."""
import json
import re
import subprocess
import threading
import time
import uuid

from . import config


JID_RE = re.compile(r"\d{14}-[0-9a-f]{6}")


def _paths(jid):
    lp = config.safe_path(config.JOBS_DIR, f"{jid}.log")
    sp = config.safe_path(config.JOBS_DIR, f"{jid}.json")
    if lp is None or sp is None:
        raise ValueError("id de tarea no válido")
    return lp, sp


def _write_state(jid, **state):
    _, sp = _paths(jid)
    cur = json.loads(sp.read_text()) if sp.exists() else {}
    cur.update(state)
    sp.write_text(json.dumps(cur))


def start(title, commands, on_done=None, env=None):
    """commands: lista de cadenas shell o de listas argv. on_done(ok, log_text)."""
    config.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    jid = time.strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
    _write_state(jid, id=jid, title=title, status="running", started=time.time())

    def worker():
        lp, _ = _paths(jid)
        ok = True
        with open(lp, "w") as log:
            for cmd in commands:
                shown = cmd if isinstance(cmd, str) else " ".join(cmd)
                log.write(f"$ {shown}\n")
                log.flush()
                if config.DRY_RUN:
                    log.write("(DRY_RUN: omitido)\n")
                    continue
                try:
                    p = subprocess.Popen(cmd, shell=isinstance(cmd, str), stdout=log,
                                         stderr=subprocess.STDOUT, env=env)
                    rc = p.wait(timeout=1800)
                except Exception as e:  # noqa: BLE001
                    log.write(f"ERROR: {e}\n")
                    rc = 1
                log.write(f"[código de salida {rc}]\n\n")
                log.flush()
                if rc != 0:
                    ok = False
                    break
        text = lp.read_text()
        extra = ""
        if on_done:
            try:
                extra = on_done(ok, text) or ""
            except Exception as e:  # noqa: BLE001
                ok, extra = False, f"Error post-tarea: {e}"
        if extra:
            with open(lp, "a") as log:
                log.write(extra + "\n")
        _write_state(jid, status="ok" if ok else "error", finished=time.time())

    threading.Thread(target=worker, daemon=True).start()
    return jid


def get(jid):
    if not jid or not JID_RE.fullmatch(jid):
        return None
    lp, sp = _paths(jid)
    if not sp.exists():
        return None
    st = json.loads(sp.read_text())
    st["log"] = lp.read_text() if lp.exists() else ""
    return st


def recent(n=15):
    if not config.JOBS_DIR.exists():
        return []
    out = []
    for sp in sorted(config.JOBS_DIR.glob("*.json"), reverse=True)[:n]:
        try:
            out.append(json.loads(sp.read_text()))
        except (OSError, ValueError):
            pass
    return out
