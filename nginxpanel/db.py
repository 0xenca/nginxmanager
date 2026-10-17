"""SQLite: tablas de usuarios/auditoría + entidades genéricas (JSON)."""
import json
import sqlite3
import threading
import time

from flask import g

from . import config

ENTITY_TABLES = ("hosts", "backends", "streams", "certs", "access_lists", "groups")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    perms TEXT NOT NULL DEFAULT '{}',
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    last_login REAL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, username TEXT, ip TEXT, action TEXT NOT NULL, detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS host_status (
    host_id INTEGER PRIMARY KEY, ts REAL NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, ts REAL NOT NULL, username TEXT);
CREATE INDEX IF NOT EXISTS login_attempts_ip ON login_attempts(ip, ts);
"""
for _t in ENTITY_TABLES:
    SCHEMA += f"""
CREATE TABLE IF NOT EXISTS {_t} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);"""

_init_lock = threading.Lock()
_initialized = False


def connect():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    global _initialized
    with _init_lock:
        if _initialized:
            return
        conn = connect()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
        _initialized = True


def get_db():
    if "db" not in g:
        init_db()
        g.db = connect()
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- entidades genéricas ----------

def _row_to_entity(row):
    d = json.loads(row["data"])
    d["id"] = row["id"]
    d["created_at"] = row["created_at"]
    d["updated_at"] = row["updated_at"]
    return d


def list_entities(table, db=None):
    assert table in ENTITY_TABLES
    db = db or get_db()
    return [_row_to_entity(r) for r in db.execute(f"SELECT * FROM {table} ORDER BY id")]


def get_entity(table, eid, db=None):
    assert table in ENTITY_TABLES
    db = db or get_db()
    r = db.execute(f"SELECT * FROM {table} WHERE id=?", (eid,)).fetchone()
    return _row_to_entity(r) if r else None


def save_entity(table, data, eid=None, db=None):
    assert table in ENTITY_TABLES
    db = db or get_db()
    clean = {k: v for k, v in data.items() if k not in ("id", "created_at", "updated_at")}
    now = time.time()
    if eid:
        db.execute(f"UPDATE {table} SET data=?, updated_at=? WHERE id=?",
                   (json.dumps(clean), now, eid))
    else:
        cur = db.execute(f"INSERT INTO {table}(data, created_at, updated_at) VALUES (?,?,?)",
                         (json.dumps(clean), now, now))
        eid = cur.lastrowid
    db.commit()
    return eid


def delete_entity(table, eid, db=None):
    assert table in ENTITY_TABLES
    db = db or get_db()
    db.execute(f"DELETE FROM {table} WHERE id=?", (eid,))
    db.commit()


# ---------- estado de hosts (última comprobación manual) ----------

def get_statuses(db=None):
    db = db or get_db()
    return {r["host_id"]: json.loads(r["data"]) for r in db.execute("SELECT host_id, data FROM host_status")}


def save_statuses(results, db=None):
    db = db or get_db()
    for hid, data in results.items():
        db.execute("INSERT INTO host_status(host_id, ts, data) VALUES (?,?,?) ON CONFLICT(host_id) "
                   "DO UPDATE SET ts=excluded.ts, data=excluded.data", (hid, data["ts"], json.dumps(data)))
    db.commit()


def delete_status(hid, db=None):
    db = db or get_db()
    db.execute("DELETE FROM host_status WHERE host_id=?", (hid,))
    db.commit()


# ---------- ajustes ----------

DEFAULT_SETTINGS = {
    "ipv6": True,
    "default_behavior": "drop",          # drop (444) | 404
    "client_max_body_size": "64m",
    "rate_limit_rps": 20,
    "conn_limit_zone_mb": 10,
    "cache_keys_zone_mb": 50,
    "cache_max_size": "2g",
    "waf_scanners": True,
    "waf_probes": True,
    "waf_injection": True,
    "waf_bad_methods": True,
    "waf_empty_ua": False,
    "blocklist": "",
    "trusted_proxies": "",
    "le_email": "",
    "le_staging": False,
    "include_legacy": False,
    "http_custom": "",
    "gzip": True,
    "bootstrapped": False,
}


def get_settings(db=None):
    db = db or get_db()
    s = dict(DEFAULT_SETTINGS)
    for r in db.execute("SELECT key, value FROM settings"):
        s[r["key"]] = json.loads(r["value"])
    return s


def set_settings(values, db=None):
    db = db or get_db()
    for k, v in values.items():
        db.execute("INSERT INTO settings(key, value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, json.dumps(v)))
    db.commit()


# ---------- auditoría ----------

def audit(username, ip, action, detail="", db=None):
    db = db or get_db()
    db.execute("INSERT INTO audit(ts, username, ip, action, detail) VALUES (?,?,?,?,?)",
               (time.time(), username, ip, action, detail[:2000]))
    db.commit()
