"""Lectura, filtrado, exportación y analíticas de los logs JSON de nginx."""
import collections
import csv
import gzip
import io
import ipaddress
import json
import re
import time
from datetime import datetime

from . import config

ACCESS_COLS = ["time", "ip", "host", "method", "uri", "status", "bytes", "rt", "urt",
               "referer", "ua", "proto", "cache", "tls", "waf", "hid"]
STREAM_COLS = ["time", "ip", "proto", "port", "status", "sent", "recv", "dur", "upstream"]
KINDS = {"access": ACCESS_COLS, "stream": STREAM_COLS}
ERR_TS = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")


def log_files(kind):
    """Ficheros de un tipo (incluye rotados .1, .2.gz…), del más antiguo al más nuevo."""
    if not config.LOG_DIR.exists():
        return []
    files = [p for p in config.LOG_DIR.glob(f"{kind}.log*") if p.is_file()]
    return sorted(files, key=lambda p: p.stat().st_mtime)


def all_files():
    if not config.LOG_DIR.exists():
        return []
    out = []
    for p in sorted(config.LOG_DIR.iterdir()):
        if p.is_file():
            st = p.stat()
            out.append({"name": p.name, "size": st.st_size, "mtime": st.st_mtime})
    return out


def safe_file(name):
    p = (config.LOG_DIR / name).resolve()
    if p.parent != config.LOG_DIR.resolve() or not p.is_file():
        return None
    return p


def _open(p):
    if p.suffix == ".gz":
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, "r", encoding="utf-8", errors="replace")


def _ts(s):
    try:
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return 0.0


def parse_dt(s):
    """'2026-10-01T10:00' (datetime-local) -> epoch local."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


# ---------------- filtros ----------------

class Filter:
    def __init__(self, args):
        self.from_ts = parse_dt(args.get("from"))
        self.to_ts = parse_dt(args.get("to"))
        self.ip_raw = (args.get("ip") or "").strip()
        self.net = None
        if self.ip_raw:
            try:
                self.net = ipaddress.ip_network(self.ip_raw, strict=False)
            except ValueError:
                self.net = None   # se usa como prefijo de texto
        self.host = (args.get("host") or "").strip().lower()
        self.status = (args.get("status") or "").strip().lower()
        self.method = (args.get("method") or "").strip().upper()
        self.path = (args.get("path") or "").strip()
        self.ua = (args.get("ua") or "").strip().lower()
        self.waf = args.get("waf") in ("1", "on", "true")
        self.port = (args.get("port") or "").strip()
        self.text = (args.get("q") or "").strip().lower()
        self.hids = None   # conjunto de ids de host (filtro por grupo); lo fija la vista

    def as_dict(self):
        return {k: v for k, v in vars(self).items() if k != "net"}

    def _status_ok(self, st):
        f = self.status
        if not f:
            return True
        if re.fullmatch(r"[1-5]xx", f):
            return str(st).startswith(f[0])
        if f.startswith(">="):
            return f[2:].isdigit() and int(st) >= int(f[2:])
        if f.startswith("!"):
            return str(st) != f[1:]
        return str(st) == f

    def raw_precheck(self, line):
        """Descarte rápido antes de parsear JSON."""
        if self.ip_raw and not self.net and self.ip_raw not in line:
            return False
        if self.net and self.net.prefixlen == self.net.max_prefixlen and str(self.net.network_address) not in line:
            return False
        if self.text and self.text not in line.lower():
            return False
        return True

    def match(self, e):
        if self.hids is not None and str(e.get("hid", "")) not in self.hids:
            return False
        t = e["_ts"]
        if self.from_ts and t < self.from_ts:
            return False
        if self.to_ts and t > self.to_ts:
            return False
        if self.ip_raw:
            if self.net:
                try:
                    if ipaddress.ip_address(e.get("ip", "")) not in self.net:
                        return False
                except ValueError:
                    return False
            elif not str(e.get("ip", "")).startswith(self.ip_raw):
                return False
        if self.host and self.host not in str(e.get("host", "")).lower():
            return False
        if not self._status_ok(e.get("status", "")):
            return False
        if self.method and e.get("method") != self.method:
            return False
        if self.path and self.path not in str(e.get("uri", "")):
            return False
        if self.ua and self.ua not in str(e.get("ua", "")).lower():
            return False
        if self.waf and not e.get("waf"):
            return False
        if self.port and str(e.get("port", "")) != self.port:
            return False
        return True


def iter_entries(kind, flt):
    for p in log_files(kind):
        if flt.from_ts and p.stat().st_mtime < flt.from_ts:
            continue   # el fichero se cerró antes del inicio del rango
        with _open(p) as fh:
            for line in fh:
                if not line.startswith("{") or not flt.raw_precheck(line):
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                e["_ts"] = _ts(e.get("time"))
                if flt.match(e):
                    yield e


def search(kind, flt, page=1, per_page=100, max_scan_seconds=25):
    keep = collections.deque(maxlen=page * per_page)
    total = 0
    start = time.time()
    truncated = False
    for e in iter_entries(kind, flt):
        keep.append(e)
        total += 1
        if total % 5000 == 0 and time.time() - start > max_scan_seconds:
            truncated = True
            break
    rows = list(keep)[::-1][(page - 1) * per_page: page * per_page]
    return {"rows": rows, "total": total, "pages": max(1, -(-total // per_page)),
            "truncated": truncated, "elapsed": round(time.time() - start, 2)}


def export(kind, flt, fmt="csv"):
    cols = KINDS[kind]
    if fmt == "jsonl":
        for e in iter_entries(kind, flt):
            e.pop("_ts", None)
            yield json.dumps(e, ensure_ascii=False) + "\n"
        return
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    yield buf.getvalue()
    for e in iter_entries(kind, flt):
        buf.seek(0)
        buf.truncate()
        w.writerow([e.get(c, "") for c in cols])
        yield buf.getvalue()


# ---------------- error log ----------------

def error_lines(name="error.log", q="", from_ts=None, to_ts=None, limit=500, level=""):
    p = safe_file(name)
    if not p:
        return []
    out = collections.deque(maxlen=limit)
    ql = q.lower()
    with _open(p) as fh:
        for line in fh:
            if ql and ql not in line.lower():
                continue
            if level and f"[{level}]" not in line:
                continue
            if from_ts or to_ts:
                m = ERR_TS.match(line)
                if m:
                    t = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").timestamp()
                    if (from_ts and t < from_ts) or (to_ts and t > to_ts):
                        continue
            out.append(line.rstrip("\n"))
    return list(out)[::-1]


# ---------------- analíticas ----------------

RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}


def _bucket_size(span):
    if span <= 3 * 3600:
        return 60
    if span <= 26 * 3600:
        return 1800
    if span <= 8 * 86400:
        return 3 * 3600
    return 86400


def analytics(rng="24h", host="", from_s=None, to_s=None, hids=None):
    now = time.time()
    if from_s or to_s:
        t0 = parse_dt(from_s) or now - 86400
        t1 = parse_dt(to_s) or now
    else:
        t1 = now
        t0 = now - RANGES.get(rng, 86400)
    span = max(60, t1 - t0)
    bsize = _bucket_size(span)
    nb = int(span // bsize) + 1
    start = int(t0 // bsize) * bsize
    series = {k: [0] * nb for k in ("2xx", "3xx", "4xx", "5xx", "blocked")}
    bytes_series = [0] * nb

    flt = Filter({"host": host})
    flt.hids = hids
    flt.from_ts, flt.to_ts = t0, t1
    total = bytes_total = 0
    rts = []
    ips = collections.Counter()
    hosts = collections.Counter()
    paths = collections.Counter()
    statuses = collections.Counter()
    uas = collections.Counter()
    wafs = collections.Counter()
    cache = collections.Counter()
    methods = collections.Counter()
    err_paths = collections.Counter()
    scan_start = time.time()
    truncated = False
    for e in iter_entries("access", flt):
        total += 1
        st = int(e.get("status") or 0)
        b = int(e.get("bytes") or 0)
        bytes_total += b
        idx = min(nb - 1, max(0, int((e["_ts"] - start) // bsize)))
        if e.get("waf"):
            series["blocked"][idx] += 1
            wafs[e["waf"]] += 1
        else:
            cls = f"{st // 100}xx"
            if cls in series:
                series[cls][idx] += 1
        bytes_series[idx] += b
        if len(rts) < 300000:
            try:
                rts.append(float(e.get("rt") or 0))
            except ValueError:
                pass
        ips[e.get("ip", "?")] += 1
        hosts[e.get("host", "?")] += 1
        path = str(e.get("uri", "")).split("?", 1)[0][:200]
        paths[path] += 1
        statuses[st] += 1
        uas[str(e.get("ua", ""))[:160]] += 1
        methods[e.get("method", "?")] += 1
        if e.get("cache"):
            cache[e["cache"]] += 1
        if st >= 500:
            err_paths[f"{e.get('host')}{path}"] += 1
        if total % 20000 == 0 and time.time() - scan_start > 40:
            truncated = True
            break

    rts.sort()
    def pct(p):
        return round(rts[min(len(rts) - 1, int(len(rts) * p))] * 1000) if rts else 0
    labels = []
    for i in range(nb):
        t = time.localtime(start + i * bsize)
        labels.append(time.strftime("%d/%m %H:%M" if bsize < 86400 else "%d/%m", t))
    errors = sum(v for k, v in statuses.items() if k >= 500)
    hits = cache.get("HIT", 0)
    cache_total = sum(cache.values())
    return {
        "range": rng, "from": t0, "to": t1, "bucket": bsize, "truncated": truncated,
        "total": total, "unique_ips": len(ips), "bytes": bytes_total,
        "avg_ms": round(sum(rts) / len(rts) * 1000) if rts else 0, "p95_ms": pct(0.95),
        "error_rate": round(errors / total * 100, 2) if total else 0,
        "blocked": sum(wafs.values()),
        "cache_hit": round(hits / cache_total * 100, 1) if cache_total else None,
        "labels": labels, "series": series, "bytes_series": bytes_series,
        "top_ips": ips.most_common(15), "top_hosts": hosts.most_common(15),
        "top_paths": paths.most_common(15), "top_status": statuses.most_common(12),
        "top_ua": uas.most_common(10), "waf": wafs.most_common(), "cache": cache.most_common(),
        "methods": methods.most_common(), "err_paths": err_paths.most_common(10),
    }


def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
