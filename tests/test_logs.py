import gzip
import json
import time
from datetime import datetime

from nginxpanel import config, logs


def iso(ts):
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def write_access_log(entries, name="access.log", gz=False):
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(e) + "\n" for e in entries) + "not json\n"
    p = config.LOG_DIR / name
    if gz:
        with gzip.open(p, "wt") as fh:
            fh.write(text)
    else:
        p.write_text(text)
    return p


def entry(ago, **kw):
    e = {"time": iso(time.time() - ago), "ip": "10.0.0.1", "host": "app.example.com", "method": "GET",
         "uri": "/", "status": 200, "bytes": 1000, "rt": 0.010, "ua": "curl/8", "cache": "", "waf": "", "hid": "1"}
    e.update(kw)
    return e


def setup_function():
    if config.LOG_DIR.exists():
        for p in config.LOG_DIR.iterdir():
            p.unlink()


def test_filters():
    write_access_log([
        entry(60), entry(50, ip="192.168.1.20", status=404, uri="/missing"),
        entry(40, status=502, host="api.example.com", hid="2"), entry(30, method="POST", ua="sqlmap/1.7", waf="scanner",
                                                                      status=403),
    ])
    def count(**args):
        return logs.search("access", logs.Filter(args))["total"]
    assert count() == 4
    assert count(ip="192.168.0.0/16") == 1
    assert count(ip="10.0.0") == 3
    assert count(status="5xx") == 1
    assert count(status=">=400") == 3
    assert count(status="!200") == 3
    assert count(method="POST") == 1
    assert count(waf="1") == 1
    assert count(host="api") == 1
    assert count(path="/miss") == 1
    assert count(ua="SQLMAP") == 1
    assert count(q="missing") == 1
    flt = logs.Filter({})
    flt.hids = {"2"}
    assert logs.search("access", flt)["total"] == 1


def test_rotated_gz_files_are_read_and_listed():
    write_access_log([entry(7200)], name="access.log.2.gz", gz=True)
    write_access_log([entry(60)])
    assert logs.search("access", logs.Filter({}))["total"] == 2
    assert {f["name"] for f in logs.all_files()} == {"access.log", "access.log.2.gz"}
    assert logs.safe_file("access.log.2.gz") is not None
    assert logs.safe_file("../../etc/passwd") is None


def test_export_csv_and_jsonl():
    write_access_log([entry(60, uri="/a,b")])
    csv_text = "".join(logs.export("access", logs.Filter({}), "csv"))
    assert csv_text.splitlines()[0].startswith("time,ip,host")
    assert '"/a,b"' in csv_text
    lines = "".join(logs.export("access", logs.Filter({}), "jsonl")).splitlines()
    assert json.loads(lines[0])["uri"] == "/a,b" and "_ts" not in lines[0]


def test_analytics():
    write_access_log([entry(600), entry(500, status=500, uri="/boom"), entry(400, waf="sqli", status=403),
                      entry(300, cache="HIT"), entry(200, cache="MISS", ip="10.0.0.2")])
    a = logs.analytics("1h")
    assert a["total"] == 5
    assert a["unique_ips"] == 2
    assert a["blocked"] == 1
    assert a["error_rate"] == 20.0
    assert a["cache_hit"] == 50.0
    assert a["top_ips"][0] == ("10.0.0.1", 4)
    assert a["err_paths"] == [("app.example.com/boom", 1)]
    assert sum(a["series"]["2xx"]) == 3 and sum(a["series"]["blocked"]) == 1


def test_error_log_lines():
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    (config.LOG_DIR / "error.log").write_text(
        "2026/10/01 10:00:00 [warn] 1#1: first\n2026/10/01 11:00:00 [error] 1#1: second 10.0.0.9\n")
    assert logs.error_lines("error.log") == ["2026/10/01 11:00:00 [error] 1#1: second 10.0.0.9",
                                             "2026/10/01 10:00:00 [warn] 1#1: first"]
    assert len(logs.error_lines("error.log", level="warn")) == 1
    assert len(logs.error_lines("error.log", q="10.0.0.9")) == 1
    assert len(logs.error_lines("error.log", from_ts=logs.parse_dt("2026-10-01T10:30"))) == 1


def test_human_bytes():
    assert logs.human_bytes(512) == "512 B"
    assert logs.human_bytes(1536) == "1.5 KB"
    assert logs.human_bytes(5 * 1024 ** 3) == "5.0 GB"
