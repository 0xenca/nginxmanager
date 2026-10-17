"""Certificates: Let's Encrypt (webroot), uploaded (PEM) and self-signed."""
import calendar
import os
import re
import shutil
import tempfile
import time
from pathlib import Path

from . import config
from .nginx import cert_paths, run


def cert_dir(cid):
    return config.DATA_DIR / "certs" / str(cid)


def certname_for(cid, domains):
    base = re.sub(r"[^a-z0-9.-]", "-", domains[0].replace("*.", "wildcard."))
    return f"panel-{cid}-{base}"[:60]


def read_info(fullchain_path):
    code, out = run(["openssl", "x509", "-in", str(fullchain_path), "-noout",
                     "-enddate", "-subject", "-issuer", "-ext", "subjectAltName"])
    if code != 0:
        return None
    info = {}
    m = re.search(r"notAfter=(.+)", out)
    if m:
        try:
            info["expires"] = calendar.timegm(time.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z"))
        except ValueError:
            pass
    m = re.search(r"issuer=(.+)", out)
    info["issuer"] = m.group(1).strip() if m else ""
    info["san"] = re.findall(r"DNS:([^,\s]+)", out)
    return info


def refresh(cert):
    p = cert_paths(cert)
    if p:
        info = read_info(p["fullchain"]) or {}
        cert.update({k: v for k, v in info.items() if k != "san"})
        if info.get("san"):
            cert["domains"] = info["san"]
        cert["status"] = "ok"
    return cert


def _pubkey(args):
    code, out = run(["openssl"] + args)
    return out if code == 0 else None


def store_custom(cid, cert_pem, key_pem, chain_pem=""):
    """Checks that the certificate and key match and stores them. Returns (ok, msg)."""
    cert_pem = cert_pem.strip() + "\n"
    key_pem = key_pem.strip() + "\n"
    if "BEGIN CERTIFICATE" not in cert_pem or "PRIVATE KEY" not in key_pem:
        return False, "Unrecognized PEM format"
    if "ENCRYPTED" in key_pem:
        return False, "The private key is password-protected; remove the passphrase first (openssl pkey -in k.pem -out k2.pem)"
    with tempfile.TemporaryDirectory() as td:
        c, k = Path(td) / "c.pem", Path(td) / "k.pem"
        c.write_text(cert_pem)
        k.write_text(key_pem)
        pc = _pubkey(["x509", "-in", str(c), "-noout", "-pubkey"])
        pk = _pubkey(["pkey", "-in", str(k), "-pubout"])
        if not pc or not pk:
            return False, "Could not read the certificate or the key"
        if pc.strip() != pk.strip():
            return False, "The private key does not match the certificate"
    d = cert_dir(cid)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    full = cert_pem + (chain_pem.strip() + "\n" if chain_pem.strip() else "")
    (d / "fullchain.pem").write_text(full)
    (d / "privkey.pem").write_text(key_pem)
    os.chmod(d / "privkey.pem", 0o600)
    return True, "Certificate saved"


def make_selfsigned(cid, domains, days=825):
    d = cert_dir(cid)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    san = ",".join(f"DNS:{x}" for x in domains)
    code, out = run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                     "-nodes", "-days", str(days), "-subj", f"/CN={domains[0]}", "-addext",
                     f"subjectAltName={san}", "-keyout", str(d / "privkey.pem"), "-out", str(d / "fullchain.pem")])
    if code == 0:
        os.chmod(d / "privkey.pem", 0o600)
    return code == 0, out


def certbot_issue_cmd(cert, settings):
    cmd = ["certbot", "certonly", "--webroot", "-w", str(config.ACME_ROOT), "--cert-name", cert["certname"],
           "--non-interactive", "--agree-tos", "--keep-until-expiring", "--expand",
           "--deploy-hook", f"{config.NGINX_BIN} -s reload"]
    for dname in cert["domains"]:
        cmd += ["-d", dname]
    if settings.get("le_email"):
        cmd += ["--email", settings["le_email"]]
    else:
        cmd += ["--register-unsafely-without-email"]
    if settings.get("le_staging"):
        cmd += ["--staging"]
    return cmd


def certbot_renew_cmd(cert):
    return ["certbot", "renew", "--cert-name", cert["certname"], "--force-renewal", "--non-interactive"]


def remove_files(cert):
    if cert["kind"] == "letsencrypt":
        if shutil.which("certbot") and not config.DRY_RUN:
            run(["certbot", "delete", "--cert-name", cert["certname"], "--non-interactive"])
    else:
        shutil.rmtree(cert_dir(cert["id"]), ignore_errors=True)


def days_left(cert):
    if not cert.get("expires"):
        return None
    return int((cert["expires"] - time.time()) // 86400)
