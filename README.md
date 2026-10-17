# nginx-panel

[![Tests](https://github.com/0xenca/nginxmanager/actions/workflows/tests.yml/badge.svg)](https://github.com/0xenca/nginxmanager/actions/workflows/tests.yml)

A Python (Flask) web panel to install and manage nginx on a Linux server: hosts,
load-balanced backends, SSL, WebSocket, TCP/UDP streams, a basic WAF, caching, users with
permissions, analytics and a log viewer.

Covered by an automated test suite (validators, config generation, the web UI end to end,
real `nginx -t` runs and the installer) that runs on every push. See [Tests](#tests).

## Installation

```bash
git clone https://github.com/0xenca/nginxmanager.git && cd nginxmanager
sudo ./install.sh                                  # panel on all interfaces, port 8181
sudo ./install.sh --with-nginx                     # also installs nginx + stream module + certbot
sudo ./install.sh --allow 192.168.88.0/24,10.8.0.0/24   # only these networks can use the panel
sudo ./install.sh --bind 127.0.0.1                 # local only (access through an SSH tunnel)
```

The installer creates `/opt/nginx-panel` (venv), the `nginx-panel` service (gunicorn),
`/etc/nginx-panel.env`, log rotation and an `admin` user with a random password that it
prints at the end.

Access: `http://SERVER-IP:8181`. The allowed networks can be changed later in
`/etc/nginx-panel.env` (`NP_ALLOWED_NETS`) + `systemctl restart nginx-panel`.

First use: **System → Install nginx** (if it is not installed) → **Take control of nginx**.

## Manual installation (without `install.sh`)

The same steps the installer performs, for anyone who prefers to review or adapt them. Run
everything as root (`sudo -i`) from the project folder (cloned with
`git clone https://github.com/0xenca/nginxmanager.git && cd nginxmanager`, or extracted
from a release archive).

**1. System dependencies**

```bash
# Debian / Ubuntu
apt-get update
apt-get install -y python3 python3-venv openssl logrotate
apt-get install -y nginx libnginx-mod-stream certbot     # optional: nginx + stream + certbot

# RHEL / Rocky / Alma
dnf install -y python3 openssl logrotate
dnf install -y epel-release && dnf install -y nginx nginx-mod-stream certbot   # optional
```

**2. Code and virtual environment**

```bash
mkdir -p /opt/nginx-panel
cp -r nginxpanel requirements.txt /opt/nginx-panel/
python3 -m venv /opt/nginx-panel/venv
/opt/nginx-panel/venv/bin/pip install --upgrade pip
/opt/nginx-panel/venv/bin/pip install -r /opt/nginx-panel/requirements.txt

install -d -m 700 /var/lib/nginx-panel        # database
install -d -m 750 /var/log/nginx/panel        # host logs
```

**3. The `nginx-panel` command**

```bash
cat > /usr/local/bin/nginx-panel <<'EOF'
#!/bin/sh
set -a; [ -f /etc/nginx-panel.env ] && . /etc/nginx-panel.env; set +a
cd /opt/nginx-panel && exec /opt/nginx-panel/venv/bin/python -m nginxpanel "$@"
EOF
chmod 755 /usr/local/bin/nginx-panel
```

**4. Configuration**: `/etc/nginx-panel.env` (adjust the IP, port and networks):

```bash
cat > /etc/nginx-panel.env <<'EOF'
# nginx-panel configuration (read when the service starts)
NP_BIND=0.0.0.0
NP_PANEL_PORT=8181
NP_BEHIND_PROXY=0
# Networks allowed to use the panel (comma-separated CIDRs). Empty = any.
NP_ALLOWED_NETS=
# Set to 1 if you access the panel over HTTPS (Secure cookies)
NP_SECURE_COOKIES=0
EOF
chmod 600 /etc/nginx-panel.env
```

**5. systemd service**

```bash
cat > /etc/systemd/system/nginx-panel.service <<'EOF'
[Unit]
Description=nginx-panel (web administration for nginx)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/nginx-panel.env
WorkingDirectory=/opt/nginx-panel
ExecStart=/opt/nginx-panel/venv/bin/gunicorn --workers 1 --threads 8 --timeout 120 \
  --no-control-socket --bind ${NP_BIND}:${NP_PANEL_PORT} --access-logfile - nginxpanel.wsgi:app
Restart=on-failure
# Needs root: writes to /etc/nginx, reloads nginx, runs certbot and apt.
User=root
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
```

**6. Log rotation** (on RHEL/Rocky replace `adm` with `root`):

```bash
cat > /etc/logrotate.d/nginx-panel <<'EOF'
/var/log/nginx/panel/*.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    create 0640 root adm
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid) || true
    endscript
}
EOF
```

**7. Start it and create the administrator**

```bash
systemctl daemon-reload
systemctl enable --now nginx-panel
nginx-panel create-admin admin --random      # prints the generated password
systemctl status nginx-panel
```

Open `http://SERVER-IP:8181`, change the password, enable 2FA and continue with
**System → Take control of nginx**.

## Features

| Area | Details |
|---|---|
| Hosts | Reverse proxy or redirect. Multiple domains and wildcards. Direct target or backend. |
| Groups | Folders to organize hosts (Internal, Public, Customers…), with a color. Grouped, collapsible list (state is remembered), search, multi-select to move hosts between groups, "+ Host" straight into a group, enable/disable a whole group in a single config change, and group filter in analytics, logs and exports. Deleting a group never deletes its hosts. |
| Host status | On-demand diagnostics (⟳ button: all, per group or per host; never automatic). Layered: DNS (does it resolve? does it point here?), local nginx (code, latency, TLS), via DNS the way a client would reach it (detects NAT loopback, firewall, or another machine answering), direct backend (each load-balanced server), certificate (trusted, name, expiry) and HTTP→HTTPS redirect. One-line summary with expandable details; the last result is stored. |
| Listen interface | Each host and stream chooses which server IP it is published on (dropdown with the detected IPs) or "All interfaces" (default). The panel adds a `default_server` for each specific IP and makes hosts on "all" listen on it too, so foreign domains neither slip through nor do hosts disappear. |
| Unknown domains | `default_server` returns 444 (closes without responding) and on HTTPS rejects the TLS handshake if the SNI does not match (`ssl_reject_handshake`). Neither the bare IP nor a foreign domain shows anything. |
| Backends | Upstreams with round robin, least_conn, ip_hash or consistent hash; weights, backup, down, max_fails, keepalive. |
| SSL | Let's Encrypt (HTTP-01 via webroot, automatic renewal with reload), PEM upload with key↔certificate verification, self-signed. Force HTTPS, HTTP/2, HSTS. |
| WebSocket | Upgrade/Connection and 1 h timeouts per host. |
| Streams | TCP, UDP or both, multiple targets with load balancing and IP ACLs. |
| Protection | Basic WAF (scanners, `.env`/`.git`/phpMyAdmin probes, SQLi, XSS, traversal, Log4Shell, TRACE methods), global blocklist, per-IP rate and connection limits, security headers, `server_tokens off`, anti-slowloris timeouts. |
| Access lists | Allow/deny by IP/CIDR + basic authentication, combinable (`satisfy all/any`). |
| Cache | Per host: static files only, or everything (honors Cache-Control and never caches requests with `Authorization` or a session cookie). `X-Cache-Status` header. |
| Analytics | Requests by status over time, bandwidth, p95, % of 5xx, cache hit ratio, top IPs/paths/hosts/UAs, blocked attacks. One-click IP blocking. |
| Logs | JSON logs. Filters by date, IP or CIDR, host, status (`404`, `5xx`, `>=400`, `!200`), method, path, UA, blocked only. CSV/JSONL export of the filtered results, file download (including rotated `.gz`), error.log viewer. |
| Users | Per-area permissions (no access / view / manage), administrators, TOTP 2FA, lockout after 5 failures, audit log of every action. |
| System | nginx installation, `nginx -t`, reload, restart, backup before every change and restore. |

## How changes are applied

Every change regenerates the **whole** configuration from the DB into `/etc/nginx/panel/`,
backs up the previous one, runs `nginx -t` and only then reloads. If `nginx -t` fails, it
restores the files, reverts the change in the DB and shows the error. nginx is never left broken.

The panel rewrites `/etc/nginx/nginx.conf` (the original is kept as `nginx.conf.panel-orig`)
and, by default, **stops loading `sites-enabled/` and `conf.d/`**. If you have existing sites,
migrate them or enable them under Security → Advanced (it clashes if any of them declares `default_server`).

## Securing the panel itself

The panel runs as **root** (it writes to `/etc/nginx`, runs certbot and apt). Treat it like SSH:

- By default it listens on all interfaces (0.0.0.0:8181). Restrict who can reach it with
  `NP_ALLOWED_NETS` (the panel answers 403 to everyone else) and/or with the firewall.
- To use it over HTTPS, publish it as a host in the panel itself with a certificate and an
  access list; set `NP_BEHIND_PROXY=1` and `NP_SECURE_COOKIES=1` in `/etc/nginx-panel.env`,
  restart, and close port 8181 in the firewall.
- Enable 2FA under My account.
- Custom directives (free text that reaches nginx) are only visible to administrators.
  Everything else goes through validators that prevent directive injection.
- Sessions: HttpOnly + SameSite=Strict cookie, CSRF on every POST, strict CSP.

## Commands

```bash
nginx-panel create-admin USERNAME [--random]  # create or recover an admin (resets their 2FA)
nginx-panel apply                             # regenerate the config from the DB
systemctl status nginx-panel
journalctl -u nginx-panel -f
```

## Known limitations

- **Status is checked from the server itself.** "Reachable" means nginx and the backend
  respond from the inside; the "Via DNS" check gets closer to what a client sees, but it is
  no substitute for a check from outside your network (NAT loopback, CGNAT, ISP firewall).
- **Basic WAF, not ModSecurity/Coraza.** It stops scanners and automated exploitation with few
  false positives; it does not replace a WAF with OWASP CRS rules.
- **Wildcards `*.domain`** need DNS-01: upload them as a custom certificate.
- **Analytics** parse the logs on every query. This works fine up to several hundred MB per
  range; with more volume the query is cut short and says so.
- No GeoIP in this version.
- Tested on Ubuntu 24.04 with nginx 1.26 (CI uses Ubuntu 24.04's nginx 1.24). Debian (nginx 1.22, `listen … http2` syntax) and
  RHEL/Rocky (dnf + EPEL) are supported, but not tested.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

All paths are redirected to a temporary directory and nginx is never reloaded, so the suite is
safe to run on any machine. If an `nginx` binary is available, the generated configuration is
also validated with a real `nginx -t` (otherwise those tests are skipped; set
`NP_REQUIRE_NGINX=1` to make that an error). `nginx -t` opens the listening ports, so as a
non-root user run `sudo setcap cap_net_bind_service=+ep "$(command -v nginx)"` first.

The [GitHub Actions workflow](.github/workflows/tests.yml) runs on every push and pull request:

| Job | What it checks |
|---|---|
| Lint | `compileall`, ShellCheck on `install.sh`, executable bit |
| Unit tests | the suite on Python 3.10, 3.11, 3.12 and 3.13 (without nginx) |
| Tests with real nginx | the suite with Ubuntu's nginx + stream module, including `nginx -t` and rollback |
| install.sh | a real install on a fresh Ubuntu runner: service up, login with the generated password, taking control of nginx, 444 for unknown domains, re-install keeps users |

## Structure

```
nginxpanel/
  __init__.py   Flask factory, security headers
  views.py      routes
  nginx.py      environment detection, generation, apply with rollback
  forms.py      declarative forms + anti-injection validators
  certs.py      Let's Encrypt / PEM / self-signed
  checks.py     on-demand host reachability diagnostics
  logs.py       filtering, export and analytics
  auth.py       sessions, permissions, CSRF, TOTP, lockout
  jobs.py       background jobs (apt, certbot)
  templates/nginx/*.j2   nginx configuration templates
tests/          pytest suite (see Tests)
.github/workflows/tests.yml   CI
```
