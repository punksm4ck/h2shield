# H2Shield Linux — Usage Guide

## Quick start

```bash
# install GTK deps (once)
sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-pango-1.0 iproute2 curl

# run the GUI (root for hardening; read-only audit works unprivileged)
sudo python3 h2shield_linux.py
```

---

## The four tabs

### Listening Surface

Every TCP/UDP port currently in a listening state, classified by reachability:

| Scope | Meaning |
|-------|---------|
| **All** | Bound to `0.0.0.0` or `::` — reachable wherever routing allows |
| **LAN** | Bound to a real NIC address — reachable on your local network |
| **LinkLocal** | `fe80::` / `169.254.x` — same segment only, not routable |
| **Loopback** | `127.0.0.1` / `::1` — this machine only |

`Risk=True` rows float to the top. These are TCP listeners on web ports (80, 443, 8080, 8443, 8000, and your custom service ports) with Scope=All or LAN. **These are the only rows that matter for HTTP/2 Bomb.**

### nginx / Apache

Shows detected server version, whether the installed version includes the upstream patch, and whether HTTP/2 directives are present in the current config. The `needs_harden` flag is the decision value: `True` means HTTP/2 is on and the upstream patch isn't installed.

### Actions / Log

A running log of every action taken (or planned in dry-run). After a Harden run, this shows exactly what changed. The log persists for the session.

### Config Diffs

A unified diff of every config file modified during a Harden run. Review this before you close the window — if anything looks wrong, restore from `/opt/h2shield/config_backups/`.

---

## Button reference

### Run Audit

Passive scan. Never writes anything. Populates all four tabs and shows the current hardening state. Safe to run at any time.

### Audit + Harden

Runs the audit, then:
1. Shows a confirmation dialog explaining exactly what will change
2. Backs up every config file it will touch (timestamped, in `/opt/h2shield/config_backups/`)
3. Patches HTTP/2 directives out of nginx / Apache configs
4. Runs `nginx -t` or `apachectl -t` before reloading — if the config test fails, it logs the error and does **not** reload
5. Applies a cgroup memory cap to nginx workers (1.5 GB, kills before swap)
6. Only touches servers where `needs_harden=True`; leaves patched/already-hardened servers alone

### Verify

Read-only confirmation that hardening landed:
- Re-reads the config and checks for any remaining HTTP/2 directives
- Shows server version and patch status
- If something is listening on `:443`, runs `curl --http2` and reports whether HTTP/2 is negotiated

### Install Self-Heal

Writes two systemd unit files and enables the timer:

```
/etc/systemd/system/h2shield-heal.service
/etc/systemd/system/h2shield-heal.timer   (daily 03:00, persistent)
```

The timer runs `h2shield_linux.py --headless --harden`. If your configs drift back (e.g. a package upgrade re-enables HTTP/2), the next run re-applies the fix and logs it.

To check whether the timer is working:
```bash
systemctl status h2shield-heal.timer
journalctl -u h2shield-heal.service -n 20
```

### Open Reports

Opens `/opt/h2shield/reports/` in your file manager. Each audit writes a JSON report with the full surface scan, server state, and any actions taken.

---

## Deploying to remote boxes

```bash
# copy and run headless (no display needed):
scp h2shield_linux.py user@remote:/tmp/
ssh user@remote sudo python3 /tmp/h2shield_linux.py --headless

# GUI over SSH with X forwarding:
ssh -X user@remote sudo python3 /tmp/h2shield_linux.py
```

---

## What to check before hardening a production box

1. **Run Audit first** and read the Listening Surface tab — confirm the at-risk rows are what you expect
2. **Check nginx/Apache tab** — verify `needs_harden=True` is correct; if your server isn't HTTP/2-enabled, it'll say `needs_harden=False` and nothing changes
3. **Know your maintenance window** — Harden reloads the web server (`nginx -s reload` or `apachectl graceful`), which is a graceful reload with minimal impact but still real
4. **Have a backup path** — configs are backed up automatically to `/opt/h2shield/config_backups/`, but know how to restore: `cp /opt/h2shield/config_backups/nginx.conf.TIMESTAMP.bak /etc/nginx/nginx.conf && nginx -s reload`
5. **Review the Config Diffs tab after the run** — confirm the diff matches what you expected

---

## Uninstalling

```bash
# disable self-heal timer
sudo systemctl disable --now h2shield-heal.timer
sudo rm /etc/systemd/system/h2shield-heal.{service,timer}
sudo systemctl daemon-reload

# remove cgroup drop-in (if installed)
sudo rm -rf /etc/systemd/system/nginx.service.d/h2shield-memory.conf
sudo systemctl daemon-reload && sudo systemctl restart nginx

# remove app data (backups, reports, logs)
sudo rm -rf /opt/h2shield

# the script itself (wherever you put it)
rm h2shield_linux.py
```

To restore a hardened config:
```bash
# find the backup
ls /opt/h2shield/config_backups/

# restore
sudo cp /opt/h2shield/config_backups/nginx.conf.TIMESTAMP.bak /etc/nginx/nginx.conf
sudo nginx -t && sudo nginx -s reload
```
