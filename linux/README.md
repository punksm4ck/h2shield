# AEGIS H2-Shield — Linux

**HTTP/2 Bomb (CVE-2026-49975) server-surface auditor and hardener for Kubuntu / Debian-family Linux.**

A GTK3 GUI (with a headless/cron mode) that audits your listening surface, detects nginx and Apache HTTP/2 state, backs up and patches configs to disable HTTP/2, applies per-worker cgroup memory caps, and self-heals via a systemd timer.

> **Windows version:** see the companion repo [punksm4ck/h2shield](https://github.com/punksm4ck/h2shield) for the PowerShell 7 / WPF version that handles IIS / HTTP.SYS.

---

## What this actually does — and what it doesn't

HTTP/2 Bomb is a **server-side** memory-exhaustion attack. It hits processes that listen for inbound HTTP/2 and parse HPACK — nginx, Apache httpd (mod_http2), Envoy, Pingora. It **does not** affect arbitrary GUI apps or non-HTTP/2 ports.

This tool:

1. Inventories every listening TCP/UDP port and owning process via `ss`
2. Classifies each endpoint by actual reachability: **All** / **LAN** / **LinkLocal** / **Loopback**
3. Flags `Risk=True` only for reachable web-protocol listeners (ports 80, 443, 8080…)
4. Detects nginx and Apache versions plus HTTP/2 state in their configs
5. **Hardens**: backs up configs, generates a diff for review, patches out HTTP/2 directives, reloads the server
6. Applies per-nginx-worker cgroup memory caps (MemoryMax) via a systemd drop-in so a flooded worker is OOM-killed rather than swapping the box
7. Verifies the result (registry-equivalent config re-read + optional live `curl --http2` probe)
8. Self-heals: a systemd timer re-audits daily and re-applies hardening if drift is detected

---

## CVE status (as of 2026-06-03)

| Server    | Patch available? | Mitigation |
|-----------|-----------------|------------|
| **nginx** | Yes — v1.29.8+ adds `max_headers` directive | Upgrade, or `http2 off;` |
| **Apache httpd** | Yes — mod_http2 ≥ 2.0.41 | Upgrade mod_http2, or `Protocols http/1.1` |
| **Envoy** | Partial — patch released June 3 2026, Calif still validating | Disable HTTP/2 |
| **Pingora** | No patch yet | Disable HTTP/2 |
| **IIS** | No patch yet | See Windows companion repo |

The CVE (CVE-2026-49975) was discovered by Calif using OpenAI Codex and disclosed 2026-06-02. It chains the HPACK Bomb compression technique (CVE-2016-6581) with a Slowloris-style connection hold to exhaust server worker memory. The CVE identifier strictly tracks the Apache httpd variant; "HTTP/2 Bomb" is the umbrella name used across all five servers.

---

## Requirements

- Python 3.8+
- `ss` (from `iproute2`)
- For the GUI: `python3-gi`, `gir1.2-gtk-3.0`
- For live negotiation tests: `curl`
- For cgroup memory caps: `systemd`
- Run as **root** (or `sudo`) for hardening actions; read-only audit works as a normal user

```bash
sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-pango-1.0 iproute2 curl
```

---

## Usage

### GUI (interactive)
```bash
sudo python3 h2shield_linux.py
```

The window opens and runs a passive audit on render. Buttons stay live throughout.

| Button | What it does |
|--------|-------------|
| **Run Audit** | Passive scan — read-only, never mutates |
| **Audit + Harden** | Backs up configs, patches HTTP/2 out, reloads servers, applies cgroup caps |
| **Verify** | Re-reads config + optional live curl probe — confirms hardening landed |
| **Install Self-Heal** | Writes a systemd service + timer for daily re-audit |
| **Open Reports** | Opens `/opt/h2shield/reports/` in your file manager |

The **Config Diffs tab** shows a unified diff of every file changed during a Harden run — review it before you close the window.

### Headless (cron / systemd)
```bash
# audit only
sudo python3 h2shield_linux.py --headless

# audit + apply hardening
sudo python3 h2shield_linux.py --headless --harden
```

### Auto-update
```bash
sudo python3 h2shield_linux.py --update-url https://raw.example.com/h2shield_linux.py
```

---

## What Harden actually changes

**nginx:**
- Removes ` http2` from `listen` directives (`listen 443 ssl http2` → `listen 443 ssl`)
- Replaces `http2 on;` with `http2 off;`
- Writes a unified diff before touching anything
- Backs up every modified file to `/opt/h2shield/config_backups/`
- Runs `nginx -t` before reload; restores nothing automatically if the test fails (check the diff and backup)

**Apache:**
- Removes `h2`/`h2c` from `Protocols` lines (`Protocols h2 h2c http/1.1` → `Protocols http/1.1`)
- Sets `H2Engine Off`
- Same backup + diff approach

**cgroup memory cap (nginx):**
- Writes `/etc/systemd/system/nginx.service.d/h2shield-memory.conf` with `MemoryMax=1536M MemorySwapMax=0`
- A worker that exceeds 1.5 GB is OOM-killed and respawns; this is strictly better than a box pushed into swap

---

## File layout

```
/opt/h2shield/
├── logs/             # headless run logs
├── reports/          # JSON audit reports (one per run)
└── config_backups/   # timestamped backups of every patched config file
```

---

## Deploying to multiple boxes

```bash
# from your control machine, over SSH:
scp h2shield_linux.py user@target-box:/tmp/
ssh user@target-box sudo python3 /tmp/h2shield_linux.py --headless
```

For a GUI session on a remote box, forward X11:
```bash
ssh -X user@target-box sudo python3 /tmp/h2shield_linux.py
```

---

## Self-healing

After **Install Self-Heal** (or `--headless` cron setup):

```
/etc/systemd/system/h2shield-heal.service
/etc/systemd/system/h2shield-heal.timer   ← runs daily at 03:00, persistent=true
```

To check status:
```bash
systemctl status h2shield-heal.timer
journalctl -u h2shield-heal.service -n 50
```

To disable:
```bash
sudo systemctl disable --now h2shield-heal.timer
```

---

## Limitations and honest caveats

- Config patching is conservative but not exhaustive. Complex `include` chains, non-standard config paths, or heavily templated configs may not be fully detected. Always review the Config Diffs tab.
- The `Risk=True` flag marks reachable web-protocol listeners — it does not prove a service is HTTP/2-capable, only that it's on a port that typically runs web services. Trace unfamiliar processes before hardening.
- The live curl `--http2` negotiation test requires a running listener on `:443` and may not reflect the exact TLS config of a production site.
- This tool does not firewall or block ports. It addresses the HTTP/2 protocol-level attack surface only.

---

## License

MIT — see [LICENSE](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Defensive-only scope; no offensive tooling.

## Reporting vulnerabilities in this tool

See [SECURITY.md](SECURITY.md).
