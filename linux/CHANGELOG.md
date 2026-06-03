# Changelog

All notable changes to H2Shield Linux are documented here.

## [1.0.0] — 2026-06-03

Initial release.

### Added
- GTK3 GUI with four tabs: Listening Surface, nginx/Apache, Actions/Log, Config Diffs
- Background-thread audit (UI never freezes; buttons stay live throughout)
- Real-time progress: stage name, elapsed time, ETA, live endpoint counts
- `ss -tulpn` surface scan with Scope tiering (All / LAN / LinkLocal / Loopback)
- Risk classification: `Risk=True` only for reachable TCP web-protocol listeners
- nginx detection: version check, `>=1.29.8` patched-version flag, full config scan via `nginx -T`
- Apache detection: version, mod_http2 version, dpkg-based patch check, config tree scan
- **Hardening — audit-only default**: dry-run shows diffs before any change is made
- **Hardening — Harden mode**: backs up every config file before touching it, generates unified diff, patches HTTP/2 directives out, reloads server; only runs if `http2_enabled=True` and `patched_version=False`
- Per-nginx-worker cgroup memory cap via systemd drop-in (`MemoryMax=1536M MemorySwapMax=0`)
- Verify button: re-reads config state, optional live `curl --http2` negotiation probe
- Headless mode (`--headless [--harden]`) for cron and systemd timer use
- Self-heal: installs `h2shield-heal.service` + `h2shield-heal.timer` (daily 03:00, persistent)
- JSON audit reports written to `/opt/h2shield/reports/`
- Auto-update via `--update-url` flag
- `--headless` mode usable without GTK (servers without a display)
