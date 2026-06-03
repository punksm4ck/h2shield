# H2Shield

**A Windows server-surface auditor and HTTP/2 hardener for the "HTTP/2 Bomb" denial-of-service class (CVE-2026-49975).**

H2Shield is a single-file PowerShell 7 application that deploys a self-contained WPF GUI to audit a Windows host's inbound network surface, identify which listeners are genuinely reachable and web-facing, and disable HTTP/2 at the HTTP.SYS kernel layer on machines running IIS — the mitigation recommended for unpatched servers affected by HTTP/2 Bomb.

It is built for home-lab and small-fleet operators who manage a handful of Windows boxes directly and want a repeatable, copy-pasteable hardening pass rather than a heavyweight agent.

---

## What HTTP/2 Bomb is

HTTP/2 Bomb is a remote denial-of-service attack against the default HTTP/2 configuration of most major web servers — nginx, Apache httpd, Microsoft IIS, Envoy, and Cloudflare Pingora. It chains two long-known techniques: an HPACK compression bomb (originally CVE-2016-6581) that makes a tiny request expand into gigabytes of server-side memory, and a Slowloris-style flow-control hold that pins that memory in place so a short spike becomes a lasting outage.

It was disclosed publicly on June 2, 2026 by the research firm Calif, who found it using OpenAI's Codex to read public fix commits and recognize that the two halves compose against these specific servers.

**A note on the CVE number.** CVE-2026-49975 was assigned specifically to the *Apache httpd* fix (committed by Stefan Eissing on May 27, 2026, making cookie headers count against `LimitRequestFields`). "HTTP/2 Bomb" is the umbrella name for the attack class across all five servers; only the Apache variant received a CVE. This project uses CVE-2026-49975 as shorthand for the whole class, matching how the security press refers to it, but the distinction is worth knowing.

### Patch status (as of 2026-06-03 — verify current state before relying on this)

| Server | Status |
|---|---|
| nginx | Fixed in **1.29.8** (`max_headers` directive, default 1000). Stopgap: `http2 off;` |
| Apache httpd | Fix in **mod_http2 v2.0.41** (standalone / trunk); not yet in a stable 2.4.x at disclosure. Stopgap: `Protocols http/1.1` |
| Envoy | **Patch released ~2026-06-03**, under validation by the researchers. Previously listed as unpatched. |
| Microsoft IIS | **No vendor patch** at time of writing. Mitigation: disable HTTP/2, or front with a proxy enforcing header-count limits. |
| Cloudflare Pingora | **No vendor patch** at time of writing. |

This table goes stale quickly. Always check the upstream sources (linked below) for current patch availability.

---

## What H2Shield actually does — and doesn't

**Scope honesty matters for a security tool, so read this.**

HTTP/2 Bomb is a **server-side** attack. It only affects a process that *listens* for inbound HTTP/2 and decodes HPACK. On Windows, that means **IIS (via the HTTP.SYS kernel driver)**. It does **not** affect arbitrary GUI applications, desktop programs, or non-HTTP/2 listeners. A Python Flask app, a PyQt tray tool, or a game server cannot be "bombed" by this exploit — they don't run an HPACK decoder.

So H2Shield does the things that genuinely reduce this class of risk, and nothing it can't honestly back up:

### It does
- **Inventories every listening TCP/UDP endpoint** and the process that owns it.
- **Classifies reachability** into tiers — `All` (bound to `0.0.0.0`/`::`), `LAN`, `LinkLocal` (`fe80::`/`169.254.x`), `Loopback` — so you see what's actually reachable versus normal local OS chatter.
- **Flags genuine risk**: only TCP listeners that are both reachable *and* on a web port (80, 443, 8080, 8443, 8000, 8337, 3210, 5000, 7000) are marked `Risk=True`. This is the broad "web listener you should know about" signal, not a claim that each one is HTTP/2-vulnerable.
- **Detects IIS / HTTP.SYS state** and whether HTTP/2 is currently enabled.
- **Hardens** (when you choose to): writes `EnableHttp2Tls=0` and `EnableHttp2Cleartext=0` to HTTP.SYS, clamps `MaxFieldLength`/`MaxRequestBytes`, and — only when IIS is running — sets a private-memory recycle cap on each AppPool so a flooded worker is recycled instead of dragging the box into swap.
- **Verifies** the hardening landed: reads the registry values back and, if a site is live on 443, runs a `curl --http2` negotiation to confirm the server refuses HTTP/2.
- **Self-heals** via an optional scheduled task that re-audits and re-applies hardening if it detects drift.

### It does not
- Scan or "shield" individual desktop/GUI applications against this exploit — there is no attack surface there for HTTP/2 Bomb.
- Patch nginx, Apache, Envoy, or Pingora. On Windows the relevant server is IIS; the Linux servers are out of scope for this tool (a Kubuntu port is planned — see Roadmap).
- Replace upstream vendor patches. Disabling HTTP/2 is a *mitigation* for unpatched IIS, not a fix. If a patch becomes available, apply it.
- Provide any offensive capability. There is no exploit code here.

---

## Requirements

- **Windows 10/11 or Windows Server** (developed and tested on Windows 11).
- **PowerShell 7+** (`pwsh`). Windows PowerShell 5.1 is not supported.
- **Administrator** privileges (the hardening writes to `HKLM` and touches services).
- IIS is **not** required to run the audit — on a box without IIS, H2Shield simply reports that there is no HTTP/2 server surface to harden.

---

## Quick start

Open an **elevated PowerShell 7** session and run:

```powershell
# from a local copy of the script
Unblock-File .\AEGIS_H2Shield.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\AEGIS_H2Shield.ps1
```

The GUI launches and runs a passive audit automatically. Review the **Listening Surface** and **IIS / HTTP.SYS** tabs before taking any action.

See [`docs/USAGE.md`](docs/USAGE.md) for the full button-by-button walkthrough and [`docs/SECURITY_NOTES.md`](docs/SECURITY_NOTES.md) for the reasoning behind each hardening step.

---

## The GUI

| Button | Action |
|---|---|
| **Run Audit** | Read-only. Inventories listeners, classifies reachability, flags web-facing risk. |
| **Audit + Harden** | Applies the HTTP/2-disable mitigation. **State-aware**: restarts HTTP.SYS/W3SVC only when IIS is actually running; on a stopped/disabled-IIS box it writes registry values only and performs no service restart. |
| **Verify** | Read-only. Confirms the four registry values, reports IIS/HTTP.SYS state, and runs a live `curl --http2` test if a site is serving on 443. |
| **Install Self-Heal** | Registers a SYSTEM scheduled task that re-audits and re-applies hardening on drift. |
| **Open Reports** | Opens the JSON audit-report folder. |

A progress panel shows real per-stage progress, elapsed time, and live endpoint counts. The audit runs in a background runspace so the UI never freezes.

---

## ⚠️ Important safety notes

- **Disabling HTTP/2 is a mitigation, not a cure.** Clients fall back to HTTP/1.1 transparently, at a small efficiency cost. Apply vendor patches when available.
- **The hardening is state-aware for a reason.** Earlier development builds force-restarted the HTTP.SYS kernel driver unconditionally, which could wedge a box (with IIS stopped/disabled) into a `StopPending` service state requiring a reboot. The current build only restarts when IIS is live. If you are running an older copy, replace it.
- **Test on a non-critical box first.** This writes to `HKLM` and can restart your web server. On a remote machine, confirm you have an out-of-band way back in (the tool's audit will show you your remote-access listeners) before hardening.
- **The "at-risk" flag is a surface signal, not a vulnerability assertion.** A flagged Python/Flask listener is a reachable web service worth reviewing — it is *not* HTTP/2-Bomb-vulnerable, because those servers don't speak HTTP/2 with HPACK.

---

## Manual mitigation (no GUI)

If you just want the IIS mitigation without the tool, the entirety of it is four registry values plus letting HTTP.SYS pick them up on its next start:

```powershell
$reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
Set-ItemProperty $reg -Name EnableHttp2Tls       -Value 0     -Type DWord
Set-ItemProperty $reg -Name EnableHttp2Cleartext -Value 0     -Type DWord
Set-ItemProperty $reg -Name MaxFieldLength       -Value 16384 -Type DWord
Set-ItemProperty $reg -Name MaxRequestBytes      -Value 32768 -Type DWord
# Restart HTTP.SYS + W3SVC ONLY if IIS is currently running; otherwise the
# values apply automatically the next time HTTP.SYS starts.
```

---

## Roadmap

- [ ] Kubuntu / Linux port: `ss`-based surface scan, `nftables` integration, and the nginx (`max_headers` / `http2 off`) and Apache (`Protocols http/1.1`) mitigations.
- [ ] Optional HTML report export alongside the JSON.
- [ ] Configurable web-port list and memory-cap thresholds.
- [ ] Signed releases.

---

## References

- Calif research writeup: <https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb>
- oss-sec disclosure: <https://seclists.org/oss-sec/2026/q2/790>
- NVD / Tenable CVE-2026-49975
- Prior art: CVE-2016-6581 (HPACK Bomb), CVE-2025-53020 (Apache ~4000:1 amplification)

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

H2Shield is provided as-is, without warranty. It modifies system configuration and restarts services. You are responsible for testing it in your own environment and for the consequences of running it. The author is not liable for downtime, data loss, or any other damage. This is a defensive mitigation tool; it contains no exploit code.
