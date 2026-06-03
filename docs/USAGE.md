# H2Shield — Usage Guide

This walks through deploying and operating H2Shield on a Windows host.

## 1. Prerequisites

- PowerShell 7+ (`pwsh --version` should report 7.x).
- An elevated (Administrator) session.
- The script file, `AEGIS_H2Shield.ps1`.

If your execution policy blocks unsigned local scripts, either run through `pwsh -ExecutionPolicy Bypass` (as shown below) or set, once, for your user:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then clear the "downloaded from the internet" mark on the file:

```powershell
Unblock-File .\AEGIS_H2Shield.ps1
```

## 2. First run (audit only)

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\AEGIS_H2Shield.ps1
```

On launch the tool:
1. Copies itself to `C:\AEGIS_Source\H2Shield\` (a stable home so the self-heal task can find it).
2. Opens the GUI and runs a passive audit automatically.

**Do not click Harden yet.** Read the results first.

### Reading the Listening Surface tab

Each row is a listening endpoint:

- **Scope** — reachability tier:
  - `All` — bound to `0.0.0.0` or `::`, reachable wherever routing allows.
  - `LAN` — bound to a real NIC address; reachable on your local network.
  - `LinkLocal` — `fe80::` / `169.254.x`; same-segment only, effectively local.
  - `Loopback` — `127.0.0.1` / `::1`; this machine only.
- **Risk** — `True` only when a listener is TCP, reachable (not loopback/link-local), and on a known web port. This is the "web-facing listener worth reviewing" signal.

Most `svchost`/`System` UDP entries (123, 137/138, 1900, etc.) are normal Windows service chatter and will correctly show `Risk=False`.

### Reading the IIS / HTTP.SYS tab

- `IISInstalled: false` → this box has no HTTP/2 server surface. There is nothing for Harden to do; the box is already in its hardened end-state for this CVE.
- `IISInstalled: true` → check `EnableHttp2Tls` / `EnableHttp2Cleartext`. If they are null/unset, HTTP/2 is on (the vulnerable default) and the status bar will show `Drift: True`.

## 3. Hardening

Only meaningful on a box with IIS. Click **Audit + Harden** and confirm the dialog.

The hardening is **state-aware**:
- **IIS running** → writes registry values, sets AppPool memory caps, and restarts HTTP.SYS + W3SVC (brief outage, a few seconds) to apply immediately.
- **IIS stopped or disabled** → writes registry values only. No service restart. The values apply automatically the next time HTTP.SYS starts. This avoids the kernel-driver-restart hang that an unconditional restart can cause on a stopped-IIS box.

## 4. Verifying

Click **Verify** (read-only). It reports:
- The four registry values and whether HTTP/2 is disabled.
- W3SVC and HTTP.SYS service state.
- If something is listening on 443, a live `curl --http2` negotiation result. If the server still negotiates HTTP/2, you need to restart HTTP.SYS (or reboot). If it negotiates HTTP/1.x, the mitigation is working.
- If nothing is on 443 (sites down), the live test is skipped and the registry value is what governs HTTP/2 when sites next start.

## 5. Self-heal (optional)

Click **Install Self-Heal** to register a SYSTEM scheduled task (`AEGIS_H2Shield_Heal`) that runs daily and at startup, re-audits, and re-applies hardening if it detects drift. A separate per-user logon task can launch the GUI at boot.

To remove them:

```powershell
Disable-ScheduledTask -TaskName AEGIS_H2Shield_Heal
Unregister-ScheduledTask -TaskName AEGIS_H2Shield_Heal -Confirm:$false
```

## 6. Remote deployment over RDP / Chrome Remote Desktop

H2Shield's hardening touches **IIS and HTTP.SYS only** — it does not affect RDP or Chrome Remote Desktop, which run on separate services and ports. The HTTP.SYS restart will not drop your remote session.

Still, on a remote box you cannot physically reach:
1. Run audit-only first and confirm your remote-access listeners appear in the grid and are not on 80/443.
2. Confirm your remote-access service is set to auto-start so it survives a reboot.
3. Have an out-of-band fallback before hardening, in case of the unexpected.

## Reports

Every audit writes a timestamped JSON report to `C:\AEGIS_Source\H2Shield\reports\`. Use **Open Reports** to browse them.

## Logs

Activity is logged to `C:\AEGIS_Source\H2Shield\logs\h2shield.log`.
