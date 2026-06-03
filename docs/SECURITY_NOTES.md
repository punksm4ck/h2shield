# H2Shield — Security Notes

This document explains the reasoning behind each design decision, so you can audit the tool's logic rather than trusting it.

## Why HTTP/2 Bomb only affects IIS on Windows

The attack targets a process that listens for inbound HTTP/2 and decodes HPACK (the HTTP/2 header-compression scheme). On Windows, inbound HTTP/2 is terminated by **HTTP.SYS**, the kernel-mode HTTP stack, which IIS sits on top of. No other common Windows software runs an HPACK decoder on an inbound listener. Therefore:

- Desktop/GUI applications are not affected — they are not HTTP/2 servers.
- Python (Flask/waitress/`http.server`), Node, and similar dev servers are not affected — they speak HTTP/1.x, not HTTP/2 with HPACK.
- The only thing worth hardening for *this CVE* on a Windows box is IIS / HTTP.SYS.

This is why the tool does not attempt to "shield" arbitrary applications: there is no attack surface there to shield.

## Why disable HTTP/2 rather than tune limits

For unpatched servers (IIS has no vendor patch at time of writing), disabling HTTP/2 entirely is the only mitigation that *closes* the vector rather than narrowing it. Header-count and size limits reduce amplification but do not eliminate the memory-pinning behavior that turns a spike into an outage. Disabling HTTP/2 forces clients to HTTP/1.1, which is transparent to them and not vulnerable to this attack.

The registry values used:

| Value | Setting | Purpose |
|---|---|---|
| `EnableHttp2Tls` | `0` | Disables HTTP/2 over TLS (h2). |
| `EnableHttp2Cleartext` | `0` | Disables HTTP/2 cleartext (h2c). Only present on newer Windows builds; written harmlessly either way. |
| `MaxFieldLength` | `16384` | Defense-in-depth cap on a single header field, even on HTTP/1.1. |
| `MaxRequestBytes` | `32768` | Defense-in-depth cap on the full request line + headers. |

These live under `HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters`. HTTP.SYS reads them at service start.

## Why the restart is state-aware

HTTP.SYS is a kernel driver with many dependents. The change to HTTP/2 state takes effect when HTTP.SYS next starts. Two cases:

- **IIS running**: the new value isn't live until HTTP.SYS restarts. So the tool stops W3SVC, restarts HTTP, and starts W3SVC. This is a brief outage but necessary to apply the mitigation immediately.
- **IIS stopped or disabled**: nothing is serving HTTP/2 right now, and HTTP.SYS will read the new values whenever it next starts (e.g., when you re-enable and start IIS). Force-restarting the kernel driver in this state is both unnecessary and risky — it can wedge the service into a `StopPending` state that requires a reboot to clear. So the tool writes the values and performs **no** service restart.

The state check is `W3SVC.Status -eq 'Running' -and StartType -ne 'Disabled'`. This was a real defect in early development builds (an unconditional `Restart-Service HTTP -Force`) and is the single most important correctness fix in the tool.

## Why the AppPool memory cap

If a worker process (`w3wp`) balloons — which is exactly the failure mode of an HPACK bomb — a private-memory recycle cap (1.5 GB) causes IIS to recycle that worker rather than let it consume all RAM and drag the host into swap. This is defense-in-depth: it limits the blast radius of any memory-exhaustion attack, not just this one. It is only applied when IIS is running, because the IIS configuration provider (`IIS:\AppPools`) is not readable when the service is stopped.

## Why the reachability tiers

A naive "is this bound to something other than loopback?" check flags a huge amount of normal Windows behavior (mDNS, SSDP/UPnP, NetBIOS, RPC) as "exposed," which buries the signal. The tiered classification (`All` / `LAN` / `LinkLocal` / `Loopback`) plus a web-port `Risk` flag surfaces the listeners that actually matter and correctly demotes link-local and loopback noise. The `Risk` flag is intentionally a *web-surface* signal, not a per-CVE vulnerability claim.

## What the tool deliberately cannot do

- It contains no exploit or proof-of-concept code.
- It does not exfiltrate data; reports are written locally only.
- It does not modify application code or third-party server configs; its only system changes are the documented HTTP.SYS registry values and (when IIS is running) AppPool recycle caps and a service restart.

## Reporting a security issue

If you find a security problem in H2Shield itself, please open a private security advisory on the repository rather than a public issue. See [SECURITY.md](../SECURITY.md).
