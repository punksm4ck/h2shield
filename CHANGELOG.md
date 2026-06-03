# Changelog

All notable changes to H2Shield are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versioning is semver-ish.

## [1.2.0] - 2026-06-03

### Fixed
- **State-aware hardening (critical).** The Harden routine now restarts the
  HTTP.SYS kernel driver only when IIS is actually running
  (`W3SVC.Status -eq 'Running' -and StartType -ne 'Disabled'`). Previously it
  issued an unconditional `Restart-Service HTTP -Force`, which on a
  stopped/disabled-IIS box could wedge the service into `StopPending` and
  require a reboot. On stopped/disabled IIS the tool now writes registry values
  only; they apply on the next HTTP.SYS start. Applied to both the GUI and the
  headless self-heal path.
- AppPool memory-cap step is now gated behind `IIS running`, since the IIS
  config provider is unreadable when the service is stopped.

### Added
- **Verify button.** Read-only confirmation: reads back the four registry
  values, reports W3SVC/HTTP.SYS state, and runs a live `curl --http2`
  negotiation when a site is serving on 443 (gracefully skipped when sites are
  down).
- Harden confirmation dialog now states exactly what will happen in each
  service-state case.
- Version shown in the window title.

## [1.1.0] - 2026-06-03

### Changed
- **Reachability classification overhaul.** Replaced the single boolean
  `Exposed` column with a `Scope` tier (`All` / `LAN` / `LinkLocal` /
  `Loopback`) plus a separate web-port `Risk` flag. This removes the false
  signal from normal Windows UDP/link-local chatter and surfaces only listeners
  that actually matter. Applied consistently across the GUI and headless paths.

## [1.0.3] - 2026-06-03

### Fixed
- Replaced `-f` format operators with string concatenation in the timer tick,
  log header, and `Write-Log`, fixing a crash when dynamic content (e.g.
  process names) contained literal `{`/`}` characters.

## [1.0.2] - 2026-06-03

### Added
- Background-runspace audit driven by a `DispatcherTimer`, with a real
  per-stage progress bar, live elapsed timer, and real endpoint counts. UI no
  longer freezes during audits.

## [1.0.1] - 2026-06-03

### Fixed
- Audit performance: resolve all processes once into a PID→name map instead of
  per-socket `Get-Process` with per-process `.Path` resolution (which threw
  access-denied exceptions in a tight loop and froze the UI).
- `-InstallTask` now falls through to launch the GUI instead of returning early.

## [1.0.0] - 2026-06-03

### Added
- Initial release: WPF GUI auditor/hardener for CVE-2026-49975. Listening-port
  inventory, IIS/HTTP.SYS detection, HTTP/2-disable hardening, self-heal
  scheduled task, JSON reports.
