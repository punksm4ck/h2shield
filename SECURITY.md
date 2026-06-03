# Security Policy

## Scope

This policy covers security issues **in H2Shield itself** — for example, a flaw
in the tool that could damage a host, leak data, or cause unintended privileged
behavior. For the underlying HTTP/2 Bomb vulnerability (CVE-2026-49975), refer
to the upstream server vendors (Microsoft, nginx, Apache, Envoy, Cloudflare).

## Reporting a vulnerability

Please report security issues privately using GitHub's **Security Advisories**
feature on this repository (Security → Advisories → Report a vulnerability)
rather than opening a public issue.

Include:
- A description of the issue and its impact.
- Steps to reproduce.
- The affected version (see the script header / window title).
- Your environment (Windows version, PowerShell version, IIS state).

## What to expect

This is a personal/hobby project maintained by one person, so response times
are best-effort. Confirmed issues will be fixed and credited in the changelog
unless you prefer otherwise.

## Out of scope

- The HTTP/2 Bomb vulnerability itself (report to the server vendor).
- Issues that require already having Administrator on the host (the tool
  requires admin by design).
- Social-engineering or physical-access scenarios.
