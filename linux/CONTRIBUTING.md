# Contributing

## Scope

H2Shield is a **defensive** tool. Contributions must stay within that scope:

- Surface scanning and classification improvements
- Additional web server detections (Envoy, Pingora, Caddy, etc.)
- Config patching correctness and edge-case handling
- Headless/CI improvements
- Documentation and accuracy fixes

**Not in scope:** anything that adds offensive capability, fabricates metrics, or makes claims the code doesn't back up.

## Before submitting a PR

1. `python3 -m py_compile h2shield_linux.py` — must pass
2. Test the audit path on a real box (or a VM with nginx/Apache installed)
3. If you add a new hardening action: include the corresponding backup + dry-run + diff path
4. Update CHANGELOG.md

## Accuracy standard

If you find that something this tool claims is wrong — a CVE number, a version threshold, a patch status — open an issue immediately. Shipping inaccurate security information is worse than shipping nothing.
