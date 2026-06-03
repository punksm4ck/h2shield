# Contributing to H2Shield

Thanks for your interest. H2Shield is a small, focused defensive tool, and
contributions that keep it focused and honest are very welcome.

## Ground rules

- **Defensive only.** No exploit code, proof-of-concept attack payloads, or
  offensive tooling. H2Shield mitigates; it does not attack.
- **Scope honesty.** Don't add features that claim to defend against things
  they can't. If a change implies protection, it must actually provide it.
- **No secrets in commits.** Never commit API keys, credentials, tokens,
  internal hostnames, or IPs. See `.gitignore`.

## Development setup

- PowerShell 7+ on Windows (the GUI uses WPF, which requires Windows).
- Test in a VM or a non-critical box. The tool writes to `HKLM` and can restart
  services.

## Before opening a PR

1. **Parse-check the script:**
   ```powershell
   $null = [System.Management.Automation.Language.Parser]::ParseFile(
     "$PWD\AEGIS_H2Shield.ps1", [ref]$null, [ref]$errors)
   $errors   # should be empty
   ```
2. **Test the three core flows** on a box with IIS and one without:
   - Run Audit (no mutation)
   - Audit + Harden (verify state-aware behavior in both running and
     stopped/disabled IIS states)
   - Verify
3. **Bump the version** in the script header and add a `CHANGELOG.md` entry.
4. Keep the single-file design unless there's a strong reason to split it — the
   copy-paste-into-a-terminal workflow is a core feature.

## Style

- PowerShell 7 idioms; `pwsh`, not Windows PowerShell 5.1.
- Avoid the `-f` format operator on strings that may contain runtime content
  with `{`/`}` — use concatenation. (This caused a real crash; see CHANGELOG
  1.0.3.)
- Comment the *why*, not just the *what*, especially for any service or
  registry manipulation.

## Reporting bugs

Open an issue with: Windows version, `pwsh --version`, whether IIS is present
and its service state, and the relevant lines from
`C:\AEGIS_Source\H2Shield\logs\h2shield.log`. Redact any sensitive hostnames or
IPs from audit output before pasting.

## Security issues

For vulnerabilities in H2Shield itself, use a private security advisory — see
[SECURITY.md](SECURITY.md). Don't file them as public issues.
