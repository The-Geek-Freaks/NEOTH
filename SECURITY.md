# Security Policy

NEOTH stores private conversations and operator credentials. Security issues are taken seriously.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes (current development) |
| < 0.1   | No |

Once 1.0 ships, the last two minor releases will be supported.

## Reporting a Security Issue

**Do not open a public GitHub issue for security bugs.**

Send a private report via GitHub Security Advisories:
https://github.com/owner/neoth/security/advisories/new

Or email: security@neoth.dev (PGP key in repo at `keys/security.asc`).

Include:
- Affected version (`neoth --version`)
- Reproduction steps or PoC
- Impact assessment (what an attacker can do)
- Suggested fix if you have one

## Response Timeline

- **72 hours:** Acknowledgement of report
- **7 days:** Initial triage + severity rating (CVSS 3.1)
- **30 days:** Fix released for High/Critical issues
- **90 days:** Public disclosure after fix ships (coordinated)

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). Reporters get credit in the changelog unless they request anonymity.

## Scope

In scope:
- The `neothd` daemon and `neoth` CLI
- WAL format and tamper-evidence guarantees
- Skill/plugin sandbox (WASM host, capability tokens)
- Channel adapters (Telegram, WhatsApp, Slack)
- Configuration file parsing (`freedom.yaml`, `policy.yaml`)

Out of scope:
- Third-party LLM providers (report to Anthropic/Google/OpenAI directly)
- Operating system vulnerabilities (report to OS vendor)
- Issues that require pre-existing root access to the operator's machine
- Theoretical attacks without working PoC

## Hardening Defaults

NEOTH applies these at startup — no operator action required:

- `umask 0o077` before any file write
- `~/.neoth/freedom.yaml` enforced to mode `0600`
- WAL segments written with mode `0600`
- Secrets redacted from logs via regex patterns (see `policy.example.yaml`)
- No network egress before operator has consented to channel configuration

## Known Limitations

Documented in `PLAN/ADVERSARIAL/` — these are accepted risks for v0.1, not unreported issues:

- **Single-operator threat model.** No multi-tenant isolation. Anyone with read access to `~/.neoth/freedom.yaml` can impersonate the operator.
- **Plaintext secrets at rest.** Channel tokens and LLM API keys live in `~/.neoth/freedom.yaml` as plaintext, protected only by filesystem mode 0600 on Unix. Disk images, hypervisor snapshots, swap files, and hibernation images expose these secrets. Operators on shared infrastructure, laptops without full-disk encryption, or backup destinations they do not fully trust should rotate tokens regularly and treat any image of the device as compromised.
- **Phase-2 plugin sandbox not yet enforced.** WASM plugin host arrives at Day-23. Pre-Day-23, the "plugin" pathway is compiled-in only; do not load untrusted skill code before that milestone.
- **Cloud LLM exposure.** Cloud LLM providers (Anthropic, Google, OpenAI) see message content unless the operator enables local Qwen3-4B inference. Provider terms of service apply — review them.
- **Windows permission gap.** On Windows, NEOTH calls `icacls.exe` after creating WAL segments and `freedom.yaml` to explicitly grant the current user Full Control. This narrows effective access to the owner in practice, but inherited ACEs from `~/.neoth/` are NOT removed automatically (running `icacls /inheritance:r` mid-write would lock out the daemon's own threads). For full sealing, run once after `neoth init`:
  ```powershell
  icacls "$env:USERPROFILE\.neoth" /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"
  ```
  Even with that, Windows operators should enable BitLocker (or equivalent FDE) and avoid shared user accounts. Atomic `CreateFileW` with `SECURITY_ATTRIBUTES` tracked for v0.5.
- **Windows durability semantics.** `sync_data()` on Windows maps to `FlushFileBuffers`, which flushes the OS page cache but does not necessarily flush the drive's volatile write cache. On power loss, the last frame written may be lost. Linux/macOS via `fdatasync(2)` provides stronger guarantees.

## Hall of Fame

(Empty — be the first.)
