# S10 — GitHub PAT Revocation Action Required

> **Reference document (operator action).** Procedure executed during pre-1.0
> setup of the original deployment. Kept for future operators who may need to
> handle a similar credential leak. Not part of the normal install flow.

> Status: STANDING since v0.5 (2026-05-12). NOT yet revoked. **Pre-Day-1-block.**
> Severity: Medium / Exploitability 5 (precondition already met — token in plaintext in publicly-readable git config on Jarvis VM).

## The Token

**`ghp_REDACTED-REVOKE-THIS-TOKEN`** (full token, currently in)

Location:
```
tgf@192.168.178.117  →  ~/.openclaw-git-mirror/.git/config
                        (git remote origin URL)
```

Discovered during initial Jarvis recon (RECON/01_QUELLEN_ANALYSE.md). Token is embedded in the `https://<token>@github.com/...` clone URL.

## Why It Matters

- File permissions on `.git/config`: typically `0644` (world-readable on shared system)
- Any user-mode process on the VM can `cat ~/.openclaw-git-mirror/.git/config` and exfiltrate
- Token grants push access to `TheGeekFreaks/openclaw-backup` GitHub repo
- Token has been in plaintext for months. Probability of compromise: unknown but non-zero.

## Required Actions (operator must do)

### 1. Revoke the token on GitHub

```
https://github.com/settings/tokens
→ Find the token starting with "ghp_REDACTED-REVOKE-THIS-TOKEN"
→ Click "Delete"
→ Confirm
```

Time: 30 seconds.

### 2. Rotate to a new credential

Replace with one of:

**(a) SSH key (recommended)**:
```bash
ssh -T git@github.com
# If first time:
ssh-keygen -t ed25519 -C "tgf@192.168.178.117"
# Add ~/.ssh/id_ed25519.pub to GitHub → Settings → SSH and GPG keys
cd ~/.openclaw-git-mirror
git remote set-url origin git@github.com:TheGeekFreaks/openclaw-backup.git
```

**(b) Fine-grained PAT (if SSH not feasible)**:
- GitHub → Settings → Personal Access Tokens → Fine-grained
- Scope: only `TheGeekFreaks/openclaw-backup` repo
- Permissions: only `Contents: read+write` (no admin)
- Save to `~/.git-credentials` with `chmod 0600`
- Update remote: `git remote set-url origin https://NewToken@github.com/...`

**(c) GitHub App / Deploy Key (for production)**:
- Better long-term option for an automated mirror

### 3. Audit recent activity

Check if the token was misused:
```
https://github.com/settings/security-log
→ Filter by token (search for the ghp_REDACTED-REVOKE-THIS-TOKEN prefix)
→ Review IP addresses and actions
```

If activity is suspicious: 
- Force-push a clean commit to the backup repo (or delete & recreate)
- Check for unauthorized branches / commits

### 4. Audit other places the token might be cached

Grep for the token prefix in any other location:

```bash
# On Jarvis VM
grep -r "ghp_REDACTED-REVOKE-THIS-TOKEN" ~/ 2>/dev/null
grep -r "ghp_REDACTED-REVOKE-THIS-TOKEN" /tmp /var/log 2>/dev/null

# On local Windows
# (in cmd or PowerShell)
findstr /S /C:"ghp_REDACTED-REVOKE-THIS-TOKEN" "%USERPROFILE%\*"
```

### 5. Prevent recurrence

Add to NEOTH `~/.neoth/policy.yaml`:
```yaml
git:
  remote_urls:
    forbid_inline_tokens: true   # reject any `https://<token>@...` remote URL
  startup_audit:
    scan_paths: [~, ~/.git, /tmp]
    patterns:
      - 'ghp_[A-Za-z0-9]{36}'
      - 'github_pat_[A-Za-z0-9_]{82}'
      - 'gho_[A-Za-z0-9]{36}'
      - 'glpat-[A-Za-z0-9\-_]{20}'
      - 'sk-[A-Za-z0-9]{48,}'        # OpenAI / Anthropic
      - 'AKIA[0-9A-Z]{16}'           # AWS
    on_find: alert_operator
```

Daemon startup scans these patterns and refuses to start (or alerts loudly) if found in operator's home or common config dirs.

## Status After Action

Once revoked + rotated:
1. Add entry to `~/.neoth/audit.log`: `[2026-05-14 HH:MM] PAT ghp_REDACTED-REVOKE-THIS-TOKEN REVOKED — rotated to <SSH key fingerprint OR new PAT prefix>`
2. Delete this file or move to `archive/`.

## Day-1 Gate

NEOTH `cargo new neothd` should NOT proceed until:
- [ ] Old PAT revoked (verify in GitHub Settings)
- [ ] New credential active (verify with `git fetch` from a clean checkout)
- [ ] Recurrence prevention policy added to NEOTH `policy.yaml`

Time to fix: 5 minutes for revocation+rotation, +5 minutes for policy.yaml addition.
