# Vault mirror

The vault mirror is an optional, dedicated Git mirror of a NEOTH backup
archive. It never opens an operator vault directory or an arbitrary existing
repository as its worktree. The archive includes WAL data and excludes
`credentials.yaml`.

It is off by default. Enable it only with an accepted `freedom.yaml` block:

```yaml
vault_mirror:
  enabled: true
  allow_nightly_push: false
  allow_manual_push: true
  remote_url: "ssh://git@git.example.invalid/operator/neoth-vault.git"
  branch: "neoth-vault"
  interval_secs: 86400
  retain_verified_runs: 14
  allow_managed_retention: false
```

`enabled` permits the feature. `allow_nightly_push` separately permits the
daemon cadence. `allow_manual_push` separately permits `--push`. A
manual-only configuration must keep `allow_nightly_push: false`.

Remote configuration contains no token, password, private key, askpass
program, or credential-manager setting. HTTPS uses the operator's existing
Git Credential Manager setup. SSH uses the existing SSH agent and host setup.
Git terminal prompting and askpass prompting are disabled for mirror children.

Use the following commands:

```text
neoth backup mirror status --output json
neoth backup mirror run --output json
neoth backup mirror run --push --output json
neoth backup mirror repair --output json
```

`status` is read-only and starts no Git process. `run` without `--push` writes
a durable `prepared` archive receipt but starts no local Git process and makes
no network call. `run --push` requires both `enabled` and
`allow_manual_push`. `repair` reconciles only an unresolved receipt against
its exact remote branch head; an unknown push outcome is never automatically
replayed. A later deliberate run may replace a prior `prepared` receipt.

The run lock is a kernel-exclusive persistent-inode lock. The operating system
releases it when its owning process crashes; it is not a stale-file guard that
requires automatic deletion.

Managed retention remains off unless `allow_managed_retention: true`. When
enabled, it removes only receipt-backed mirror run manifests through a normal
Git commit. It does not delete remote refs or Git history objects.

This document describes the W184 implementation surface. W184 is not admitted
or release proof; hosted acceptance remains required.
