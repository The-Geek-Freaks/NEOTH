# Upgrading NEOTH

NEOTH is a single self-contained daemon binary with an append-only WAL +
SQLite views DB under `~/.neoth/`. Upgrades are designed to be safe and
in-place: your memory, config, and audit log survive across versions.

> New install instead? See [install.md](install.md) /
> [getting-started.md](getting-started.md).

## TL;DR

```bash
# Built-in self-update (verifies a signed release, atomic swap + rollback):
neoth update --self --apply

# Then confirm health:
neoth doctor
```

## How the self-update works

`neoth update --self --apply` runs the audited update path:

1. **Check** the configured release channel (`freedom.yaml::auto_update.repo`,
   default the official repo) for a newer version.
2. **Download** the matching artifact for your platform + its SHA-256 companion.
3. **Verify** — the SHA-256 must match, AND (once a release-signing key is
   provisioned) a **minisign signature** is required by default. Pass
   `--allow-unsigned` only on a trusted network if no key is pinned yet.
4. **Atomic swap** — the running binary is renamed to `*.bak.<timestamp>` and
   the new binary moved into place, so a failed swap rolls back cleanly.

Unattended auto-apply is **off by default** and only ever runs at autonomy
`Elevated`/`Full` (`freedom.yaml::auto_update.auto_apply`). At lower autonomy
the daemon notifies but never self-replaces without you.

## Manual upgrade (download yourself)

1. Stop the daemon (`neoth serve` → Ctrl-C, or your service manager).
2. Replace the `neoth` binary with the new release for your platform.
3. Start the daemon. The indexer replays any WAL segments written since the
   last run; the views DB schema is migrated forward automatically.

## What survives an upgrade

- **Memory + audit log** — `~/.neoth/wal/*.wal` (append-only) and the views DB
  are version-stable; a newer binary migrates the schema forward on first start.
- **Config** — `freedom.yaml` (+ `credentials.yaml`) are read as-is. New config
  keys take their documented defaults; nothing is rewritten unless you change it.
- **Keys** — the WAL HMAC key (and, if you enabled it, the AEAD master key) stay
  put. See "Encryption keys" below.

## After upgrading: always run `neoth doctor`

`neoth doctor` validates the views DB integrity, WAL segments, key files,
provider/channel config, and surfaces any staged **self-heal proposals** (if
the daemon hit a panic, it stages a categorised, advisory fix suggestion you
can review). Fix any `FAIL` before resuming.

## Encryption keys (if you enabled AEAD-at-rest)

If you turned on WAL/config encryption, the master key lives at
`~/.neoth/wal/master.key` (DPAPI-wrapped on Windows, mode-0600 elsewhere).

- **Back it up before any OS reinstall / machine migration.** On Windows the
  key is bound to your user account — a reinstall without a backup makes
  encrypted sealed segments permanently unreadable.
  ```bash
  neoth security backup-master-key --out /path/to/offline/backup.key
  ```
- **Restore on a new machine** before starting the daemon:
  ```bash
  neoth security restore-master-key --from /path/to/offline/backup.key
  ```

## Downgrade

Downgrading is best-effort: an older binary may not understand a newer views-DB
schema. Keep the `*.bak.<timestamp>` the self-updater left, or restore the
binary you upgraded from, and run `neoth doctor`. The WAL itself is
forward-and-backward readable (legacy plaintext + newer segment formats both
parse).
