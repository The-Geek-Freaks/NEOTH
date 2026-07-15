# Upgrading NEOTH

The `neoth` core is self-contained; desktop release archives also ship the
`neothd` compatibility launcher, `neothd-gui`, `neoth-migrate`, and
`neoth-relay`, plus the self-contained `neoth-keet-bridge`. State lives under
`~/.neoth/`. Upgrades are designed to be safe and in-place: your memory, config,
and audit log survive across versions.

> New install instead? See [install.md](install.md) /
> [getting-started.md](getting-started.md).

## TL;DR

```bash
# Built-in self-update (verifies one signed release bundle + rollback):
neoth update --self --apply

# Then confirm health:
neoth doctor
```

## How the self-update works

`neoth update --self --apply` runs the audited update path:

1. **Check** the configured feed and ring
   (`freedom.yaml::auto_update.{repo,channel}`) for a newer SemVer release.
   `stable` accepts final tags, `rc` adds RC tags, and `nightly` adds
   nightly-tagged releases; alpha/beta and malformed tags fail closed.
2. **Download** the matching platform archive plus its SHA-256 and signature
   companions. Response and extraction sizes are bounded.
3. **Verify** — the SHA-256 must match, AND a **minisign signature** is required
   by default. Official releases pin the key at build time and publish the
   signature companion. Pass `--allow-unsigned` only as an explicit recovery
   action for a trusted non-release build.
4. **Bundle preflight** — every companion currently installed beside `neoth`
   must exist in the same verified archive before any executable is touched.
   This includes `neoth-keet-bridge`; source-only core installations remain
   core-only.
5. **Transactional replace** — companions are backed up and replaced first;
   `neoth` is the commit point and moves last. A partial failure restores prior
   executables in reverse order. Backups use `*.bak.<timestamp>` names.

Background self-update is **off by default**. When `auto_update.enabled` is on,
the daemon checks at `check_interval_secs`; setting that interval to `0`
disables the task. `auto_apply: true` at `Elevated`/`Full` permits only verified
**staging** plus notification. The daemon never replaces its own executable:
the commit step remains `neoth update --self --apply`. Manual check/apply uses
the same repo, release ring, and optional validated `target_triple`; changing
any of them invalidates a previously staged artifact and forces a fresh fetch.

## Manual upgrade (download yourself)

1. Stop the daemon (`neoth serve` → Ctrl-C, or your service manager) and any
   running `neoth-keet-bridge` process so every executable can be replaced.
2. Prefer the current binary installer, which verifies and replaces the whole
   installed bundle. If replacing manually, update `neoth` and every installed
   companion from the **same** platform archive; never mix release versions.
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
schema. Keep the `*.bak.<timestamp>` files the self-updater left, or restore the
complete prior binary bundle, and run `neoth doctor`. The WAL itself is
forward-and-backward readable (legacy plaintext + newer segment formats both
parse).
