# Upgrading NEOTH

The `neoth` core is self-contained; desktop release archives also ship the
`neothd` compatibility launcher, `neothd-gui`, `neoth-migrate`, and
`neoth-relay`, plus the self-contained `neoth-keet-bridge` and a release-bound
Graphify self-knowledge snapshot. State lives under
`~/.neoth/`. Upgrades are designed to be safe and in-place: your memory, config,
and audit log survive across versions.

> New install instead? See [install.md](install.md) /
> [getting-started.md](getting-started.md).

## TL;DR

```bash
# Built-in self-update (portable installs; signed bundle + crash recovery):
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
4. **Closed extraction and bundle preflight** — the authenticated archive must
   have one exact version-and-target-bound root. Traversal, links, hardlinks,
   reparse points, special files, duplicate/case-colliding names, excessive
   depth/count, and oversized members are rejected in a private staging
   directory. The complete binary, support/legal/example, and release-bound
   `self-knowledge/` set must match the compiled platform profile exactly.
5. **Journaled replace** — every package-owned portable member is applied by
   one native transaction; `neoth` is the final commit point. An existing public
   entrypoint is copied to a verified backup and then atomically replaced, so
   its pathname never disappears in a crash window. The result reports a
   durable transaction ID. If the process or machine stops mid-commit, the next
   normal `neoth` or `neothd` start validates and recovers the executable-bound
   journal before command dispatch; a later installer run does the same.
   Portable support/legal/example files and the snapshot are isolated below
   `neoth-support/`, rather than claiming generic names in a shared binary root.
   User config, credentials, WAL, memory, and Wiki/User Overlays are outside the
   transaction and are never replaced.

   On Windows portable installs, the running CLI cannot replace itself. It
   launches the verified `neoth.exe` from the target bundle, requests a graceful
   daemon drain, and exits. That helper waits for the old PID, re-verifies the
   archive and signature, stops/restarts the Task Scheduler supervisor when
   configured, commits the same transaction, writes a durable result receipt,
   and only then emits `SELF_UPDATE_APPLIED`. The CLI reports
   `handoff_scheduled` until that real commit exists; unsigned recovery builds
   cannot use the detached path. Portable Windows staging, handoff and cleanup
   deliberately refuse an elevated process token before touching their private
   staging namespace. Use the signed Windows Setup package for an administrator
   or machine-wide installation/update.

The member transaction intentionally refuses native Linux DEB/RPM installs and
signed `NEOTH.app` installs. Updating those files behind dpkg/rpm would corrupt
the package database, and changing files inside an app bundle would invalidate
Apple's outer code signature. The built-in updater currently reports that
typed boundary and stops. Automatic selection and execution of the exact signed
Windows Setup, macOS PKG/App replacement, and Linux DEB/RPM through the native
package manager are still open v1.0 release work; use the authenticated native
installer manually until those handoffs are wired and clean-machine tested.

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
- **Self-knowledge overlays** — the immutable release baseline is upgraded, but
  the materialized NEOTH Wiki and its `User Overlays` are operator state under
  `NEOTH_HOME`; installers, package uninstall, and self-update never replace or
  remove them.

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
schema. Install a complete older signed bundle through the same platform
installer path, then run `neoth doctor`; do not mix individual files from two
releases. The WAL itself is forward-and-backward readable (legacy plaintext +
newer segment formats both parse).
