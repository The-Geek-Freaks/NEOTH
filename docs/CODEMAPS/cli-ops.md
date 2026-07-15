# CLI Codemap — Operational Commands

**Last Updated:** 2026-07-14
**Entry Points:** `SRC/neothd/src/cli/hysteria.rs`, `SRC/neothd/src/cli/cluster.rs`, `SRC/neothd/src/cli/cluster_swarm.rs`, `SRC/neothd/src/cli/cloud.rs`

## cli/hysteria.rs

`neoth hysteria status|render-config|test`

Inspect + test the Hysteria transport config. No `start` / `stop` subcommands — the daemon
owns the lifecycle via `HysteriaSupervisor` in `neoth serve`.

### Subcommands

| Subcommand | What it does |
|------------|-------------|
| `status` | Print `configured` bool, binary location, server endpoint, local_socks_port. |
| `render-config` | Render `freedom.yaml::hysteria` as the YAML the subprocess would receive. Auth value is redacted (`auth: <redacted>`). Pure preview — no spawn. |
| `test` | TCP-probe `127.0.0.1:<local_socks_port>` within `HEALTH_TIMEOUT` (2 s). Exits non-zero if unreachable. |

### Config source

Reads `FreedomConfig::load_from_default_path()`. Missing config is not an error for `status`
(reports "not configured"). Missing config IS an error for `test` (no port to probe).

### Auth redaction

`redact_auth_line(yaml, auth)` replaces `auth: <literal-value>` with `auth: <redacted>` in
terminal output. Acts only on the exact value supplied; substring collisions elsewhere in the
YAML are not over-redacted.

## cli/cluster.rs

`neoth cluster status|events|export-foreign|plan|list|topology|discover|swarm|confirm|revoke|enable|disable|restore`

Operator-facing surface for the authenticated cluster implementation. A disabled
cluster or one with no active peer transport still resolves honestly to
`local-only`; enabled builds can discover and confirm peers, inspect replicated
foreign frames, restore same-origin backups, and read the live resource-snapshot
dashboard. The peeroxide/Hyperswarm path is NEOTH's own protocol, not Keet
interop.

### Subcommands

| Subcommand | What it does |
|------------|-------------|
| `status` | Reports effective cluster mode/policy and the actual confirmed-peer count from `cluster.yaml`; malformed registry state is an error, not a silent zero. |
| `plan --peers a:10,b:5.5 [--policy local-only|least-loaded]` | Parse synthetic peer-load table, run the selected policy's `pick_peer`, print decision. |
| `list` / `topology` | List confirmed peers, last-seen state, persisted heartbeat RTT, and stability. |
| `discover [--timeout N] [--force]` | Browse authenticated mDNS announcements without mutating the peer registry. The policy gate can refuse discovery unless the operator explicitly forces this one scan. |
| `confirm` / `revoke` / `enable` / `disable` | Atomically maintain the confirmed-peer registry and the mDNS policy switch. |
| `events` / `export-foreign` | Inspect or export replicated foreign frames without mixing them into local recall. |
| `restore <export> [--dry-run] [--yes]` | Restore only frames whose origin matches the local node identity; cross-origin rows are counted and skipped. |
| `swarm [--watch] [--stale-secs N]` | In `cluster` builds, read local/peer CPU, RAM, and VRAM snapshot frames from WAL. Config supplies sampling cadence and the default positive stale window. |

### Policies

| Policy | Struct | Behaviour |
|--------|--------|-----------|
| `local-only` | `LocalOnly` | Always returns `RoutingDecision::Local`. |
| `least-loaded` | `LeastLoaded` | Returns `RoutingDecision::Remote(peer)` for the healthy peer with the highest `tokens_per_sec`, falls back to `Local` when no healthy peers. |

Peer spec format for `plan`: `name:tokens_per_sec[,name:tokens_per_sec,...]`.
Both `0` and floating-point values are valid. This is a deterministic policy
preview; it does not create a peer session.

### Swarm data flow

`resource_snapshot_cron` emits `EXTENDED/LocalSnapshot` and authenticated peer
gossip contributes `EXTENDED/SwarmResourceSnapshot`. `cluster_swarm` scans the
relevant WAL window, keeps the newest record per node, and prunes snapshots
older than the effective `stale_after_secs`. `--watch` reruns that read every
five seconds; it does not change daemon sampling.

### Imports

`crate::cluster::{LeastLoaded, LocalOnly, OrchestratingPolicy, PeerLoad, RoutingDecision}`

## cli/cloud.rs

`neoth cloud status|sync`

Operate the local-folder cloud archive mirror. NEOTH mirrors `~/.neoth/archive/sessions/`
into `<cloud_archive_dest>/<cloud_archive_subdir>/` using the operator's existing desktop
sync client.

### Subcommands

| Subcommand | What it does |
|------------|-------------|
| `status` | Print `destination`, `subdir`, `auto_sync_interval_secs`, archive root existence, dest existence. |
| `sync [--dest PATH] [--subdir NAME] [--dry-run]` | Run one mirror pass. `--dry-run` lists files that would be copied without writing. Idempotent: skip-unchanged strategy. |

### freedom.yaml fields read

| Field | Default | Meaning |
|-------|---------|---------|
| `cloud_archive_dest` | — | Path to cloud client's local sync folder (e.g. `~/Dropbox`). Required for sync. |
| `cloud_archive_subdir` | `"NEOTH"` | Subdirectory name inside the sync folder. |
| `cloud_archive_auto_sync_secs` | `3600` | Background sync interval (used by `cloud_sync_task`). |

### Sync implementation

Delegates to `cli::obsidian::sync_archive(archive_root, dest, subdir, dry_run)`. Returns
`{ considered, copied }` stats. NEOTH does not call any cloud vendor API; it only writes to
the local filesystem inside the desktop client's sync folder.

## Related Areas

- `transport/hysteria.rs` — `locate_binary`, `render_yaml_config`, `probe_socks_port`
- `cluster/` — routing policies, authenticated discovery/transports, foreign-event views, and swarm snapshot wire format
- `daemon/resource_snapshot_cron.rs` — local sampling and WAL emission
- `cli/cloud_sync_task.rs` — background periodic sync task spawned by `neoth serve`
- `cli/doctor.rs` — `check_hysteria_config`, `check_cloud_archive_dest`, `check_disk_space`
- `memory/archive.rs` — `default_archive_root` used by cloud sync
