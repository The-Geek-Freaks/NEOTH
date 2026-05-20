# CLI Codemap — Operational Commands

**Last Updated:** 2026-05-15
**Entry Points:** `SRC/neothd/src/cli/hysteria.rs`, `SRC/neothd/src/cli/cluster.rs`, `SRC/neothd/src/cli/cloud.rs`

## cli/hysteria.rs

`neoth hysteria status|render-config|test`

Inspect + test the Hysteria transport config. No `start` / `stop` subcommands — the daemon
owns the lifecycle via `HysteriaSupervisor` in `neothd serve`.

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

`neoth cluster status|plan`

Operator-facing cluster routing surface. v0.1.x is single-node only; Hyperswarm transport
deferred (see `QUELLEN/research/R-A1_hyperswarm.md`).

### Subcommands

| Subcommand | What it does |
|------------|-------------|
| `status` | Always reports `mode=single-node`, `policy=local-only`, `peer_count=0`. Reads `operator_id` from `freedom.yaml`. |
| `plan --peers a:10,b:5.5 [--policy local-only|least-loaded]` | Parse synthetic peer-load table, run the selected policy's `pick_peer`, print decision. |

### Policies

| Policy | Struct | Behaviour |
|--------|--------|-----------|
| `local-only` | `LocalOnly` | Always returns `RoutingDecision::Local`. |
| `least-loaded` | `LeastLoaded` | Returns `RoutingDecision::Remote(peer)` for the healthy peer with the highest `tokens_per_sec`, falls back to `Local` when no healthy peers. |

Peer spec format for `plan`: `name:tokens_per_sec[,name:tokens_per_sec,...]`. Both `0` and
floating-point values are valid.

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
- `cluster/` — `LocalOnly`, `LeastLoaded`, `OrchestratingPolicy` trait
- `cli/cloud_sync_task.rs` — background periodic sync task spawned by `neothd serve`
- `cli/doctor.rs` — `check_hysteria_config`, `check_cloud_archive_dest`, `check_disk_space`
- `memory/archive.rs` — `default_archive_root` used by cloud sync
