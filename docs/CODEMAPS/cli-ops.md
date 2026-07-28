# CLI Codemap — Operational Commands

**Last Updated:** 2026-07-27
**Entry Points:** `SRC/neothd/src/cli/hysteria.rs`, `SRC/neothd/src/cli/cluster.rs`, `SRC/neothd/src/cli/buddy.rs`, `SRC/neothd/src/cluster/membership.rs`, `SRC/neothd/src/cli/cluster_swarm.rs`, `SRC/neothd/src/cli/cloud.rs`

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
`local-only`; enabled builds can discover candidates, enroll exact carrier
bindings through the membership authority, inspect replicated
foreign frames, restore same-origin backups, and read the live resource-snapshot
dashboard. The peeroxide/Hyperswarm path is NEOTH's own protocol, not Keet
interop.

### Subcommands

| Subcommand | What it does |
|------------|-------------|
| `status` | Reports effective cluster mode/policy plus the versioned member/binding snapshot and pending outbox count from `cluster-membership.db`; malformed authority state is an error, not a silent zero. |
| `plan --peers a:10,b:5.5 [--policy local-only|least-loaded]` | Parse synthetic peer-load table, run the selected policy's `pick_peer`, print decision. |
| `list` / `topology` | Read stable nodes, `Discovered`/`Pending`/`Active`/`Revoked` state, epochs, tombstones, and exact carrier bindings from the membership authority. |
| `discover [--timeout N] [--force]` | Browse candidate-only mDNS v2 records. The ClusterKey HMAC filters the rendezvous domain; a separate signed `EndpointAttestation` authenticates the advertised stable identity and exact Peeroxide endpoint. Neither check grants membership or mutates authority. |
| `confirm` | Legacy manual/Tailscale intake only: records the submitted transport as unattested `Pending`. The explicit `--via mdns` form is rejected because signed mDNS candidates must use authority invite/attestation confirmation. It cannot create an `Active` membership. |
| `revoke` | Revoke a stable membership through the daemon authority RPC when live, or the guarded offline authority otherwise. It closes the process-local admission gate, durably writes a `Pending` UUIDv7 request bound to the exact snapshot/digest/authority/member generation, publishes cancellation, then tears down/drains/classifies all captured external carrier effects. Uncertain remote outcomes become durable `Indeterminate`; only then are the tombstone and outbox committed. |
| `enable` / `disable` | Mutate the cluster transport configuration; neither command grants node membership. |
| `events` / `export-foreign` | Inspect or export replicated foreign frames without mixing them into local recall. |
| `restore <export> [--dry-run] [--yes]` | Restore only frames whose origin matches the local node identity; cross-origin rows are counted and skipped. |
| `swarm [--watch] [--stale-secs N]` | In `cluster` builds, read local/peer CPU, RAM, and VRAM snapshot frames from WAL. Config supplies sampling cadence and the default positive stale window. |

### Membership operations

`neoth buddy cluster status|invite|confirm|revoke`

These commands use the same daemon/offline `MembershipController` as
`neoth cluster`. `invite` creates a short-lived, carrier-bound, one-time
authority record for one stable signing identity, authenticated transport, and
endpoint. `confirm` accepts only the peer's signed `EndpointAttestation` with
the exact invitation digest and bindings; only that transition produces
`Active`. `revoke` closes admission, persists the exact-bound `Pending` UUIDv7
request, publishes cancellation, and tears down/drains/classifies captured
carrier effects before it commits the versioned tombstone plus durable
membership/audit/teardown outbox. Uncertain remote outcomes remain durable
`Indeterminate`; orphaned `Pending` recovery is `Indeterminate`, never silent
`Completed`. Its reason/source/status intent metadata are plaintext in local
SQLite (no secrets); OS file permissions are the storage boundary.

The shared passphrase-derived `ClusterKey` and its HMAC prove rendezvous-secret
possession only. Runtime authorization comes from an exact `MembershipGrant`
issued by `cluster-membership.db` for the stable `LocalNodeIdentity` and current
carrier/auth/membership epochs.

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
- `cluster/membership.rs` — stable local identity, SQLite authority, invites, signed carrier bindings, grants, tombstones, outbox, and teardown receipts
- `cluster/` — routing policies, candidate discovery/transports, foreign-event views, and swarm snapshot wire format
- `daemon/resource_snapshot_cron.rs` — local sampling and WAL emission
- `cli/cloud_sync_task.rs` — background periodic sync task spawned by `neoth serve`
- `cli/doctor.rs` — `check_hysteria_config`, `check_cloud_archive_dest`, `check_disk_space`
- `memory/archive.rs` — `default_archive_root` used by cloud sync
