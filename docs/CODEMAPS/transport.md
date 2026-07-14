# Transport Codemap — Hysteria Egress Proxy

**Last Updated:** 2026-07-14
**Entry Points:** `SRC/neothd/src/transport/hysteria.rs`

## Architecture

```
freedom.yaml::hysteria { server, auth, local_socks_port }
  |
  | neoth serve startup (before provider construction)
  |
  | HysteriaSupervisor::spawn(config)
  |   locate_binary()        → $NEOTH_HYSTERIA_BIN | PATH | ~/.neoth/bin/hysteria[.exe]
  |   render_yaml_config()   → sanitize server + auth (control-char injection guard)
  |   write ~/.neoth/hysteria/config.yaml
  |   std::process::Command("hysteria client --config <path>")
  |   → HysteriaSupervisor { child, socks_port, config_path }
  |
  | HysteriaSupervisor::install_as_process_proxy()
  |   → providers::http_client::set_process_proxy("socks5://127.0.0.1:<port>")
  |
  | providers constructed through providers::http_client::build_client()
  |   → process proxy first, NEOTH_HTTP_PROXY environment fallback second
  |
  | HysteriaSupervisor::start_watchdog()
  |   → child poll every 5 s; respawn with 1–60 s exponential backoff
  |
  | Drop(HysteriaSupervisor):
  |   child.kill() + child.wait()
  |   fs::remove_file(config_path)   — secrets don't linger on disk
```

## Key Exports

| Item | Type | Purpose |
|------|------|---------|
| `HysteriaConfig` | struct | `server: String`, `auth: String`, `local_socks_port: u16` (default 1080) |
| `HysteriaSupervisor` | struct | Subprocess + watchdog owner; Drop aborts watchdog, kills/reaps child, and removes config |
| `HysteriaSupervisor::spawn(config)` | `Result<Self>` | Write config + fork subprocess |
| `locate_binary()` | `Result<PathBuf>` | Search order: env → PATH → ~/.neoth/bin/ |
| `render_yaml_config(cfg)` | `String` | Pure function; rejects control chars in server/auth |
| `probe_socks_port(port)` | `async Result<()>` | TCP-connect to 127.0.0.1:port within 2 s |
| `HEALTH_TIMEOUT` | `Duration` | 2 seconds |

## YAML injection guard

`render_yaml_config` inspects `server` and `auth` for newline (`\n`), carriage return
(`\r`), or any control character. On detection the value is replaced with the sentinel
`"<<rejected: contains control characters>>"` rather than sanitized, so Hysteria itself
will reject the config and the operator sees a clear failure. The guard prevents
YAML-injection attacks (e.g. appending `\nsocks5:\n  listen: 0.0.0.0:1080` to bind the
proxy to all interfaces).

## Binary lookup order

1. `$NEOTH_HYSTERIA_BIN` env var (must point to an existing file)
2. `hysteria` / `hysteria.exe` on `$PATH`
3. `~/.neoth/bin/hysteria[.exe]`

Missing binary → `anyhow::bail!` with an actionable message citing all three search paths
and the GitHub releases URL.

## Rendered YAML shape

```yaml
server: <server>
auth: <auth>
socks5:
  listen: 127.0.0.1:<local_socks_port>
```

Three fields only. `HysteriaConfig` deliberately has no
`serde(deny_unknown_fields)`, and the source test
`hysteria_config_tolerates_unknown_fields` proves extra keys do not make
`freedom.yaml` fail to load. They are ignored, however: `render_yaml_config`
emits only `server`, `auth`, and the loopback SOCKS5 listener. Extra Hysteria
options are therefore not a pass-through surface and must not be documented as
one.

## CLI surface

`neoth hysteria status|render-config|test` — see `cli-ops.md` for full detail.

`neoth doctor` includes a `hysteria` check: PASS when unconfigured (Hysteria is optional);
WARN when configured but binary not found; PASS when configured + binary found.

## Provider wiring

Phase 3b is shipped. `neoth serve` starts and probes Hysteria before provider
construction, installs the local SOCKS5 URL in the shared process-proxy slot,
and then constructs provider clients through `providers::http_client`. An
operator-set `NEOTH_HTTP_PROXY` remains a fallback for one-shot commands.

The health probe proves only that the local TCP listener accepted a connection;
it does not perform a SOCKS5 handshake or prove remote QUIC egress. In Strict
autonomy, a configured Hysteria spawn/probe failure aborts daemon startup. Other
autonomy modes warn and may continue with direct egress.

## Related Areas

- `cli/hysteria.rs` — operator-facing status + test commands
- `cli/doctor.rs` — `check_hysteria_config` health check
- `config/mod.rs` — `FreedomConfig::hysteria: Option<HysteriaConfig>`
- `cli/serve.rs` — starts, probes, wires, and owns `HysteriaSupervisor`
- `providers/http_client.rs` — shared process/environment proxy-aware reqwest builder
