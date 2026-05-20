# Transport Codemap — Hysteria Egress Proxy

**Last Updated:** 2026-05-15
**Entry Points:** `SRC/neothd/src/transport/hysteria.rs`

## Architecture

```
freedom.yaml::hysteria { server, auth, local_socks_port }
  |
  | neothd serve startup (before provider construction)
  |
  | HysteriaSupervisor::spawn(config)
  |   locate_binary()        → $NEOTH_HYSTERIA_BIN | PATH | ~/.neoth/bin/hysteria[.exe]
  |   render_yaml_config()   → sanitize server + auth (control-char injection guard)
  |   write ~/.neoth/hysteria/config.yaml
  |   std::process::Command("hysteria client --config <path>")
  |   → HysteriaSupervisor { child, socks_port, config_path }
  |
  | std::env::set_var("NEOTH_HTTP_PROXY", "socks5://127.0.0.1:<socks_port>")
  |
  | providers constructed (pick up proxy from env)
  |
  | Drop(HysteriaSupervisor):
  |   child.kill() + child.wait()
  |   fs::remove_file(config_path)   — secrets don't linger on disk
```

## Key Exports

| Item | Type | Purpose |
|------|------|---------|
| `HysteriaConfig` | struct | `server: String`, `auth: String`, `local_socks_port: u16` (default 1080) |
| `HysteriaSupervisor` | struct | Subprocess wrapper; Drop kills + cleans up |
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

Three fields only. Operators who need obfuscation / multipath / TLS SNI edit
`freedom.yaml::hysteria` with extra keys and pass them through as-is (the struct
`Deserialize` is permissive for unknown fields — TODO: verify this with the actual
freedom.yaml deserialization code).

## CLI surface

`neoth hysteria status|render-config|test` — see `cli-ops.md` for full detail.

`neoth doctor` includes a `hysteria` check: PASS when unconfigured (Hysteria is optional);
WARN when configured but binary not found; PASS when configured + binary found.

## Phase 3b follow-up

Wire reqwest provider clients through `NEOTH_HTTP_PROXY`. v0.1.x sets the env var but
existing provider constructors do not read it; they use the default reqwest client.

## Related Areas

- `cli/hysteria.rs` — operator-facing status + test commands
- `cli/doctor.rs` — `check_hysteria_config` health check
- `config/freedom_config.rs` — `FreedomConfig::hysteria: Option<HysteriaConfig>`
- `daemon/serve.rs` — spawns `HysteriaSupervisor` before provider construction
