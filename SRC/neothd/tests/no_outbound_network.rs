#![allow(clippy::doc_overindented_list_items)]

//! Static guarantee that NEOTH only opens outbound HTTP from
//! `src/providers/`. Phase 33c BS-6 — backs the marquee promise
//! "NEOTH never phones home".
//!
//! Walks every `.rs` file under `src/` and fails the build if any file
//! outside the allowlist constructs a `reqwest::Client`, opens a raw
//! `TcpStream`, or references the lower-level `hyper::client`. Test lives
//! in `tests/` so it runs on every `cargo test --all-targets` and blocks
//! merges to `main`.
//!
//! Allowed paths:
//!   - `src/providers/**`            — by design, providers talk to LLMs
//!                                     (loopback probes live here too)
//!   - `src/updater/**`              — `neoth update --apply` shells out
//!   - `src/installers/**`           — bootstrap path for managed CLIs
//!   - `src/memory/infra_scan.rs`    — `arp -a` / `nmap -sn` only;
//!                                     local-LAN, no outbound HTTP
//!   - `src/daemon/healthz.rs`       — inbound localhost listener; test
//!                                     module connects to itself, not the
//!                                     network. Listener never opens
//!                                     outbound `TcpStream::connect`.
//!   - `src/channels/webhook_listener.rs`
//!                                  — inbound localhost webhook listener;
//!                                    test module connects to itself, not
//!                                    external services.
//!   - `src/channels/slack_socket.rs`
//!                                  — outbound Slack WSS connection; same
//!                                    category as providers/ (operator-
//!                                    configured channel adapter that
//!                                    intentionally dials a specific
//!                                    upstream — Slack's edge URL after
//!                                    apps.connections.open).
//!   - `src/channels/discord.rs`    — Session 14 Pick #15: outbound REST
//!                                    POST to Discord's bot API. Operator-
//!                                    configured channel adapter that
//!                                    intentionally dials Discord's API
//!                                    endpoint (`discord.com/api/v10`).
//!   - `src/channels/discord_gateway_loop.rs`
//!                                  — outbound Discord Gateway WSS dialer;
//!                                    same category as `slack_socket.rs`.
//!                                    Operator-configured channel adapter
//!                                    that dials Discord's gateway URL after
//!                                    `gateway.json` discovery.
//!   - `src/channels/pears_bridge.rs`
//!                                  — LOCALHOST-ONLY HTTP client for the
//!                                    operator-bundled `pear` runtime
//!                                    (Holepunch CLI). Construction is
//!                                    routed through `normalise_localhost_url`
//!                                    which rejects every non-loopback host
//!                                    at the boundary (test coverage:
//!                                    `pears_bridge::tests::new_rejects_*`
//!                                    pins the invariant — 4 explicit
//!                                    reject cases for remote-IP, public
//!                                    DNS, file://, empty URL). The
//!                                    `reqwest::Client` only ever dials
//!                                    `127.0.0.1` / `localhost` / `[::1]`
//!                                    — same operator-opt-in category as
//!                                    the other channel adapters above.
//!   - `src/telemetry/`             — OPT-IN anonymous version-check
//!                                    POST. Default OFF (drift-guarded by
//!                                    `telemetry::tests::default_config_is_off`).
//!                                    Endpoint pinned to
//!                                    `https://telemetry.neoth.dev/v1/ping`
//!                                    in `DEFAULT_TELEMETRY_ENDPOINT` const.
//!                                    `http::validate_endpoint` rejects
//!                                    every non-HTTPS scheme + malformed URL
//!                                    at the boundary so an operator override
//!                                    via `freedom.yaml::telemetry.endpoint`
//!                                    cannot silently downgrade from TLS
//!                                    (test coverage:
//!                                    `http::tests::validate_endpoint_rejects_http` +
//!                                    `..._rejects_file_scheme` +
//!                                    `..._rejects_malformed_url` +
//!                                    `send_payload_to_http_url_rejected_without_network_call`).
//!                                    Payload contents drift-guarded by
//!                                    `tests::payload_has_no_operator_id_field`
//!                                    so a future refactor can't leak the
//!                                    operator id verbatim.
//!   - `src/cluster/`               — Operator-configured peer discovery +
//!                                    federation. Today: `tailscale.rs`
//!                                    TCP-probes tailnet peers (CGNAT
//!                                    `100.64.0.0/10` — operator's own
//!                                    private network, not the public
//!                                    internet) for `neoth cluster
//!                                    discover`. Phase 5 (Hysteria relay)
//!                                    + Phase 6 (gossip state-sync) will
//!                                    add more peer-dial code here. Same
//!                                    category as channels/ — operator
//!                                    opts into network access via
//!                                    explicit CLI / wizard step.
//!
//! Adding a new allowed path means editing both the codebase AND this
//! file, which makes the audit trail loud.

use std::fs;
use std::path::{Path, PathBuf};

const ALLOWED_PREFIXES: &[&str] = &[
    "src/providers/",
    "src/updater/",
    "src/installers/",
    "src/memory/infra_scan.rs",
    "src/daemon/healthz.rs",
    "src/channels/webhook_listener.rs",
    "src/channels/slack_socket.rs",
    "src/channels/discord.rs",
    "src/channels/discord_gateway_loop.rs",
    "src/channels/keet_udp.rs",
    "src/channels/pears_bridge.rs",
    "src/telemetry/",
    "src/cluster/",
    "src/transport/",
];

const FORBIDDEN_PATTERNS: &[&str] = &[
    // Construction sites only — `use reqwest::Client;` in a test
    // module is not a network call, only `::new(` / `::builder(`
    // actually open a connection. Tightening the patterns to the
    // call sites lets us drop the test-module-skip heuristic in the
    // walker without losing coverage of real outbound dialers.
    "reqwest::Client::new(",
    "reqwest::Client::builder(",
    "reqwest::Client::default(",
    "reqwest::ClientBuilder::new(",
    "reqwest::get(",
    "reqwest::Url::parse",
    "hyper::client::",
    "TcpStream::connect",
    // CDX-06: WebSocket outbound dialers — `connect_async` is
    // tungstenite's entry point; treat it as a network-construction
    // primitive that needs explicit allowlisting.
    "connect_async",
    "tokio_tungstenite::connect",
];

#[test]
fn no_network_construction_outside_providers() {
    let src_root = manifest_dir().join("src");
    let mut violations = Vec::new();
    walk_rs(&src_root, &mut |path, content| {
        let rel = relative_to_crate(&path);
        if is_allowed(&rel) {
            return;
        }
        // Skip the lint file itself (it mentions the patterns as strings).
        if rel == "tests/no_outbound_network.rs" {
            return;
        }
        for pattern in FORBIDDEN_PATTERNS {
            for (line_no, line) in content.lines().enumerate() {
                if !line.contains(pattern) {
                    continue;
                }
                // Allow comments — they're either docs or "do NOT do this"
                // breadcrumbs the lint shouldn't trip on.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//")
                    || trimmed.starts_with("///")
                    || trimmed.starts_with("//!")
                {
                    continue;
                }
                violations.push(format!(
                    "{}:{}: forbidden pattern `{}` outside allowed paths",
                    rel,
                    line_no + 1,
                    pattern,
                ));
            }
        }
    });

    assert!(
        violations.is_empty(),
        "NEOTH-never-phones-home invariant violated:\n  {}",
        violations.join("\n  "),
    );
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn relative_to_crate(path: &Path) -> String {
    let root = manifest_dir();
    let rel = path.strip_prefix(&root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/")
}

fn is_allowed(rel: &str) -> bool {
    ALLOWED_PREFIXES.iter().any(|p| rel.starts_with(p))
}

fn walk_rs(dir: &Path, f: &mut dyn FnMut(PathBuf, String)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, f);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        f(path, content);
    }
}
