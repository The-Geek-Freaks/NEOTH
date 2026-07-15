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
//!   - `src/channels/line_api.rs`  — outbound LINE Messaging API REST calls;
//!                                    operator-configured channel adapter
//!                                    using the operator's bot token. Same
//!                                    category as Discord/Slack channel
//!                                    egress, not unsolicited phone-home.
//!   - `src/channels/mattermost.rs`
//!                                  — outbound Mattermost WebSocket dialer
//!                                    for a self-hosted/operator-configured
//!                                    server. Same explicit channel-adapter
//!                                    category as Slack socket mode.
//!   - `src/channels/matrix_client.rs`
//!                                  — operator-configured Matrix homeserver
//!                                    authentication. Token bootstrap makes
//!                                    one timeout-bounded, redirect-disabled
//!                                    `/account/whoami` request so the SDK
//!                                    session can bind the token to its exact
//!                                    user and device before syncing.
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
//!   - `src/email/imap_fetch.rs`    — EM-01b operator-configured inbound
//!                                    IMAP fetch (`neoth email fetch`),
//!                                    gated behind the `imap_fetch` build
//!                                    feature AND the operator's own IMAP
//!                                    credentials. Dials the configured IMAP
//!                                    host (default `imap.gmail.com:993`)
//!                                    over rustls TLS with `BODY.PEEK[]`
//!                                    (non-destructive). Same operator-
//!                                    opt-in category as the channel adapters
//!                                    above — an explicit, configured upstream,
//!                                    never an unsolicited phone-home.
//!   - `src/daemon/omi_{client,ingest_task}.rs`
//!                                  — default-OFF OMI conversation import and
//!                                    optional official export. Legacy mode is
//!                                    local-only. Developer API mode permits a
//!                                    public endpoint only when the operator
//!                                    explicitly enables `allow_cloud_api`, and
//!                                    requires a dedicated `omi_dev_*` key.
//!   - `src/daemon/email_ingest_cron.rs`
//!                                  — GOLD-ADAPT-JV-PAPERLESS-01 default-OFF
//!                                    email → Paperless NGX cron. IMAP is
//!                                    feature-gated and credential-gated; the
//!                                    HTTP POST only runs when the operator
//!                                    configured `paperless_url` +
//!                                    `paperless_token`. The client is
//!                                    timeout-bounded and redirects are disabled.
//!   - `src/security/osv_check.rs` — supply-chain malware gate for explicit
//!                                    installer/update flows. It queries OSV
//!                                    before installing a requested package and
//!                                    fails open on network errors.
//!   - `src/sources/hackernews.rs` — explicit self-reflection source fetching
//!                                    public HN Firebase API stories for tech
//!                                    currency gap analysis.
//!   - `src/cli/serve.rs`          — GOOSE-03 operator-approval gate: sends
//!                                    an elicitation message to the operator's
//!                                    Telegram bot (token + user-id from
//!                                    FreedomConfig) when a GOOSE action needs
//!                                    human approval.  Fire-and-forget;
//!                                    never auto-triggered; same opt-in
//!                                    category as the Telegram channel adapter.
//!   - `src/cli/doctor/checks/live_probes.rs`
//!                                  — `neoth doctor` live connectivity probes
//!                                    (HTTP-GET + TCP-connect).  Operator-
//!                                    initiated diagnostic only; timeout-bounded
//!                                    + TLS-verifying; dials operator-configured
//!                                    endpoints, never automatic phone-home.
//!   - `src/daemon/webhook_manager.rs`
//!                                  — operator-configured outbound webhook
//!                                    delivery (enabled=false by default).
//!                                    https_only, redirect(Policy::none)
//!                                    for SSRF prevention, HMAC-signed,
//!                                    WAL-audited.  `#[cfg(test)]` unit
//!                                    at line 753 builds the same client for
//!                                    a contract test; dials no external host.
//!   - `src/security/dep_health.rs`
//!                                  — GOLD-ADAPT-SNYK-03b: queries
//!                                    `registry.npmjs.org` for deprecated /
//!                                    abandoned package signals before install.
//!                                    Operator-triggered; fails-open on any
//!                                    network error.  Same supply-chain gate
//!                                    category as `security/osv_check.rs`.
//!   - `src/daemon/companion.rs`   — `#[cfg(test)]` loopback tests: spin up
//!                                    the companion HTTP server on 127.0.0.1:0
//!                                    and use reqwest to hit that exact port.
//!                                    Never dials external addresses.
//!   - `src/daemon/kanban_sse.rs`  — `#[cfg(test)]` loopback tests: spin up
//!                                    the kanban SSE server on 127.0.0.1:0
//!                                    (accept guard rejects non-loopback peers)
//!                                    and use reqwest to consume that port.
//!                                    Never dials external addresses.
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
    "src/daemon/audit_rpc/",
    "src/channels/webhook_listener.rs",
    "src/channels/slack_socket.rs",
    "src/channels/discord.rs",
    "src/channels/discord_gateway_loop.rs",
    "src/channels/line_api.rs",
    "src/channels/mattermost.rs",
    // Operator-configured Matrix homeserver egress. Token bootstrap performs
    // one bounded `/account/whoami` request to recover and verify the token's
    // user + device identity before handing the exact session to matrix-sdk.
    // Redirects are disabled and response bodies are capped; no implicit
    // endpoint is used.
    "src/channels/matrix_client.rs",
    // Explicit operator-owned Baileys sidecar egress. The adapter uses only
    // its dedicated bearer token, refuses redirects/userinfo/query fragments,
    // permits plaintext HTTP only on loopback, and requires HTTPS remotely.
    // It never falls back to Meta Cloud credentials or an implicit endpoint.
    "src/channels/whatsapp_baileys.rs",
    "src/telemetry/",
    "src/cluster/",
    "src/transport/",
    "src/email/imap_fetch.rs",
    "src/daemon/omi_client.rs",
    "src/daemon/omi_ingest_task.rs",
    // GOLD-ADAPT-JV-PAPERLESS-01 — default-OFF email ingest cron. IMAP fetch is
    // build-feature + credential gated; Paperless NGX upload requires the
    // operator-configured `paperless_url` + `paperless_token`, uses a 10 s
    // timeout, and refuses redirects. This is an explicit integration push,
    // not unsolicited phone-home.
    "src/daemon/email_ingest_cron.rs",
    "src/security/osv_check.rs",
    "src/sources/hackernews.rs",
    // GOLD-ADOPT-26 RSS feed poller — fetches operator-configured feed URLs
    // (production routes through providers::http_client; test bodies build a
    // plain client for the wiremock localhost server).
    "src/cli/rss_feed_task.rs",
    // GOLD-ADOPT-11 — live HuggingFace GGUF-variant lookup builds a
    // timeout-bounded client for the HF model-search API.
    "src/models/gguf_variants.rs",
    // GOOSE-03 operator-approval gate — send the human-readable elicitation
    // message to the operator's Telegram bot when `telegram_token` +
    // `telegram_user_id` are configured in FreedomConfig.  Fire-and-forget;
    // a failed delivery lets the gate time out (fail-closed).  The token and
    // user-id are operator-supplied; no implicit outbound; same
    // operator-opt-in category as the Telegram channel adapter in channels/.
    "src/cli/serve.rs",
    // `neoth doctor` live connectivity probes — operator-initiated diagnostic
    // subcommand.  `http_get_probe` builds a timeout-bounded TLS-verifying
    // ClientBuilder; `tcp_connect_probe` opens a raw TcpStream to the
    // operator-configured endpoint.  Never runs automatically — triggered by
    // the explicit `neoth doctor` CLI invocation.
    "src/cli/doctor/checks/live_probes.rs",
    // Webhook delivery cron — operator-configured outbound POST to registered
    // webhook URLs.  Production client: https_only(true), redirect(Policy::none)
    // to prevent SSRF via 3xx, 10 s timeout, SSRF IP-block guard, HMAC-signed
    // payload, WAL-audited delivery.  Enabled only when
    // `webhook_manager.enabled = true` in FreedomConfig (default: false).
    // #[cfg(test)] unit at line 753 builds the same client to verify the
    // Policy::none contract — dials no external host.
    "src/daemon/webhook_manager.rs",
    // GOLD-ADAPT-SNYK-03b — queries `registry.npmjs.org/<pkg>` for deprecated /
    // abandoned signals before `npm install -g`.  Operator-triggered (install
    // wizard / `neoth security dep-health`); fails-open on any network error so
    // an offline install is never bricked.  Same supply-chain gate category
    // as `security/osv_check.rs`.
    "src/security/dep_health.rs",
    // Test-loopback: companion server unit tests spin up an axum listener on
    // 127.0.0.1:0, then use reqwest::Client::new() to hit that exact loopback
    // port.  Never dials any external address.  #[cfg(test)] block at line 447.
    "src/daemon/companion.rs",
    // Test-loopback: kanban SSE unit tests spin up the SSE HTTP server on
    // 127.0.0.1:0 (loopback-only accept guard: `if !peer.ip().is_loopback()
    // { continue; }`), then use reqwest::Client::new() to consume that local
    // port.  Never dials any external address.  #[cfg(test)] block at line 259.
    "src/daemon/kanban_sse.rs",
    // Test-loopback: oai_serve unit tests start the OpenAI-compat HTTP server on
    // 127.0.0.1:0, then use reqwest::Client::new() to hit `/v1/models` and
    // `/v1/unknown` on that local port.  Never dials any external address —
    // #[cfg(test)] blocks only.
    "src/oai_serve/server.rs",
    // Operator-configured egress (NOT phone-home): the GOLD-ADAPT-ODY-21 webhook
    // manager POSTs to endpoints the operator sets in freedom.yaml.  Its client
    // is built `https_only(true)` + `redirect::Policy::none()` (SSRF guard) — the
    // single vetted outbound dialer in this file.
    "src/cli/serve_tasks.rs",
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
