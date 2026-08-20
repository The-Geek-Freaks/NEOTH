#![allow(clippy::doc_overindented_list_items)]

//! Static drift guard for direct, pre-expansion network-client, socket, and
//! known-DHT construction visible in checked-in `neothd` Rust source outside
//! explicitly reviewed boundary modules. Phase 33c BS-6.
//!
//! Walks every `.rs` file under `src/` and fails the build if a non-boundary
//! module directly constructs a `reqwest::Client`, opens a raw `TcpStream`, or
//! references the lower-level `hyper::client`, or starts peeroxide's public-DHT
//! primitives. `#[cfg(test)]` source regions are deliberately excluded: they
//! are not compiled into the production artifact and can use hermetic
//! in-process loopback sockets. This is a source-boundary exception, not a
//! whole-program network policy: a dialer immediately outside that region still
//! fails the guard. It does not inventory dispatch through approved shared-client
//! factories or external proc-macro expansions; locked dependency/supply-chain
//! review and runtime policy/audit own those concerns. This test runs under
//! `cargo test --all-targets`.
//!
//! Explicitly reviewed boundary modules:
//!   - concrete `src/providers/*.rs` — reviewed provider client constructions
//!                                     (loopback probes included)
//!   - `src/updater/self_update.rs`  — `neoth update --apply` flow
//!   - concrete `src/installers/*.rs` — reviewed managed-CLI bootstrap flows
//!   - `src/memory/infra_scan.rs`    — `arp -a` / `nmap -sn` only;
//!                                     local-LAN scan only
//!   - `src/daemon/healthz.rs`       — inbound localhost listener; test
//!                                     module connects to itself, not the
//!                                     network. Listener never opens
//!                                     outbound `TcpStream::connect`.
//!   - `src/graphify_runner.rs`      — only the Linux containment guardian's
//!                                     fixed AF_INET/AF_INET6/AF_UNIX negative
//!                                     libc socket probe. The AST gate verifies
//!                                     its exact caller chain and fail-closed
//!                                     result handling; the module is not
//!                                     generally allowlisted.
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
//!                                    egress, not implicit network activity.
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
//!                                    only when the operator configures it.
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
//!                                    endpoints, only for that explicit command.
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
//!   - `src/daemon/kanban_sse.rs`  — `#[cfg(test)]` loopback tests: spin up
//!                                    the kanban SSE server on 127.0.0.1:0
//!                                    (accept guard rejects non-loopback peers)
//!                                    and use reqwest to consume that port.
//!                                    Never dials external addresses.
//!
//! Adding a new allowed path means editing both the codebase AND this
//! file, which makes the audit trail loud.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ForeignItem, ImplItem, Item, Local, Meta, TraitItem, Type, UseTree,
    spanned::Spanned,
};

const ALLOWED_PREFIXES: &[&str] = &[
    // Direct provider constructions, reviewed one-by-one; new descendants are
    // scan-required rather than inheriting a directory-wide network boundary.
    "src/providers/anthropic_api.rs",
    "src/providers/aws_bedrock.rs",
    "src/providers/azure_openai.rs",
    "src/providers/cohere_api.rs",
    "src/providers/copilot.rs",
    "src/providers/cost.rs",
    "src/providers/gemini_api.rs",
    "src/providers/http_client.rs",
    "src/providers/known_endpoints.rs",
    "src/providers/local_probe.rs",
    "src/providers/ollama_api.rs",
    "src/providers/openai_api.rs",
    "src/updater/self_update.rs",
    "src/installers/n8n.rs",
    "src/installers/ollama.rs",
    "src/installers/omi.rs",
    "src/installers/paperless.rs",
    "src/memory/infra_scan.rs",
    "src/daemon/healthz.rs",
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
    // Operator-owned Keet companion egress. The bridge client is pinned to a
    // validated loopback/private origin, disables all proxies so the bearer
    // never leaves the host, refuses redirects, and bounds every body.
    "src/channels/keet_bridge.rs",
    // Readiness probe helpers: production probes reuse the adapters' own
    // clients; the only reqwest construction here is the in-file unit test
    // dialing its in-process wiremock server, never the network.
    "src/channels/readiness.rs",
    // OMI probe readiness: `neoth omi probe` opens a bounded 2 s TCP connect
    // to the operator's OWN configured native OMI listener (loopback by
    // default) to report whether the local ingest socket is up — a
    // self-connect diagnostic, not outbound egress.
    "src/cli/omi.rs",
    // Local n8n control-plane listener. The only TcpStream::connect is the
    // in-file `#[tokio::test]` dialing its own in-process server on
    // `Ipv4Addr::LOCALHOST` to exercise idle-connection shutdown — it
    // connects to itself, never the network.
    "src/n8n_api/server.rs",
    "src/telemetry/http.rs",
    // The default peeroxide transport is a real public-DHT dialer: it opts
    // into peeroxide's public bootstrap set, starts the swarm actor, and joins
    // the operator-selected cluster topic. Keep this exact implementation file
    // reviewed instead of allowing every future cluster or companion module.
    "src/cluster/hyperswarm.rs",
    // Explicit, operator-initiated cluster discovery transports.
    "src/cluster/tailscale.rs",
    "src/cluster/mdns.rs",
    "src/transport/hysteria.rs",
    "src/transport/ssh_socks5.rs",
    "src/transport/ssh_tunnel.rs",
    "src/email/imap_fetch.rs",
    "src/daemon/omi_client.rs",
    "src/daemon/omi_ingest_task.rs",
    // GOLD-ADAPT-JV-PAPERLESS-01 — default-OFF email ingest cron. IMAP fetch is
    // build-feature + credential gated; Paperless NGX upload requires the
    // operator-configured `paperless_url` + `paperless_token`, uses a 10 s
    // timeout, and refuses redirects. This is an explicit integration push,
    // explicit operator-configured integration.
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
    // Operator-configured egress: the GOLD-ADAPT-ODY-21 webhook
    // manager POSTs to endpoints the operator sets in freedom.yaml.  Its client
    // is built `https_only(true)` + `redirect::Policy::none()` (SSRF guard) — the
    // single vetted outbound dialer in this file.
    "src/cli/serve_tasks.rs",
    // Init-wizard provider-key verification. This is the sole production
    // `reqwest::blocking::Client` construction and runs only after the
    // operator supplies a key and accepts a connectivity check.
    "src/cli/init/catalog.rs",
];

#[test]
fn no_direct_pre_expansion_network_construction_outside_reviewed_boundaries() {
    let src_root = manifest_dir()
        .join("src")
        .canonicalize()
        .expect("canonical crate source root");
    let module_graph = TestOnlyModuleGraph::build(&src_root)
        .expect("module graph requires a canonical source root");
    let test_only_external_modules = module_graph.exempt_files();
    let mut violations = Vec::new();
    let graphify_launch_contract = match graphify_module_and_binary_contract(&src_root) {
        Ok(()) => true,
        Err(error) => {
            violations.push(format!("Graphify module/binary launch contract failed: {error}"));
            false
        }
    };
    match production_public_rendezvous_callers(&src_root) {
        Ok(callers) if callers == ["src/daemon/companion.rs"] => {}
        Ok(callers) => violations.push(format!(
            "spawn_public_rendezvous must have exactly one production caller, src/daemon/companion.rs; found {}",
            callers.join(", ")
        )),
        Err(error) => violations.push(format!("spawn_public_rendezvous caller audit failed: {error}")),
    }
    for target in module_graph.production_outside_targets() {
        violations.push(format!(
            "{}: production external module target escapes canonical src_root",
            target.display()
        ));
    }
    violations.extend(module_graph.production_unresolved_modules().iter().cloned());
    walk_rs(&src_root, &mut |path, content| {
        let Ok((canonical_path, rel)) = canonical_in_root_relative(&src_root, &path) else {
            violations.push(format!(
                "{}: source traversal escaped canonical src_root",
                path.display()
            ));
            return;
        };
        // `canonical_in_root_relative` is intentionally rooted at `SRC/neothd/src`,
        // while reviewed-boundary declarations are repository-relative.  Keep the
        // raw value only for the self-test path below; every policy decision and
        // emitted finding must use one canonical spelling.
        let repo_rel = format!("src/{rel}");
        if is_allowed(&repo_rel) {
            return;
        }
        // Skip the lint file itself (it mentions the patterns as strings).
        if rel == "tests/no_outbound_network.rs" {
            return;
        }
        if test_only_external_modules.contains(&canonical_path) {
            return;
        }
        collect_network_violations(
            &mut violations,
            &repo_rel,
            &content,
            repo_rel == "src/daemon/audit_rpc/transport/unix.rs",
            repo_rel == "src/media/stt_provider.rs",
            repo_rel == "src/graphify_runner.rs" && graphify_launch_contract,
        );
    })
    .expect("source traversal and reads must succeed");

    assert!(
        violations.is_empty(),
        "direct pre-expansion network-construction drift guard violated:\n  {}",
        violations.join("\n  "),
    );
}

fn graphify_module_and_binary_contract(src_root: &Path) -> Result<(), String> {
    let library = fs::read_to_string(src_root.join("lib.rs"))
        .map_err(|error| format!("read src/lib.rs: {error}"))?;
    if !graphify_library_module_contract_is_exact(&library) {
        return Err(
            "src/lib.rs must contain one unconditional public graphify_runner module without path override"
                .to_owned(),
        );
    }

    let binary = fs::read_to_string(src_root.join("main.rs"))
        .map_err(|error| format!("read src/main.rs: {error}"))?;
    if !graphify_binary_main_contract_is_exact(&binary) {
        return Err(
            "src/main.rs must dispatch the Linux guardian before every public runtime path"
                .to_owned(),
        );
    }
    Ok(())
}

fn graphify_library_module_contract_is_exact(content: &str) -> bool {
    let Ok(file) = syn::parse_file(content) else {
        return false;
    };
    let modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident.to_string() == "graphify_runner" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [module] = modules.as_slice() else {
        return false;
    };
    module.attrs.is_empty()
        && matches!(&module.vis, syn::Visibility::Public(_))
        && module.content.is_none()
        && module.semi.is_some()
}

fn graphify_binary_main_contract_is_exact(content: &str) -> bool {
    let Ok(file) = syn::parse_file(content) else {
        return false;
    };
    let mut counter = NamedFunctionCounter {
        name: "main",
        count: 0,
    };
    counter.visit_file(&file);
    if counter.count != 1 {
        return false;
    }
    let mains = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident.to_string() == "main" => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [main] = mains.as_slice() else {
        return false;
    };
    graphify_function_tokens_match(content, main, GRAPHIFY_BINARY_MAIN_CONTRACT)
}

struct NamedFunctionCounter<'name> {
    name: &'name str,
    count: usize,
}

impl<'ast> Visit<'ast> for NamedFunctionCounter<'_> {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if function.sig.ident.to_string() == self.name {
            self.count += 1;
        }
        visit::visit_item_fn(self, function);
    }
}

/// `spawn_public_rendezvous` owns a public-DHT bootstrap/spawn/join sequence.
/// Its definition stays in the reviewed hyperswarm boundary, but production
/// access to that typed capability is intentionally limited to Companion
/// pairing; aliases must resolve to the same one caller rather than hiding a
/// second public rendezvous protocol.
fn production_public_rendezvous_callers(src_root: &Path) -> Result<Vec<String>, String> {
    let mut callers = Vec::new();
    let mut parse_errors = Vec::new();
    walk_rs(src_root, &mut |path, content| {
        let Ok((_, rel)) = canonical_in_root_relative(src_root, &path) else {
            parse_errors.push(format!(
                "cannot canonicalize caller-audit source {}",
                path.display()
            ));
            return;
        };
        let Ok(file) = syn::parse_file(&content) else {
            parse_errors.push(format!("unparseable caller-audit source src/{rel}"));
            return;
        };
        let test_only_ranges = test_only_item_ranges(&content).unwrap_or_default();
        let mut visitor = PublicRendezvousCallerVisitor {
            test_only_ranges: &test_only_ranges,
            scopes: vec![Scope::crate_root()],
            calls: 0,
        };
        visitor.visit_file(&file);
        for _ in 0..visitor.calls {
            callers.push(format!("src/{rel}"));
        }
    })?;
    if !parse_errors.is_empty() {
        return Err(parse_errors.join(", "));
    }
    callers.sort();
    Ok(callers)
}

struct PublicRendezvousCallerVisitor<'source> {
    test_only_ranges: &'source [Range<usize>],
    scopes: Vec<Scope>,
    calls: usize,
}

impl PublicRendezvousCallerVisitor<'_> {
    fn is_test_only<T: Spanned>(&self, node: &T) -> bool {
        let range = node.span().byte_range();
        self.test_only_ranges
            .iter()
            .any(|test| test.start <= range.start && range.end <= test.end)
    }

    fn precollect_uses(&mut self, items: &[Item]) {
        // Imports are order-independent in Rust. Iterate so an alias declared
        // later can unlock an earlier grouped/glob alias before caller paths
        // are resolved.
        loop {
            let before = self
                .scopes
                .last()
                .expect("caller-audit scope is present")
                .aliases
                .len();
            for item in items {
                let Item::Use(item) = item else {
                    continue;
                };
                if self.is_test_only(item) {
                    continue;
                }
                let mut aliases = HashMap::new();
                collect_use_aliases(&item.tree, &mut Vec::new(), &self.scopes, &mut aliases);
                self.scopes
                    .last_mut()
                    .expect("caller-audit scope is present")
                    .aliases
                    .extend(aliases);
            }
            if self
                .scopes
                .last()
                .expect("caller-audit scope is present")
                .aliases
                .len()
                == before
            {
                break;
            }
        }
        self.calls += items
            .iter()
            .filter_map(|item| match item {
                // A private import is necessary to resolve local calls, but it
                // cannot export the rendezvous capability.  Only a non-inherited
                // visibility is an independently auditable capability escape.
                Item::Use(item)
                    if !self.is_test_only(item)
                        && !matches!(item.vis, syn::Visibility::Inherited) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .filter(|item| {
                let mut aliases = HashMap::new();
                collect_use_aliases(&item.tree, &mut Vec::new(), &self.scopes, &mut aliases);
                aliases.values().any(|target| {
                    resolve_segments(target, &self.scopes).is_ok_and(is_public_rendezvous_path)
                        || target
                            .last()
                            .is_some_and(|name| name == "spawn_public_rendezvous")
                })
            })
            .count();
    }

    fn precollect_statement_uses(&mut self, statements: &[syn::Stmt]) {
        let items = statements
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Item(item) => Some(item.clone()),
                syn::Stmt::Local(_) | syn::Stmt::Expr(_, _) | syn::Stmt::Macro(_) => None,
            })
            .collect::<Vec<_>>();
        self.precollect_uses(&items);
    }

    fn in_scope(&mut self, kind: ScopeKind, f: impl FnOnce(&mut Self)) {
        self.scopes.push(Scope {
            aliases: HashMap::new(),
            kind,
        });
        f(self);
        self.scopes.pop();
    }
}

impl<'ast> Visit<'ast> for PublicRendezvousCallerVisitor<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.precollect_uses(&file.items);
        visit::visit_file(self, file);
    }

    fn visit_item_use(&mut self, _item: &'ast syn::ItemUse) {}

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if self.is_test_only(item) {
            return;
        }
        self.in_scope(ScopeKind::Module, |visitor| {
            if let Some((_, items)) = &item.content {
                visitor.precollect_uses(items);
            }
            visit::visit_item_mod(visitor, item);
        });
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if self.is_test_only(item) {
            return;
        }
        self.in_scope(ScopeKind::Other, |visitor| {
            visit::visit_item_fn(visitor, item)
        });
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.in_scope(ScopeKind::Other, |visitor| {
            visitor.precollect_statement_uses(&block.stmts);
            visit::visit_block(visitor, block);
        });
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if !self.is_test_only(path)
            && (resolve_expr_path(path, &self.scopes).is_ok_and(is_public_rendezvous_path)
                || path.path.is_ident("spawn_public_rendezvous"))
        {
            self.calls += 1;
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        if !self.is_test_only(expression)
            && macro_tokens_reference_public_rendezvous(&expression.mac.tokens, &self.scopes)
        {
            self.calls += 1;
        }
        visit::visit_expr_macro(self, expression);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if !self.is_test_only(item)
            && macro_tokens_reference_public_rendezvous(&item.mac.tokens, &self.scopes)
        {
            self.calls += 1;
        }
        visit::visit_item_macro(self, item);
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if !self.is_test_only(statement)
            && macro_tokens_reference_public_rendezvous(&statement.mac.tokens, &self.scopes)
        {
            self.calls += 1;
        }
        visit::visit_stmt_macro(self, statement);
    }
}

fn macro_tokens_reference_public_rendezvous(
    tokens: &proc_macro2::TokenStream,
    scopes: &[Scope],
) -> bool {
    macro_token_paths(tokens)
        .iter()
        .any(|path| resolve_segments(path, scopes).is_ok_and(is_public_rendezvous_path))
        || tokens.clone().into_iter().any(|token| match token {
            TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => {
                let wrapped = proc_macro2::TokenStream::from(TokenTree::Group(group.clone()));
                syn::parse2::<syn::Block>(wrapped).is_ok_and(|block| {
                    let mut visitor = PublicRendezvousCallerVisitor {
                        test_only_ranges: &[],
                        scopes: scopes.to_vec(),
                        calls: 0,
                    };
                    visitor.visit_block(&block);
                    visitor.calls > 0
                }) || macro_tokens_reference_public_rendezvous(&group.stream(), scopes)
            }
            TokenTree::Group(group) => {
                macro_tokens_reference_public_rendezvous(&group.stream(), scopes)
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => false,
        })
}

fn is_public_rendezvous_path(path: Vec<String>) -> bool {
    matches!(
        path.as_slice(),
        [first, second, third]
            if first == "cluster"
                && second == "hyperswarm"
                && third == "spawn_public_rendezvous"
    )
}

fn collect_network_violations(
    violations: &mut Vec<String>,
    rel: &str,
    content: &str,
    allows_audit_rpc_af_unix: bool,
    allows_stt_pidfd_syscalls: bool,
    allows_graphify_denial_probe: bool,
) {
    for (line_no, pattern) in forbidden_network_constructions_with_boundaries(
        content,
        allows_audit_rpc_af_unix,
        allows_stt_pidfd_syscalls,
        allows_graphify_denial_probe,
    ) {
        violations.push(format!(
            "{}:{}: direct network-construction pattern `{}` outside explicitly reviewed boundary modules",
            rel,
            line_no,
            pattern,
        ));
    }
}

/// Return network-construction calls which remain in the production source
/// boundary.  Test-only regions must be explicitly compiled out with
/// `#[cfg(test)]`; a bare `#[test]` attribute is not treated as a broad source
/// escape hatch by this static guard.
fn forbidden_network_constructions_in_production(content: &str) -> Vec<(usize, &'static str)> {
    forbidden_network_constructions_with_boundaries(content, false, false, false)
}

fn forbidden_network_constructions_with_boundaries(
    content: &str,
    allows_audit_rpc_af_unix: bool,
    allows_stt_pidfd_syscalls: bool,
    allows_graphify_denial_probe: bool,
) -> Vec<(usize, &'static str)> {
    let Ok(file) = syn::parse_file(content) else {
        // Parse failure deliberately grants no exception.  A malformed source
        // file must not turn this source-boundary check into a fail-open gate.
        return vec![(0, "unparseable Rust source")];
    };
    let test_only_ranges = test_only_item_ranges(content).unwrap_or_default();
    let reviewed_graphify_socket_call = if allows_graphify_denial_probe {
        reviewed_graphify_libc_probe_contract(&file, content)
    } else {
        None
    };
    let mut visitor = ProductionNetworkVisitor {
        content,
        test_only_ranges: &test_only_ranges,
        scopes: vec![Scope::crate_root()],
        socket_bindings: vec![HashMap::new()],
        macro_rule_scopes: vec![HashMap::new()],
        allows_audit_rpc_af_unix,
        allows_stt_pidfd_syscalls,
        allows_graphify_denial_probe,
        reviewed_graphify_socket_call: reviewed_graphify_socket_call.clone(),
        function_names: Vec::new(),
        violations: Vec::new(),
    };
    visitor.visit_file(&file);
    if allows_graphify_denial_probe && reviewed_graphify_socket_call.is_none() {
        visitor
            .violations
            .push((0, "invalid Graphify libc address-family denial contract"));
    }
    visitor.violations
}

const GRAPHIFY_BINARY_MAIN_CONTRACT: &str = r#"
fn main() -> Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(exit_code) =
        ::neothd::graphify_runner::run_linux_graphify_containment_guard_if_requested()
    {
        ::std::process::exit(exit_code);
    }

    if let Some(result) = neothd::media::pdf::run_internal_pdf_worker_if_requested() {
        result.map_err(anyhow::Error::msg)?;
        return Ok(());
    }

    let worker = std::thread::Builder::new()
        .name("neoth-main".to_string())
        .stack_size(MAIN_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("build the tokio runtime")?
                .block_on(neothd::run())
        })
        .context("spawn the neoth main worker thread")?;
    let outcome: Result<()> = worker
        .join()
        .map_err(|_| anyhow::anyhow!("neoth main worker thread panicked"))?;

    if let Err(e) = &outcome
        && let Some(neothd::QuietExit(code)) = e.downcast_ref::<neothd::QuietExit>()
    {
        std::process::exit(*code);
    }
    outcome
}
"#;

const GRAPHIFY_GUARD_MAIN_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn linux_graphify_containment_guard_main(arguments: Vec<OsString>) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let mut arguments = arguments.into_iter();
    let unit_name = next_guard_argument(&mut arguments, "unit name")?;
    let expected_mount_namespace = next_guard_argument(&mut arguments, "host mount namespace")?;
    let expected_network_namespace = next_guard_argument(&mut arguments, "host network namespace")?;
    let working_directory =
        PathBuf::from(next_guard_argument(&mut arguments, "working directory")?);
    let staging = PathBuf::from(next_guard_argument(&mut arguments, "staging directory")?);
    let python = PathBuf::from(next_guard_argument(&mut arguments, "Python executable")?);
    if arguments.next().as_deref() != Some(OsStr::new("--")) {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "missing Graphify argument separator",
        ));
    }
    let python_arguments = arguments.collect::<Vec<_>>();
    if !is_graphify_module_invocation(&python_arguments) {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "guardian received a non-Graphify Python invocation",
        ));
    }
    verify_linux_guardian_boundary(
        &unit_name,
        &expected_mount_namespace,
        &expected_network_namespace,
        &working_directory,
        &staging,
    )?;
    std::env::set_current_dir(&working_directory).with_context(|| {
        format!(
            "enter guarded Graphify working directory {}",
            working_directory.display()
        )
    })?;
    let error = std::process::Command::new(&python)
        .args(python_arguments)
        .exec();
    Err(error).with_context(|| format!("exec guarded Graphify Python {}", python.display()))
}
"#;

const GRAPHIFY_BOUNDARY_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn verify_linux_guardian_boundary(
    unit_name: &OsStr,
    expected_mount_namespace: &OsStr,
    expected_network_namespace: &OsStr,
    working_directory: &Path,
    staging: &Path,
) -> Result<()> {
    let cgroup = current_linux_unified_cgroup()?;
    if cgroup.rsplit('/').next() != unit_name.to_str() {
        return ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(
            "guardian cgroup {cgroup} is not bound to the expected transient unit"
        )));
    }
    if read_linux_namespace("mnt")?.as_os_str() == expected_mount_namespace {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "the service retained the host mount namespace",
        ));
    }
    if read_linux_namespace("net")?.as_os_str() == expected_network_namespace {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "the service retained the host network namespace",
        ));
    }
    verify_linux_cgroup_limits(&cgroup)?;
    verify_linux_network_denied()?;
    verify_linux_write_boundary(working_directory, staging)?;
    Ok(())
}
"#;

const GRAPHIFY_NETWORK_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn verify_linux_network_denied() -> Result<()> {
    verify_linux_graphify_address_family_denied("AF_INET", ::libc::AF_INET)?;
    verify_linux_graphify_address_family_denied("AF_INET6", ::libc::AF_INET6)?;
    verify_linux_graphify_address_family_denied("AF_UNIX", ::libc::AF_UNIX)?;

    let routes =
        std::fs::read_to_string("/proc/net/route").context("read effective IPv4 routes")?;
    if routes.lines().skip(1).any(|line| !line.trim().is_empty()) {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "effective network namespace retains IPv4 routes",
        ));
    }
    if !std::fs::read_to_string("/proc/net/ipv6_route")
        .context("read effective IPv6 routes")?
        .trim()
        .is_empty()
    {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "effective network namespace retains IPv6 routes",
        ));
    }
    Ok(())
}
"#;

const GRAPHIFY_SOCKET_HELPER_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn verify_linux_graphify_address_family_denied(name: &str, domain: ::libc::c_int) -> Result<()> {
    let descriptor = unsafe {
        ::libc::socket(
            domain,
            ::libc::SOCK_STREAM | ::libc::SOCK_CLOEXEC,
            0,
        )
    };
    if descriptor >= 0 {
        unsafe { ::libc::close(descriptor) };
        return ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(
            "effective address-family policy still permits {name}"
        )));
    }

    let error = ::std::io::Error::last_os_error();
    if error.raw_os_error() == ::std::option::Option::Some(::libc::EAFNOSUPPORT) {
        return ::std::result::Result::Ok(());
    }
    ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(
        "could not prove effective address-family denial for {name}: {error}"
    )))
}
"#;

const GRAPHIFY_CONTAINED_PROCESS_CONTRACT: &str = r#"
async fn run_contained_process<I, S>(
    executable: &Path,
    args: I,
    current_dir: Option<&Path>,
    environment: &GraphifyEnvironment,
    limits: &GraphifyRunLimits,
) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args
        .into_iter()
        .map(|argument| argument.as_ref().to_os_string())
        .collect::<Vec<_>>();

    #[cfg(target_os = "linux")]
    let (mut command, linux_unit) =
        LinuxGraphifyUnit::command(executable, &args, current_dir, environment, limits)?;
    #[cfg(not(target_os = "linux"))]
    let mut command = Command::new(executable);

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(not(target_os = "linux"))]
    {
        command.args(&args);
        if let Some(current_dir) = current_dir {
            command.current_dir(current_dir);
        }
        environment.apply(&mut command);
        configure_containment(&mut command)?;
    }

    let child = command
        .spawn()
        .with_context(|| format!("spawn {}", limits.label))?;
    #[cfg(target_os = "linux")]
    let mut child = ContainedChild::activate(child, linux_unit)
        .with_context(|| format!("activate {} process containment", limits.label))?;
    #[cfg(not(target_os = "linux"))]
    let mut child = ContainedChild::activate(child)
        .with_context(|| format!("activate {} process containment", limits.label))?;
    let stdout = match child.child_mut().stdout.take() {
        Some(stdout) => stdout,
        None => {
            child.terminate_and_reap().await?;
            bail!("Graphify child stdout pipe was not created");
        }
    };
    let stderr = match child.child_mut().stderr.take() {
        Some(stderr) => stderr,
        None => {
            child.terminate_and_reap().await?;
            bail!("Graphify child stderr pipe was not created");
        }
    };

    let run = async {
        tokio::try_join!(
            async { child.child_mut().wait().await.map_err(anyhow::Error::from) },
            read_capped(stdout, limits.stdout_cap_bytes, "stdout"),
            read_capped(stderr, limits.stderr_cap_bytes, "stderr"),
        )
    };
    match tokio::time::timeout(limits.timeout, run).await {
        Ok(Ok((status, stdout, stderr))) => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        Ok(Err(error)) => {
            child.terminate_and_reap().await?;
            Err(error).with_context(|| format!("{} output collection failed", limits.label))
        }
        Err(_) => {
            child.terminate_and_reap().await?;
            bail!(
                "{} exceeded its {:?} execution deadline",
                limits.label,
                limits.timeout
            );
        }
    }
}
"#;

const GRAPHIFY_FLAG_DISPATCH_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
pub fn run_linux_graphify_containment_guard_if_requested() -> Option<i32> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new(LINUX_GRAPHIFY_GUARD_FLAG)) {
        return None;
    }
    Some(
        match linux_graphify_containment_guard_main(arguments.collect()) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!(
                    "{LINUX_GRAPHIFY_SYSTEMD_ERROR}: Graphify containment guardian refused execution: {error:#}"
                );
                125
            }
        },
    )
}
"#;

const GRAPHIFY_NEXT_ARGUMENT_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn next_guard_argument(
    arguments: &mut impl Iterator<Item = OsString>,
    name: &str,
) -> Result<OsString> {
    let value = arguments
        .next()
        .with_context(|| format!("missing Graphify guardian {name}"))?;
    if value.as_os_str().is_empty() {
        return ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(
            "Graphify guardian {name} is empty"
        )));
    }
    Ok(value)
}
"#;

const GRAPHIFY_NAMESPACE_READER_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn read_linux_namespace(kind: &str) -> Result<OsString> {
    let path = ::std::format!("/proc/self/ns/{kind}");
    let namespace = std::fs::read_link(&path)
        .with_context(|| ::std::format!("{LINUX_GRAPHIFY_SYSTEMD_ERROR}: read {path}"))?;
    if namespace.as_os_str().is_empty() {
        return ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(
            "{LINUX_GRAPHIFY_SYSTEMD_ERROR}: {path} is empty"
        )));
    }
    Ok(namespace.into_os_string())
}
"#;

const GRAPHIFY_CGROUP_MEMBERSHIP_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn current_linux_unified_cgroup() -> Result<String> {
    let contents =
        std::fs::read_to_string("/proc/self/cgroup").context("read guardian cgroup membership")?;
    let mut unified = None;
    for line in contents.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next();
        let controllers = fields.next();
        let path = fields.next();
        if hierarchy == Some("0")
            && controllers == Some("")
            && unified
                .replace(
                    path.context("guardian cgroup entry has no path")?
                        .to_owned(),
                )
                .is_some()
        {
            return ::std::result::Result::Err(::anyhow::Error::msg(
                "guardian has multiple unified cgroup entries",
            ));
        }
    }
    let cgroup = unified.context("guardian has no unified cgroup-v2 membership")?;
    if !cgroup.starts_with('/') || cgroup.contains("..") {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "guardian cgroup path is not normalized",
        ));
    }
    Ok(cgroup)
}
"#;

const GRAPHIFY_CGROUP_LIMITS_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn verify_linux_cgroup_limits(cgroup: &str) -> Result<()> {
    let directory = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
    let bounded_value = |name: &str, ceiling: u64| -> Result<()> {
        let value = std::fs::read_to_string(directory.join(name))
            .with_context(|| format!("read effective cgroup {name}"))?;
        let value = value
            .trim()
            .parse::<u64>()
            .with_context(|| format!("parse effective cgroup {name}"))?;
        if value > ceiling {
            return ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(
                "effective cgroup {name} is not bounded to {ceiling}"
            )));
        }
        Ok(())
    };
    bounded_value("memory.max", 1_073_741_824)?;
    bounded_value("pids.max", 64)?;
    let cpu_max = std::fs::read_to_string(directory.join("cpu.max"))
        .context("read effective cgroup cpu.max")?;
    let mut cpu_max = cpu_max.split_ascii_whitespace();
    let quota = cpu_max
        .next()
        .context("effective cgroup cpu.max has no quota")?;
    let period = cpu_max
        .next()
        .context("effective cgroup cpu.max has no period")?
        .parse::<u64>()
        .context("parse effective cgroup cpu.max period")?;
    let quota = quota
        .parse::<u64>()
        .context("effective cgroup cpu.max quota is unlimited")?;
    if quota > period.saturating_mul(2) {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            "effective cgroup cpu.max exceeds the two-core limit",
        ));
    }
    Ok(())
}
"#;

const GRAPHIFY_WRITE_BOUNDARY_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn verify_linux_write_boundary(working_directory: &Path, staging: &Path) -> Result<()> {
    let nonce = new_linux_graphify_unit_name()?;
    if working_directory != staging {
        let denied_probe = working_directory.join(::std::format!(".{nonce}.write-probe"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&denied_probe)
        {
            Ok(_) => {
                let _ = std::fs::remove_file(&denied_probe);
                return ::std::result::Result::Err(::anyhow::Error::msg(
                    "effective filesystem boundary permits a host working-directory write",
                ));
            }
            Err(error)
                if ::std::matches!(
                    error.raw_os_error(),
                    Some(libc::EACCES | libc::EROFS)
                ) => {}
            Err(error) => return Err(error).context("prove host working-directory write denial"),
        }
    }
    let staging_probe = staging.join(::std::format!(".{nonce}.write-probe"));
    std::fs::write(&staging_probe, b"guard")
        .context("prove the exact Graphify staging write capability")?;
    std::fs::remove_file(&staging_probe).context("remove Graphify staging proof")?;
    let run_probe = Path::new("/run").join(::std::format!(".{nonce}.write-probe"));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&run_probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&run_probe);
            return ::std::result::Result::Err(::anyhow::Error::msg(
                "effective filesystem boundary permits a host runtime-directory write",
            ));
        }
        Err(error)
            if ::std::matches!(
                error.raw_os_error(),
                Some(libc::EACCES | libc::EROFS | libc::ENOENT)
            ) => {}
        Err(error) => return Err(error).context("prove host runtime-directory write denial"),
    }
    Ok(())
}
"#;

const GRAPHIFY_SYSTEMD_PROPERTIES_CONTRACT: &str = r#"
#[cfg(target_os = "linux")]
fn linux_systemd_properties(
    working_directory: &Path,
    staging: &Path,
    runtime_millis: u128,
) -> Vec<OsString> {
    ::std::vec![
        ::std::format!("--working-directory={}", working_directory.display()).into(),
        "--property=Delegate=no".into(),
        "--property=KillMode=control-group".into(),
        "--property=SendSIGKILL=yes".into(),
        "--property=TimeoutStopSec=2s".into(),
        "--property=Restart=no".into(),
        "--property=UMask=0077".into(),
        "--property=NoNewPrivileges=yes".into(),
        "--property=PrivateNetwork=yes".into(),
        "--property=PrivateTmp=yes".into(),
        "--property=PrivateDevices=yes".into(),
        "--property=ProtectSystem=strict".into(),
        "--property=ProtectHome=read-only".into(),
        "--property=InaccessiblePaths=/run /var/run".into(),
        ::std::format!("--property=ReadWritePaths={}", staging.display()).into(),
        "--property=RestrictSUIDSGID=yes".into(),
        "--property=RestrictAddressFamilies=none".into(),
        "--property=IPAddressDeny=any".into(),
        "--property=LockPersonality=yes".into(),
        "--property=SystemCallArchitectures=native".into(),
        "--property=CapabilityBoundingSet=".into(),
        "--property=MemoryMax=1073741824".into(),
        "--property=TasksMax=64".into(),
        "--property=CPUQuota=200%".into(),
        "--property=LimitCORE=0".into(),
        ::std::format!("--property=RuntimeMaxSec={runtime_millis}ms").into(),
        "--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE VIRTUAL_ENV HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY OPENAI_API_KEY ANTHROPIC_API_KEY".into(),
    ]
}
"#;

const GRAPHIFY_SYSTEMD_COMMAND_CONTRACT: &str = r#"
fn command(
    executable: &Path,
    args: &[OsString],
    current_dir: Option<&Path>,
    environment: &GraphifyEnvironment,
    limits: &GraphifyRunLimits,
) -> Result<(::tokio::process::Command, Self)> {
    if !environment.overrides.is_empty() {
        return ::std::result::Result::Err(::anyhow::Error::msg(
            LINUX_GRAPHIFY_NETWORK_ERROR,
        ));
    }
    Self::ensure_manager_available()?;
    let systemd_run = trusted_linux_systemd_tool("systemd-run")?;
    let systemctl = trusted_linux_systemd_tool("systemctl")?;
    let executable = canonical_linux_safe_path(executable, "Graphify Python executable")?;
    let guardian = trusted_linux_graphify_guardian()?;
    let (working_directory, staging, ephemeral_staging) =
        prepare_linux_graphify_staging(current_dir)?;
    let unit_name = new_linux_graphify_unit_name()?;
    let host_mount_namespace = read_linux_namespace("mnt")?;
    let host_network_namespace = read_linux_namespace("net")?;
    if ephemeral_staging.is_some() {
        ensure_linux_private_staging_leaf(&working_directory)?;
        ensure_linux_private_staging_leaf(&staging)?;
    } else {
        ensure_linux_private_path_ancestry(&working_directory, "Graphify working directory")?;
        ensure_linux_private_path_ancestry(&staging, "Graphify output staging")?;
    }
    let runtime_millis = limits.timeout.as_millis();
    if runtime_millis == 0 {
        return ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(
            "{LINUX_GRAPHIFY_SYSTEMD_ERROR}: Graphify runtime limit is not representable"
        )));
    }

    let mut command = ::tokio::process::Command::new(systemd_run);
    command
        .arg("--user")
        .arg("--quiet")
        .arg("--wait")
        .arg("--pipe")
        .arg("--collect")
        .arg("--service-type=exec")
        .arg(::std::format!("--unit={unit_name}"))
        .env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_AUDIT")
        .env_remove("PYTHONPATH")
        .env_remove("PYTHONHOME")
        .env_remove("VIRTUAL_ENV");
    command.args(linux_systemd_properties(
        &working_directory,
        &staging,
        runtime_millis,
    ));
    for (name, value) in environment.systemd_assignments()? {
        let mut assignment = OsString::from("--setenv=");
        assignment.push(name);
        assignment.push("=");
        assignment.push(value);
        command.arg(assignment);
    }
    command
        .arg("--")
        .arg(guardian)
        .arg(LINUX_GRAPHIFY_GUARD_FLAG)
        .arg(&unit_name)
        .arg(host_mount_namespace)
        .arg(host_network_namespace)
        .arg(&working_directory)
        .arg(&staging)
        .arg(executable)
        .arg("--")
        .args(args);

    Ok((
        command,
        Self {
            systemctl,
            unit_name,
            _ephemeral_staging: ephemeral_staging,
        },
    ))
}
"#;

const GRAPHIFY_CONTRACT_FUNCTIONS: [(&str, &str); 12] = [
    (
        "run_contained_process",
        GRAPHIFY_CONTAINED_PROCESS_CONTRACT,
    ),
    (
        "run_linux_graphify_containment_guard_if_requested",
        GRAPHIFY_FLAG_DISPATCH_CONTRACT,
    ),
    (
        "linux_graphify_containment_guard_main",
        GRAPHIFY_GUARD_MAIN_CONTRACT,
    ),
    ("next_guard_argument", GRAPHIFY_NEXT_ARGUMENT_CONTRACT),
    (
        "verify_linux_guardian_boundary",
        GRAPHIFY_BOUNDARY_CONTRACT,
    ),
    ("read_linux_namespace", GRAPHIFY_NAMESPACE_READER_CONTRACT),
    (
        "current_linux_unified_cgroup",
        GRAPHIFY_CGROUP_MEMBERSHIP_CONTRACT,
    ),
    (
        "verify_linux_cgroup_limits",
        GRAPHIFY_CGROUP_LIMITS_CONTRACT,
    ),
    ("verify_linux_network_denied", GRAPHIFY_NETWORK_CONTRACT),
    (
        "verify_linux_graphify_address_family_denied",
        GRAPHIFY_SOCKET_HELPER_CONTRACT,
    ),
    (
        "verify_linux_write_boundary",
        GRAPHIFY_WRITE_BOUNDARY_CONTRACT,
    ),
    (
        "linux_systemd_properties",
        GRAPHIFY_SYSTEMD_PROPERTIES_CONTRACT,
    ),
];

fn graphify_contract_fixture() -> String {
    let functions = GRAPHIFY_CONTRACT_FUNCTIONS
        .iter()
        .map(|(_, expected)| *expected)
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "use ::anyhow::{{Context, Result, bail}};\n{functions}\n#[cfg(target_os = \"linux\")]\nimpl LinuxGraphifyUnit {{\n{GRAPHIFY_SYSTEMD_COMMAND_CONTRACT}\n}}"
    )
}

fn reviewed_graphify_libc_probe_contract(
    file: &syn::File,
    content: &str,
) -> Option<Range<usize>> {
    let mut counts = GraphifyContractFunctionCounter::default();
    counts.visit_file(file);
    if counts.counts.iter().any(|count| *count != 1)
        || !graphify_macro_environment_is_exact(file)
    {
        return None;
    }

    let mut helper = None;
    for (name, expected) in GRAPHIFY_CONTRACT_FUNCTIONS {
        let mut matches = file.items.iter().filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident.to_string() == name => Some(function),
            _ => None,
        });
        let function = matches.next()?;
        if matches.next().is_some() || !graphify_function_tokens_match(content, function, expected) {
            return None;
        }
        if name == "verify_linux_graphify_address_family_denied" {
            helper = Some(function);
        }
    }
    if !graphify_systemd_command_contract_is_exact(file, content) {
        return None;
    }

    let mut socket_calls = AbsoluteLibcSocketCallCollector::default();
    socket_calls.visit_item_fn(helper?);
    let [socket_call] = socket_calls.ranges.as_slice() else {
        return None;
    };
    Some(socket_call.clone())
}

fn graphify_macro_environment_is_exact(file: &syn::File) -> bool {
    let mut security_bindings = Vec::new();
    let mut has_top_level_glob = false;
    for item in &file.items {
        let Item::Use(import) = item else {
            continue;
        };
        collect_named_use_bindings(
            &import.tree,
            &mut Vec::new(),
            import.leading_colon.is_some(),
            matches!(&import.vis, syn::Visibility::Inherited),
            &mut security_bindings,
            &mut has_top_level_glob,
        );
    }
    security_bindings.sort_by(|left, right| left.2.cmp(&right.2));
    let expected_security_bindings = vec![
        (
            true,
            true,
            vec!["anyhow".to_owned(), "Context".to_owned()],
        ),
        (
            true,
            true,
            vec!["anyhow".to_owned(), "Result".to_owned()],
        ),
        (
            true,
            true,
            vec!["anyhow".to_owned(), "bail".to_owned()],
        ),
    ];
    if has_top_level_glob || security_bindings != expected_security_bindings {
        return false;
    }

    let mut macros = BailMacroDefinitionVisitor::default();
    macros.visit_file(file);
    !macros.found
}

fn collect_named_use_bindings(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    absolute: bool,
    private: bool,
    security_bindings: &mut Vec<(bool, bool, Vec<String>)>,
    has_glob: &mut bool,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_named_use_bindings(
                &path.tree,
                prefix,
                absolute,
                private,
                security_bindings,
                has_glob,
            );
            prefix.pop();
        }
        UseTree::Name(name)
            if matches!(name.ident.to_string().as_str(), "Context" | "Result" | "bail") =>
        {
            let mut target = prefix.clone();
            target.push(name.ident.to_string());
            security_bindings.push((absolute, private, target));
        }
        UseTree::Rename(rename)
            if matches!(
                rename.rename.to_string().as_str(),
                "Context" | "Result" | "bail"
            ) =>
        {
            let mut target = prefix.clone();
            target.push(rename.ident.to_string());
            security_bindings.push((absolute, private, target));
        }
        UseTree::Group(group) => {
            for child in &group.items {
                collect_named_use_bindings(
                    child,
                    prefix,
                    absolute,
                    private,
                    security_bindings,
                    has_glob,
                );
            }
        }
        UseTree::Glob(_) => *has_glob = true,
        UseTree::Name(_) | UseTree::Rename(_) => {}
    }
}

#[derive(Default)]
struct BailMacroDefinitionVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for BailMacroDefinitionVisitor {
    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if item
            .ident
            .as_ref()
            .is_some_and(|name| name.to_string() == "bail")
        {
            self.found = true;
        }
        visit::visit_item_macro(self, item);
    }
}

fn graphify_function_tokens_match(
    content: &str,
    function: &syn::ItemFn,
    expected: &str,
) -> bool {
    let start = function
        .attrs
        .iter()
        .find(|attribute| !attribute.path().is_ident("doc"))
        .map(|attribute| attribute.span())
        .or_else(|| match &function.vis {
            syn::Visibility::Inherited => None,
            visibility => Some(visibility.span()),
        })
        .unwrap_or_else(|| function.sig.span())
        .byte_range()
        .start;
    let end = function.block.span().byte_range().end;
    graphify_source_tokens_match(content, start..end, expected)
}

fn graphify_impl_function_tokens_match(
    content: &str,
    function: &syn::ImplItemFn,
    expected: &str,
) -> bool {
    let start = function
        .attrs
        .iter()
        .find(|attribute| !attribute.path().is_ident("doc"))
        .map(|attribute| attribute.span())
        .or_else(|| match &function.vis {
            syn::Visibility::Inherited => None,
            visibility => Some(visibility.span()),
        })
        .unwrap_or_else(|| function.sig.span())
        .byte_range()
        .start;
    let end = function.block.span().byte_range().end;
    graphify_source_tokens_match(content, start..end, expected)
}

fn graphify_source_tokens_match(content: &str, range: Range<usize>, expected: &str) -> bool {
    let Some(actual) = content.get(range) else {
        return false;
    };
    let Ok(actual) = actual.parse::<proc_macro2::TokenStream>() else {
        return false;
    };
    let Ok(expected) = expected.parse::<proc_macro2::TokenStream>() else {
        return false;
    };
    actual.to_string() == expected.to_string()
}

fn graphify_systemd_command_contract_is_exact(file: &syn::File, content: &str) -> bool {
    let commands = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if graphify_linux_cfg_is_exact(&implementation.attrs)
                    && matches!(
                        &*implementation.self_ty,
                        Type::Path(path)
                            if path.qself.is_none() && path.path.is_ident("LinuxGraphifyUnit")
                    ) => Some(implementation),
            _ => None,
        })
        .flat_map(|implementation| implementation.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident.to_string() == "command" => {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [command] = commands.as_slice() else {
        return false;
    };
    graphify_impl_function_tokens_match(content, command, GRAPHIFY_SYSTEMD_COMMAND_CONTRACT)
}

fn graphify_linux_cfg_is_exact(attributes: &[Attribute]) -> bool {
    let [attribute] = attributes else {
        return false;
    };
    if !attribute.path().is_ident("cfg") {
        return false;
    }
    let Ok(Meta::NameValue(predicate)) = attribute.parse_args::<Meta>() else {
        return false;
    };
    predicate.path.is_ident("target_os")
        && matches!(
            predicate.value,
            Expr::Lit(ref literal)
                if matches!(&literal.lit, syn::Lit::Str(value) if value.value() == "linux")
        )
}

#[derive(Default)]
struct GraphifyContractFunctionCounter {
    counts: [usize; GRAPHIFY_CONTRACT_FUNCTIONS.len()],
}

impl<'ast> Visit<'ast> for GraphifyContractFunctionCounter {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        for (index, (name, _)) in GRAPHIFY_CONTRACT_FUNCTIONS.iter().enumerate() {
            if function.sig.ident.to_string() == *name {
                self.counts[index] += 1;
            }
        }
        visit::visit_item_fn(self, function);
    }
}

#[derive(Default)]
struct AbsoluteLibcSocketCallCollector {
    ranges: Vec<Range<usize>>,
}

impl<'ast> Visit<'ast> for AbsoluteLibcSocketCallCollector {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if absolute_call_path_is(call, &["libc", "socket"]) {
            self.ranges.push(call.span().byte_range());
        }
        visit::visit_expr_call(self, call);
    }
}

fn absolute_call_path_is(call: &syn::ExprCall, expected: &[&str]) -> bool {
    let Expr::Path(function) = &*call.func else {
        return false;
    };
    let actual = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    call.attrs.is_empty()
        && function.attrs.is_empty()
        && function.qself.is_none()
        && function.path.leading_colon.is_some()
        && actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
}

#[derive(Clone)]
struct Scope {
    aliases: HashMap<String, Vec<String>>,
    kind: ScopeKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Crate,
    Module,
    Other,
}

impl Scope {
    fn crate_root() -> Self {
        Self {
            aliases: HashMap::new(),
            kind: ScopeKind::Crate,
        }
    }

    fn module() -> Self {
        Self {
            aliases: HashMap::new(),
            kind: ScopeKind::Module,
        }
    }

    fn other() -> Self {
        Self {
            aliases: HashMap::new(),
            kind: ScopeKind::Other,
        }
    }
}

fn collect_use_aliases(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    scopes: &[Scope],
    aliases: &mut HashMap<String, Vec<String>>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_aliases(&path.tree, prefix, scopes, aliases);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let mut target = prefix.clone();
            if name.ident == "self" {
                target = prefix.clone();
            } else {
                target.push(name.ident.to_string());
            }
            // In `use x::{self, Y}`, `self` imports the module as its final
            // prefix segment (`x`), not under the literal local name `self`.
            // Keeping that binding name makes later `x::Y` resolution match
            // Rust's actual import semantics.
            let local_name = if name.ident == "self" {
                prefix
                    .last()
                    .expect("a `self` use-tree always has a prefix")
                    .clone()
            } else {
                name.ident.to_string()
            };
            // `use serde_json;` means the path is already directly spelled
            // `serde_json`; retaining `serde_json -> serde_json` turns every
            // later lookup into a synthetic cycle.  It adds no resolution
            // information, so do not record exact identity bindings.
            let is_identity = target.len() == 1 && target.first() == Some(&local_name);
            if !is_identity {
                aliases.insert(local_name, target);
            }
        }
        UseTree::Rename(rename) => {
            let mut target = prefix.clone();
            if rename.ident != "self" {
                target.push(rename.ident.to_string());
            }
            aliases.insert(rename.rename.to_string(), target);
        }
        UseTree::Group(group) => {
            for child in &group.items {
                collect_use_aliases(child, prefix, scopes, aliases);
            }
        }
        UseTree::Glob(_) => match resolve_segments(prefix, scopes)
            .unwrap_or_else(|_| prefix.clone())
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["reqwest"] => {
                for name in ["Client", "ClientBuilder", "Url", "get"] {
                    aliases.insert(
                        name.to_string(),
                        vec!["reqwest".to_string(), name.to_string()],
                    );
                }
            }
            ["reqwest", "blocking"] => {
                for name in ["Client", "get"] {
                    aliases.insert(
                        name.to_string(),
                        vec![
                            "reqwest".to_string(),
                            "blocking".to_string(),
                            name.to_string(),
                        ],
                    );
                }
            }
            ["std", "net"] | ["tokio", "net"] => {
                for name in ["TcpStream", "TcpSocket", "UdpSocket"] {
                    aliases.insert(
                        name.to_string(),
                        prefix.iter().cloned().chain([name.to_string()]).collect(),
                    );
                }
            }
            ["tokio_tungstenite"] => {
                aliases.insert(
                    "connect_async".to_string(),
                    vec!["tokio_tungstenite".to_string(), "connect_async".to_string()],
                );
            }
            ["libc"] => {
                for name in [
                    "socket",
                    "connect",
                    "syscall",
                    "AF_UNIX",
                    "AF_INET",
                    "AF_INET6",
                    "SYS_socket",
                    "SYS_connect",
                    "SYS_pidfd_open",
                    "SYS_close_range",
                ] {
                    aliases.insert(name.to_string(), vec!["libc".to_string(), name.to_string()]);
                }
            }
            ["cluster", "hyperswarm"] => {
                aliases.insert(
                    "spawn_public_rendezvous".to_string(),
                    vec![
                        "cluster".to_string(),
                        "hyperswarm".to_string(),
                        "spawn_public_rendezvous".to_string(),
                    ],
                );
            }
            path if path.last() == Some(&"WinSock") => {
                for name in [
                    "socket",
                    "connect",
                    "WSASocketA",
                    "WSASocketW",
                    "WSAConnect",
                ] {
                    aliases.insert(
                        name.to_string(),
                        prefix.iter().cloned().chain([name.to_string()]).collect(),
                    );
                }
            }
            _ => {}
        },
    }
}

fn resolve_path(path: &syn::Path, scopes: &[Scope]) -> Result<Vec<String>, ()> {
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    resolve_segments(&segments, scopes)
}

fn resolve_expr_path(expression: &syn::ExprPath, scopes: &[Scope]) -> Result<Vec<String>, ()> {
    if expression.qself.is_none() {
        return resolve_path(&expression.path, scopes);
    }
    let mut segments = match expression.qself.as_ref().map(|qself| &*qself.ty) {
        Some(Type::Path(type_path)) if type_path.qself.is_none() => {
            resolve_path(&type_path.path, scopes)?
        }
        _ => return Ok(Vec::new()),
    };
    let qself_position = expression.qself.as_ref().expect("checked qself").position;
    segments.extend(
        expression
            .path
            .segments
            .iter()
            .skip(qself_position)
            .map(|segment| segment.ident.to_string()),
    );
    Ok(segments)
}

fn resolve_segments(original: &[String], scopes: &[Scope]) -> Result<Vec<String>, ()> {
    resolve_segments_with_seen(original.to_vec(), scopes, &mut HashSet::new())
}

fn resolve_segments_with_seen(
    mut segments: Vec<String>,
    scopes: &[Scope],
    seen: &mut HashSet<String>,
) -> Result<Vec<String>, ()> {
    if let Some(first) = segments.first().map(String::as_str) {
        match first {
            "self" => {
                segments.remove(0);
                let Some(current_module) = scopes
                    .iter()
                    .rposition(|scope| scope.kind != ScopeKind::Other)
                else {
                    return Err(());
                };
                return resolve_segments_with_seen(segments, &scopes[..=current_module], seen);
            }
            "super" => {
                segments.remove(0);
                let module_scopes = scopes
                    .iter()
                    .enumerate()
                    .filter_map(|(index, scope)| (scope.kind != ScopeKind::Other).then_some(index))
                    .collect::<Vec<_>>();
                // Each source file is scanned in isolation, so a module file
                // can legitimately have only its local crate-root scope.  Its
                // lexical parent is unavailable in that per-file model.  Do
                // not re-enter the same scope (which turns `use super::X`
                // into a self-cycle); preserve the remaining path so known
                // external bases such as `super::reqwest` still resolve.
                if module_scopes.len() < 2 {
                    return Ok(segments);
                }
                let parent_module = module_scopes[module_scopes.len() - 2];
                return resolve_segments_with_seen(segments, &scopes[..=parent_module], seen);
            }
            "crate" => {
                segments.remove(0);
                let Some(root_module) = scopes
                    .iter()
                    .position(|scope| scope.kind == ScopeKind::Crate)
                else {
                    return Err(());
                };
                return resolve_segments_with_seen(segments, &scopes[..=root_module], seen);
            }
            _ => {}
        }
    }

    loop {
        let Some(first) = segments.first().cloned() else {
            return Ok(segments);
        };
        let Some((scope_index, alias)) =
            scopes
                .iter()
                .enumerate()
                .rev()
                .find_map(|(scope_index, scope)| {
                    scope.aliases.get(&first).map(|alias| (scope_index, alias))
                })
        else {
            return Ok(segments);
        };
        // `use crate::A` at crate scope creates the syntactic alias
        // `A -> crate::A`. It is a terminal spelling of the root item, not a
        // second alias expansion; otherwise resolving it recurses forever.
        // The identical spelling in a nested scope must *not* terminalize: it
        // still has to re-enter the crate scope so a real root alias can be
        // resolved.
        if scopes[scope_index].kind == ScopeKind::Crate
            && alias.len() == 2
            && alias[0] == "crate"
            && alias[1] == first
        {
            return Ok(segments);
        }
        if !seen.insert(first) {
            return Err(());
        }
        segments.splice(0..1, alias.clone());
        if matches!(
            segments.first().map(String::as_str),
            Some("self" | "super" | "crate")
        ) {
            return resolve_segments_with_seen(segments, scopes, seen);
        }
    }
}

fn macro_token_paths(input: &proc_macro2::TokenStream) -> Vec<Vec<String>> {
    fn flatten(tokens: proc_macro2::TokenStream, output: &mut Vec<String>) {
        let mut tokens = tokens.into_iter().peekable();
        while let Some(token) = tokens.next() {
            match token {
                TokenTree::Ident(identifier) => output.push(identifier.to_string()),
                TokenTree::Punct(punctuation) if punctuation.as_char() == ':' => {
                    if matches!(tokens.peek(), Some(TokenTree::Punct(next)) if next.as_char() == ':')
                    {
                        tokens.next();
                        output.push("::".to_string());
                    } else {
                        output.push(";".to_string());
                    }
                }
                TokenTree::Group(group) => {
                    flatten(group.stream(), output);
                    output.push(";".to_string());
                }
                _ => output.push(";".to_string()),
            }
        }
    }

    let mut flat = Vec::new();
    flatten(input.clone(), &mut flat);
    let mut paths = Vec::new();
    for start in 0..flat.len() {
        for end in start + 1..=flat.len().min(start + 11) {
            let candidate = &flat[start..end];
            if candidate.iter().any(|token| token == ";") {
                break;
            }
            let mut path = Vec::new();
            let mut expect_ident = true;
            for token in candidate {
                if expect_ident {
                    if token == "::" {
                        break;
                    }
                    path.push(token.clone());
                } else if token != "::" {
                    break;
                }
                expect_ident = !expect_ident;
            }
            if !expect_ident && !path.is_empty() {
                paths.push(path);
            }
        }
    }
    paths
}

struct ProductionNetworkVisitor<'source> {
    content: &'source str,
    test_only_ranges: &'source [Range<usize>],
    scopes: Vec<Scope>,
    socket_bindings: Vec<HashMap<String, BindingKind>>,
    macro_rule_scopes: Vec<HashMap<String, MacroRuleNetworkSummary>>,
    allows_audit_rpc_af_unix: bool,
    allows_stt_pidfd_syscalls: bool,
    allows_graphify_denial_probe: bool,
    reviewed_graphify_socket_call: Option<Range<usize>>,
    function_names: Vec<String>,
    violations: Vec<(usize, &'static str)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    Socket,
    DhtStartup,
    DhtSwarm,
    Other,
}

#[derive(Clone, Copy, Default)]
struct MacroRuleNetworkSummary {
    metavariable_base: bool,
    guarded_terminal: bool,
}

impl ProductionNetworkVisitor<'_> {
    fn is_test_only<T: Spanned>(&self, node: &T) -> bool {
        let range = node.span().byte_range();
        self.test_only_ranges
            .iter()
            .any(|test| test.start <= range.start && range.end <= test.end)
    }

    fn report<T: Spanned>(&mut self, node: &T, pattern: &'static str) {
        if !self.is_test_only(node) {
            self.violations.push((
                line_number_at_offset(self.content, node.span().byte_range().start),
                pattern,
            ));
        }
    }

    fn in_scope(&mut self, f: impl FnOnce(&mut Self)) {
        self.scopes.push(Scope::other());
        self.socket_bindings.push(HashMap::new());
        self.macro_rule_scopes.push(HashMap::new());
        f(self);
        self.scopes.pop();
        self.socket_bindings.pop();
        self.macro_rule_scopes.pop();
    }

    fn in_module_scope(&mut self, f: impl FnOnce(&mut Self)) {
        self.scopes.push(Scope::module());
        self.socket_bindings.push(HashMap::new());
        self.macro_rule_scopes.push(HashMap::new());
        f(self);
        self.scopes.pop();
        self.socket_bindings.pop();
        self.macro_rule_scopes.pop();
    }

    fn current_scope(&mut self) -> &mut HashMap<String, Vec<String>> {
        self.scopes
            .last_mut()
            .map(|scope| &mut scope.aliases)
            .expect("file scope is always present")
    }

    fn mark_network_binding(&mut self, local: &Local) {
        if self.is_test_only(local) {
            return;
        }
        let kind = match &local.init {
            Some(initializer) => network_constructor_kind(&initializer.expr, &self.scopes),
            None => BindingKind::Other,
        };
        let kind = if kind == BindingKind::Other
            && local
                .init
                .as_ref()
                .is_some_and(|initializer| self.expression_is_dht_startup_finish(&initializer.expr))
        {
            // `SwarmStartup::finish` transfers the explicit bootstrap owner
            // into the historic tuple, whose second member is the DHT swarm
            // command handle. Preserve join tracking across that transfer.
            BindingKind::DhtSwarm
        } else {
            kind
        };
        let bindings = self
            .socket_bindings
            .last_mut()
            .expect("binding scope is always present");
        match &local.pat {
            syn::Pat::Ident(binding) => {
                bindings.insert(binding.ident.to_string(), kind);
            }
            // `peeroxide::spawn(...).await` returns the swarm handle as the
            // second tuple member. Record that exact binding so `.join(...)`
            // is guarded without treating unrelated joins as DHT construction.
            syn::Pat::Tuple(tuple) if kind == BindingKind::DhtSwarm => {
                if let Some(syn::Pat::Ident(binding)) = tuple.elems.iter().nth(1) {
                    bindings.insert(binding.ident.to_string(), kind);
                }
            }
            _ => {}
        }
    }

    fn is_proven_socket_binding(&self, expression: &syn::Expr) -> bool {
        let Expr::Path(path) = expression else {
            return false;
        };
        let Some(identifier) = path.path.get_ident() else {
            return false;
        };
        self.socket_bindings
            .iter()
            .rev()
            .find_map(|bindings| bindings.get(&identifier.to_string()).copied())
            == Some(BindingKind::Socket)
    }

    fn is_proven_dht_swarm_binding(&self, expression: &syn::Expr) -> bool {
        self.binding_kind(expression) == Some(BindingKind::DhtSwarm)
    }

    fn is_proven_dht_startup_binding(&self, expression: &syn::Expr) -> bool {
        self.binding_kind(expression) == Some(BindingKind::DhtStartup)
    }

    fn binding_kind(&self, expression: &syn::Expr) -> Option<BindingKind> {
        let Expr::Path(path) = expression else {
            return None;
        };
        let identifier = path.path.get_ident()?;
        self.socket_bindings
            .iter()
            .rev()
            .find_map(|bindings| bindings.get(&identifier.to_string()).copied())
    }

    fn expression_is_dht_startup_finish(&self, expression: &Expr) -> bool {
        let expression = peel_network_expression(expression);
        match expression {
            Expr::MethodCall(call) => {
                call.method == "finish" && self.is_proven_dht_startup_binding(&call.receiver)
            }
            Expr::Match(expression) => self.expression_is_dht_startup_finish(&expression.expr),
            _ => false,
        }
    }

    fn in_audit_rpc_unix_socket_boundary(&self) -> bool {
        self.allows_audit_rpc_af_unix
            && self
                .function_names
                .last()
                .is_some_and(|name| name == "connect_std_with_deadline")
    }

    fn is_reviewed_stt_syscall(&self, call: &syn::ExprCall) -> bool {
        self.allows_stt_pidfd_syscalls
            && self
                .function_names
                .last()
                .is_some_and(|name| name == "configure")
            && call.args.first().is_some_and(|argument| {
                let Expr::Path(path) = argument else {
                    return false;
                };
                resolve_expr_path(path, &self.scopes).is_ok_and(|path| {
                    matches!(
                        path.as_slice(),
                        [first, second]
                            if first == "libc"
                                && matches!(second.as_str(), "SYS_pidfd_open" | "SYS_close_range")
                    )
                })
            })
    }

    fn record_use(&mut self, item: &syn::ItemUse) {
        if self.is_test_only(item) {
            return;
        }
        let scopes = &self.scopes;
        let mut aliases = HashMap::new();
        collect_use_aliases(&item.tree, &mut Vec::new(), scopes, &mut aliases);
        self.current_scope().extend(aliases);
    }

    fn record_type_alias(&mut self, item: &syn::ItemType) {
        if self.is_test_only(item) {
            return;
        }
        if let Type::Path(type_path) = &*item.ty
            && type_path.qself.is_none()
        {
            match resolve_path(&type_path.path, &self.scopes) {
                Ok(path) => {
                    self.current_scope().insert(item.ident.to_string(), path);
                }
                Err(()) => self.report(item, "cyclic type alias"),
            }
        }
    }

    fn precollect_scope_items(&mut self, items: &[Item]) {
        // Rust name resolution does not make `use` and type aliases depend on
        // their textual order. Iterate to a fixed point so a later module alias
        // can also unlock an earlier glob import.
        loop {
            let before = self.current_scope().len();
            for item in items {
                match item {
                    Item::Use(item) => self.record_use(item),
                    Item::Type(item) => self.record_type_alias(item),
                    _ => {}
                }
            }
            if self.current_scope().len() == before {
                break;
            }
        }
    }

    fn precollect_scope_statements(&mut self, statements: &[syn::Stmt]) {
        let items = statements
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Item(item) => Some(item.clone()),
                syn::Stmt::Local(_) | syn::Stmt::Expr(_, _) | syn::Stmt::Macro(_) => None,
            })
            .collect::<Vec<_>>();
        self.precollect_scope_items(&items);
    }

    fn macro_contains_network_path(&self, tokens: &proc_macro2::TokenStream) -> bool {
        let direct_path = macro_token_paths(tokens).iter().any(|path| {
            resolve_segments(path, &self.scopes)
                .is_ok_and(|path| forbidden_constructor(&path).is_some())
        });
        direct_path
            || macro_tokens_forward_raw_socket(tokens, &self.scopes)
            || macro_groups_contain_network_path(tokens, &self.scopes, self.content)
    }

    fn macro_invocation_constructs_guarded_type(
        &self,
        macro_name: Option<&syn::Ident>,
        is_qualified: bool,
        tokens: &proc_macro2::TokenStream,
    ) -> bool {
        let summary = macro_name.and_then(|name| {
            self.macro_rule_scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(&name.to_string()))
        });
        let mut identifiers = Vec::new();
        collect_macro_identifiers(tokens, &mut identifiers);

        let resolves_guarded_base = identifiers.iter().any(|identifier| {
            resolve_segments(std::slice::from_ref(identifier), &self.scopes)
                .is_ok_and(|path| guarded_network_base(&path))
        }) || macro_token_paths(tokens).iter().any(|path| {
            resolve_segments(path, &self.scopes).is_ok_and(|path| guarded_network_base(&path))
        });

        let has_terminal = identifiers
            .iter()
            .any(|identifier| guarded_macro_constructor_terminal(identifier));
        resolves_guarded_base
            && match summary {
                Some(summary) => {
                    summary.metavariable_base && (summary.guarded_terminal || has_terminal)
                }
                // Re-exported qualified macros can outlive their lexical
                // definition scope. A guarded base therefore fails closed:
                // `types::register!(ClientAlias)` is an intentional, bounded
                // false positive until the macro becomes locally reviewable.
                None => is_qualified,
            }
    }

    fn record_macro_rule_summary(&mut self, item: &syn::ItemMacro) {
        let Some(name) = &item.ident else {
            return;
        };
        self.macro_rule_scopes
            .last_mut()
            .expect("macro-rule scope is present")
            .insert(
                name.to_string(),
                macro_rule_network_summary(&item.mac.tokens),
            );
    }
}

fn macro_tokens_forward_raw_socket(tokens: &proc_macro2::TokenStream, scopes: &[Scope]) -> bool {
    macro_token_paths(tokens).iter().any(|path| {
            resolve_segments(path, scopes).is_ok_and(|path| {
                matches!(path.as_slice(), [first, second] if first == "libc" && matches!(second.as_str(), "socket" | "connect"))
                    || (matches!(path.first().map(String::as_str), Some("windows" | "windows_sys"))
                        && path.windows(2).any(|pair| {
                            pair[0] == "WinSock"
                                && matches!(pair[1].as_str(), "socket" | "connect" | "WSASocketA" | "WSASocketW" | "WSAConnect")
                        }))
            })
        })
}

fn macro_rule_network_summary(tokens: &proc_macro2::TokenStream) -> MacroRuleNetworkSummary {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut summary = MacroRuleNetworkSummary::default();
    for index in 0..tokens.len() {
        let is_metavariable_base = matches!(&tokens[index], TokenTree::Punct(punctuation) if punctuation.as_char() == '$')
            && matches!(tokens.get(index + 1), Some(TokenTree::Ident(_)))
            && matches!(
                (tokens.get(index + 2), tokens.get(index + 3)),
                (Some(TokenTree::Punct(first)), Some(TokenTree::Punct(second)))
                    if first.as_char() == ':' && second.as_char() == ':'
            );
        if is_metavariable_base {
            summary.metavariable_base = true;
            if let Some(TokenTree::Ident(terminal)) = tokens.get(index + 4) {
                summary.guarded_terminal |=
                    guarded_macro_constructor_terminal(&terminal.to_string());
            }
        }
        if let TokenTree::Group(group) = &tokens[index] {
            let nested = macro_rule_network_summary(&group.stream());
            summary.metavariable_base |= nested.metavariable_base;
            summary.guarded_terminal |= nested.guarded_terminal;
        }
    }
    summary
}

fn collect_macro_identifiers(tokens: &proc_macro2::TokenStream, output: &mut Vec<String>) {
    for token in tokens.clone() {
        match token {
            TokenTree::Ident(identifier) => output.push(identifier.to_string()),
            TokenTree::Group(group) => collect_macro_identifiers(&group.stream(), output),
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

fn guarded_macro_constructor_terminal(identifier: &str) -> bool {
    matches!(
        identifier,
        "new" | "builder" | "default" | "get" | "parse" | "connect" | "bind" | "new_v4" | "new_v6"
    )
}

fn guarded_network_base(path: &[String]) -> bool {
    matches!(
        path.iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        ["reqwest", "Client"]
            | ["reqwest", "ClientBuilder"]
            | ["reqwest", "Url"]
            | ["reqwest", "blocking", "Client"]
            | ["std", "net", "TcpStream"]
            | ["tokio", "net", "TcpStream"]
            | ["tokio", "net", "TcpSocket"]
            | ["std", "net", "UdpSocket"]
            | ["tokio", "net", "UdpSocket"]
            | ["tungstenite"]
    )
}

fn macro_groups_contain_network_path(
    tokens: &proc_macro2::TokenStream,
    scopes: &[Scope],
    source: &str,
) -> bool {
    for token in tokens.clone() {
        let TokenTree::Group(group) = token else {
            continue;
        };
        if group.delimiter() == Delimiter::Brace {
            let wrapped = proc_macro2::TokenStream::from(TokenTree::Group(group.clone()));
            if let Ok(block) = syn::parse2::<syn::Block>(wrapped) {
                let mut visitor = ProductionNetworkVisitor {
                    content: source,
                    test_only_ranges: &[],
                    scopes: scopes.to_vec(),
                    socket_bindings: vec![HashMap::new(); scopes.len()],
                    macro_rule_scopes: vec![HashMap::new(); scopes.len()],
                    allows_audit_rpc_af_unix: false,
                    allows_stt_pidfd_syscalls: false,
                    allows_graphify_denial_probe: false,
                    reviewed_graphify_socket_call: None,
                    function_names: Vec::new(),
                    violations: Vec::new(),
                };
                visitor.visit_block(&block);
                if !visitor.violations.is_empty() {
                    return true;
                }
            } else if macro_tokens_look_network_capable(&group.stream()) {
                // A source-generating group that mentions a dial-capable name
                // but cannot be structurally parsed is not trusted.
                return true;
            }
        }
        if macro_groups_contain_network_path(&group.stream(), scopes, source) {
            return true;
        }
    }
    false
}

fn macro_tokens_look_network_capable(tokens: &proc_macro2::TokenStream) -> bool {
    let names = tokens
        .clone()
        .into_iter()
        .filter_map(|token| match token {
            TokenTree::Ident(identifier) => Some(identifier.to_string()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    [
        "reqwest",
        "TcpStream",
        "TcpSocket",
        "UdpSocket",
        "tokio_tungstenite",
        "tungstenite",
        "connect",
        "connect_async",
        "Client",
        "ClientBuilder",
    ]
    .iter()
    .any(|name| names.contains(*name))
}

fn network_constructor_kind(expression: &Expr, scopes: &[Scope]) -> BindingKind {
    if let Some(kind) = expression_contains_peeroxide_spawn(expression, scopes) {
        return kind;
    }
    let expression = peel_network_expression(expression);
    let Expr::Call(call) = expression else {
        return BindingKind::Other;
    };
    let Expr::Path(path) = &*call.func else {
        return BindingKind::Other;
    };
    let Ok(path) = resolve_expr_path(path, scopes) else {
        return BindingKind::Other;
    };
    let parts = path.iter().map(String::as_str).collect::<Vec<_>>();
    if matches!(
        parts.as_slice(),
        ["tokio", "net", "TcpSocket", "new_v4" | "new_v6"]
            | ["std", "net", "UdpSocket", "bind"]
            | ["tokio", "net", "UdpSocket", "bind"]
    ) {
        BindingKind::Socket
    } else {
        BindingKind::Other
    }
}

fn peel_network_expression(expression: &Expr) -> &Expr {
    match expression {
        Expr::Await(awaited) => peel_network_expression(&awaited.base),
        Expr::Try(tried) => peel_network_expression(&tried.expr),
        Expr::MethodCall(call)
            if call.method == "unwrap"
                || call.method == "expect"
                || call.method == "map_err"
                || call.method == "context"
                || call.method == "with_context" =>
        {
            peel_network_expression(&call.receiver)
        }
        Expr::Paren(paren) => peel_network_expression(&paren.expr),
        Expr::Group(group) => peel_network_expression(&group.expr),
        expression => expression,
    }
}

fn expression_contains_peeroxide_spawn(expression: &Expr, scopes: &[Scope]) -> Option<BindingKind> {
    let expression = peel_network_expression(expression);
    match expression {
        Expr::Call(call) => match &*call.func {
            Expr::Path(path)
                if resolve_expr_path(path, scopes).is_ok_and(
                    |path| matches!(path.as_slice(), [first, second] if first == "peeroxide" && second == "spawn"),
                ) =>
            {
                Some(BindingKind::DhtSwarm)
            }
            Expr::Path(path)
                if resolve_expr_path(path, scopes).is_ok_and(
                    |path| matches!(path.as_slice(), [first, second] if first == "peeroxide" && second == "spawn_starting"),
                ) =>
            {
                Some(BindingKind::DhtStartup)
            }
            _ => None,
        },
        Expr::Match(expression) => expression_contains_peeroxide_spawn(&expression.expr, scopes),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for ProductionNetworkVisitor<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.precollect_scope_items(&file.items);
        visit::visit_file(self, file);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if is_libc_syscall(call, &self.scopes) && !self.is_reviewed_stt_syscall(call) {
            self.report(call, "libc::syscall");
        }
        if let Some(pattern) = raw_socket_constructor(call, &self.scopes) {
            let is_reviewed_unix_ipc = self.in_audit_rpc_unix_socket_boundary()
                && ((pattern == "libc::socket"
                    && call
                        .args
                        .first()
                        .is_some_and(|argument| is_libc_af_unix(argument, &self.scopes)))
                    || pattern == "libc::connect");
            let is_reviewed_graphify_probe = self.allows_graphify_denial_probe
                && pattern == "libc::socket"
                && self
                    .reviewed_graphify_socket_call
                    .as_ref()
                    .is_some_and(|range| *range == call.span().byte_range());
            if !is_reviewed_graphify_probe && !is_reviewed_unix_ipc {
                self.report(call, pattern);
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        match resolve_expr_path(expression, &self.scopes) {
            Ok(path) => {
                if let Some(pattern) = forbidden_constructor(&path)
                    && pattern != "libc::syscall"
                {
                    self.report(expression, pattern);
                }
            }
            Err(()) => self.report(expression, "cyclic network alias"),
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "connect" && self.is_proven_socket_binding(&call.receiver) {
            self.report(call, "socket instance .connect");
        }
        if call.method == "join" && self.is_proven_dht_swarm_binding(&call.receiver) {
            self.report(call, "peeroxide SwarmHandle .join");
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        if expression.mac.path.is_ident("include") {
            self.report(expression, "production include! macro");
        } else if is_inline_assembly_macro_path(&expression.mac.path, &self.scopes) {
            self.report(expression, "production inline assembly macro");
        } else if self.macro_contains_network_path(&expression.mac.tokens)
            || self.macro_invocation_constructs_guarded_type(
                expression
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|segment| &segment.ident),
                expression.mac.path.segments.len() > 1,
                &expression.mac.tokens,
            )
        {
            self.report(expression, "network construction in macro token stream");
        }
        visit::visit_expr_macro(self, expression);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if item.mac.path.is_ident("macro_rules") {
            self.record_macro_rule_summary(item);
        }
        if item.mac.path.is_ident("include") {
            self.report(item, "production include! macro");
        } else if is_inline_assembly_macro_path(&item.mac.path, &self.scopes) {
            self.report(item, "production inline assembly macro");
        } else if self.macro_contains_network_path(&item.mac.tokens)
            || (!item.mac.path.is_ident("macro_rules")
                && self.macro_invocation_constructs_guarded_type(
                    item.mac.path.segments.last().map(|segment| &segment.ident),
                    item.mac.path.segments.len() > 1,
                    &item.mac.tokens,
                ))
        {
            self.report(item, "network construction in macro token stream");
        }
        visit::visit_item_macro(self, item);
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if statement.mac.path.is_ident("include") {
            self.report(statement, "production include! macro");
        } else if is_inline_assembly_macro_path(&statement.mac.path, &self.scopes) {
            self.report(statement, "production inline assembly macro");
        } else if self.macro_contains_network_path(&statement.mac.tokens)
            || self.macro_invocation_constructs_guarded_type(
                statement
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|segment| &segment.ident),
                statement.mac.path.segments.len() > 1,
                &statement.mac.tokens,
            )
        {
            self.report(statement, "network construction in macro token stream");
        }
        visit::visit_stmt_macro(self, statement);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.record_use(item);
        visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.record_type_alias(item);
        visit::visit_item_type(self, item);
    }

    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        if !self.is_test_only(item)
            && item.items.iter().any(|foreign| {
                matches!(
                    foreign,
                    ForeignItem::Fn(function)
                        if raw_socket_ffi_name(&function.sig.ident.to_string())
                            || function.attrs.iter().any(|attribute| {
                                attribute.path().is_ident("link_name")
                                    && matches!(
                                        &attribute.meta,
                                        Meta::NameValue(value)
                                            if matches!(&value.value,
                                                Expr::Lit(literal)
                                                    if matches!(&literal.lit,
                                                        syn::Lit::Str(name) if raw_socket_ffi_name(&name.value())))
                                    )
                            })
                )
            })
        {
            self.report(item, "raw socket FFI declaration");
        }
        visit::visit_item_foreign_mod(self, item);
    }

    fn visit_local(&mut self, local: &'ast Local) {
        self.mark_network_binding(local);
        visit::visit_local(self, local);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if self.is_test_only(item) {
            return;
        }
        self.in_module_scope(|visitor| {
            if let Some((_, items)) = &item.content {
                visitor.precollect_scope_items(items);
            }
            visit::visit_item_mod(visitor, item);
        });
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if self.is_test_only(item) {
            return;
        }
        self.in_scope(|visitor| visit::visit_item_impl(visitor, item));
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if self.is_test_only(item) {
            return;
        }
        self.in_scope(|visitor| visit::visit_item_trait(visitor, item));
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if self.is_test_only(item) {
            return;
        }
        self.function_names.push(item.sig.ident.to_string());
        self.in_scope(|visitor| {
            visitor.precollect_scope_statements(&item.block.stmts);
            visit::visit_item_fn(visitor, item);
        });
        self.function_names.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if self.is_test_only(item) {
            return;
        }
        self.function_names.push(item.sig.ident.to_string());
        self.in_scope(|visitor| {
            visitor.precollect_scope_statements(&item.block.stmts);
            visit::visit_impl_item_fn(visitor, item);
        });
        self.function_names.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if self.is_test_only(item) {
            return;
        }
        self.in_scope(|visitor| {
            if let Some(default) = &item.default {
                visitor.precollect_scope_statements(&default.stmts);
            }
            visit::visit_trait_item_fn(visitor, item);
        });
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.in_scope(|visitor| {
            visitor.precollect_scope_statements(&block.stmts);
            visit::visit_block(visitor, block);
        });
    }
}

fn raw_socket_ffi_name(name: &str) -> bool {
    matches!(
        name,
        "socket"
            | "connect"
            | "syscall"
            | "WSASocketA"
            | "WSASocketW"
            | "WSAConnect"
            | "WSAConnectByList"
            | "WSAConnectByNameA"
            | "WSAConnectByNameW"
    )
}

fn forbidden_constructor(path: &[String]) -> Option<&'static str> {
    let parts = path.iter().map(String::as_str).collect::<Vec<_>>();
    match parts.as_slice() {
        ["reqwest", "Client", "new"] => Some("reqwest::Client::new"),
        ["reqwest", "Client", "builder"] => Some("reqwest::Client::builder"),
        ["reqwest", "Client", "default"] => Some("reqwest::Client::default"),
        ["reqwest", "ClientBuilder", "new"] => Some("reqwest::ClientBuilder::new"),
        ["reqwest", "get"] => Some("reqwest::get"),
        ["reqwest", "Url", "parse"] => Some("reqwest::Url::parse"),
        ["reqwest", "blocking", "Client", "new"] => Some("reqwest::blocking::Client::new"),
        ["reqwest", "blocking", "Client", "builder"] => Some("reqwest::blocking::Client::builder"),
        ["reqwest", "blocking", "get"] => Some("reqwest::blocking::get"),
        ["std", "net", "TcpStream", "connect"] | ["tokio", "net", "TcpStream", "connect"] => {
            Some("TcpStream::connect")
        }
        ["std", "net", "TcpStream", "connect_timeout"]
        | ["tokio", "net", "TcpStream", "connect_timeout"] => Some("TcpStream::connect_timeout"),
        ["tokio", "net", "TcpSocket", "new_v4"] => Some("tokio::net::TcpSocket::new_v4"),
        ["tokio", "net", "TcpSocket", "new_v6"] => Some("tokio::net::TcpSocket::new_v6"),
        ["tokio", "net", "TcpSocket", "connect"] => Some("TcpSocket::connect"),
        ["std", "net", "UdpSocket", "bind"] => Some("std::net::UdpSocket::bind"),
        ["tokio", "net", "UdpSocket", "bind"] => Some("tokio::net::UdpSocket::bind"),
        ["std", "net", "UdpSocket", "connect"] | ["tokio", "net", "UdpSocket", "connect"] => {
            Some("UdpSocket::connect")
        }
        ["tokio_tungstenite", "connect_async"] => Some("tokio_tungstenite::connect_async"),
        ["tungstenite", "connect"] => Some("tungstenite::connect"),
        ["libc", "syscall"] => Some("libc::syscall"),
        ["peeroxide", "SwarmConfig", "with_public_bootstrap"] => {
            Some("peeroxide::SwarmConfig::with_public_bootstrap")
        }
        ["peeroxide", "spawn"] => Some("peeroxide::spawn"),
        ["peeroxide", "spawn_starting"] => Some("peeroxide::spawn_starting"),
        ["hyper", "client", ..] => Some("hyper::client"),
        _ => None,
    }
}

fn raw_socket_constructor(call: &syn::ExprCall, scopes: &[Scope]) -> Option<&'static str> {
    let Expr::Path(function) = &*call.func else {
        return None;
    };
    let path = resolve_expr_path(function, scopes).ok()?;
    let parts = path.iter().map(String::as_str).collect::<Vec<_>>();
    match parts.as_slice() {
        ["libc", "socket"] => Some("libc::socket"),
        ["libc", "connect"] => Some("libc::connect"),
        _ if matches!(parts.first().copied(), Some("windows" | "windows_sys"))
            && parts.windows(2).any(|window| {
                window[0] == "WinSock"
                    && matches!(
                        window[1],
                        "socket"
                            | "connect"
                            | "WSASocketA"
                            | "WSASocketW"
                            | "WSAConnect"
                            | "WSAConnectByList"
                            | "WSAConnectByNameA"
                            | "WSAConnectByNameW"
                    )
            }) =>
        {
            Some("Windows WinSock socket/connect")
        }
        _ => None,
    }
}

fn is_libc_syscall(call: &syn::ExprCall, scopes: &[Scope]) -> bool {
    let Expr::Path(function) = &*call.func else {
        return false;
    };
    resolve_expr_path(function, scopes).is_ok_and(
        |path| matches!(path.as_slice(), [first, second] if first == "libc" && second == "syscall"),
    )
}

fn is_inline_assembly_macro_path(path: &syn::Path, scopes: &[Scope]) -> bool {
    let is_assembly_name = |name: &str| matches!(name, "asm" | "global_asm");
    path.segments
        .last()
        .is_some_and(|segment| is_assembly_name(&segment.ident.to_string()))
        || resolve_path(path, scopes)
            .ok()
            .and_then(|resolved| resolved.last().cloned())
            .is_some_and(|name| is_assembly_name(&name))
}

fn is_libc_af_unix(argument: &Expr, scopes: &[Scope]) -> bool {
    let Expr::Path(path) = argument else {
        return false;
    };
    resolve_expr_path(path, scopes).is_ok_and(
        |path| matches!(path.as_slice(), [first, second] if first == "libc" && second == "AF_UNIX"),
    )
}

/// Exact byte ranges of AST nodes proved disabled with `test=false`.
///
/// Parsing gives each annotated node's span rather than a whole-line
/// approximation, so a production item following test code on the same line
/// remains in scope.  The visitor reaches ordinary items, associated items,
/// foreign items, trait items, and attributed local bindings. Unknown cfg
/// atoms remain in scope: only a false proof earns an exemption.
fn test_only_item_ranges(content: &str) -> Option<Vec<Range<usize>>> {
    let file = syn::parse_file(content).ok()?;
    let mut visitor = TestOnlySpanVisitor {
        content,
        ranges: Vec::new(),
    };
    visitor.visit_file(&file);
    Some(visitor.ranges)
}

struct TestOnlySpanVisitor<'source> {
    content: &'source str,
    ranges: Vec<Range<usize>>,
}

impl TestOnlySpanVisitor<'_> {
    /// Returns true when the complete visited node is test-only and has been
    /// recorded.  Its descendants cannot contain production code, so callers
    /// deliberately do not recurse in that case.
    fn record_if_test_only<T: Spanned>(&mut self, attrs: &[Attribute], node: &T) -> bool {
        if !item_is_guaranteed_disabled_in_production(attrs) {
            return false;
        }
        if let Some(range) = spanned_byte_range(self.content, attrs, node) {
            self.ranges.push(range);
            true
        } else {
            // A span that cannot be bounded is not exempted: fail closed.
            false
        }
    }
}

impl<'ast> Visit<'ast> for TestOnlySpanVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !self.record_if_test_only(item_attrs(item), item) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !self.record_if_test_only(impl_item_attrs(item), item) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if !self.record_if_test_only(trait_item_attrs(item), item) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast ForeignItem) {
        if !self.record_if_test_only(foreign_item_attrs(item), item) {
            visit::visit_foreign_item(self, item);
        }
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if !self.record_if_test_only(&local.attrs, local) {
            visit::visit_local(self, local);
        }
    }
}

/// Conservative three-valued `cfg` projection for this source gate's
/// production model (`test=false`). `test` is false, unknown platform/feature
/// atoms stay unknown, and compound predicates use their boolean truth tables.
/// Callers may exempt source only when the result is provably false.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CfgTruth {
    True,
    False,
    Unknown,
}

impl CfgTruth {
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

fn cfg_truth_under_test_false(meta: &Meta) -> CfgTruth {
    match meta {
        Meta::Path(path) if path.is_ident("test") => CfgTruth::False,
        Meta::Path(_) | Meta::NameValue(_) => CfgTruth::Unknown,
        Meta::List(list) if list.path.is_ident("not") => {
            let Ok(inner) = syn::parse2::<Meta>(list.tokens.clone()) else {
                return CfgTruth::Unknown;
            };
            cfg_truth_under_test_false(&inner).not()
        }
        Meta::List(list) if list.path.is_ident("all") => {
            let Ok(arguments) = list.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return CfgTruth::Unknown;
            };
            let mut saw_unknown = false;
            for argument in arguments {
                match cfg_truth_under_test_false(&argument) {
                    CfgTruth::False => return CfgTruth::False,
                    CfgTruth::Unknown => saw_unknown = true,
                    CfgTruth::True => {}
                }
            }
            if saw_unknown {
                CfgTruth::Unknown
            } else {
                CfgTruth::True
            }
        }
        Meta::List(list) if list.path.is_ident("any") => {
            let Ok(arguments) = list.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return CfgTruth::Unknown;
            };
            let mut saw_unknown = false;
            for argument in arguments {
                match cfg_truth_under_test_false(&argument) {
                    CfgTruth::True => return CfgTruth::True,
                    CfgTruth::Unknown => saw_unknown = true,
                    CfgTruth::False => {}
                }
            }
            if saw_unknown {
                CfgTruth::Unknown
            } else {
                CfgTruth::False
            }
        }
        Meta::List(_) => CfgTruth::Unknown,
    }
}

fn item_is_guaranteed_disabled_in_production(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && matches!(
                &attribute.meta,
                Meta::List(list)
                    if syn::parse2::<Meta>(list.tokens.clone())
                        .is_ok_and(|condition| cfg_truth_under_test_false(&condition) == CfgTruth::False)
            )
    })
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(item) => &item.attrs,
        ImplItem::Fn(item) => &item.attrs,
        ImplItem::Macro(item) => &item.attrs,
        ImplItem::Type(item) => &item.attrs,
        ImplItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(item) => &item.attrs,
        TraitItem::Fn(item) => &item.attrs,
        TraitItem::Macro(item) => &item.attrs,
        TraitItem::Type(item) => &item.attrs,
        TraitItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn foreign_item_attrs(item: &ForeignItem) -> &[Attribute] {
    match item {
        ForeignItem::Fn(item) => &item.attrs,
        ForeignItem::Macro(item) => &item.attrs,
        ForeignItem::Static(item) => &item.attrs,
        ForeignItem::Type(item) => &item.attrs,
        ForeignItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn spanned_byte_range<T: Spanned>(
    content: &str,
    attrs: &[Attribute],
    node: &T,
) -> Option<Range<usize>> {
    let start = attrs
        .first()
        .map(Spanned::span)
        .unwrap_or_else(|| node.span());
    let start = start.byte_range();
    let end = node.span().byte_range();
    (start.start <= start.end
        && end.start <= end.end
        && start.start <= end.end
        && end.end <= content.len()
        && content.is_char_boundary(start.start)
        && content.is_char_boundary(end.end))
    .then_some(start.start..end.end)
}

/// Path-aware graph of external module edges.  An external file is exempt
/// only when every resolved incoming edge is test-only.  The same canonical
/// file imported once from production therefore remains scanned.
struct TestOnlyModuleGraph {
    src_root: PathBuf,
    incoming: HashMap<PathBuf, IncomingContexts>,
    seen_contexts: HashSet<(PathBuf, bool)>,
    production_outside_targets: Vec<PathBuf>,
    production_unresolved_modules: Vec<String>,
}

#[derive(Default)]
struct IncomingContexts {
    test_only: bool,
    production_or_invalid: bool,
}

impl TestOnlyModuleGraph {
    fn build(src_root: &Path) -> Option<Self> {
        let src_root = src_root.canonicalize().ok()?;
        let mut graph = Self {
            src_root: src_root.clone(),
            incoming: HashMap::new(),
            seen_contexts: HashSet::new(),
            production_outside_targets: Vec::new(),
            production_unresolved_modules: Vec::new(),
        };
        for root in crate_root_files(&src_root) {
            graph.record_incoming(&root, false);
            graph.visit_file(&root, false);
        }
        Some(graph)
    }

    fn exempt_files(&self) -> HashSet<PathBuf> {
        self.incoming
            .iter()
            .filter_map(|(path, contexts)| {
                (contexts.test_only && !contexts.production_or_invalid).then_some(path.clone())
            })
            .collect()
    }

    fn production_outside_targets(&self) -> &[PathBuf] {
        &self.production_outside_targets
    }

    fn production_unresolved_modules(&self) -> &[String] {
        &self.production_unresolved_modules
    }

    fn record_incoming(&mut self, path: &Path, test_only: bool) {
        let contexts = self.incoming.entry(path.to_path_buf()).or_default();
        if test_only {
            contexts.test_only = true;
        } else {
            contexts.production_or_invalid = true;
        }
    }

    fn visit_file(&mut self, path: &Path, inherited_test_only: bool) {
        let Ok(canonical_path) = path.canonicalize() else {
            return;
        };
        if !canonical_path.starts_with(&self.src_root)
            || !self
                .seen_contexts
                .insert((canonical_path.clone(), inherited_test_only))
        {
            return;
        }
        let Ok(content) = fs::read_to_string(&canonical_path) else {
            self.record_incoming(&canonical_path, false);
            return;
        };
        let Ok(file) = syn::parse_file(&content) else {
            self.record_incoming(&canonical_path, false);
            return;
        };
        self.visit_items(
            &file.items,
            &canonical_path,
            &module_directory_for_file(&canonical_path),
            inherited_test_only,
        );
    }

    fn visit_items(
        &mut self,
        items: &[Item],
        source_file: &Path,
        module_directory: &Path,
        inherited_test_only: bool,
    ) {
        for item in items {
            let item_is_test_only =
                inherited_test_only || item_is_guaranteed_disabled_in_production(item_attrs(item));
            let Item::Mod(module) = item else {
                continue;
            };
            if let Some((_, child_items)) = &module.content {
                self.visit_items(
                    child_items,
                    source_file,
                    &module_directory.join(module.ident.to_string()),
                    item_is_test_only,
                );
                continue;
            }

            let resolution = resolve_external_module_file(
                source_file,
                module_directory,
                &module.attrs,
                &module.ident.to_string(),
            );
            match resolution {
                ExternalModuleResolution::Resolved(target) => {
                    let Ok(target) = target.canonicalize() else {
                        continue;
                    };
                    if !target.starts_with(&self.src_root) {
                        if !item_is_test_only {
                            self.production_outside_targets.push(target);
                        }
                        continue;
                    }
                    self.record_incoming(&target, item_is_test_only);
                    self.visit_file(&target, item_is_test_only);
                }
                ExternalModuleResolution::Ambiguous(candidates) => {
                    // Every candidate stays scanned; an ambiguous edge must
                    // never coexist with a test-only whole-file exemption.
                    for candidate in candidates {
                        if let Ok(candidate) = candidate.canonicalize()
                            && candidate.starts_with(&self.src_root)
                        {
                            self.record_incoming(&candidate, false);
                        }
                    }
                }
                ExternalModuleResolution::Unresolved if !item_is_test_only => {
                    self.production_unresolved_modules.push(format!(
                        "{}: unresolved production external module `{}`",
                        source_file.display(),
                        module.ident
                    ));
                }
                ExternalModuleResolution::Unresolved => {}
            }
        }
    }
}

fn test_only_external_module_files(src_root: &Path) -> HashSet<PathBuf> {
    TestOnlyModuleGraph::build(src_root)
        .map(|graph| graph.exempt_files())
        .unwrap_or_default()
}

fn crate_root_files(src_root: &Path) -> Vec<PathBuf> {
    let mut roots = ["lib.rs", "main.rs"]
        .into_iter()
        .map(|name| src_root.join(name))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    let bin = src_root.join("bin");
    if let Ok(entries) = fs::read_dir(bin) {
        roots.extend(entries.flatten().map(|entry| entry.path()).filter(|path| {
            path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        }));
    }
    roots
}

enum ExternalModuleResolution {
    Resolved(PathBuf),
    Ambiguous(Vec<PathBuf>),
    Unresolved,
}

fn resolve_external_module_file(
    source_file: &Path,
    module_directory: &Path,
    attrs: &[Attribute],
    module_name: &str,
) -> ExternalModuleResolution {
    let candidates = match module_path_attribute(attrs) {
        Some(Some(path)) => match source_file.parent() {
            Some(parent) => vec![parent.join(path)],
            None => return ExternalModuleResolution::Unresolved,
        },
        Some(None) => return ExternalModuleResolution::Unresolved,
        None => vec![
            module_directory.join(format!("{module_name}.rs")),
            module_directory.join(module_name).join("mod.rs"),
        ],
    };
    let existing = candidates
        .into_iter()
        .filter(|candidate| candidate.is_file())
        .collect::<Vec<_>>();
    match existing.as_slice() {
        [] => ExternalModuleResolution::Unresolved,
        [target] => ExternalModuleResolution::Resolved(target.clone()),
        _ => ExternalModuleResolution::Ambiguous(existing),
    }
}

/// `None` means no path attribute; `Some(None)` means malformed and therefore
/// unresolvable.  This prevents a malformed `#[path]` from falling back to a
/// different file that the compiler would not use.
fn module_path_attribute(attrs: &[Attribute]) -> Option<Option<PathBuf>> {
    for attribute in attrs {
        if attribute.path().is_ident("path") {
            return Some(path_value_from_meta(&attribute.meta));
        }
        if let Some(path) = cfg_attr_production_path(attribute) {
            return Some(path);
        }
    }
    None
}

fn path_value_from_meta(meta: &Meta) -> Option<PathBuf> {
    match meta {
        Meta::NameValue(value) => match &value.value {
            syn::Expr::Lit(expression) => match &expression.lit {
                syn::Lit::Str(path) => Some(PathBuf::from(path.value())),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Resolve `cfg_attr(not(test), path = "...")` as the production compiler
/// does. Any condition not proved test-only is conservatively resolved and
/// scanned as production; a missing target becomes a hard gate violation.
fn cfg_attr_production_path(attribute: &Attribute) -> Option<Option<PathBuf>> {
    if !attribute.path().is_ident("cfg_attr") {
        return None;
    }
    let Meta::List(list) = &attribute.meta else {
        return Some(None);
    };
    let Ok(arguments) =
        list.parse_args_with(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)
    else {
        return Some(None);
    };
    let mut arguments = arguments.into_iter();
    let Some(condition) = arguments.next() else {
        return Some(None);
    };
    let path_attribute = arguments.find(|argument| argument.path().is_ident("path"));
    let path_attribute = path_attribute?;
    match cfg_truth_under_test_false(&condition) {
        CfgTruth::False => None,
        CfgTruth::True | CfgTruth::Unknown => Some(path_value_from_meta(&path_attribute)),
    }
}

fn module_directory_for_file(source_file: &Path) -> PathBuf {
    let parent = source_file.parent().unwrap_or_else(|| Path::new(""));
    match source_file.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") | None => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
    }
}

fn line_number_at_offset(content: &str, offset: usize) -> usize {
    content[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

#[test]
fn cfg_test_boundary_allows_only_the_compiled_out_loopback_dialer() {
    let source = r#"
#[cfg(test)]
mod tests {
    async fn loopback_only() {
        let _ = tokio::net::TcpStream::connect(("127.0.0.1", 1)).await;
    }
}

async fn production_dialer() {
    let _ = tokio::net::TcpStream::connect(("example.invalid", 443)).await;
}
"#;

    let violations = forbidden_network_constructions_in_production(source);
    assert_eq!(
        violations,
        vec![(10, "TcpStream::connect")],
        "a production dialer after a cfg(test) block must remain guarded"
    );
}

#[test]
fn cfg_projection_exempts_only_predicates_proven_false_with_test_disabled() {
    let source = r#"
#[cfg(all(test, feature = "ssh-tunnel"))]
fn all_test_and_unknown() { let _ = reqwest::Client::new(); }
#[cfg(any(test, feature = "ssh-tunnel"))]
fn any_test_or_unknown() { let _ = reqwest::Client::new(); }
#[cfg(not(not(test)))]
fn double_negated_test() { let _ = reqwest::Client::new(); }
#[cfg(feature = "ssh-tunnel")]
fn unknown_feature() { let _ = reqwest::Client::new(); }
"#;

    assert_eq!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .filter(|(_, pattern)| *pattern == "reqwest::Client::new")
            .count(),
        2,
        "all(test, unknown) and not(not(test)) are disabled; any(test, unknown) and unknown remain scanned"
    );
}

#[test]
fn cfg_test_boundary_ignores_literal_and_comment_braces() {
    // The parser owns literal/comment syntax, so none of these braces can
    // influence the precise AST span of the cfg(test) module.
    let source = r###"
#[cfg(test)]
mod loopback_tests {
    const NORMAL: &str = "{";
    const BYTE: &[u8] = b"}";
    const CHARACTER: char = '{';
    const RAW: &str = r#"{"#;
    const BYTE_RAW: &[u8] = br##"}"##;
    fn lifetime_only<'a>(_value: &'a str) {}
    // A line comment with an unmatched {
    /* A block comment with an unmatched } and nested /* { */ text. */
    async fn loopback_only() {
        let _ = tokio::net::TcpStream::connect(("127.0.0.1", 1)).await;
    }
}

async fn production_dialer() {
    let _ = tokio::net::TcpStream::connect(("example.invalid", 443)).await;
}
"###;

    let violations = forbidden_network_constructions_in_production(source);
    assert_eq!(
        violations.len(),
        1,
        "only the post-scope dialer must be seen"
    );
    assert_eq!(violations[0].1, "TcpStream::connect");
    assert!(
        violations[0].0 > 12,
        "the reported dialer must be outside the cfg(test) module"
    );
}

#[test]
fn cfg_test_ast_spans_preserve_same_line_and_multiline_production_items() {
    let source = r####"
#[cfg(test)] mod inline_tests {
    const NORMAL: &str = "{";
    const BYTE: &[u8] = b"}";
    const CHARACTER: char = '{';
    const RAW: &str = r#"{"#;
    const BYTE_RAW: &[u8] = br##"}"##;
    const CONTINUED: &str = "brace { \
        still }";
    // comment {
    /* nested /* } */ comment */
    async fn loopback() { let _ = tokio::net::TcpStream::connect(("127.0.0.1", 1)).await; }
} fn same_line_production() { let _ = tokio::net::TcpStream::connect(("example.invalid", 443)); }

#[cfg(
    test
)]
test_only_macro!
{
    tokio::net::TcpStream::connect(("127.0.0.1", 1));
}

#[cfg(test)]
mod out_of_line_tests;

fn later_production() { let _ = tokio::net::TcpStream::connect(("example.invalid", 443)); }
"####;

    let ranges = test_only_item_ranges(source).expect("source must parse");
    assert_eq!(ranges.len(), 3, "module, macro, and external module span");

    let violations = forbidden_network_constructions_in_production(source);
    assert_eq!(
        violations,
        vec![(13, "TcpStream::connect"), (26, "TcpStream::connect"),],
        "same-line and later production dialers must never inherit a test item exception"
    );
}

#[test]
fn cfg_test_byte_spans_handle_unicode_and_crlf_without_hiding_same_line_code() {
    let source = "const PREFIX: &str = \"é\";\r\n#[cfg(test)] mod tests {\r\n    fn loopback() { let _ = tokio::net::TcpStream::connect((\"127.0.0.1\", 1)); }\r\n} fn production() { let _ = tokio::net::TcpStream::connect((\"example.invalid\", 443)); }\r\n";

    assert_eq!(
        forbidden_network_constructions_in_production(source),
        vec![(4, "TcpStream::connect")],
        "Unicode plus CRLF must retain AST byte spans so only the production dialer is detected"
    );
}

#[test]
fn cfg_test_source_tree_covers_nested_inline_and_external_modules() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(src.join("fixtures/loopback")).expect("nested external module directory");
    let lib = src.join("lib.rs");
    let external = src.join("fixtures/loopback.rs");
    let grandchild = src.join("fixtures/loopback/grandchild.rs");

    fs::write(
        &lib,
        r#"
mod parent {
    #[cfg(test)]
    mod inline {
        fn loopback() { let _ = tokio::net::TcpStream::connect(("127.0.0.1", 1)); }
    }

    #[cfg(test)]
    #[path = "fixtures/loopback.rs"]
    mod external;

    fn production() { let _ = tokio::net::TcpStream::connect(("example.invalid", 443)); }
}
"#,
    )
    .expect("root source");
    fs::write(&external, "mod grandchild;\n").expect("external test module");
    fs::write(
        &grandchild,
        "fn loopback() { let _ = tokio::net::TcpStream::connect((\"127.0.0.1\", 1)); }\n",
    )
    .expect("inherited external child");

    let external_files = test_only_external_module_files(&src);
    assert!(external_files.contains(&external.canonicalize().expect("external canonical")));
    assert!(external_files.contains(&grandchild.canonicalize().expect("child canonical")));

    let root_source = fs::read_to_string(&lib).expect("root source read");
    assert_eq!(
        forbidden_network_constructions_in_production(&root_source),
        vec![(12, "TcpStream::connect")],
        "nested inline cfg(test) is byte-exempt but the neighboring production item is not"
    );
    assert!(
        forbidden_network_constructions_in_production(
            &fs::read_to_string(&grandchild).expect("child source read")
        )
        .iter()
        .any(|(_, pattern)| *pattern == "TcpStream::connect"),
        "the external child is only omitted by the canonical test-only file set"
    );
}

#[test]
fn external_module_graph_resolves_production_cfg_attr_path_without_exemption() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(&src).expect("source root");
    let lib = src.join("lib.rs");
    let production = src.join("production_dialer.rs");
    fs::write(
        &lib,
        r#"
#[cfg_attr(not(test), path = "production_dialer.rs")]
mod redirected;
"#,
    )
    .expect("crate root");
    fs::write(
        &production,
        "fn production() { let _ = tokio::net::TcpStream::connect((\"example.invalid\", 443)); }\n",
    )
    .expect("production redirected module");

    let canonical_production = production.canonicalize().expect("production canonical");
    let graph = TestOnlyModuleGraph::build(&src).expect("module graph");
    assert!(
        !graph.exempt_files().contains(&canonical_production),
        "a production cfg_attr path must stay in the direct-construction scan"
    );
    assert!(
        forbidden_network_constructions_in_production(
            &fs::read_to_string(&production).expect("production source read")
        )
        .iter()
        .any(|(_, pattern)| *pattern == "TcpStream::connect"),
        "the redirected production module's dialer remains guarded"
    );
}

#[test]
fn external_module_graph_scans_composite_cfg_attr_paths_unless_test_only() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(&src).expect("source root");
    let lib = src.join("lib.rs");
    let not_any = src.join("not_any_dialer.rs");
    let windows = src.join("windows_dialer.rs");
    fs::write(
        &lib,
        r#"
#[cfg_attr(not(any(test)), path = "not_any_dialer.rs")]
mod not_any;
#[cfg_attr(all(not(test), target_os = "windows"), path = "windows_dialer.rs")]
mod windows_only;
"#,
    )
    .expect("crate root");
    for path in [&not_any, &windows] {
        fs::write(
            path,
            "fn production() { let _ = tokio::net::TcpStream::connect((\"example.invalid\", 443)); }\n",
        )
        .expect("redirected production module");
    }

    let graph = TestOnlyModuleGraph::build(&src).expect("module graph");
    for path in [&not_any, &windows] {
        assert!(
            !graph
                .exempt_files()
                .contains(&path.canonicalize().expect("production canonical")),
            "composite cfg_attr path must remain production-scan required"
        );
    }
    assert!(
        graph.production_unresolved_modules().is_empty(),
        "existing conservative cfg_attr targets resolve instead of disappearing"
    );
}

#[test]
fn external_module_graph_exempts_only_cfg_predicates_proven_false_in_production() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(&src).expect("source root");
    fs::write(
        src.join("lib.rs"),
        r#"
#[cfg(all(test, feature = "ssh-tunnel"))]
#[path = "all_test_feature.rs"]
mod all_test_feature;
#[cfg(any(test, feature = "ssh-tunnel"))]
#[path = "any_test_feature.rs"]
mod any_test_feature;
#[cfg(not(not(test)))]
#[path = "double_not_test.rs"]
mod double_not_test;
#[cfg(feature = "ssh-tunnel")]
#[path = "unknown_feature.rs"]
mod unknown_feature;
"#,
    )
    .expect("crate root");
    let files = [
        "all_test_feature.rs",
        "any_test_feature.rs",
        "double_not_test.rs",
        "unknown_feature.rs",
    ];
    for file in files {
        fs::write(
            src.join(file),
            "fn production() { let _ = reqwest::Client::new(); }\n",
        )
        .expect("external module fixture");
    }

    let graph = TestOnlyModuleGraph::build(&src).expect("module graph");
    let exempt = graph.exempt_files();
    for file in ["all_test_feature.rs", "double_not_test.rs"] {
        assert!(
            exempt.contains(&src.join(file).canonicalize().expect("test-only canonical")),
            "{file} is provably disabled with test=false and may be exempt"
        );
    }
    for file in ["any_test_feature.rs", "unknown_feature.rs"] {
        assert!(
            !exempt.contains(&src.join(file).canonicalize().expect("production canonical")),
            "{file} has an unknown production predicate and must stay scanned"
        );
    }
}

#[test]
fn public_rendezvous_source_invariant_rejects_a_second_or_aliased_caller() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(src.join("cluster")).expect("cluster source root");
    fs::create_dir_all(src.join("daemon")).expect("daemon source root");
    fs::create_dir_all(src.join("cli")).expect("rogue source root");
    fs::write(src.join("lib.rs"), "mod cluster; mod daemon; mod cli;\n").expect("crate root");
    fs::write(src.join("cluster/mod.rs"), "pub mod hyperswarm;\n").expect("cluster module");
    fs::write(
        src.join("cluster/hyperswarm.rs"),
        "pub(crate) async fn spawn_public_rendezvous() {}\n",
    )
    .expect("reviewed definition");
    fs::write(src.join("daemon/mod.rs"), "pub mod companion;\n").expect("daemon module");
    fs::write(
        src.join("daemon/companion.rs"),
        "async fn pairing() { crate::cluster::hyperswarm::spawn_public_rendezvous().await; }\n",
    )
    .expect("approved caller");
    fs::write(src.join("cli/mod.rs"), "pub mod rogue;\n").expect("cli module");
    fs::write(
        src.join("cli/rogue.rs"),
        "use crate::cluster::hyperswarm::*;\nmacro_rules! rendezvous { () => { spawn_public_rendezvous() }; }\nasync fn rogue() { rendezvous!().await; }\n",
    )
    .expect("macro-expanded glob-import rogue caller");

    assert_eq!(
        production_public_rendezvous_callers(&src.canonicalize().expect("source canonical"))
            .expect("caller scan"),
        vec!["src/cli/rogue.rs", "src/daemon/companion.rs"],
        "the source invariant must resolve hyperswarm globs inside macro-expanded callers"
    );
}

#[test]
fn public_rendezvous_source_invariant_fails_closed_on_unparseable_production_source() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(&src).expect("source root");
    fs::write(src.join("lib.rs"), "fn complete() {}\n").expect("crate root");
    fs::write(src.join("broken.rs"), "fn broken(\n").expect("broken production source");

    let error =
        production_public_rendezvous_callers(&src.canonicalize().expect("source canonical"))
            .expect_err("a parse error must not erase caller-audit evidence");
    assert!(
        error.contains("unparseable caller-audit source src/broken.rs"),
        "the source invariant reports the exact production file it could not audit"
    );
}

#[test]
fn public_rendezvous_source_invariant_rejects_internal_wrappers_and_public_reexports() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(src.join("cluster")).expect("cluster source root");
    fs::write(src.join("lib.rs"), "mod cluster;\n").expect("crate root");
    fs::write(src.join("cluster/mod.rs"), "pub mod hyperswarm;\n").expect("cluster module");
    fs::write(
        src.join("cluster/hyperswarm.rs"),
        "pub(crate) async fn spawn_public_rendezvous() {}\nasync fn wrapper() { spawn_public_rendezvous().await; }\npub use spawn_public_rendezvous as escaped;\n",
    )
    .expect("definition plus escapes");

    assert_eq!(
        production_public_rendezvous_callers(&src.canonicalize().expect("source canonical"))
            .expect("caller scan"),
        vec!["src/cluster/hyperswarm.rs", "src/cluster/hyperswarm.rs"],
        "the definition is inert, but wrappers and pub reexports are forbidden capability escapes"
    );
}

#[test]
fn public_rendezvous_source_invariant_detects_unqualified_wrapper_without_reexport() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(src.join("cluster")).expect("cluster source root");
    fs::write(src.join("lib.rs"), "mod cluster;\n").expect("crate root");
    fs::write(src.join("cluster/mod.rs"), "pub mod hyperswarm;\n").expect("cluster module");
    fs::write(
        src.join("cluster/hyperswarm.rs"),
        "pub(crate) async fn spawn_public_rendezvous() {}\nasync fn wrapper() { spawn_public_rendezvous().await; }\n",
    )
    .expect("definition plus wrapper");
    assert_eq!(
        production_public_rendezvous_callers(&src.canonicalize().expect("source canonical"))
            .expect("caller scan"),
        vec!["src/cluster/hyperswarm.rs"],
        "a bare wrapper call in the defining file is a caller while the definition is not"
    );
}

#[test]
fn public_rendezvous_source_invariant_allows_private_imports_without_calls() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(src.join("cluster")).expect("cluster source root");
    fs::write(src.join("lib.rs"), "mod cluster;\n").expect("crate root");
    fs::write(src.join("cluster/mod.rs"), "pub mod hyperswarm;\n").expect("cluster module");
    fs::write(
        src.join("cluster/hyperswarm.rs"),
        "pub(crate) async fn spawn_public_rendezvous() {}\nuse spawn_public_rendezvous as local_rendezvous;\n",
    )
    .expect("definition plus private import");

    assert!(
        production_public_rendezvous_callers(&src.canonicalize().expect("source canonical"))
            .expect("caller scan")
            .is_empty(),
        "private imports remain available for local resolution but are not capability escapes"
    );
}

#[test]
fn line_number_at_offset_is_one_based() {
    assert_eq!(line_number_at_offset("first\nsecond\n", 0), 1);
    assert_eq!(line_number_at_offset("first\nsecond\n", 6), 2);
}

#[test]
fn external_module_graph_requires_every_incoming_edge_to_be_test_only() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(&src).expect("source root");
    let lib = src.join("lib.rs");
    let shared = src.join("shared.rs");
    let outside = temp.path().join("outside.rs");
    let ambiguous_file = src.join("ambiguous.rs");
    let ambiguous_mod = src.join("ambiguous/mod.rs");
    fs::create_dir_all(ambiguous_mod.parent().expect("ambiguous module parent"))
        .expect("ambiguous module directory");
    fs::write(
        &lib,
        r#"
#[cfg(test)]
#[path = "shared.rs"]
mod test_import;
#[path = "shared.rs"]
mod production_import;
#[cfg(test)]
#[path = "../outside.rs"]
mod out_of_root;
#[path = "../outside.rs"]
mod production_out_of_root;
#[cfg(test)]
mod ambiguous;
"#,
    )
    .expect("crate root");
    fs::write(
        &shared,
        "fn production() { let _ = tokio::net::TcpStream::connect((\"example.invalid\", 443)); }\n",
    )
    .expect("shared source");
    fs::write(
        &outside,
        "fn loopback() { let _ = tokio::net::TcpStream::connect((\"127.0.0.1\", 1)); }\n",
    )
    .expect("outside source");
    fs::write(&ambiguous_file, "fn first() {}\n").expect("ambiguous flat source");
    fs::write(&ambiguous_mod, "fn second() {}\n").expect("ambiguous nested source");

    let exempt = test_only_external_module_files(&src);
    assert!(
        !exempt.contains(&shared.canonicalize().expect("shared canonical")),
        "a production edge must cancel a cfg(test) edge to the same canonical file"
    );
    assert!(
        !exempt.contains(&outside.canonicalize().expect("outside canonical")),
        "targets outside canonical src_root are never exempted"
    );
    let graph = TestOnlyModuleGraph::build(&src).expect("module graph");
    assert!(
        graph
            .production_outside_targets()
            .contains(&outside.canonicalize().expect("outside canonical")),
        "a production #[path] target outside src_root is a hard gate failure"
    );
    assert!(
        !exempt.contains(
            &ambiguous_file
                .canonicalize()
                .expect("ambiguous flat canonical")
        ) && !exempt.contains(
            &ambiguous_mod
                .canonicalize()
                .expect("ambiguous nested canonical")
        ),
        "an ambiguous edge must force every candidate to remain scanned"
    );
    assert!(
        forbidden_network_constructions_in_production(
            &fs::read_to_string(&shared).expect("shared source read")
        )
        .iter()
        .any(|(_, pattern)| *pattern == "TcpStream::connect")
    );
}

#[test]
fn external_module_graph_unifies_available_symlink_aliases_by_canonical_path() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(&src).expect("source root");
    let shared = src.join("shared.rs");
    let alias = src.join("test_alias.rs");
    fs::write(&shared, "fn module() {}\n").expect("shared source");
    if create_file_symlink(&shared, &alias).is_err() {
        // Windows developer-mode / privilege policy can deny symlink creation;
        // direct canonical-alias coverage above remains platform-independent.
        return;
    }
    fs::write(
        src.join("lib.rs"),
        r#"
#[cfg(test)]
#[path = "test_alias.rs"]
mod test_import;
#[path = "shared.rs"]
mod production_import;
"#,
    )
    .expect("crate root");

    let exempt = test_only_external_module_files(&src);
    assert!(
        !exempt.contains(&shared.canonicalize().expect("shared canonical")),
        "the symlink and production import resolve to one canonical graph node"
    );
}

#[test]
fn external_module_graph_keeps_production_hardlink_path_scanned() {
    // Git's tree model has no hardlink entries, so exact-head CI always sees
    // ordinary paths.  Locally, a hardlink still cannot hide the production
    // spelling: the canonical allowlist is path-authoritative and that path is
    // independently scanned below.
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    fs::create_dir_all(&src).expect("source root");
    let shared = src.join("shared.rs");
    let hardlink = src.join("test_hardlink.rs");
    fs::write(
        &shared,
        "fn production() { let _ = tokio::net::TcpStream::connect((\"example.invalid\", 443)); }\n",
    )
    .expect("shared source");
    fs::hard_link(&shared, &hardlink).expect("portable hard link");
    fs::write(
        src.join("lib.rs"),
        r#"
#[cfg(test)]
#[path = "test_hardlink.rs"]
mod test_import;
#[path = "shared.rs"]
mod production_import;
"#,
    )
    .expect("crate root");

    let exempt = test_only_external_module_files(&src);
    assert!(
        !exempt.contains(&shared.canonicalize().expect("production canonical")),
        "hard links may retain distinct paths, but the production pathname is never exempt"
    );
    assert!(
        forbidden_network_constructions_in_production(
            &fs::read_to_string(&shared).expect("shared source read")
        )
        .iter()
        .any(|(_, pattern)| *pattern == "TcpStream::connect")
    );
}

#[test]
fn canonical_allowlist_rejects_allowed_spelling_symlink_outside_source_root() {
    let temp = tempfile::tempdir().expect("temporary source tree");
    let src = temp.path().join("src");
    let providers = src.join("providers");
    fs::create_dir_all(&providers).expect("allowed-looking directory");
    let outside = temp.path().join("outside.rs");
    let alias = providers.join("escaped.rs");
    fs::write(&outside, "fn outside() {}\n").expect("outside source");
    if create_file_symlink(&outside, &alias).is_err() {
        return;
    }

    let canonical_root = src.canonicalize().expect("source canonical");
    assert!(
        canonical_in_root_relative(&canonical_root, &alias).is_err(),
        "an allowed-looking providers/ alias must not bypass canonical src_root ownership"
    );
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_file_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "file symlinks are unsupported on this platform",
    ))
}

#[test]
fn cfg_test_visitor_covers_associated_and_local_items_without_hiding_production() {
    let source = r#"
struct Service;
impl Service {
    #[cfg(test)]
    fn test_loopback() { let _ = tokio::net::TcpStream::connect(("127.0.0.1", 1)); }
    fn production() { let _ = tokio::net::TcpStream::connect(("example.invalid", 443)); }
}
trait Contract {
    #[cfg(test)]
    fn test_loopback() { let _ = tokio::net::TcpStream::connect(("127.0.0.1", 1)); }
    fn production() { let _ = tokio::net::TcpStream::connect(("example.invalid", 443)); }
}
fn locals() {
    #[cfg(test)]
    let _loopback = { tokio::net::TcpStream::connect(("127.0.0.1", 1)) };
    let _production = tokio::net::TcpStream::connect(("example.invalid", 443));
}
"#;

    let violations = forbidden_network_constructions_in_production(source);
    assert_eq!(
        violations.len(),
        3,
        "associated/local cfg(test) nodes are excluded while their production siblings remain"
    );
    assert!(
        violations
            .iter()
            .all(|(_, pattern)| *pattern == "TcpStream::connect")
    );
}

#[test]
fn ast_network_gate_detects_renamed_and_whitespace_obscured_constructors() {
    let source = r#"
use reqwest::{Client as HttpClient, Url as HttpUrl};
use tokio::net::TcpStream as Socket;
use tokio_tungstenite::connect_async as websocket_connect;
type ClientAlias = reqwest::Client;

fn production() {
    let _ = HttpClient /* comment */ :: builder /* spacing */ ();
    let _ = ClientAlias::new();
    let _ = HttpUrl::parse("https://example.invalid");
    let _ = Socket::connect(("example.invalid", 443));
    let _ = websocket_connect("wss://example.invalid");
    let _constructor = reqwest::Client::new;
    let _qualified = <reqwest::Client>::new;
}

#[cfg(test)]
fn test_only() {
    let _ = HttpClient::new();
}
"#;

    let violations = forbidden_network_constructions_in_production(source);
    assert_eq!(violations.len(), 7);
    assert!(
        violations
            .iter()
            .any(|(_, p)| *p == "reqwest::Client::builder")
    );
    assert!(violations.iter().any(|(_, p)| *p == "reqwest::Client::new"));
    assert!(violations.iter().any(|(_, p)| *p == "reqwest::Url::parse"));
    assert!(violations.iter().any(|(_, p)| *p == "TcpStream::connect"));
    assert!(
        violations
            .iter()
            .any(|(_, p)| *p == "tokio_tungstenite::connect_async")
    );
}

#[test]
fn ast_network_gate_resolves_transitive_scoped_and_grouped_aliases() {
    let source = r#"
use reqwest as r;
use r::{self as web, Client as ClientOne};
use web::Client as ClientTwo;
use r::*;
type ClientThree = ClientTwo;

fn production() {
    let _ = ClientThree::new();
    let _ = web::Client::builder();
    let _ = Client::default();
}

#[cfg(test)]
mod test_scope {
    use reqwest::Client as ClientThree;
    fn loopback() { let _ = ClientThree::new(); }
}
"#;

    let violations = forbidden_network_constructions_in_production(source);
    assert_eq!(
        violations.len(),
        3,
        "transitive, self-grouped, and aliased-glob names resolve without a cfg(test) shadow leaking outward"
    );
}

#[test]
fn alias_resolver_ignores_identity_imports_without_creating_cycles() {
    let source = r#"
use serde_json;
fn production() { let _ = serde_json::to_string("safe"); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source).is_empty(),
        "a direct identity import carries no alias information and must not cycle"
    );
}

#[test]
fn alias_resolver_keeps_network_paths_visible_after_identity_imports() {
    let source = r#"
use reqwest;
fn production() { let _ = reqwest::Client::new(); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "reqwest::Client::new"),
        "identity imports must leave direct reqwest paths visible to the gate"
    );
}

#[test]
fn alias_resolver_terminalizes_only_exact_root_crate_self_aliases() {
    let mut root = Scope::crate_root();
    root.aliases
        .insert("A".to_string(), vec!["crate".to_string(), "A".to_string()]);

    assert_eq!(
        resolve_segments(&["A".to_string()], &[root]),
        Ok(vec!["A".to_string()]),
        "the root spelling A -> crate::A is terminal rather than a cyclic alias"
    );
}

#[test]
fn alias_resolver_keeps_non_self_root_crate_aliases_resolvable() {
    let mut root = Scope::crate_root();
    root.aliases.insert(
        "A".to_string(),
        vec!["crate".to_string(), "External".to_string()],
    );
    root.aliases.insert(
        "External".to_string(),
        vec!["reqwest".to_string(), "Client".to_string()],
    );

    assert_eq!(
        resolve_segments(&["A".to_string()], &[root]),
        Ok(vec!["reqwest".to_string(), "Client".to_string()]),
        "only the exact root self-alias terminalizes; other root crate aliases continue"
    );
}

#[test]
fn alias_resolver_keeps_nested_crate_aliases_resolvable_through_root() {
    let mut root = Scope::crate_root();
    root.aliases.insert(
        "External".to_string(),
        vec!["reqwest".to_string(), "Client".to_string()],
    );
    let mut nested = Scope::module();
    nested.aliases.insert(
        "A".to_string(),
        vec!["crate".to_string(), "External".to_string()],
    );

    assert_eq!(
        resolve_segments(&["A".to_string()], &[root, nested]),
        Ok(vec!["reqwest".to_string(), "Client".to_string()]),
        "a nested use crate::A must re-enter root scope to resolve its external alias"
    );
}

#[test]
fn grouped_self_use_binds_the_prefix_final_segment() {
    let file =
        syn::parse_file("use crate::network::{self, Client};").expect("grouped self import parses");
    let Item::Use(item) = &file.items[0] else {
        panic!("fixture contains a use item");
    };
    let mut aliases = HashMap::new();
    collect_use_aliases(
        &item.tree,
        &mut Vec::new(),
        &[Scope::crate_root()],
        &mut aliases,
    );

    assert_eq!(
        aliases.get("network"),
        Some(&vec!["crate".to_string(), "network".to_string()]),
        "use x::{{self, Y}} binds x locally rather than the literal name self"
    );
    assert_eq!(
        aliases.get("Client"),
        Some(&vec![
            "crate".to_string(),
            "network".to_string(),
            "Client".to_string(),
        ]),
        "the grouped sibling retains the shared prefix"
    );
    assert!(!aliases.contains_key("self"));
}

#[test]
fn alias_resolver_does_not_cycle_on_isolated_module_super_import() {
    let source = r#"
use super::store;
fn production() { store::insert(); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source).is_empty(),
        "an isolated module file must preserve unresolved super paths without cycling"
    );
}

#[test]
fn alias_resolver_detects_external_network_base_after_isolated_super_import() {
    let source = r#"
use super::reqwest;
fn production() { let _ = reqwest::Client::new(); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "reqwest::Client::new"),
        "the isolated super fallback must retain an externally recognizable network base"
    );
}

#[test]
fn ast_network_gate_resolves_self_super_and_crate_alias_paths() {
    let source = r#"
use reqwest::Client;
use reqwest::Url as __neoth_network_gate_module_scope__;
fn root() { let _ = self::Client::new(); }
mod nested {
    use reqwest::Client;
    fn nested() {
        let _ = self::Client::builder();
        let _ = super::Client::default();
        let _ = crate::Client::new();
    }
}
"#;

    assert_eq!(
        forbidden_network_constructions_in_production(source).len(),
        4,
        "self/super/crate paths must resolve through lexical module scopes"
    );
}

#[test]
fn ast_network_gate_tracks_instance_socket_connects() {
    let source = r#"
use tokio::net::TcpSocket as Socket;
use std::net::UdpSocket as Datagram;
fn production() {
    let tcp = Socket::new_v4();
    let _ = tcp.connect("example.invalid:443");
    let udp = Datagram::bind("0.0.0.0:0");
    let _ = udp.connect("8.8.8.8:53");
}
"#;

    assert_eq!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .filter(|(_, pattern)| *pattern == "socket instance .connect")
            .count(),
        2
    );
}

#[test]
fn ast_network_gate_rejects_network_paths_in_macro_rules_tokens() {
    let source = r#"
macro_rules! dial {
    () => { tokio::net::TcpStream::connect(("example.invalid", 443)) };
}
fn production() { dial!(); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "network construction in macro token stream"),
        "macro_rules bodies must not hide a production dialer"
    );
}

#[test]
fn ast_network_gate_resolves_aliases_inside_macro_token_streams() {
    let source = r#"
use reqwest::Client as C;
macro_rules! dial { () => { C::new() }; }
fn production() { dial!(); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "network construction in macro token stream")
    );
}

#[test]
fn ast_network_gate_allows_generic_macro_metavariable_path_composition() {
    let source = r#"
macro_rules! define_channel_kinds {
    ($variant:ident) => { fn kind() { let _ = Self::$variant; } };
}
struct ChannelKinds;
impl ChannelKinds {
    const READY: u8 = 1;
    fn production() { define_channel_kinds!(READY); }
}
"#;

    assert!(
        forbidden_network_constructions_in_production(source).is_empty(),
        "generic Self::$variant composition alone is not direct network construction"
    );
}

#[test]
fn ast_network_gate_rejects_guarded_aliases_at_macro_invocation() {
    let source = r#"
use reqwest::Client as C;
macro_rules! construct { ($ty:ty, $method:ident) => { $ty::$method() }; }
fn production() { construct!(C, new); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "network construction in macro token stream")
    );
}

#[test]
fn ast_network_gate_correlates_hard_coded_macro_constructor_with_alias_argument() {
    let source = r#"
use reqwest::Client as C;
macro_rules! make { ($ty:ty) => { $ty::new() }; }
fn production() { let _ = make!(C); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "network construction in macro token stream"),
        "a macro body with a hard-coded guarded terminal must be correlated to its alias argument"
    );
}

#[test]
fn ast_network_gate_allows_unrelated_macro_alias_and_terminal_arguments() {
    let source = r#"
use reqwest::Client as C;
macro_rules! register_variant { ($ty:ty, $name:ident) => { () }; }
fn production() { register_variant!(C, new); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source).is_empty(),
        "invocation arguments alone must not be mistaken for macro expansion"
    );
}

#[test]
fn ast_network_gate_intentionally_fails_closed_for_unknown_qualified_macro() {
    let source = r#"
use reqwest::Client as C;
fn production() { types::register!(C); }
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "network construction in macro token stream"),
        "an unknown qualified macro with a guarded base is an intentional fail-closed violation"
    );
}

#[test]
fn ast_network_gate_resolves_aliases_declared_after_their_use() {
    let source = r#"
fn production() {
    let _ = ClientAlias::new();
}
type ClientAlias = reqwest::Client;
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "reqwest::Client::new"),
        "a lexical type alias must resolve even when it appears after its use"
    );
}

#[test]
fn ast_network_gate_detects_blocking_client_builder() {
    let source = r#"
fn production() {
    let _ = reqwest::blocking::Client::builder();
}
"#;

    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "reqwest::blocking::Client::builder"),
        "blocking provider-key probes are direct client construction too"
    );
}

#[test]
fn reviewed_boundaries_do_not_grant_network_authority_to_new_descendants() {
    assert!(
        is_allowed("src/providers/anthropic_api.rs"),
        "the reviewed concrete boundary remains allowed"
    );
    assert!(
        !is_allowed("src/providers/anthropic_api.rs_rogue.rs"),
        "a lexical suffix must not inherit a concrete file's review authority"
    );
    let rogue = "src/providers/rogue_dialer.rs";
    assert!(
        !is_allowed(rogue),
        "a new provider descendant must not inherit a recursive network exception"
    );
    assert!(
        forbidden_network_constructions_in_production(
            "fn rogue() { let _ = reqwest::Client::new(); }"
        )
        .iter()
        .any(|(_, pattern)| *pattern == "reqwest::Client::new"),
        "a descendant's direct client construction remains a gate finding"
    );
}

#[test]
fn ast_network_gate_tracks_peeroxide_public_dht_construction_and_join() {
    let source = r#"
async fn production() {
    let config = peeroxide::SwarmConfig::with_public_bootstrap();
    let startup = peeroxide::spawn_starting(config).await.unwrap();
    startup.bootstrapped().await.unwrap();
    let (_task, handle, _connections) = startup.finish().await.unwrap();
    handle.join([0; 32], peeroxide::JoinOpts::default()).await.unwrap();
}
"#;

    let violations = forbidden_network_constructions_in_production(source);
    assert!(
        violations
            .iter()
            .any(|(_, pattern)| *pattern == "peeroxide::SwarmConfig::with_public_bootstrap")
    );
    assert!(
        violations
            .iter()
            .any(|(_, pattern)| *pattern == "peeroxide::spawn_starting")
    );
    assert!(
        violations
            .iter()
            .any(|(_, pattern)| *pattern == "peeroxide SwarmHandle .join")
    );
}

#[test]
fn ast_network_gate_tracks_legacy_peeroxide_spawn_too() {
    let source = r#"
async fn production() {
    let (_task, handle, _connections) = peeroxide::spawn(config).await.unwrap();
    handle.join([0; 32], peeroxide::JoinOpts::default()).await.unwrap();
}
"#;

    let violations = forbidden_network_constructions_in_production(source);
    assert!(
        violations
            .iter()
            .any(|(_, pattern)| *pattern == "peeroxide::spawn")
    );
    assert!(
        violations
            .iter()
            .any(|(_, pattern)| *pattern == "peeroxide SwarmHandle .join")
    );
}

#[test]
fn ast_network_gate_rejects_raw_inet_sockets_and_allows_only_reviewed_af_unix_ipc() {
    let inet = r#"
fn production() {
    unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0); }
    unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0); }
    unsafe { libc::connect(0, std::ptr::null(), 0); }
}
"#;
    let inet_hits = forbidden_network_constructions_in_production(inet);
    assert_eq!(
        inet_hits
            .iter()
            .filter(|(_, pattern)| *pattern == "libc::socket")
            .count(),
        2
    );
    assert!(
        inet_hits
            .iter()
            .any(|(_, pattern)| *pattern == "libc::connect")
    );

    let unix_ipc = r#"
fn connect_std_with_deadline() {
    unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0); }
    unsafe { libc::connect(0, std::ptr::null(), 0); }
}
"#;
    assert!(
        forbidden_network_constructions_with_boundaries(unix_ipc, true, false, false).is_empty(),
        "only the audit-RPC AF_UNIX boundary may construct its Unix IPC socket"
    );
    assert!(
        forbidden_network_constructions_in_production(unix_ipc)
            .iter()
            .any(|(_, pattern)| *pattern == "libc::socket"),
        "AF_UNIX remains forbidden everywhere except the exact audited boundary"
    );
}

#[test]
fn ast_network_gate_allows_only_the_exact_wired_graphify_libc_denial_contract() {
    assert!(graphify_library_module_contract_is_exact(
        "pub mod graphify_runner;"
    ));
    assert!(graphify_binary_main_contract_is_exact(
        GRAPHIFY_BINARY_MAIN_CONTRACT
    ));
    let complete = graphify_contract_fixture();
    assert!(
        forbidden_network_constructions_with_boundaries(&complete, false, false, true).is_empty(),
        "the exact guardian -> boundary -> network -> libc probe chain is reviewed"
    );
    assert_eq!(
        forbidden_network_constructions_in_production(&complete)
            .iter()
            .filter(|(_, pattern)| *pattern == "libc::socket")
            .count(),
        1,
        "the libc socket remains forbidden without the exact Graphify source boundary"
    );
}

#[test]
fn ast_network_gate_rejects_graphify_module_swap_and_removed_binary_dispatch() {
    for source in [
        "#[path = \"graphify_runner_alt.rs\"] pub mod graphify_runner;",
        "#[cfg_attr(target_os = \"linux\", path = \"graphify_runner_alt.rs\")] pub mod graphify_runner;",
        "mod graphify_runner;",
        "pub mod graphify_runner { }",
    ] {
        assert!(
            !graphify_library_module_contract_is_exact(source),
            "Graphify module selection must be unconditional, public, and path-fixed"
        );
    }

    let removed_dispatch = GRAPHIFY_BINARY_MAIN_CONTRACT.replacen(
        "::neothd::graphify_runner::run_linux_graphify_containment_guard_if_requested()",
        "::std::option::Option::None",
        1,
    );
    assert!(
        !graphify_binary_main_contract_is_exact(&removed_dispatch),
        "the binary must dispatch the private Linux guardian before Clap/Tokio"
    );
}

#[test]
fn ast_network_gate_rejects_graphify_probe_cfg_decoys_and_unwired_callers() {
    let complete = graphify_contract_fixture();
    let assert_rejected = |source: &str, reason: &str| {
        assert!(
            forbidden_network_constructions_with_boundaries(source, false, false, true)
                .iter()
                .any(|(_, pattern)| {
                    *pattern == "invalid Graphify libc address-family denial contract"
                }),
            "{reason}"
        );
    };

    let cfg_helper = complete.replacen(
        "#[cfg(target_os = \"linux\")]\nfn verify_linux_graphify_address_family_denied",
        "#[cfg(any())]\nfn verify_linux_graphify_address_family_denied",
        1,
    );
    assert_rejected(
        &cfg_helper,
        "a cfg-disabled helper must invalidate the exception",
    );

    let cfg_socket = complete.replacen(
        "    let descriptor = unsafe {",
        "    #[cfg(any())]\n    let descriptor = unsafe {",
        1,
    );
    assert_rejected(
        &cfg_socket,
        "a cfg-disabled socket statement must invalidate the exception",
    );

    let early_return = complete.replacen(
        "    verify_linux_graphify_address_family_denied(\"AF_INET\", ::libc::AF_INET)?;",
        "    return Ok(());\n    verify_linux_graphify_address_family_denied(\"AF_INET\", ::libc::AF_INET)?;",
        1,
    );
    assert_rejected(
        &early_return,
        "an early success before the address-family probes must invalidate the exception",
    );

    let nested_decoy = format!(
        "{complete}\nfn decoy() {{\n{GRAPHIFY_SOCKET_HELPER_CONTRACT}\n}}"
    );
    assert_rejected(
        &nested_decoy,
        "a nested same-name decoy must not satisfy the unique top-level contract",
    );

    let unwired_boundary = complete.replacen(
        "    verify_linux_network_denied()?;",
        "",
        1,
    );
    assert_rejected(
        &unwired_boundary,
        "removing the real boundary call must invalidate the exception",
    );

    let unwired_main = complete.replacen(
        "verify_linux_guardian_boundary(",
        "skip_linux_guardian_boundary(",
        1,
    );
    assert_rejected(
        &unwired_main,
        "the attestation call must stay on the path before Python exec",
    );

    let linux_branch_removed = complete.replacen(
        "LinuxGraphifyUnit::command(executable, &args, current_dir, environment, limits)?;",
        "Command::new(executable);",
        1,
    );
    assert_rejected(
        &linux_branch_removed,
        "Linux must construct the manager-owned contained command",
    );

    let direct_python_unit = complete.replacen(
        ".arg(guardian)\n        .arg(LINUX_GRAPHIFY_GUARD_FLAG)",
        ".arg(executable)\n        .arg(\"--uncontained\")",
        1,
    );
    assert_rejected(
        &direct_python_unit,
        "the transient unit must start the guardian rather than Python",
    );

    let shadowed_bail = format!("macro_rules! bail {{ ($($token:tt)*) => {{}}; }}\n{complete}");
    assert_rejected(
        &shadowed_bail,
        "a local bail macro must not redirect fail-closed branches",
    );

    let rebound_bail = complete.replacen(
        "use ::anyhow::{Context, Result, bail};",
        "use ::malicious::{Context, Result, bail};",
        1,
    );
    assert_rejected(
        &rebound_bail,
        "the remaining non-guardian bail macro binding must stay absolute anyhow",
    );
}

#[test]
fn ast_network_gate_rejects_graphify_probe_semantic_weakening() {
    let complete = graphify_contract_fixture();
    let assert_rejected = |source: &str, reason: &str| {
        assert!(
            forbidden_network_constructions_with_boundaries(source, false, false, true)
                .iter()
                .any(|(_, pattern)| {
                    *pattern == "invalid Graphify libc address-family denial contract"
                }),
            "{reason}"
        );
    };

    assert_rejected(
        &complete.replacen(
            "        unsafe { ::libc::close(descriptor) };",
            "",
            1,
        ),
        "a permitted socket must still be closed before the guardian fails",
    );
    assert_rejected(
        &complete.replacen(
            "return ::std::result::Result::Err(::anyhow::Error::msg(::std::format!(\n            \"effective address-family policy still permits {name}\"",
            "return ::std::result::Result::Ok(::anyhow::Error::msg(::std::format!(\n            \"effective address-family policy still permits {name}\"",
            1,
        ),
        "a permitted socket must be fatal",
    );
    assert_rejected(
        &complete.replacen("::libc::EAFNOSUPPORT", "::libc::ENOMEM", 1),
        "only systemd's exact address-family policy errno may attest denial",
    );

    let wrong_family = complete.replacen(
        "verify_linux_graphify_address_family_denied(\"AF_UNIX\", ::libc::AF_UNIX)?;",
        "verify_linux_graphify_address_family_denied(\"AF_UNIX\", ::libc::AF_INET)?;",
        1,
    );
    assert_rejected(
        &wrong_family,
        "AF_INET, AF_INET6, and AF_UNIX must each be probed exactly once"
    );

    for property in [
        "--property=PrivateNetwork=yes",
        "--property=RestrictAddressFamilies=none",
        "--property=IPAddressDeny=any",
    ] {
        let changed = complete.replacen(property, "--property=WEAKENED", 1);
        assert_rejected(
            &changed,
            "every mandatory network property must remain exact",
        );
    }
}

#[test]
fn ast_network_gate_rejects_raw_socket_macros_without_literal_domains() {
    for source in [
        r#"macro_rules! call_socket { ($f:path, $domain:expr) => { $f($domain, 1, 0) }; } const INET: i32 = libc::AF_INET; fn production() { call_socket!(libc::socket, INET); }"#,
        r#"macro_rules! call_socket { ($f:path, $domain:expr) => { $f($domain, 1, 0) }; } fn production() { call_socket!(libc::socket, 2); }"#,
    ] {
        assert!(
            forbidden_network_constructions_in_production(source)
                .iter()
                .any(|(_, pattern)| *pattern == "network construction in macro token stream"),
            "raw socket forwarding is forbidden even when its domain is aliased or numeric"
        );
    }
}

#[test]
fn ast_network_gate_rejects_link_name_raw_socket_ffi_aliases() {
    let source = r#"
unsafe extern "C" {
    #[link_name = "socket"]
    fn open_fd(domain: i32, kind: i32, protocol: i32) -> i32;
    #[link_name = "WSAConnect"]
    fn innocuous_name() -> i32;
    #[link_name = "syscall"]
    fn numeric_escape(number: i64) -> i64;
}
"#;
    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "raw socket FFI declaration")
    );
}

#[test]
fn ast_network_gate_rejects_syscall_and_inline_assembly_escape_hatches() {
    let syscall = "fn production() { unsafe { libc::syscall(libc::SYS_socket, 2, 1, 0); } }";
    assert!(
        forbidden_network_constructions_in_production(syscall)
            .iter()
            .any(|(_, pattern)| *pattern == "libc::syscall")
    );
    let assembly = r#"fn production() { unsafe { asm!("syscall"); } }"#;
    assert!(
        forbidden_network_constructions_in_production(assembly)
            .iter()
            .any(|(_, pattern)| *pattern == "production inline assembly macro")
    );
    for assembly in [
        r#"fn production() { unsafe { core::arch::asm!("syscall"); } }"#,
        r#"use core::arch::asm as raw_asm; fn production() { unsafe { raw_asm!("syscall"); } }"#,
    ] {
        assert!(
            forbidden_network_constructions_in_production(assembly)
                .iter()
                .any(|(_, pattern)| *pattern == "production inline assembly macro"),
            "qualified and imported inline assembly macros remain fail-closed"
        );
    }
}

#[test]
fn ast_network_gate_allows_only_exact_stt_pidfd_syscall_constants() {
    let allowed = r#"
struct FasterWhisperContainmentSetup;
impl FasterWhisperContainmentSetup {
    fn configure() {
        unsafe { libc::syscall(libc::SYS_pidfd_open, 1, 0); }
        unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32); }
    }
}
"#;
    assert!(
        forbidden_network_constructions_with_boundaries(allowed, false, true, false).is_empty(),
        "only exact pidfd lifecycle syscall constants are allowed in configure"
    );

    let glob_allowed = r#"
use libc::*;
struct FasterWhisperContainmentSetup;
impl FasterWhisperContainmentSetup {
    fn configure() { unsafe { syscall(SYS_pidfd_open, 1, 0); } }
}
"#;
    assert!(
        forbidden_network_constructions_with_boundaries(glob_allowed, false, true, false)
            .is_empty(),
        "libc glob spelling must resolve to the same exact reviewed pidfd syscall"
    );

    for rejected in [
        "unsafe { libc::syscall(libc::SYS_socket, 2, 1, 0); }",
        "const SYSCALL: i64 = libc::SYS_pidfd_open; unsafe { libc::syscall(SYSCALL, 1, 0); }",
        "unsafe { libc::syscall(434, 1, 0); }",
    ] {
        let source = format!(
            "struct FasterWhisperContainmentSetup; impl FasterWhisperContainmentSetup {{ fn configure() {{ {rejected} }} }}"
        );
        assert!(
            forbidden_network_constructions_with_boundaries(&source, false, true, false)
                .iter()
                .any(|(_, pattern)| *pattern == "libc::syscall"),
            "only the exact libc constant spelling is exempt"
        );
    }

    let glob_socket = r#"
use libc::*;
struct FasterWhisperContainmentSetup;
impl FasterWhisperContainmentSetup {
    fn configure() { unsafe { syscall(SYS_socket, 2, 1, 0); } }
}
"#;
    assert!(
        forbidden_network_constructions_with_boundaries(glob_socket, false, true, false)
            .iter()
            .any(|(_, pattern)| *pattern == "libc::syscall"),
        "libc glob SYS_socket must not bypass the exact pidfd syscall boundary"
    );
}

#[test]
fn ast_network_gate_rejects_windows_winsock_constructors() {
    let source = r#"
fn production() {
    unsafe { windows_sys::Win32::Networking::WinSock::socket(2, 1, 0); }
}
"#;
    assert!(
        forbidden_network_constructions_in_production(source)
            .iter()
            .any(|(_, pattern)| *pattern == "Windows WinSock socket/connect")
    );
}

#[test]
fn ast_network_gate_resolves_internal_use_and_type_aliases_in_macro_blocks() {
    let source = r#"
macro_rules! use_alias { () => {{ use reqwest::Client as C; C::new() }}; }
macro_rules! type_alias { () => {{ type C = reqwest::Client; C::builder() }}; }
fn production() { use_alias!(); type_alias!(); }
"#;

    let macro_hits = forbidden_network_constructions_in_production(source)
        .iter()
        .filter(|(_, pattern)| *pattern == "network construction in macro token stream")
        .count();
    assert_eq!(
        macro_hits, 2,
        "macro-local aliases must not hide constructors"
    );
}

#[test]
fn ast_network_gate_rejects_production_include_macros() {
    let source = r#"
fn production() {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}
#[cfg(test)]
fn test_only() {
    include!("fixture.rs");
}
"#;

    assert_eq!(
        forbidden_network_constructions_in_production(source),
        vec![(3, "production include! macro")]
    );
}

#[test]
fn unparsable_source_fails_closed_without_test_item_exemptions() {
    let source = r#"
#[cfg(test)]
mod incomplete {
    let _ = tokio::net::TcpStream::connect(("127.0.0.1", 1));
"#;

    assert!(test_only_item_ranges(source).is_none());
    assert_eq!(
        forbidden_network_constructions_in_production(source),
        vec![(0, "unparseable Rust source")],
        "a parse error must leave the source-boundary guard fail-closed"
    );
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_allowed(rel: &str) -> bool {
    ALLOWED_PREFIXES.iter().any(|allowed| {
        // Concrete reviewed files require an exact match. A trailing slash is
        // the deliberate opt-in for a reviewed directory boundary; it is not
        // inferred from a common filename prefix.
        if allowed.ends_with('/') {
            rel.starts_with(allowed)
        } else {
            rel == *allowed
        }
    })
}

fn canonical_in_root_relative(src_root: &Path, path: &Path) -> Result<(PathBuf, String), String> {
    let canonical_path = path
        .canonicalize()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let relative = canonical_path.strip_prefix(src_root).map_err(|_| {
        format!(
            "{} is outside {}",
            canonical_path.display(),
            src_root.display()
        )
    })?;
    let relative = relative.to_string_lossy().replace('\\', "/");
    Ok((canonical_path, relative))
}

fn walk_rs(dir: &Path, f: &mut dyn FnMut(PathBuf, String)) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, f)?;
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let content =
            fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        f(path, content);
    }
    Ok(())
}
