//! SC-01 — static guarantee that NEOTH never opens a raw HTTP/2 `CONNECT`
//! tunnel (the classic SSRF / internal-service-proxy primitive). Companion to
//! `no_outbound_network.rs` (which bounds WHERE outbound HTTP is constructed)
//! and `wal_emit_sites.rs` (the established Rust-as-static-analysis pattern —
//! NEOTH ships no Semgrep/OpenGrep infra).
//!
//! Walks every `.rs` under `src/` and fails the build if any file references
//! the `CONNECT` HTTP method (`Method::CONNECT` or a `"CONNECT"` literal) AND
//! constructs an HTTP client (`reqwest::` / `hyper::` / `h2::`) — i.e. a file
//! that could actually dial a CONNECT tunnel — unless it is on the (currently
//! empty) allowlist. Today nothing matches; the guard catches a future
//! regression.

use std::fs;
use std::path::{Path, PathBuf};

/// Files permitted to combine an HTTP client with a `CONNECT` reference.
/// Empty by design — NEOTH has no legitimate CONNECT-tunnel use. Adding an
/// entry is a loud, reviewed change.
const ALLOWED: &[&str] = &[];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn rel(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn no_raw_http2_connect_tunnel() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);

    let mut offenders = Vec::new();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let references_connect = text.contains("Method::CONNECT") || text.contains("\"CONNECT\"");
        let constructs_http_client =
            text.contains("reqwest::") || text.contains("hyper::") || text.contains("h2::");
        if references_connect && constructs_http_client {
            let r = rel(path, &src_root);
            if !ALLOWED.contains(&r.as_str()) {
                offenders.push(r);
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "SC-01: raw HTTP/2 CONNECT tunneling is forbidden (SSRF / internal-proxy \
         primitive). These files combine an HTTP client with a CONNECT reference:\n  {}\n  \
         If this is a deliberate, reviewed exception, add the path to ALLOWED in \
         tests/no_http2_connect_tunnel.rs with a justification.",
        offenders.join("\n  ")
    );
}

#[test]
fn allowlist_has_no_stale_entries() {
    // Hygiene: every ALLOWED path must still exist (a deleted/renamed file left
    // in the allowlist silently weakens the guard).
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in ALLOWED {
        assert!(
            src_root.join(entry).exists(),
            "SC-01: stale allowlist entry (file no longer exists): {entry}"
        );
    }
}
