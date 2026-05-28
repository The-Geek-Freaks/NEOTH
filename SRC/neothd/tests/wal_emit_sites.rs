//! SC-01a — static guarantee that every WAL `EVENT_TYPE_*` constant defined in
//! `src/wal/events.rs` has at least one wiring site (emit or handler) elsewhere
//! in the source tree.
//!
//! Catches the "defined but never emitted/handled" class at PR time — the same
//! gap that left `0x77 KANBAN_TASK_PROGRESS` (SD-02) and `0x38 CHANNEL_EDIT`
//! (SD-03) as dead constants until they were wired. A brand-new event code
//! added to `events.rs` with no producer now fails `cargo test`.
//!
//! "Wired" = the constant name appears as a whole token in any `.rs` file under
//! `src/` other than `events.rs` itself (its definition, the band-range
//! `assert`s, and the name-list test all live in `events.rs` and must not count
//! as wiring — they reference every constant by construction).
//!
//! This is a coarse guard: a prose mention in a comment also counts as wiring.
//! That is intentional — the goal is to block a *totally* unwired new code, not
//! to verify emit semantics. Mirrors the philosophy of
//! `tests/no_outbound_network.rs`.
//!
//! RESERVED: codes intentionally defined ahead of their producer. Each MUST
//! carry a justification. Removing a code from RESERVED without wiring it will
//! (correctly) fail this test; wiring a RESERVED code without removing it from
//! the list ALSO fails (stale-allowlist hygiene).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// `(const-name, why-it-is-not-yet-wired)`. Keep this list short + justified.
const RESERVED: &[(&str, &str)] = &[
    (
        "EVENT_TYPE_CHANNEL_ACK",
        "SP-5 C-prime: ack_received deferred until a 2nd production messenger lands",
    ),
    (
        "EVENT_TYPE_SELF_UPDATE_APPLIED",
        "V03-09: the emit site is the daemon-internal scheduled-update task \
         (single-writer safety) — `neoth update --self --apply` runs in a \
         separate process and must not open a 2nd writer on the live segment",
    ),
];

#[test]
fn every_event_type_constant_is_wired() {
    let src_root = manifest_dir().join("src");
    let events_rs = src_root.join("wal").join("events.rs");

    let events_src = fs::read_to_string(&events_rs).expect("read src/wal/events.rs");
    let defined = defined_event_types(&events_src);
    assert!(
        !defined.is_empty(),
        "no EVENT_TYPE_* constants found in events.rs — did the file move?"
    );

    // Collect every EVENT_TYPE_* token referenced OUTSIDE events.rs.
    let mut wired: HashSet<String> = HashSet::new();
    walk_rs(&src_root, &mut |path, content| {
        if same_path(&path, &events_rs) {
            return;
        }
        for tok in event_type_tokens(&content) {
            wired.insert(tok);
        }
    });

    let reserved: HashSet<&str> = RESERVED.iter().map(|(n, _)| *n).collect();

    let mut orphans: Vec<String> = defined
        .iter()
        .filter(|name| !wired.contains(name.as_str()) && !reserved.contains(name.as_str()))
        .cloned()
        .collect();
    orphans.sort();

    assert!(
        orphans.is_empty(),
        "WAL event types defined but never emitted/handled (SC-01a):\n  {}\n\n\
         Each must get a real emit/handler site, or be added to RESERVED in \
         tests/wal_emit_sites.rs WITH a justification.",
        orphans.join("\n  "),
    );

    // Hygiene: a RESERVED entry that HAS since been wired must be removed from
    // the allowlist so the list stays honest.
    let mut stale: Vec<&str> = reserved
        .iter()
        .filter(|name| wired.contains(**name))
        .copied()
        .collect();
    stale.sort_unstable();
    assert!(
        stale.is_empty(),
        "RESERVED entries are now wired — remove them from the allowlist:\n  {}",
        stale.join("\n  "),
    );
}

/// Extract `pub const EVENT_TYPE_X: u8 = …` names from the events.rs source.
fn defined_event_types(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let Some(rest) = line.trim_start().strip_prefix("pub const EVENT_TYPE_") else {
            continue;
        };
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() {
            out.push(format!("EVENT_TYPE_{ident}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Every `EVENT_TYPE_*` whole-token reference in a source string. Maximal
/// identifier runs keep `EVENT_TYPE_JOB` from matching inside
/// `EVENT_TYPE_JOB_FIRED`, and `::`-qualified paths resolve to the bare token.
fn event_type_tokens(src: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_ident(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            let tok = &src[start..i];
            if tok.starts_with("EVENT_TYPE_") {
                out.push(tok.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn same_path(a: &Path, b: &Path) -> bool {
    // Canonicalize is overkill + can fail on Windows long paths; the walker and
    // `events_rs` are built from the same `manifest_dir()` root, so a direct
    // comparison is sufficient and allocation-free.
    a == b
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
