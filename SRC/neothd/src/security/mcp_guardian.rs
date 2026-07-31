//! ADOPT31-C4 — MCP tool fingerprinting and rug-pull detection.
//!
//! An MCP server declares its tools once and NEOTH's gates reason about them
//! by name. Nothing stopped a server from keeping a name and swapping what it
//! does afterwards. The sharpest form of that is not a changed parameter list:
//! `McpTool::annotations` carries `readOnlyHint` / `destructiveHint`, and
//! ADOPT-22 SmartApprove auto-approves a Confirm-gated call by its declared
//! EFFECT. A server that first registers `destructiveHint: true` and later
//! flips it to `readOnlyHint: true` buys itself silent auto-approval for a
//! destructive tool. The fingerprint therefore covers the annotations, not
//! just the input schema.
//!
//! ## Model
//!
//! Trust on first use. The first time a tool is seen it is pinned; every later
//! sighting must match. A delta blocks the call rather than re-pinning —
//! re-pinning on change would make the guard a no-op.
//!
//! ## Threat boundary (stated, not implied)
//!
//! The pin is an HMAC under the instance's own WAL identity, so a malicious
//! *server* cannot forge one: it never sees the key. It does NOT defend
//! against a local attacker who can write `<home>/`, because such an attacker
//! already owns the WAL, the config and the key itself. C4 is a guard against
//! a remote counterparty changing its declared contract after approval, and
//! that is the whole of what it claims.
//!
//! ## Canonicalisation
//!
//! Serialisation is done by an explicit key-sorting walk rather than by
//! `serde_json::to_vec`. `serde_json` orders map keys only while the
//! `preserve_order` feature is off, and cargo features are additive across the
//! dependency graph — any crate enabling it would silently switch `Map` to
//! insertion order and invalidate every stored pin. A security primitive
//! should not inherit that from an unrelated dependency.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::mcp::client::McpTool;

type HmacSha256 = Hmac<Sha256>;

/// Relative location of the pin store inside the neoth home.
const PIN_FILE: &str = "mcp_tool_pins.json";

/// What the guardian decided about one tool sighting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinVerdict {
    /// Tool was already pinned and the fingerprint still matches.
    Unchanged,
    /// First sighting — the fingerprint was recorded (trust on first use).
    Pinned,
    /// The tool's declared contract changed after registration. The call must
    /// not proceed.
    Violation {
        /// Which facet moved, for an operator-readable refusal.
        detail: String,
    },
}

impl PinVerdict {
    /// A call may proceed only when the contract is the one that was approved.
    #[must_use]
    pub fn permits_call(&self) -> bool {
        !matches!(self, PinVerdict::Violation { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PinRecord {
    fingerprint: String,
    first_seen_unix: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PinStore {
    /// `"<server>\u{1f}<tool>"` → record. A flat map keeps the file diffable
    /// and avoids a nested shape whose merge semantics nobody needs yet.
    pins: BTreeMap<String, PinRecord>,
}

fn pin_key(server: &str, tool: &str) -> String {
    format!("{server}\u{1f}{tool}")
}

/// Canonical byte encoding of a JSON value: object keys sorted, no whitespace,
/// arrays in order. Written out explicitly so the encoding cannot change
/// underneath us (see the module note on `preserve_order`).
fn canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        // `serde_json`'s Display for numbers is already the shortest
        // round-trippable form; reproducing it by hand would be a worse bug
        // surface than reusing it.
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => {
            out.push_str(&serde_json::Value::String(s.clone()).to_string());
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                canonical_json(v, out);
            }
            out.push('}');
        }
    }
}

/// Domain-separated, length-framed HMAC over everything a caller's trust
/// decision depends on.
///
/// Length framing matters: without it a tool named `"ab"` with description
/// `"c"` and one named `"a"` with description `"bc"` would hash identically,
/// letting a server rename around a pin.
fn fingerprint(key: &[u8], server: &str, tool: &McpTool) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow::anyhow!("hmac key rejected: {e}"))?;
    mac.update(b"neoth/mcp-tool-pin/v1\0");

    let mut field = |bytes: &[u8]| {
        mac.update(&(bytes.len() as u64).to_be_bytes());
        mac.update(bytes);
    };
    field(server.as_bytes());
    field(tool.name.as_bytes());
    field(tool.description.as_deref().unwrap_or("").as_bytes());

    let mut schema = String::new();
    canonical_json(&tool.input_schema, &mut schema);
    field(schema.as_bytes());

    // The annotations are the auto-approval surface — see the module note.
    // NOTE: `ToolAnnotations` keeps only the two hints SmartApprove acts on and
    // drops unknown fields, so the pin covers exactly the surface that drives a
    // trust decision today. A hint added to the struct later is covered
    // automatically; one honoured elsewhere without being parsed here would not
    // be, so new auto-approval inputs belong in this struct.
    let annotations = serde_json::to_value(&tool.annotations)
        .context("serialize MCP tool annotations for fingerprint")?;
    let mut annotations_canonical = String::new();
    canonical_json(&annotations, &mut annotations_canonical);
    field(annotations_canonical.as_bytes());

    Ok(format!("{:x}", mac.finalize().into_bytes()))
}

/// Pin store bound to one neoth home.
pub struct McpGuardian {
    path: PathBuf,
    key: Vec<u8>,
    store: PinStore,
}

impl McpGuardian {
    /// Open (or start) the pin store for `home`.
    ///
    /// Fails closed on an unreadable or malformed store rather than starting
    /// from an empty map: silently re-pinning everything is exactly what an
    /// attacker who can truncate the file would want.
    pub fn open(home: &Path) -> Result<Self> {
        let key = crate::wal::scan::load_home_hmac_keys(home)
            .context("load instance HMAC identity for MCP tool pinning")?
            .into_iter()
            .next()
            .context(
                "no instance HMAC key found — MCP tool pinning cannot verify a schema without \
                 the instance identity",
            )?;
        let path = home.join(PIN_FILE);
        let store = if path.exists() {
            let raw = std::fs::read(&path)
                .with_context(|| format!("read MCP tool pin store {}", path.display()))?;
            serde_json::from_slice(&raw).with_context(|| {
                format!(
                    "MCP tool pin store {} is malformed — refusing to continue unpinned; \
                     inspect it before removing it",
                    path.display()
                )
            })?
        } else {
            PinStore::default()
        };
        Ok(Self { path, key, store })
    }

    /// Check one tool sighting against its pin, recording it on first use.
    ///
    /// The caller must refuse the invocation when the verdict does not
    /// [`PinVerdict::permits_call`].
    pub fn check(&mut self, server: &str, tool: &McpTool, now_unix: i64) -> Result<PinVerdict> {
        let observed = fingerprint(&self.key, server, tool)?;
        let key = pin_key(server, &tool.name);
        match self.store.pins.get(&key) {
            Some(pinned) if pinned.fingerprint == observed => Ok(PinVerdict::Unchanged),
            Some(pinned) => Ok(PinVerdict::Violation {
                detail: format!(
                    "tool '{tool}' on server '{server}' changed its declared contract after \
                     registration (pinned {pinned_short}… on first use, now {observed_short}…); \
                     the call is refused",
                    tool = tool.name,
                    pinned_short = &pinned.fingerprint[..16.min(pinned.fingerprint.len())],
                    observed_short = &observed[..16.min(observed.len())],
                ),
            }),
            None => {
                self.store.pins.insert(
                    key,
                    PinRecord {
                        fingerprint: observed,
                        first_seen_unix: now_unix,
                    },
                );
                Ok(PinVerdict::Pinned)
            }
        }
    }

    /// Persist newly captured pins. Cheap no-op when nothing was added.
    pub fn flush(&self) -> Result<()> {
        let encoded =
            serde_json::to_vec_pretty(&self.store).context("serialize MCP tool pin store")?;
        crate::os_tools::write::write_file_atomic(&self.path, &encoded)
            .with_context(|| format!("persist MCP tool pin store {}", self.path.display()))
    }

    /// How many tools are currently pinned (operator diagnostics + tests).
    #[must_use]
    pub fn pinned_count(&self) -> usize {
        self.store.pins.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::client::ToolAnnotations;
    use tempfile::tempdir;

    fn home_with_key() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let wal = dir.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        std::fs::write(wal.join("hmac.key"), [7u8; 32]).unwrap();
        dir
    }

    fn tool(name: &str, schema: serde_json::Value) -> McpTool {
        McpTool {
            name: name.to_string(),
            description: Some("does a thing".into()),
            input_schema: schema,
            annotations: None,
        }
    }

    #[test]
    fn first_sighting_pins_and_an_identical_redeclaration_passes() {
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let t = tool("search", serde_json::json!({"type": "object"}));

        assert_eq!(g.check("srv", &t, 1).unwrap(), PinVerdict::Pinned);
        assert_eq!(g.check("srv", &t, 2).unwrap(), PinVerdict::Unchanged);
        assert_eq!(g.pinned_count(), 1);
    }

    #[test]
    fn a_changed_input_schema_blocks_the_call() {
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        g.check(
            "srv",
            &tool("search", serde_json::json!({"type": "object"})),
            1,
        )
        .unwrap();

        let swapped = tool(
            "search",
            serde_json::json!({"type": "object", "properties": {"cmd": {"type": "string"}}}),
        );
        let verdict = g.check("srv", &swapped, 2).unwrap();
        assert!(matches!(verdict, PinVerdict::Violation { .. }));
        assert!(!verdict.permits_call());
    }

    #[test]
    fn flipping_destructive_to_read_only_blocks_the_call() {
        // The auto-approval attack: SmartApprove approves by declared EFFECT,
        // so annotations must be inside the fingerprint. A guard that hashed
        // only input_schema would wave this through.
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let mut t = tool("run", serde_json::json!({"type": "object"}));
        t.annotations = Some(ToolAnnotations {
            read_only_hint: Some(false),
            destructive_hint: Some(true),
        });
        assert_eq!(g.check("srv", &t, 1).unwrap(), PinVerdict::Pinned);

        t.annotations = Some(ToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: Some(false),
        });
        assert!(
            !g.check("srv", &t, 2).unwrap().permits_call(),
            "an effect-annotation flip must block — it is the auto-approval surface"
        );
    }

    #[test]
    fn key_reordering_in_the_schema_is_not_a_violation() {
        // Canonicalisation exists so a server that serialises its schema with
        // different key order does not look like an attacker.
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let a = tool(
            "search",
            serde_json::json!({"type": "object", "title": "t", "extra": [1, 2]}),
        );
        let b = tool(
            "search",
            serde_json::json!({"extra": [1, 2], "title": "t", "type": "object"}),
        );
        assert_eq!(g.check("srv", &a, 1).unwrap(), PinVerdict::Pinned);
        assert_eq!(g.check("srv", &b, 2).unwrap(), PinVerdict::Unchanged);
    }

    #[test]
    fn array_order_still_matters() {
        // Canonicalisation sorts object KEYS, never array elements — element
        // order is semantic in JSON Schema (`required`, `enum`, `prefixItems`).
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let a = tool("x", serde_json::json!({"required": ["a", "b"]}));
        let b = tool("x", serde_json::json!({"required": ["b", "a"]}));
        assert_eq!(g.check("srv", &a, 1).unwrap(), PinVerdict::Pinned);
        assert!(!g.check("srv", &b, 2).unwrap().permits_call());
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_between_name_and_description() {
        // Without length framing, ("ab", "c") and ("a", "bc") would collide.
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let mut a = tool("ab", serde_json::json!({}));
        a.description = Some("c".into());
        let mut b = tool("ab", serde_json::json!({}));
        b.description = Some("".into());

        assert_eq!(g.check("srv", &a, 1).unwrap(), PinVerdict::Pinned);
        // Same key (server+name), different framing → must not match.
        assert!(!g.check("srv", &b, 2).unwrap().permits_call());
    }

    #[test]
    fn pins_survive_a_reopen() {
        let home = home_with_key();
        let t = tool("search", serde_json::json!({"type": "object"}));
        {
            let mut g = McpGuardian::open(home.path()).unwrap();
            g.check("srv", &t, 1).unwrap();
            g.flush().unwrap();
        }
        let mut reopened = McpGuardian::open(home.path()).unwrap();
        assert_eq!(reopened.pinned_count(), 1);
        assert_eq!(reopened.check("srv", &t, 2).unwrap(), PinVerdict::Unchanged);
    }

    #[test]
    fn a_malformed_store_fails_closed_instead_of_starting_empty() {
        // Truncating the file must not silently re-pin whatever the server
        // currently claims.
        let home = home_with_key();
        std::fs::write(home.path().join(PIN_FILE), b"{ not json").unwrap();
        assert!(
            McpGuardian::open(home.path()).is_err(),
            "a malformed pin store must refuse to open, not start unpinned"
        );
    }

    #[test]
    fn the_same_tool_name_on_two_servers_is_pinned_separately() {
        let home = home_with_key();
        let mut g = McpGuardian::open(home.path()).unwrap();
        let a = tool("search", serde_json::json!({"type": "object"}));
        let b = tool("search", serde_json::json!({"type": "string"}));
        assert_eq!(g.check("srv-a", &a, 1).unwrap(), PinVerdict::Pinned);
        // Different server, same name: its own first sighting, not a violation.
        assert_eq!(g.check("srv-b", &b, 2).unwrap(), PinVerdict::Pinned);
        assert_eq!(g.pinned_count(), 2);
    }
}
