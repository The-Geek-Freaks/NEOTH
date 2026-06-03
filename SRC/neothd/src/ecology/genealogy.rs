//! F4-01 Phase 3 — tool genealogy: a deterministic, read-only inventory of the
//! tools NEOTH actually exercises, built from the WAL frames that DO carry tool
//! identity + the installed-skill manifest. LLM-free, like the rest of CH-13.
//!
//! ## What is grounded vs precursor-gated
//!
//! NEOTH's WAL records tool ACTIVITY for:
//!   - MCP tools — `0xC0 MCP_TOOL_CALLED` (`{server_id, tool, …, ts_unix}`),
//!   - WASM plugins — `0xC4 PLUGIN_HOSTCALL` + `0xC6 PLUGIN_CAP_USED`
//!     (`{plugin, …}`), with `0xC2 PLUGIN_LOADED` establishing the node.
//!
//! Those are the grounded use-counts here. Installed skills appear as nodes from
//! the loader manifest, but with a `0` use-count: skill *injection* is not
//! WAL-traced today (only `0x29 SKILL_INJECT_SKIPPED`, a negative signal), so a
//! truthful count is "unknown → 0" rather than a fabricated number.
//!
//! The blueprint's richer notion — a per-tool "winner-chain" correlation (which
//! tool drove a council win) + tool co-occurrence edges — is deliberately NOT
//! built: `0x63 COUNCIL_WINNER_SELECTED` carries no tool/skill id and `0xC0`
//! carries no session id, so any such linkage would be invented, not measured.
//! It awaits a council-layer precursor (tool-id on the winner frame), tracked as
//! a future ecology slice. Reporting fabricated edges would violate the CH-13
//! design pin (every signal is a pure function over REAL WAL data).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::wal::compress::decompress_frames;
use crate::wal::events::{
    EVENT_TYPE_MCP_TOOL_CALLED, EVENT_TYPE_PLUGIN_CAP_USED, EVENT_TYPE_PLUGIN_HOSTCALL,
    EVENT_TYPE_PLUGIN_LOADED,
};
use crate::wal::frame::decode_frame;
use crate::wal::segment_header::parse_segment_header;

/// Category of a tool node. Adding a kind needs a producer frame + an `as_str`
/// arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    /// An installed `~/.neoth/skills/<id>` skill.
    Skill,
    /// A WASM plugin under `~/.neoth/plugins/<id>`.
    Plugin,
    /// A tool exposed by an external MCP server (`server_id/tool`).
    McpServer,
}

impl ToolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Plugin => "plugin",
            Self::McpServer => "mcp_server",
        }
    }
}

/// One tool in the genealogy. `use_count` is the number of RECORDED uses in the
/// WAL window scanned (MCP calls / plugin hostcalls + cap-uses); it is `0` for
/// installed skills (skill injection is not WAL-traced — see module docs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolNode {
    pub tool_id: String,
    pub kind: ToolKind,
    pub use_count: u32,
    /// Unix ts of the most recent recorded use; `0` if never used (e.g. an
    /// installed-but-unused skill or a loaded-but-idle plugin).
    pub last_used_unix: i64,
}

/// The genealogy: tool nodes only (no edges yet — see module docs on why
/// co-occurrence edges are precursor-gated).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolGenealogy {
    pub nodes: Vec<ToolNode>,
}

impl ToolGenealogy {
    /// The `n` most-used tools, `use_count` descending (ties broken by id for a
    /// stable, deterministic order).
    pub fn top_tools(&self, n: usize) -> Vec<&ToolNode> {
        let mut sorted: Vec<&ToolNode> = self.nodes.iter().collect();
        sorted.sort_by(|a, b| {
            b.use_count
                .cmp(&a.use_count)
                .then_with(|| a.tool_id.cmp(&b.tool_id))
        });
        sorted.into_iter().take(n).collect()
    }
}

/// In-progress accumulator keyed by `(kind, id)`.
type Acc = HashMap<(ToolKind, String), (u32, i64)>;

/// Build the tool genealogy from the WAL + the installed-skill ids.
///
/// PURE over its inputs — the caller does the (async) skill load + passes the
/// ids. Tolerant: a missing dir / torn segment / bad payload each skips rather
/// than errors, so a partial WAL still yields every recoverable tool. Installed
/// skills are always present as nodes (use_count 0 if never exercised) so the
/// report doubles as an "available tools" inventory.
pub fn build_tool_genealogy(wal_dir: &Path, installed_skill_ids: &[String]) -> ToolGenealogy {
    let mut acc: Acc = HashMap::new();

    // Seed installed skills as zero-count nodes (honest baseline).
    for id in installed_skill_ids {
        if id.is_empty() {
            continue;
        }
        acc.entry((ToolKind::Skill, id.clone())).or_insert((0, 0));
    }

    // Walk the WAL for real tool-activity frames.
    if let Ok(entries) = std::fs::read_dir(wal_dir) {
        let mut segments: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
            .collect();
        segments.sort();
        for path in segments {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(hdr) = parse_segment_header(&bytes) else {
                continue;
            };
            let header_len = hdr.header_len();
            if bytes.len() <= header_len {
                continue;
            }
            let body = &bytes[header_len..];
            if hdr.is_compressed() {
                if let Ok(d) = decompress_frames(body) {
                    walk_tool_frames(&d, &mut acc);
                }
            } else {
                walk_tool_frames(body, &mut acc);
            }
        }
    }

    let mut nodes: Vec<ToolNode> = acc
        .into_iter()
        .map(|((kind, tool_id), (use_count, last_used_unix))| ToolNode {
            tool_id,
            kind,
            use_count,
            last_used_unix,
        })
        .collect();
    // Deterministic order: most-used first, ties by (kind, id).
    nodes.sort_by(|a, b| {
        b.use_count
            .cmp(&a.use_count)
            .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
            .then_with(|| a.tool_id.cmp(&b.tool_id))
    });
    ToolGenealogy { nodes }
}

/// Walk one (decompressed) segment body, folding every tool-activity frame into
/// the accumulator. Mirrors `correlation_detector::walk_winner_frames`.
fn walk_tool_frames(frames: &[u8], acc: &mut Acc) {
    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        if dec.header.event_type == EVENT_TYPE_PLUGIN_LOADED {
            // `loaded` establishes a plugin node WITHOUT counting as a use
            // (node existence ≠ activity), exactly like an installed skill.
            if let Some(id) = parse_plugin_loaded(dec.payload) {
                acc.entry((ToolKind::Plugin, id)).or_insert((0, 0));
            }
        } else if let Some((kind, id, ts)) = parse_tool_frame(dec.header.event_type, dec.payload) {
            let slot = acc.entry((kind, id)).or_insert((0, 0));
            slot.0 = slot.0.saturating_add(1);
            if ts > slot.1 {
                slot.1 = ts;
            }
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
}

/// Extract `(kind, tool_id, ts_unix)` from a tool-activity frame, or `None` for
/// any other event / an unparseable payload. `0xC2 PLUGIN_LOADED` establishes a
/// plugin node but is NOT a use (count stays whatever activity it has).
fn parse_tool_frame(event_type: u8, payload: &[u8]) -> Option<(ToolKind, String, i64)> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let ts = v.get("ts_unix").and_then(|t| t.as_i64()).unwrap_or(0);
    if event_type == EVENT_TYPE_MCP_TOOL_CALLED {
        let server = v.get("server_id").and_then(|s| s.as_str()).unwrap_or("");
        let tool = v.get("tool").and_then(|s| s.as_str()).unwrap_or("");
        if server.is_empty() && tool.is_empty() {
            return None;
        }
        let id = if server.is_empty() {
            tool.to_string()
        } else {
            format!("{server}/{tool}")
        };
        return Some((ToolKind::McpServer, id, ts));
    }
    if event_type == EVENT_TYPE_PLUGIN_HOSTCALL {
        let id = v.get("plugin_id").and_then(|s| s.as_str())?.to_string();
        if id.is_empty() {
            return None;
        }
        return Some((ToolKind::Plugin, id, ts));
    }
    if event_type == EVENT_TYPE_PLUGIN_CAP_USED {
        // 0xC6 names the plugin under `plugin` (not `plugin_id`).
        let id = v.get("plugin").and_then(|s| s.as_str())?.to_string();
        if id.is_empty() {
            return None;
        }
        return Some((ToolKind::Plugin, id, ts));
    }
    None
}

/// Establish a plugin node from a `0xC2 PLUGIN_LOADED` frame WITHOUT counting it
/// as a use. Kept separate from [`parse_tool_frame`] because "loaded" is node
/// existence, not activity. Returns the plugin id, or `None` if unparseable.
fn parse_plugin_loaded(payload: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let id = v.get("plugin_id").and_then(|s| s.as_str())?.to_string();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::{
        EVENT_TYPE_MCP_TOOL_CALLED, EVENT_TYPE_PLUGIN_CAP_USED, EVENT_TYPE_PLUGIN_HOSTCALL,
    };
    use crate::wal::writer::{spawn, WalWriterHandle};

    async fn append_json(writer: &WalWriterHandle, event_type: u8, payload: serde_json::Value) {
        let bytes = serde_json::to_vec(&payload).unwrap();
        let header = crate::wal::HeaderBuilder::new(event_type, &bytes).build();
        writer.append(header, bytes).await.unwrap();
    }

    #[tokio::test]
    async fn empty_wal_and_no_skills_is_empty() {
        let wal_dir = tempfile::tempdir().unwrap();
        let g = build_tool_genealogy(wal_dir.path(), &[]);
        assert!(g.nodes.is_empty());
        assert!(g.top_tools(5).is_empty());
    }

    #[tokio::test]
    async fn mcp_tool_call_increments_node() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("g-000001.wal");
        let (writer, join) = spawn(seg).unwrap();
        for ts in [100i64, 200, 300] {
            append_json(
                &writer,
                EVENT_TYPE_MCP_TOOL_CALLED,
                serde_json::json!({"server_id": "fs", "tool": "read", "ts_unix": ts}),
            )
            .await;
        }
        drop(writer);
        let _ = join.await;

        let g = build_tool_genealogy(wal_dir.path(), &[]);
        assert_eq!(g.nodes.len(), 1);
        let n = &g.nodes[0];
        assert_eq!(n.tool_id, "fs/read");
        assert_eq!(n.kind, ToolKind::McpServer);
        assert_eq!(n.use_count, 3);
        assert_eq!(n.last_used_unix, 300, "tracks the most recent use");
    }

    #[tokio::test]
    async fn plugin_hostcall_and_cap_counted_together() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("g-000001.wal");
        let (writer, join) = spawn(seg).unwrap();
        append_json(
            &writer,
            EVENT_TYPE_PLUGIN_HOSTCALL,
            serde_json::json!({"plugin_id": "faccam", "kind": "emit", "ts_unix": 10}),
        )
        .await;
        append_json(
            &writer,
            EVENT_TYPE_PLUGIN_CAP_USED,
            serde_json::json!({"plugin": "faccam", "capability": "recall_top", "hits": 2, "ts_unix": 20}),
        )
        .await;
        drop(writer);
        let _ = join.await;

        let g = build_tool_genealogy(wal_dir.path(), &[]);
        assert_eq!(g.nodes.len(), 1);
        let n = &g.nodes[0];
        assert_eq!(n.tool_id, "faccam");
        assert_eq!(n.kind, ToolKind::Plugin);
        assert_eq!(n.use_count, 2, "hostcall + cap-used both count");
        assert_eq!(n.last_used_unix, 20);
    }

    #[test]
    fn installed_skills_appear_as_zero_count_nodes() {
        let wal_dir = tempfile::tempdir().unwrap();
        let skills = vec!["verification".to_string(), "research".to_string()];
        let g = build_tool_genealogy(wal_dir.path(), &skills);
        assert_eq!(g.nodes.len(), 2);
        for n in &g.nodes {
            assert_eq!(n.kind, ToolKind::Skill);
            assert_eq!(n.use_count, 0, "skill injection is not WAL-traced → 0");
            assert_eq!(n.last_used_unix, 0);
        }
    }

    #[tokio::test]
    async fn top_tools_sorted_by_count_desc() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("g-000001.wal");
        let (writer, join) = spawn(seg).unwrap();
        // tool "a" used 3x, "b" used 1x.
        for _ in 0..3 {
            append_json(
                &writer,
                EVENT_TYPE_MCP_TOOL_CALLED,
                serde_json::json!({"server_id": "s", "tool": "a", "ts_unix": 1}),
            )
            .await;
        }
        append_json(
            &writer,
            EVENT_TYPE_MCP_TOOL_CALLED,
            serde_json::json!({"server_id": "s", "tool": "b", "ts_unix": 1}),
        )
        .await;
        drop(writer);
        let _ = join.await;

        let g = build_tool_genealogy(wal_dir.path(), &["z-skill".to_string()]);
        let top = g.top_tools(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].tool_id, "s/a");
        assert_eq!(top[0].use_count, 3);
        assert_eq!(top[1].tool_id, "s/b");
        assert_eq!(top[1].use_count, 1);
    }

    #[test]
    fn build_no_panic_on_malformed_frames() {
        // A directory with a non-WAL file + a truncated .wal must not panic.
        let wal_dir = tempfile::tempdir().unwrap();
        std::fs::write(wal_dir.path().join("notes.txt"), b"hello").unwrap();
        std::fs::write(wal_dir.path().join("torn-000001.wal"), b"\x01\x02\x03").unwrap();
        let g = build_tool_genealogy(wal_dir.path(), &[]);
        assert!(g.nodes.is_empty(), "garbage yields no tool nodes, no panic");
    }

    #[test]
    fn tool_kind_serde_snake_case_pin() {
        assert_eq!(
            serde_json::to_string(&ToolKind::McpServer).unwrap(),
            "\"mcp_server\""
        );
        assert_eq!(ToolKind::Skill.as_str(), "skill");
        assert_eq!(ToolKind::Plugin.as_str(), "plugin");
        // parse_plugin_loaded round-trips a valid 0xC2 payload.
        let id = parse_plugin_loaded(br#"{"plugin_id":"p1","version":"1"}"#);
        assert_eq!(id.as_deref(), Some("p1"));
        assert!(parse_plugin_loaded(b"not json").is_none());
    }
}
