//! ADOPT-22 — SmartApprove: session-scoped read-only tool cache.
//!
//! [`SmartApproveSession`] lazily binds each opted-in server's first real MCP
//! connection, immutable config fingerprint and declared tool annotations to
//! read-only verdicts. That exact process is retained until the dispatch loop
//! ends; no second process inherits its metadata.
//!
//! ## Integration in the gate (as wired in ADOPT-22)
//!
//! The MCP gate receives an opaque grant minted from the exact live client
//! that supplied the session snapshot
//! (`Some` only when `security.smart_approve` is set). When the autonomy gate
//! returns `Decision::Confirm`, it consults the cache keyed by
//! `(server_id, tool_name)`:
//!
//! ```text
//! is_readonly(server, tool) == Some(true)  → auto-approve, emit
//!                                            RISK_GATE_ALLOWED_BY_READONLY_CACHE
//! is_readonly(server, tool) == Some(false) → normal confirm path
//! is_readonly(server, tool) == None        → normal confirm path; NEVER
//!                                            re-query live metadata here
//! ```
//!
//! **The auto-approve decision is EFFECT-driven, not name-driven** (operator
//! point 1 — trust-creep guard): the cache is populated ONLY from the server's
//! declared tool annotations ([`classify_from_annotations`]). The earlier
//! name-based LLM judge was removed: it had no production consumer and wiring
//! it would let an adversarial session model influence an authorization gate.
//!
//! ## Security contract
//!
//! - A `true` (read-only) cache entry only upgrades `Decision::Confirm →
//!   Allow`. It NEVER touches `Decision::Deny` — the operator's hard floor
//!   is final. The server-level allowlist (gate Layer 1) runs FIRST.
//! - Auto-approve is driven by the first bound connection's `readOnlyHint`
//!   (and blocked by `destructiveHint`); a `tools/list` failure seals an empty
//!   snapshot for that server, so the normal confirm path runs fail-closed.
//! - Invocation-time cache misses and config-binding drift NEVER issue a live
//!   `tools/list` and can therefore never turn the current Confirm into Allow.
//! - The cache is keyed by `(server_id, tool_name)` so two servers can't share
//!   a verdict for a same-named tool.
//! - The cache is NOT persisted to disk. A fresh session always re-reads the
//!   live annotations, so a tool that changes its declared effect (server
//!   update) isn't permanently grandfathered as read-only.
//! - Trust assumption: SmartApprove trusts the configured server's
//!   self-declared annotations for the session. Enable only for servers under
//!   your operational control, ideally with a minimal `allow_tools` list.

use std::collections::{BTreeMap, HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::mcp::client::{McpClient, McpTool};
use crate::mcp::config::{McpServerConfig, McpServers};

/// GOLD-ADOPT-22 (operator point 1 — trust-creep guard). Classify a tool's
/// read-only status from its server-DECLARED EFFECT metadata
/// ([`crate::mcp::client::ToolAnnotations`]), **NOT its name**. This is the
/// authoritative SmartApprove signal: a renamed or repurposed tool carries its
/// own (current) annotations, so it can't be grandfathered read-only by a
/// familiar name.
///
/// - `destructiveHint == true` → `Some(false)` (NEVER auto-approve, even if a
///   `readOnlyHint` is also set — destructive wins).
/// - else `readOnlyHint == true` → `Some(true)` (read-only, auto-approvable).
/// - `readOnlyHint == false` → `Some(false)`.
/// - no decisive hint → `None` (unknown — the normal confirm path runs;
///   SmartApprove never auto-approves on a guess).
pub fn classify_from_annotations(tool: &McpTool) -> Option<bool> {
    let ann = tool.annotations.as_ref()?;
    if ann.destructive_hint == Some(true) {
        return Some(false);
    }
    ann.read_only_hint
}

/// Build the decisive verdict map for one complete `tools/list` response.
/// Tool calls are addressed by name alone, so any duplicate name makes the
/// catalogue ambiguous and disables SmartApprove for the whole server.
fn classify_tool_verdicts(tools: &[McpTool]) -> Result<HashMap<String, bool>, String> {
    let mut names = HashSet::with_capacity(tools.len());
    let mut verdicts = HashMap::new();
    for tool in tools {
        if !names.insert(tool.name.clone()) {
            return Err(tool.name.clone());
        }
        if let Some(readonly) = classify_from_annotations(tool) {
            verdicts.insert(tool.name.clone(), readonly);
        }
    }
    Ok(verdicts)
}

/// One immutable per-server session snapshot. `config_binding` covers the
/// complete launcher/policy entry (including a canonicalized environment map)
/// without retaining another plaintext copy. `tools` contains only decisive
/// effect annotations; absence remains unknown and requires confirmation.
#[derive(Debug, Clone)]
struct ServerSnapshot {
    config_binding: [u8; 32],
    tools: HashMap<String, bool>,
}

/// Opaque proof that one tool was declared read-only by the same live MCP
/// client that will receive the call. Fields are private so callers cannot
/// manufacture a Confirm bypass from a bare boolean.
#[derive(Debug)]
pub struct SmartApproveGrant {
    server_id: String,
    tool: String,
    config_binding: [u8; 32],
}

impl SmartApproveGrant {
    /// Re-check the exact server/tool/config binding at the final gate.
    pub(crate) fn authorizes(&self, cfg: &McpServerConfig, tool: &str) -> bool {
        self.server_id == cfg.id && self.tool == tool && self.config_binding == config_binding(cfg)
    }
}

/// Session-scoped read-only classification snapshot keyed by server id. A tool
/// name is only meaningful within its bound server configuration (review F5:
/// two servers can expose the same name with opposite effects).
///
/// `Some(true)` = tool declared read-only (safe to auto-allow).
/// `Some(false)` = tool declared write / destructive (normal gate path).
/// `None` = not yet classified this session.
#[derive(Debug, Default, Clone)]
pub struct ReadOnlyCache {
    inner: HashMap<String, ServerSnapshot>,
}

impl ReadOnlyCache {
    /// New empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `(server, tool)` has been classified as read-only this session.
    /// `None` when no entry exists yet. Production authorization must use
    /// [`Self::is_readonly_for`] so the config binding is enforced.
    #[cfg(test)]
    pub fn is_readonly(&self, server: &str, tool: &str) -> Option<bool> {
        self.inner
            .get(server)
            .and_then(|snapshot| snapshot.tools.get(tool))
            .copied()
    }

    /// Resolve only against the exact server configuration captured at session
    /// initialization. Any launcher, environment or policy drift is a miss and
    /// must follow the normal confirmation path.
    pub fn is_readonly_for(&self, cfg: &McpServerConfig, tool: &str) -> Option<bool> {
        let snapshot = self.inner.get(&cfg.id)?;
        if snapshot.config_binding != config_binding(cfg) {
            return None;
        }
        snapshot.tools.get(tool).copied()
    }

    /// Whether this snapshot belongs to the exact launcher/policy config. A
    /// retained process must not be reused after config drift, even for a tool
    /// that has no SmartApprove verdict.
    fn is_bound_to(&self, cfg: &McpServerConfig) -> bool {
        self.inner
            .get(&cfg.id)
            .is_some_and(|snapshot| snapshot.config_binding == config_binding(cfg))
    }

    /// Mint a grant only for an exact bound config and a decisive read-only
    /// verdict. The caller must pair it with the retained client for this
    /// snapshot; [`SmartApproveSession::bind_or_initialize`] enforces that
    /// ownership edge.
    pub(crate) fn grant_for(&self, cfg: &McpServerConfig, tool: &str) -> Option<SmartApproveGrant> {
        (self.is_readonly_for(cfg, tool) == Some(true)).then(|| SmartApproveGrant {
            server_id: cfg.id.clone(),
            tool: tool.to_string(),
            config_binding: config_binding(cfg),
        })
    }

    /// Test-only direct insertion. Production snapshots are sealed through
    /// [`Self::seed_from_tools`] and cannot be incrementally mutated.
    #[cfg(test)]
    pub fn insert(&mut self, server: impl Into<String>, tool: impl Into<String>, readonly: bool) {
        self.inner
            .entry(server.into())
            .or_insert_with(|| ServerSnapshot {
                config_binding: [0; 32],
                tools: HashMap::new(),
            })
            .tools
            .insert(tool.into(), readonly);
    }

    /// Seal one server's complete first-connection snapshot. Duplicate tool names
    /// seal an empty verdict map because an RPC name cannot select between two
    /// conflicting declarations. A second seed for the same server id is
    /// ignored: live metadata can never overwrite a reviewed session verdict.
    /// Returns `true` only for the first seed.
    pub fn seed_from_tools(&mut self, cfg: &McpServerConfig, tools: &[McpTool]) -> bool {
        let verdicts = classify_tool_verdicts(tools).unwrap_or_default();
        self.seed_verdicts(cfg, verdicts)
    }

    fn seed_verdicts(&mut self, cfg: &McpServerConfig, verdicts: HashMap<String, bool>) -> bool {
        if self.inner.contains_key(&cfg.id) {
            return false;
        }
        self.inner.insert(
            cfg.id.clone(),
            ServerSnapshot {
                config_binding: config_binding(cfg),
                tools: verdicts,
            },
        );
        true
    }

    /// TEST-ONLY name-based seeding. Deliberately NOT a production API: seeding
    /// read-only by NAME is the trust-creep vector ADOPT-22 guards against —
    /// production auto-approve goes through [`Self::seed_from_tools`] (EFFECT).
    #[cfg(test)]
    pub fn seed_static(&mut self, server: &str, read_only_tools: &[&str]) {
        let snapshot = self
            .inner
            .entry(server.to_string())
            .or_insert_with(|| ServerSnapshot {
                config_binding: [0; 32],
                tools: HashMap::new(),
            });
        for name in read_only_tools {
            snapshot.tools.insert((*name).to_string(), true);
        }
    }

    /// TEST-ONLY: tool names with no entry for `server`.
    #[cfg(test)]
    pub fn uncached<'a>(&self, server: &str, tools: &[&'a str]) -> Vec<&'a str> {
        tools
            .iter()
            .copied()
            .filter(|t| {
                self.inner
                    .get(server)
                    .is_none_or(|snapshot| !snapshot.tools.contains_key(*t))
            })
            .collect()
    }
}

/// Live clients retained for the complete dispatch-loop session. The `Option`
/// is intentionally kept in place after poisoning so a failed connection can
/// never be transparently replaced while its old metadata remains in scope.
struct SessionClients<C> {
    inner: HashMap<String, Option<C>>,
}

impl<C> Default for SessionClients<C> {
    fn default() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
}

impl<C> SessionClients<C> {
    fn insert_live(&mut self, server: String, client: C) {
        self.inner.insert(server, Some(client));
    }

    fn live_slot_mut(&mut self, server: &str) -> Option<&mut Option<C>> {
        let slot = self.inner.get_mut(server)?;
        slot.as_ref()?;
        Some(slot)
    }

    #[cfg(test)]
    fn poison(&mut self, server: &str) {
        if let Some(slot) = self.inner.get_mut(server) {
            slot.take();
        }
    }
}

/// One SmartApprove dispatch-loop session. A successful entry owns both the
/// immutable metadata snapshot and the exact still-running MCP client that
/// supplied it. Dropping the session kills every retained child process.
#[derive(Default)]
pub struct SmartApproveSession {
    cache: ReadOnlyCache,
    clients: SessionClients<McpClient>,
    duplicate_ids: HashSet<String>,
    /// ADOPT31-C4a — neoth home for the MCP tool pin store. `None` resolves to
    /// [`FreedomConfig::default_neoth_home`] at use. It is a field rather than
    /// a direct call so tests can point at a tempdir without mutating process
    /// env, matching the Session-24 `_at(base)` convention.
    home: Option<std::path::PathBuf>,
    #[cfg(test)]
    initialization_attempts: usize,
}

/// A temporary mutable borrow of one retained client plus the optional opaque
/// read-only grant for the current tool. Unknown/non-read-only tools still use
/// the retained process but receive no Confirm bypass.
pub(crate) struct BoundSmartApproveClient<'a> {
    client: &'a mut Option<McpClient>,
    grant: Option<SmartApproveGrant>,
}

impl BoundSmartApproveClient<'_> {
    pub(crate) fn parts(&mut self) -> (&mut McpClient, Option<&SmartApproveGrant>) {
        let grant = self.grant.as_ref();
        let client = self
            .client
            .as_mut()
            .expect("SmartApproveSession::bind_or_initialize returns only a live client");
        (client, grant)
    }

    /// Permanently remove this process from the current session. No reconnect
    /// may inherit its grant; a later ephemeral call is passed no grant.
    pub(crate) fn poison(&mut self) {
        self.grant = None;
        self.client.take();
    }
}

impl SmartApproveSession {
    /// Start an empty lazy session. Duplicate enabled server ids are sealed out
    /// up front because an id-keyed client cannot be bound unambiguously.
    pub fn new(servers: &McpServers) -> Self {
        let enabled = servers.enabled();
        let duplicate_ids = duplicate_server_ids(&enabled);
        for id in &duplicate_ids {
            if enabled
                .iter()
                .any(|cfg| cfg.id.as_str() == id.as_str() && cfg.smart_approve)
            {
                tracing::warn!(
                    server = %id,
                    "SmartApprove disabled because multiple enabled servers share this id"
                );
            }
        }

        Self {
            duplicate_ids,
            ..Self::default()
        }
    }

    /// ADOPT31-C4a — point the tool-pin store at an explicit neoth home.
    #[must_use]
    pub fn with_home(mut self, home: std::path::PathBuf) -> Self {
        self.home = Some(home);
        self
    }

    /// On the first real call for this server, establish one client, fetch its
    /// complete catalogue once, then retain that exact process for every call
    /// in this loop. A sealed cache entry (including a failed initialization)
    /// is never queried again. A poisoned/missing client or any config drift
    /// returns no binding; the dispatch gate resolves the original Confirm
    /// without spawning a replacement process or inheriting a stale grant.
    pub(crate) async fn bind_or_initialize<'a>(
        &'a mut self,
        cfg: &McpServerConfig,
        tool: &str,
    ) -> Option<BoundSmartApproveClient<'a>> {
        if !cfg.smart_approve || self.duplicate_ids.contains(&cfg.id) {
            return None;
        }
        if !self.cache.inner.contains_key(&cfg.id) {
            self.initialize_server(cfg).await;
        }
        if !self.cache.is_bound_to(cfg) {
            return None;
        }
        let grant = self.cache.grant_for(cfg, tool);
        let client = self.clients.live_slot_mut(&cfg.id)?;
        Some(BoundSmartApproveClient { client, grant })
    }

    /// ADOPT31-C4a — drop any tool whose fingerprint no longer matches its pin.
    ///
    /// Failing to open the pin store removes every tool from the auto-approval
    /// set rather than trusting them: SmartApprove is a *bypass* of an operator
    /// confirmation, so losing the ability to verify it must cost the bypass,
    /// not the verification. The tools stay callable behind normal Confirm.
    fn reject_repinned_tools(
        &self,
        cfg: &McpServerConfig,
        tools: Vec<crate::mcp::client::McpTool>,
    ) -> Vec<crate::mcp::client::McpTool> {
        let home = self
            .home
            .clone()
            .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
        let mut guardian = match crate::security::mcp_guardian::McpGuardian::open(&home) {
            Ok(guardian) => guardian,
            Err(error) => {
                tracing::warn!(
                    server = %cfg.id,
                    error = %error,
                    "MCP tool pins unavailable; SmartApprove grants no auto-approval this session"
                );
                return Vec::new();
            }
        };
        let now = crate::time::now_unix_i64();
        let kept: Vec<_> = tools
            .into_iter()
            .filter(|tool| match guardian.check(&cfg.id, tool, now) {
                Ok(verdict) if verdict.permits_call() => true,
                Ok(crate::security::mcp_guardian::PinVerdict::Violation { detail }) => {
                    tracing::error!(
                        server = %cfg.id,
                        tool = %tool.name,
                        "SmartApprove auto-approval withdrawn — {detail}"
                    );
                    false
                }
                Ok(_) => false,
                Err(error) => {
                    tracing::warn!(
                        server = %cfg.id,
                        tool = %tool.name,
                        error = %error,
                        "MCP tool fingerprint failed; withholding auto-approval"
                    );
                    false
                }
            })
            .collect();
        if let Err(error) = guardian.flush() {
            tracing::warn!(
                server = %cfg.id,
                error = %error,
                "MCP tool pins could not be persisted; SmartApprove grants no auto-approval this session"
            );
            return Vec::new();
        }
        kept
    }

    async fn initialize_server(&mut self, cfg: &McpServerConfig) {
        #[cfg(test)]
        {
            self.initialization_attempts += 1;
        }
        let timeout = crate::mcp::catalogue::CATALOGUE_SERVER_TIMEOUT;
        let fetch = async {
            // Keep DEFAULT_REQUEST_TIMEOUT on the client that survives this
            // block. The outer timeout caps only spawn + initial tools/list.
            let mut client = McpClient::spawn(cfg).await?;
            let tools = crate::mcp::gate::list_tools_sanitized(&mut client).await?;
            Ok::<_, crate::mcp::client::McpError>((client, tools))
        };
        match tokio::time::timeout(timeout, fetch).await {
            Ok(Ok((client, tools))) => {
                let tools = tools
                    .into_iter()
                    .map(|sanitized| sanitized.tool)
                    .collect::<Vec<_>>();
                // ADOPT31-C4a — a tool whose declared contract changed after
                // registration must not keep its auto-approval. SmartApprove
                // grants by DECLARED EFFECT, so a server that re-declares
                // `destructiveHint: true` as `readOnlyHint: true` would
                // otherwise buy itself a silent Confirm bypass. Dropping the
                // tool from the verdict map denies the BYPASS, not the tool —
                // an absent verdict means "confirmations remain required",
                // which is the same safe state as a server that declares no
                // annotations at all.
                let tools = self.reject_repinned_tools(cfg, tools);
                let verdicts = match classify_tool_verdicts(&tools) {
                    Ok(verdicts) => verdicts,
                    Err(duplicate_tool) => {
                        tracing::warn!(
                            server = %cfg.id,
                            tool = %duplicate_tool,
                            "SmartApprove disabled because tools/list contains a duplicate name"
                        );
                        HashMap::new()
                    }
                };
                // Retain the live client only when the verdict map is non-empty.
                // An all-empty seal (e.g. duplicate tool name, or a server that
                // declares zero decisive annotations) can never issue a grant,
                // so keeping the spawned child alive until session end is pure
                // resource waste.  The cache entry is still sealed to prevent
                // re-initialization; future calls reach the normal Confirm path.
                // McpClient::drop() → child.start_kill() terminates the child.
                let has_grants = !verdicts.is_empty();
                self.cache.seed_verdicts(cfg, verdicts);
                if has_grants {
                    self.clients.insert_live(cfg.id.clone(), client);
                }
                // When !has_grants, `client` drops here, invoking
                // McpClient::drop() → self.child.start_kill().
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    server = %cfg.id,
                    error = %error,
                    "SmartApprove session snapshot unavailable; confirmations remain required"
                );
                self.cache.seed_verdicts(cfg, HashMap::new());
            }
            Err(_) => {
                tracing::warn!(
                    server = %cfg.id,
                    ?timeout,
                    "SmartApprove session snapshot timed out; confirmations remain required"
                );
                self.cache.seed_verdicts(cfg, HashMap::new());
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn initialization_attempts(&self) -> usize {
        self.initialization_attempts
    }

    /// Seed the session as if a successful `tools/list` occurred and the
    /// retained client was subsequently poisoned by a transport error.
    ///
    /// Concretely:
    /// * calls `cache.seed_verdicts` with the supplied map so that
    ///   `grant_for` returns `Some` for every `true`-valued entry;
    /// * inserts a `None`-valued slot into `clients.inner` — the exact
    ///   state `BoundSmartApproveClient::poison()` leaves after calling
    ///   `self.client.take()`.
    ///
    /// Lets `dispatch_loop` integration tests verify the post-transport-error
    /// behaviour of `bind_or_initialize` → `dispatch_one` without spawning a
    /// real subprocess.  Test-only.
    #[cfg(test)]
    pub(crate) fn seed_and_poison_for_test(
        &mut self,
        cfg: &McpServerConfig,
        verdicts: std::collections::HashMap<String, bool>,
    ) {
        let _ = self.cache.seed_verdicts(cfg, verdicts);
        // Mirror what `BoundSmartApproveClient::poison()` does:
        // `self.client.take()` sets the Option<McpClient> slot to None while
        // keeping the map entry present.  `live_slot_mut` treats any
        // None-valued slot as permanently dead.
        self.clients.inner.insert(cfg.id.clone(), None);
    }

    /// Return `true` when the read-only cache holds a valid grant for
    /// `(cfg, tool)`.  Lets `dispatch_loop` tests inspect cache state
    /// across the module boundary.  Test-only.
    #[cfg(test)]
    pub(crate) fn has_grant_for_test(&self, cfg: &McpServerConfig, tool: &str) -> bool {
        self.cache.grant_for(cfg, tool).is_some()
    }
}

fn duplicate_server_ids(configs: &[&McpServerConfig]) -> HashSet<String> {
    let mut counts = HashMap::<String, usize>::new();
    for cfg in configs {
        *counts.entry(cfg.id.clone()).or_default() += 1;
    }
    counts
        .into_iter()
        .filter_map(|(id, count)| (count > 1).then_some(id))
        .collect()
}

/// Stable SHA-256 binding for all fields that define one MCP launcher and its
/// authorization posture. `HashMap` environment order is canonicalized first;
/// only the digest is retained in the snapshot.
fn config_binding(cfg: &McpServerConfig) -> [u8; 32] {
    let env = cfg.env.iter().collect::<BTreeMap<_, _>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "id": cfg.id,
        "description": cfg.description,
        "command": cfg.command,
        "args": cfg.args,
        "env": env,
        "enabled": cfg.enabled,
        "allow_tools": cfg.allow_tools,
        "trust_all_tools": cfg.trust_all_tools,
        "smart_approve": cfg.smart_approve,
        "autonomy_gate": cfg.autonomy_gate,
    }))
    .expect("McpServerConfig contains only JSON-serializable fields");
    Sha256::digest(bytes).into()
}

// ── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ReadOnlyCache -------------------------------------------------------

    #[test]
    fn new_cache_is_empty() {
        let c = ReadOnlyCache::new();
        assert_eq!(c.is_readonly("srv", "read_file"), None);
    }

    #[test]
    fn insert_and_hit_readonly() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "read_file", true);
        assert_eq!(c.is_readonly("srv", "read_file"), Some(true));
    }

    #[test]
    fn insert_and_hit_not_readonly() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "write_file", false);
        assert_eq!(c.is_readonly("srv", "write_file"), Some(false));
    }

    #[test]
    fn miss_returns_none() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "something", true);
        assert_eq!(c.is_readonly("srv", "other_tool"), None);
    }

    #[test]
    fn cache_is_scoped_per_server_no_cross_server_collision() {
        // Review F5: two servers expose the same tool name with OPPOSITE
        // effects — the read-only verdict must NOT leak across servers.
        let mut c = ReadOnlyCache::new();
        c.insert("server_a", "search", true);
        c.insert("server_b", "search", false);
        assert_eq!(c.is_readonly("server_a", "search"), Some(true));
        assert_eq!(c.is_readonly("server_b", "search"), Some(false));
        // A third server's same-named tool is still unknown.
        assert_eq!(c.is_readonly("server_c", "search"), None);
    }

    #[test]
    fn seed_static_marks_tools_as_readonly() {
        let mut c = ReadOnlyCache::new();
        c.seed_static("srv", &["list_dir", "search_web"]);
        assert_eq!(c.is_readonly("srv", "list_dir"), Some(true));
        assert_eq!(c.is_readonly("srv", "search_web"), Some(true));
        assert_eq!(c.is_readonly("srv", "write_file"), None);
    }

    #[test]
    fn uncached_returns_tools_with_no_entry() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "known_tool", true);
        let all = ["known_tool", "unknown_a", "unknown_b"];
        let uncached = c.uncached("srv", &all);
        assert_eq!(uncached.len(), 2);
        assert!(uncached.contains(&"unknown_a"));
        assert!(uncached.contains(&"unknown_b"));
        assert!(!uncached.contains(&"known_tool"));
    }

    #[test]
    fn uncached_empty_when_all_known() {
        let mut c = ReadOnlyCache::new();
        c.insert("srv", "a", true);
        c.insert("srv", "b", false);
        assert!(c.uncached("srv", &["a", "b"]).is_empty());
    }

    // ---- classify_from_annotations / seed_from_tools (effect metadata) ------

    use crate::mcp::client::{McpTool, ToolAnnotations};

    fn tool(name: &str, ann: Option<ToolAnnotations>) -> McpTool {
        McpTool {
            name: name.into(),
            description: None,
            input_schema: serde_json::json!({}),
            annotations: ann,
        }
    }

    fn server(id: &str) -> McpServerConfig {
        McpServerConfig {
            id: id.into(),
            description: None,
            command: "mcp-test-server".into(),
            args: vec!["--stdio".into()],
            env: HashMap::new(),
            enabled: true,
            allow_tools: Some(vec!["read_graph".into(), "delete_node".into()]),
            trust_all_tools: false,
            smart_approve: true,
            autonomy_gate: None,
        }
    }

    // ---- ADOPT31-C4a: a re-declared tool loses its auto-approval ----------

    fn home_with_key() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        std::fs::write(wal.join("hmac.key"), [9u8; 32]).unwrap();
        dir
    }

    #[test]
    fn an_effect_flip_after_registration_withdraws_auto_approval() {
        // The rug-pull SmartApprove is exposed to: register as destructive,
        // then re-declare as read-only to buy a silent Confirm bypass.
        let home = home_with_key();
        let cfg = server("srv");
        let session = SmartApproveSession::default().with_home(home.path().to_path_buf());

        let destructive = tool(
            "delete_node",
            Some(ToolAnnotations {
                read_only_hint: Some(false),
                destructive_hint: Some(true),
            }),
        );
        let kept = session.reject_repinned_tools(&cfg, vec![destructive]);
        assert_eq!(kept.len(), 1, "first sighting pins and passes through");

        let flipped = tool(
            "delete_node",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        );
        let kept = session.reject_repinned_tools(&cfg, vec![flipped]);
        assert!(
            kept.is_empty(),
            "a tool that re-declared its effect must not reach classify_tool_verdicts —              an absent verdict is what keeps the operator Confirm in place"
        );
    }

    #[test]
    fn an_unchanged_tool_keeps_reaching_the_classifier() {
        let home = home_with_key();
        let cfg = server("srv");
        let session = SmartApproveSession::default().with_home(home.path().to_path_buf());
        let t = tool(
            "read_graph",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        );
        assert_eq!(
            session.reject_repinned_tools(&cfg, vec![t.clone()]).len(),
            1
        );
        assert_eq!(
            session.reject_repinned_tools(&cfg, vec![t]).len(),
            1,
            "an unchanged declaration must keep its auto-approval path"
        );
    }

    #[test]
    fn an_unusable_pin_store_costs_the_bypass_not_the_tool() {
        // No hmac.key ⇒ the guardian cannot verify anything. SmartApprove is a
        // bypass of an operator confirmation, so losing verification must cost
        // the bypass. The tools stay callable behind the normal Confirm path.
        let home = tempfile::tempdir().unwrap();
        let cfg = server("srv");
        let session = SmartApproveSession::default().with_home(home.path().to_path_buf());
        let t = tool(
            "read_graph",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        );
        assert!(
            session.reject_repinned_tools(&cfg, vec![t]).is_empty(),
            "unverifiable pins must withhold auto-approval"
        );
    }

    #[test]
    fn a_first_pin_flush_failure_withholds_every_grant_and_leaves_no_pin_file() {
        let home = home_with_key();
        let pin_path = home.path().join("mcp_tool_pins.json");
        let atomic_temp_path = home.path().join(format!(
            ".neoth-write-{}-mcp_tool_pins.json.tmp",
            std::process::id()
        ));

        // `write_file_atomic` stages to this exact sibling path. A directory at
        // that path makes the real staging write fail on both Unix and Windows
        // without relying on platform-specific permission semantics.
        std::fs::create_dir(&atomic_temp_path).unwrap();

        let cfg = server("srv");
        let session = SmartApproveSession::default().with_home(home.path().to_path_buf());
        let read_only = tool(
            "read_graph",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        );

        assert!(
            session
                .reject_repinned_tools(&cfg, vec![read_only])
                .is_empty(),
            "an uncommitted TOFU pin must never become a SmartApprove grant"
        );
        assert!(
            !pin_path.exists(),
            "a failed atomic flush must not leave a trusted pin store behind"
        );
    }

    #[test]
    fn classify_read_only_hint_marks_readonly() {
        let t = tool(
            "search",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        );
        assert_eq!(classify_from_annotations(&t), Some(true));
    }

    #[test]
    fn classify_destructive_hint_always_wins_over_readonly() {
        // A server that (incoherently) marks a tool BOTH read-only AND
        // destructive must NOT be auto-approved — destructive wins.
        let t = tool(
            "wipe",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(true),
            }),
        );
        assert_eq!(classify_from_annotations(&t), Some(false));
    }

    #[test]
    fn classify_no_annotations_is_unknown() {
        // No declared effect metadata → unknown → never auto-approved on a name.
        assert_eq!(classify_from_annotations(&tool("mystery", None)), None);
        // Annotations present but no decisive hint → still unknown.
        let t = tool("partial", Some(ToolAnnotations::default()));
        assert_eq!(classify_from_annotations(&t), None);
    }

    #[test]
    fn seed_from_tools_records_only_decisive_hints() {
        let tools = vec![
            tool(
                "read_graph",
                Some(ToolAnnotations {
                    read_only_hint: Some(true),
                    destructive_hint: Some(false),
                }),
            ),
            tool(
                "delete_node",
                Some(ToolAnnotations {
                    read_only_hint: Some(false),
                    destructive_hint: Some(true),
                }),
            ),
            tool("unknown", None),
        ];
        let mut c = ReadOnlyCache::new();
        let cfg = server("graph_srv");
        assert!(c.seed_from_tools(&cfg, &tools));
        assert_eq!(c.is_readonly("graph_srv", "read_graph"), Some(true));
        assert_eq!(c.is_readonly("graph_srv", "delete_node"), Some(false));
        assert_eq!(c.is_readonly_for(&cfg, "read_graph"), Some(true));
        // Unhinted tool stays uncached — falls through to the confirm path.
        assert_eq!(c.is_readonly("graph_srv", "unknown"), None);
    }

    #[test]
    fn duplicate_tool_names_seal_the_whole_snapshot_empty_in_every_order() {
        let readonly = tool(
            "ambiguous",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        );
        let destructive = tool(
            "ambiguous",
            Some(ToolAnnotations {
                read_only_hint: Some(false),
                destructive_hint: Some(true),
            }),
        );
        for tools in [
            vec![destructive.clone(), readonly.clone()],
            vec![readonly.clone(), destructive],
            vec![readonly.clone(), readonly],
        ] {
            let cfg = server("duplicate-tools");
            let mut cache = ReadOnlyCache::new();
            assert!(cache.seed_from_tools(&cfg, &tools));
            assert_eq!(cache.is_readonly_for(&cfg, "ambiguous"), None);
            assert!(cache.grant_for(&cfg, "ambiguous").is_none());
        }
    }

    #[test]
    fn retained_client_registry_reuses_identity_and_poison_is_permanent() {
        let mut clients = SessionClients::default();
        clients.insert_live("graph_srv".into(), 41usize);
        let first_address = clients
            .live_slot_mut("graph_srv")
            .unwrap()
            .as_mut()
            .unwrap() as *mut usize as usize;
        *clients
            .live_slot_mut("graph_srv")
            .unwrap()
            .as_mut()
            .unwrap() += 1;
        let second_address = clients
            .live_slot_mut("graph_srv")
            .unwrap()
            .as_mut()
            .unwrap() as *mut usize as usize;
        assert_eq!(first_address, second_address);
        assert_eq!(
            *clients
                .live_slot_mut("graph_srv")
                .unwrap()
                .as_mut()
                .unwrap(),
            42
        );

        clients.poison("graph_srv");
        assert!(clients.live_slot_mut("graph_srv").is_none());
    }

    #[test]
    fn duplicate_enabled_server_ids_are_never_session_bindable() {
        let first = server("duplicate-id");
        let mut second = first.clone();
        second.command = "other-server".into();
        let unique = server("unique-id");
        let duplicates = duplicate_server_ids(&[&first, &second, &unique]);
        assert_eq!(duplicates, HashSet::from(["duplicate-id".to_string()]));

        let servers = McpServers {
            servers: vec![first, second, unique],
            smart_loading: true,
        };
        let session = SmartApproveSession::new(&servers);
        assert!(session.duplicate_ids.contains("duplicate-id"));
        assert!(!session.duplicate_ids.contains("unique-id"));
    }

    #[test]
    fn session_snapshot_is_immutable_after_first_seed() {
        let cfg = server("graph_srv");
        let initial = vec![tool(
            "read_graph",
            Some(ToolAnnotations {
                read_only_hint: Some(false),
                destructive_hint: Some(true),
            }),
        )];
        let drifted = vec![tool(
            "read_graph",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        )];
        let mut cache = ReadOnlyCache::new();
        assert!(cache.seed_from_tools(&cfg, &initial));
        assert!(!cache.seed_from_tools(&cfg, &drifted));
        assert_eq!(cache.is_readonly_for(&cfg, "read_graph"), Some(false));
    }

    #[test]
    fn config_drift_invalidates_the_bound_snapshot() {
        let cfg = server("graph_srv");
        let tools = vec![tool(
            "read_graph",
            Some(ToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: Some(false),
            }),
        )];
        let mut cache = ReadOnlyCache::new();
        assert!(cache.seed_from_tools(&cfg, &tools));
        assert_eq!(cache.is_readonly_for(&cfg, "read_graph"), Some(true));
        let grant = cache.grant_for(&cfg, "read_graph").unwrap();
        assert!(grant.authorizes(&cfg, "read_graph"));

        let mut changed = cfg.clone();
        changed.command = "different-server".into();
        assert_eq!(cache.is_readonly_for(&changed, "read_graph"), None);
        assert!(!grant.authorizes(&changed, "read_graph"));
    }

    #[tokio::test]
    async fn sealed_failed_snapshot_is_never_reinitialized_mid_session() {
        let cfg = server("sealed-failure");
        let mut session = SmartApproveSession::default();
        assert!(session.cache.seed_verdicts(&cfg, HashMap::new()));
        assert!(session
            .bind_or_initialize(&cfg, "read_graph")
            .await
            .is_none());
        assert!(session.cache.is_bound_to(&cfg));
        assert!(session.cache.grant_for(&cfg, "read_graph").is_none());
    }

    #[test]
    fn config_binding_canonicalizes_environment_order() {
        let mut left = server("graph_srv");
        left.env.insert("ALPHA".into(), "one".into());
        left.env.insert("BETA".into(), "two".into());
        let mut right = server("graph_srv");
        right.env.insert("BETA".into(), "two".into());
        right.env.insert("ALPHA".into(), "one".into());
        assert_eq!(config_binding(&left), config_binding(&right));
    }

    /// FOLLOW-UP-W3-SMARTAPPROVE-DUP-TOOL-CLIENT fix verification.
    ///
    /// After a duplicate-tool (or any all-empty) seal, `initialize_server`
    /// must NOT retain a live client: `clients.inner` must be absent for the
    /// server so the child process is dropped immediately rather than held
    /// until session end for zero benefit.
    ///
    /// A subsequent `bind_or_initialize` must resolve to `None` (normal
    /// Confirm path fires, no grant) and must not re-trigger initialization.
    #[tokio::test]
    async fn duplicate_tool_seal_no_client_retained_and_confirm_fires() {
        // Simulate the post-fix state: initialize_server received an Ok
        // tools/list but classify_tool_verdicts returned Err(duplicate_tool),
        // so it sealed the cache with an empty verdict map and did NOT call
        // insert_live.  We reproduce that exact cache state here without
        // spawning a real subprocess.
        let cfg = server("dup-tool-srv");
        let mut session = SmartApproveSession::default();

        // Seal with empty verdicts — the fixed initialize_server does this
        // for the duplicate-tool branch, then drops the client rather than
        // calling insert_live.
        assert!(session.cache.seed_verdicts(&cfg, HashMap::new()));

        // No insert_live was called, so the clients registry must be absent
        // (not poisoned-None, but entirely absent).
        assert!(
            !session.clients.inner.contains_key(&cfg.id),
            "no live client must be retained after a duplicate-tool (empty-verdict) seal"
        );

        // bind_or_initialize sees a sealed cache (is_bound_to = true) but no
        // live client slot → live_slot_mut returns None → returns None.
        // The dispatch gate therefore fires the normal Confirm path.
        let result = session.bind_or_initialize(&cfg, "ambiguous_tool").await;
        assert!(
            result.is_none(),
            "duplicate-tool seal must make bind_or_initialize return None (Confirm)"
        );

        // The sealed cache must prevent re-initialization entirely.
        assert_eq!(
            session.initialization_attempts(),
            0,
            "a sealed cache entry must never trigger a second initialize_server call"
        );
    }
}
