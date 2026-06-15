//! GU-03 — persona-adaptive settings-panel visibility (the rule engine).
//!
//! Pure Rust, ZERO Slint dependency, so the entire "which settings panels show
//! at which complexity level" rule set is unit-testable without a display —
//! matching the established test-seam pattern in `main.rs` (`shape_chat_output`,
//! `shape_usage_summary`, `validate_operator_id`, …). The `.slint` side binds
//! `in property <bool> show_*` to the fields of [`PanelVisibility`], which
//! `main.rs` populates from the operator's complexity level on startup.
//!
//! The complexity level is the SAME signal the wizard computes
//! (`neothd::wizard::recommend::operator_complexity_level` → W-03a). The type is
//! MIRRORED here (same `minimal`/`standard`/`full` wire form) rather than
//! depended-on, keeping the GUI crate decoupled from the daemon — the same
//! pattern as the `MinimalFreedomYaml` / `CodingSessionJson` mirrors in main.rs.

/// Mirror of `neothd::wizard::recommend::ComplexityLevel`.
/// Serde/string wire form: `"minimal"` | `"standard"` | `"full"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComplexityLevel {
    /// Beginner — only the panels a first-run operator needs.
    Minimal,
    /// Intermediate — the common panels expanded; advanced present but collapsed.
    #[default]
    Standard,
    /// Advanced — everything visible + advanced sub-sections expanded.
    Full,
}

impl ComplexityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ComplexityLevel::Minimal => "minimal",
            ComplexityLevel::Standard => "standard",
            ComplexityLevel::Full => "full",
        }
    }
}

/// Which settings tabs are visible + which advanced sub-sections are expanded.
/// Every field is independently queryable so a test can pin one panel's
/// decision without coupling to the whole set. (`chat` is the always-present
/// main surface and is intentionally NOT gated.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelVisibility {
    pub show_hemispheres: bool,
    pub show_channels: bool,
    pub show_skills: bool,
    pub show_plugins: bool,
    pub show_memory: bool,
    pub show_privacy: bool,
    pub show_cluster: bool,
    pub show_config: bool,
    pub show_code_sessions: bool,
    /// Advanced sub-section expansion within a tab (the header shows, the inner
    /// detail is collapsed until the operator opens it / is at Full).
    pub expand_cluster_advanced: bool,
    pub expand_config_advanced: bool,
}

/// GU-03 entry point — the single source of truth for panel-collapse rules.
///
/// - **Minimal** (beginner): hide everything except the panels a first-run
///   operator genuinely needs — channels (to connect Telegram), privacy (the
///   autonomy level is beginner-critical), config (provider choice). No
///   clustering / plugins / skills / memory internals / code sessions.
/// - **Standard** (intermediate): all common panels visible; advanced tabs
///   (cluster, config) present but their advanced sub-sections collapsed; no
///   plugins (a power-user surface).
/// - **Full** (advanced): everything visible + advanced sub-sections expanded.
pub fn panels_for(level: ComplexityLevel) -> PanelVisibility {
    match level {
        ComplexityLevel::Minimal => PanelVisibility {
            show_hemispheres: false,
            show_channels: true,
            show_skills: false,
            show_plugins: false,
            show_memory: false,
            show_privacy: true,
            show_cluster: false,
            show_config: true,
            show_code_sessions: false,
            expand_cluster_advanced: false,
            expand_config_advanced: false,
        },
        ComplexityLevel::Standard => PanelVisibility {
            show_hemispheres: true,
            show_channels: true,
            show_skills: true,
            show_plugins: false,
            show_memory: true,
            show_privacy: true,
            show_cluster: true,
            show_config: true,
            show_code_sessions: true,
            expand_cluster_advanced: false,
            expand_config_advanced: false,
        },
        ComplexityLevel::Full => PanelVisibility {
            show_hemispheres: true,
            show_channels: true,
            show_skills: true,
            show_plugins: true,
            show_memory: true,
            show_privacy: true,
            show_cluster: true,
            show_config: true,
            show_code_sessions: true,
            expand_cluster_advanced: true,
            expand_config_advanced: true,
        },
    }
}

/// Parse the complexity string the wizard persists. Unknown / missing → the
/// safe non-overwhelming default (`Standard`).
pub fn parse_complexity_level(s: &str) -> ComplexityLevel {
    match s.trim().to_ascii_lowercase().as_str() {
        "minimal" => ComplexityLevel::Minimal,
        "full" => ComplexityLevel::Full,
        _ => ComplexityLevel::Standard,
    }
}

/// Read the operator's complexity level from `~/.neoth/wizard_state_v2.yaml`
/// (the `complexity_level` top-level key the v2 wizard persists — W-03a). This
/// is the REAL adaptive signal: the GUI binds panel visibility to whatever the
/// wizard decided for this operator. Fallback `Standard` when the file/field is
/// absent (a pre-v2 wizard state, or the operator hasn't run the v2 wizard) —
/// the safe non-overwhelming default.
///
/// Reads the YAML with a minimal struct rather than depending on the daemon
/// crate (the GUI stays decoupled — same pattern as `MinimalFreedomYaml`).
pub fn read_complexity_level(home: &std::path::Path) -> ComplexityLevel {
    let path = home.join("wizard_state_v2.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ComplexityLevel::Standard;
    };
    #[derive(serde::Deserialize)]
    struct MinimalWizardState {
        #[serde(default)]
        complexity_level: Option<String>,
    }
    match serde_yaml::from_str::<MinimalWizardState>(&text) {
        Ok(m) => m
            .complexity_level
            .as_deref()
            .map(parse_complexity_level)
            .unwrap_or_default(),
        Err(_) => ComplexityLevel::Standard,
    }
}

// ── GR-10 — Safety Rails panel (parse `neoth security safe-mode --json`) ──────

/// One safety rail as reported by `neoth security safe-mode --json`. The GUI
/// `SafeRailRow` Slint struct is built from this in `main.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeRail {
    pub name: String,
    pub engaged: bool,
    pub detail: String,
}

/// The parsed safe-mode snapshot: every rail + the engaged/total counts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SafeModeSnapshot {
    pub rails: Vec<SafeRail>,
    pub engaged_count: i32,
    pub total: i32,
}

/// Parse the JSON emitted by `neoth security safe-mode --json`
/// (`{rails:[{name,engaged,detail}], engaged_count, total}`). PURE + robust: a
/// missing/malformed payload yields an EMPTY snapshot so the panel renders a
/// "no data" state rather than crashing the GUI. The counts are derived from
/// the rails when the top-level fields are absent (forward-compatible).
pub fn parse_safe_mode(json: &str) -> SafeModeSnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return SafeModeSnapshot::default();
    };
    let rails: Vec<SafeRail> = v
        .get("rails")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let name = r.get("name")?.as_str()?.to_string();
                    let engaged = r.get("engaged").and_then(|e| e.as_bool()).unwrap_or(false);
                    let detail = r
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(SafeRail {
                        name,
                        engaged,
                        detail,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let engaged_count = v
        .get("engaged_count")
        .and_then(|c| c.as_i64())
        .unwrap_or_else(|| rails.iter().filter(|r| r.engaged).count() as i64)
        as i32;
    let total = v
        .get("total")
        .and_then(|t| t.as_i64())
        .unwrap_or(rails.len() as i64) as i32;
    SafeModeSnapshot {
        rails,
        engaged_count,
        total,
    }
}

// ── GR-03 trust panel (parse `neoth trust --output json`) ────────────────────

/// One label→value row for the Trust panel (autonomy / privacy / recovery /
/// ledger sections all render as these).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustRow {
    pub label: String,
    pub value: String,
}

/// Parsed `neoth trust --output json`: the four read-only sections the CLI
/// exposes (autonomy posture, privacy switches, recovery-key readiness, WAL
/// trust-ledger size). The GUI renders this as a single legible "what is
/// protecting me + what can I prove" surface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustSnapshot {
    pub autonomy_level: String,
    pub autonomy_behavior: String,
    pub gated_examples: Vec<String>,
    pub privacy: Vec<TrustRow>,
    pub recovery: Vec<TrustRow>,
    pub ledger: Vec<TrustRow>,
}

/// Render any JSON scalar as a compact display string (bool → on/off; the rest
/// via their natural string form). Keeps the parser forward-compatible: a new
/// privacy switch the CLI adds shows up automatically, whatever its type.
fn trust_scalar_display(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Bool(b) => if *b { "on" } else { "off" }.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "—".to_string(),
        other => other.to_string(),
    }
}

/// PURE + robust: a missing/malformed payload yields an EMPTY snapshot (the
/// panel shows a "no daemon / no data" state rather than crashing the GUI).
/// Unknown privacy-switch keys are rendered generically so the panel never goes
/// stale when the CLI grows a new switch.
pub fn parse_trust(json: &str) -> TrustSnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return TrustSnapshot::default();
    };
    let autonomy_level = v
        .pointer("/autonomy/level")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let autonomy_behavior = v
        .pointer("/autonomy/behavior")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let gated_examples = v
        .pointer("/autonomy/gated_examples")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // Privacy switches: a flat object of mixed bool/string values — render each
    // generically, sorted by key for a stable display order.
    let privacy = object_rows(v.get("privacy_switches"));
    // Recovery keys: *_present bools → present/missing rows.
    let recovery = v
        .get("recovery")
        .and_then(|r| r.as_object())
        .map(|o| {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            keys.into_iter()
                .map(|k| TrustRow {
                    label: k.clone(),
                    value: if o.get(k).and_then(|x| x.as_bool()).unwrap_or(false) {
                        "present".to_string()
                    } else {
                        "missing".to_string()
                    },
                })
                .collect()
        })
        .unwrap_or_default();
    let ledger = object_rows(v.get("trust_ledger"));

    TrustSnapshot {
        autonomy_level,
        autonomy_behavior,
        gated_examples,
        privacy,
        recovery,
        ledger,
    }
}

/// Turn a flat JSON object into sorted label→value rows (None → empty).
fn object_rows(obj: Option<&serde_json::Value>) -> Vec<TrustRow> {
    obj.and_then(|o| o.as_object())
        .map(|o| {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            keys.into_iter()
                .map(|k| TrustRow {
                    label: k.clone(),
                    value: trust_scalar_display(o.get(k).unwrap_or(&serde_json::Value::Null)),
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── SL-03 resource tab (parse `neoth hardware --output json`) ────────────────

/// Parsed `neoth hardware --output json`: the local-machine resource snapshot
/// the SL-03 resource panel shows — CPU, memory, accelerator, VRAM, disk, and
/// which local models are cached. Headline fields are pre-formatted strings;
/// `models` is label→state rows (reusing [`TrustRow`]).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HardwareSnapshot {
    pub cpu: String,
    pub memory: String,
    pub accelerator: String,
    pub vram: String,
    /// GOLD-PROG-07 — VRAM used/total as a clamped 0.0..=1.0 fraction the Slint
    /// meter binds to. 0.0 when no GPU / total is 0, so the bar stays hidden.
    /// (`f32` is why this struct is `PartialEq` but not `Eq`.)
    pub vram_fraction: f32,
    pub disk: String,
    pub models: Vec<TrustRow>,
}

/// Bytes → whole GiB (rounded) as a display string.
fn gib(bytes: u64) -> u64 {
    bytes / (1024 * 1024 * 1024)
}

/// PURE + robust: garbage/empty → default (panel shows a "no daemon" state).
pub fn parse_hardware(json: &str) -> HardwareSnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return HardwareSnapshot::default();
    };
    let g = |p: &str| v.pointer(p).and_then(|x| x.as_u64());

    let cpu = {
        let brand = v
            .pointer("/cpu/brand")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let phys = g("/cpu/physical_cores").unwrap_or(0);
        let log = g("/cpu/logical_cores").unwrap_or(0);
        let mhz = g("/cpu/frequency_mhz").unwrap_or(0);
        if brand.is_empty() {
            String::new()
        } else {
            format!("{brand} — {phys}c/{log}t @ {mhz} MHz")
        }
    };
    let memory = match (g("/memory/available_bytes"), g("/memory/total_bytes")) {
        (Some(a), Some(t)) if t > 0 => format!("{} / {} GiB available", gib(a), gib(t)),
        _ => String::new(),
    };
    let accelerator = {
        let picked = v
            .pointer("/accelerator/picked")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let gpu = v
            .pointer("/accelerator/has_gpu_path")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        if picked.is_empty() {
            String::new()
        } else if gpu {
            format!("{picked} — GPU path active")
        } else {
            format!("{picked} — CPU only")
        }
    };
    let vram = match (g("/vram/used_mib"), g("/vram/total_mib")) {
        (Some(u), Some(t)) if t > 0 => {
            format!("{u} / {t} MiB used ({}%)", (u.saturating_mul(100)) / t)
        }
        _ => "(no GPU detected)".to_string(),
    };
    // GOLD-PROG-07 — the same used/total expressed as a clamped 0.0..=1.0
    // fraction for the live VRAM meter; 0.0 (bar hidden) when VRAM is absent or
    // total is 0 (no divide-by-zero), clamped so a stray used>total can't overrun.
    let vram_fraction = match (g("/vram/used_mib"), g("/vram/total_mib")) {
        (Some(u), Some(t)) if t > 0 => (u as f32 / t as f32).clamp(0.0, 1.0),
        _ => 0.0,
    };
    let disk = match (g("/disk/home_available_bytes"), g("/disk/home_total_bytes")) {
        (Some(a), Some(t)) if t > 0 => {
            let mount = v
                .pointer("/disk/home_mount")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            format!("{} / {} GiB free ({mount})", gib(a), gib(t))
        }
        _ => String::new(),
    };
    let models = object_rows(v.get("cached_models"))
        .into_iter()
        .map(|r| TrustRow {
            label: r.label,
            // cached_models values are bools (on/off) → cached/missing.
            value: if r.value == "on" { "cached".to_string() } else { "not cached".to_string() },
        })
        .collect();

    HardwareSnapshot {
        cpu,
        memory,
        accelerator,
        vram,
        vram_fraction,
        disk,
        models,
    }
}

// ── SL-02 cluster topology (parse `neoth cluster topology --output json`) ────

/// One peer row for the Cluster-tab topology panel. Pre-formatted strings so
/// the Slint side is pure display (mirrors [`TrustRow`] / [`HardwareSnapshot`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClusterPeerRow {
    pub label: String,
    pub addr: String,
    pub status: String,
    /// "N ms" or "---" until the first heartbeat round-trip.
    pub rtt_ms: String,
    /// EWMA heartbeat success as a percent, e.g. "87%".
    pub stability_pct: String,
    /// Human last-seen age, e.g. "2m ago" / "never".
    pub last_seen: String,
}

/// Human last-seen age from `last_seen_age_secs` (None / JSON null → "never").
/// Mirrors `cli/cluster.rs::fmt_last_seen` so the GUI matches the CLI table.
fn fmt_peer_last_seen(age: Option<i64>) -> String {
    match age {
        None => "never".to_string(),
        Some(s) if s < 5 => "just now".to_string(),
        Some(s) if s < 60 => format!("{s}s ago"),
        Some(s) if s < 3600 => format!("{}m ago", s / 60),
        Some(s) => format!("{}h ago", s / 3600),
    }
}

/// PURE + robust: parse `neoth cluster topology --output json` into peer rows.
/// Garbage / a missing `peers` array → empty (panel shows the "no peers" hint).
pub fn parse_cluster_topology(json: &str) -> Vec<ClusterPeerRow> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(peers) = v.get("peers").and_then(|p| p.as_array()) else {
        return Vec::new();
    };
    peers
        .iter()
        .map(|p| {
            let s = |k: &str| p.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            // Prefer the instance label; fall back to the short key so a row is
            // never blank.
            let label = {
                let l = s("label");
                if l.is_empty() { s("pub_key_short") } else { l }
            };
            let rtt_ms = match p.get("rtt_ms").and_then(|x| x.as_u64()) {
                Some(ms) => format!("{ms} ms"),
                None => "---".to_string(),
            };
            let stability_pct = {
                let score = p.get("stability_score").and_then(|x| x.as_f64()).unwrap_or(0.0);
                format!("{:.0}%", (score * 100.0).clamp(0.0, 100.0))
            };
            let last_seen = fmt_peer_last_seen(p.get("last_seen_age_secs").and_then(|x| x.as_i64()));
            ClusterPeerRow {
                label,
                addr: s("addr"),
                status: s("status"),
                rtt_ms,
                stability_pct,
                last_seen,
            }
        })
        .collect()
}

// ── GOLD-PROG-08 live token budget (parse `~/.neoth/usage_meter.json`) ──────

/// Parsed `~/.neoth/usage_meter.json` (written by the daemon's usage-export
/// task): the live token budget for the GUI's Config-tab meter. `available` is
/// false when the file is absent/garbage (daemon not running / no usage yet) so
/// the panel shows a "daemon not running" state rather than a misleading "0".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageMeterPanel {
    pub available: bool,
    pub responses: String,
    pub tokens: String,
    /// Honesty note: the meter counts the council path only today (WIRE-10b
    /// extends it), plus a lag-undercount warning when events were dropped.
    pub note: String,
}

/// PURE + robust: garbage/empty → default (`available=false`).
pub fn parse_usage_meter(json: &str) -> UsageMeterPanel {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return UsageMeterPanel::default();
    };
    let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    // Require at least the canonical shape (a `provider_responses` key) — a
    // stray `{}` shouldn't read as a live meter.
    if v.get("provider_responses").is_none() {
        return UsageMeterPanel::default();
    }
    let lagged = g("lagged_events");
    let note = if lagged > 0 {
        format!("council-path only · ⚠ {lagged} events dropped (token totals undercount)")
    } else {
        "council-path only".to_string()
    };
    UsageMeterPanel {
        available: true,
        responses: format!("{} provider responses", g("provider_responses")),
        tokens: format!(
            "{} in / {} out tokens",
            g("input_tokens_total"),
            g("output_tokens_total")
        ),
        note,
    }
}

// ── KF-08 council budget meter (parse `neoth council budget --output json`) ──

/// Parsed `neoth council budget --output json`: the per-message council cap +
/// the last debate's live runtime usage. Headlines are pre-formatted; the
/// last-debate runtime renders as label→value rows (empty when no debate has
/// run yet, so the panel shows a "no debate yet" state).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CouncilBudgetPanel {
    pub configured_cap: String,
    pub daily_usd_cap: String,
    pub last_debate: Vec<TrustRow>,
    /// GOLD-HON-13 — non-empty when the council recursion depth is > 1,
    /// spelling out the `3^depth` per-prompt fan-out so a deep tree is a
    /// visible cost on the Config tab, not a silent multiplier.
    pub depth_cost_warning: String,
}

/// GOLD-HON-13 — GUI mirror of `neothd::cli::init::render_council_depth_cost_warning`
/// (the GUI crate stays decoupled from `neothd`, so the `3^depth` formula is
/// replicated + tested here). Empty while flat (depth ≤ 1); a one-line ⚠ at
/// depth ≥ 2. The daemon clamps depth to 4, but the GUI reads raw JSON — the
/// defensive cap is applied to BOTH the exponent label and the computed value
/// so the displayed math stays internally consistent (GR-061).
fn council_depth_cost_warning(depth: u64) -> String {
    if depth <= 1 {
        return String::new();
    }
    let display_depth = depth.min(8);
    let calls = 3u64.saturating_pow(display_depth as u32);
    format!(
        "⚠ council depth {depth} fans every prompt out to ~3^{display_depth} = {calls} provider \
         calls — on a metered provider this multiplies the per-prompt bill in lockstep. \
         Lower hemisphere_council_depth to reduce it."
    )
}

/// PURE + robust: garbage/empty → default.
pub fn parse_council_budget(json: &str) -> CouncilBudgetPanel {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return CouncilBudgetPanel::default();
    };
    let configured_cap = match v.get("configured_cap").and_then(|x| x.as_u64()) {
        Some(c) => format!("{c} calls / message"),
        None => String::new(),
    };
    let depth_cost_warning = v
        .get("max_recursion_depth")
        .and_then(|x| x.as_u64())
        .map(council_depth_cost_warning)
        .unwrap_or_default();
    let daily_usd_cap = match v.get("daily_usd_cap").and_then(|x| x.as_f64()) {
        Some(u) => format!("${u:.2} / day"),
        None => "no daily USD cap".to_string(),
    };
    let last_debate = match v.get("runtime") {
        Some(r) if r.is_object() => {
            let u = |k: &str| r.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
            vec![
                TrustRow {
                    label: "used last message".to_string(),
                    value: format!("{} / {}", u("used_last_msg"), u("cap_at_last_debate")),
                },
                TrustRow {
                    label: "exhausted last message".to_string(),
                    value: if r.get("exhausted_last_msg").and_then(|x| x.as_bool()).unwrap_or(false) {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    },
                },
                TrustRow {
                    label: "exhaustions (rolling)".to_string(),
                    value: u("exhaustions_rolling").to_string(),
                },
            ]
        }
        _ => Vec::new(),
    };
    CouncilBudgetPanel {
        configured_cap,
        daily_usd_cap,
        last_debate,
        depth_cost_warning,
    }
}

// ── GU-01 hemispheres panel (parse `neoth hemispheres show --output json`) ───

/// One role→provider binding for the Hemispheres panel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HemisphereBinding {
    pub role: String,     // "left" | "right" | "cerebellum"
    pub provider: String, // canonical id, or "(unset)" when no provider bound
    pub model: String,    // "" when the binding uses the provider default
    pub has_key: bool,
}

/// Parsed hemisphere topology snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HemispheresSnapshot {
    pub mode: String, // "single" | "custom" | "triplet"
    pub bindings: Vec<HemisphereBinding>,
}

/// Parse `neoth hemispheres show --output json`. PURE + robust (malformed →
/// empty). A null `provider` renders as `(unset)`; a null `model` as empty.
pub fn parse_hemispheres(json: &str) -> HemispheresSnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return HemispheresSnapshot::default();
    };
    let mode = v
        .get("mode")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let bindings = v
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let role = r.get("role")?.as_str()?.to_string();
                    let provider = r
                        .get("provider")
                        .and_then(|p| p.as_str())
                        .unwrap_or("(unset)")
                        .to_string();
                    let model = r
                        .get("model")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();
                    let has_key = r.get("has_key").and_then(|k| k.as_bool()).unwrap_or(false);
                    Some(HemisphereBinding {
                        role,
                        provider,
                        model,
                        has_key,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    HemispheresSnapshot { mode, bindings }
}

// ── GU-01 skills panel (parse `neoth skills --list --output json`) ───────────

/// One installed skill for the Skills panel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillSummary {
    pub id: String,
    pub description: String,
    pub enabled: bool,
    /// Trigger keywords joined with ", " for display.
    pub keywords: String,
}

/// Parse `neoth skills --list --output json` (a JSON array of SkillManifest).
/// PURE + robust (malformed → empty). A skill missing `enabled` defaults to
/// `true` (matching the daemon's `#[serde(default = "default_true")]`).
pub fn parse_skills(json: &str) -> Vec<SkillSummary> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| {
            let id = s.get("id")?.as_str()?.to_string();
            let description = s
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let enabled = s.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true);
            let keywords = s
                .get("trigger_keywords")
                .and_then(|k| k.as_array())
                .map(|kw| {
                    kw.iter()
                        .filter_map(|w| w.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            Some(SkillSummary {
                id,
                description,
                enabled,
                keywords,
            })
        })
        .collect()
}

// ── GU-01 plugins panel (parse `neoth plugin list --output json`) ────────────

/// One discovered plugin for the Plugins panel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PluginSummary {
    pub id: String,
    pub name: String,
    pub activation: String, // "enabled" | "pending" | "disabled" | …
}

/// Parse `neoth plugin list --output json` (array of `{id,name,activation}`).
/// PURE + robust (malformed/non-array → empty; id-less entries skipped).
pub fn parse_plugins(json: &str) -> Vec<PluginSummary> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|p| {
            let id = p.get("id")?.as_str()?.to_string();
            let name = p
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let activation = p
                .get("activation")
                .and_then(|a| a.as_str())
                .unwrap_or("unknown")
                .to_string();
            Some(PluginSummary {
                id,
                name,
                activation,
            })
        })
        .collect()
}

// ── GU-01 memory panel (parse `neoth memory --size --output json`) ───────────

/// One memory block (source + path + byte size) for the Memory panel. The
/// `--size` shape deliberately carries NO content — only metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryBlockInfo {
    pub source: String, // "global" | "project" | "rule" | "memory"
    pub path: String,
    pub bytes: i64,
}

/// Parsed memory snapshot: total bytes + per-block sizes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemorySnapshot {
    pub total_bytes: i64,
    pub blocks: Vec<MemoryBlockInfo>,
}

/// Parse `neoth memory --size --output json`
/// (`{total_bytes, blocks:[{source,path,bytes}]}`). PURE + robust (malformed →
/// empty; total derived from the blocks when absent).
pub fn parse_memory_size(json: &str) -> MemorySnapshot {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return MemorySnapshot::default();
    };
    let blocks: Vec<MemoryBlockInfo> = v
        .get("blocks")
        .and_then(|b| b.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|b| {
                    let source = b
                        .get("source")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let path = b.get("path")?.as_str()?.to_string();
                    let bytes = b.get("bytes").and_then(|n| n.as_i64()).unwrap_or(0);
                    Some(MemoryBlockInfo {
                        source,
                        path,
                        bytes,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let total_bytes = v
        .get("total_bytes")
        .and_then(|t| t.as_i64())
        .unwrap_or_else(|| blocks.iter().map(|b| b.bytes).sum());
    MemorySnapshot {
        total_bytes,
        blocks,
    }
}

// ── GU-01 channels panel (credentials.yaml token PRESENCE, never the value) ──

/// One channel's connection state for the Channels panel. ONLY the connected
/// bool is derived — a secret token is NEVER read into this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    pub name: String,
    pub connected: bool,
}

/// Derive per-channel connection state from the PRESENCE of credential fields
/// in a `credentials.yaml` string. PURE + secret-safe: it deserialises each
/// token into an `Option<String>` only to test `is_some() && !is_empty()`, and
/// emits ONLY the boolean — token values never leave this function. A malformed
/// file yields "all disconnected" (never panics, never partial-leaks).
pub fn channel_status_from_credentials_yaml(yaml: &str) -> Vec<ChannelStatus> {
    // One row per messaging surface in the canonical `channels::ChannelKind`
    // (the WhatsApp Business/Baileys pair collapses to one "whatsapp" row; the
    // non-messaging `pears_bearer_token` transport is not a reachable channel).
    // Only the PRESENCE of each channel's representative credential is derived —
    // the field is read into an `Option<String>` solely to test emptiness and
    // the value never leaves this function.
    #[derive(serde::Deserialize, Default)]
    struct MinimalCreds {
        telegram_token: Option<String>,
        whatsapp_token: Option<String>,
        slack_bot_token: Option<String>,
        discord_bot_token: Option<String>,
        signal_phone_number: Option<String>,
        matrix_access_token: Option<String>,
        matrix_password: Option<String>,
        line_channel_access_token: Option<String>,
        irc_server: Option<String>,
        mattermost_token: Option<String>,
        twitch_oauth_token: Option<String>,
        keet_seed_phrase: Option<String>,
    }
    let creds: MinimalCreds = serde_yaml::from_str(yaml).unwrap_or_default();
    let present = |o: &Option<String>| o.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    let row = |name: &str, connected: bool| ChannelStatus { name: name.into(), connected };
    vec![
        row("telegram", present(&creds.telegram_token)),
        row("whatsapp", present(&creds.whatsapp_token)),
        row("slack", present(&creds.slack_bot_token)),
        row("discord", present(&creds.discord_bot_token)),
        row("signal", present(&creds.signal_phone_number)),
        row("matrix", present(&creds.matrix_access_token) || present(&creds.matrix_password)),
        row("line", present(&creds.line_channel_access_token)),
        row("irc", present(&creds.irc_server)),
        row("mattermost", present(&creds.mattermost_token)),
        row("twitch", present(&creds.twitch_oauth_token)),
        row("keet", present(&creds.keet_seed_phrase)),
    ]
}

/// Read `<neoth_home>/credentials.yaml` + derive channel connection state. A
/// missing file yields "all disconnected". The fs read is the only impurity;
/// the logic is the unit-tested [`channel_status_from_credentials_yaml`].
pub fn read_channel_status(neoth_home: &std::path::Path) -> Vec<ChannelStatus> {
    let path = neoth_home.join("credentials.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap_or_default();
    channel_status_from_credentials_yaml(&yaml)
}

// ── SPEC-05 preset selector (parse `neoth preset list --json`) ───────────────

/// One saved preset for the selector.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PresetEntry {
    pub name: String,
    pub active: bool,
}

/// Parse `neoth preset list --json` (`{presets:[{name,active}], active}`).
/// PURE + robust (malformed → empty; name-less entries skipped).
pub fn parse_presets(json: &str) -> Vec<PresetEntry> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    v.get("presets")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let name = p.get("name")?.as_str()?.to_string();
                    let active = p.get("active").and_then(|a| a.as_bool()).unwrap_or(false);
                    Some(PresetEntry { name, active })
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── SPEC-05 step5c behavioural-profile selector ──────────────────────────────

/// One behavioural profile preset (LOWKEY/Formal/Deepdive/Tutor/Opsec) for the
/// step5c selector. Distinct from [`PresetEntry`] (provider-bundle presets) —
/// this is the operator's interaction register.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfilePresetRow {
    pub name: String,
    pub description: String,
    pub recommended: bool,
    pub active: bool,
}

/// Parse `neoth profile preset list --output json`
/// (`[{name,description,recommended,active}]`). PURE + robust: malformed →
/// empty; name-less entries skipped.
pub fn parse_profile_presets(json: &str) -> Vec<ProfilePresetRow> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let name = p.get("name")?.as_str()?.to_string();
                    Some(ProfilePresetRow {
                        name,
                        description: p
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_string(),
                        recommended: p.get("recommended").and_then(|r| r.as_bool()).unwrap_or(false),
                        active: p.get("active").and_then(|a| a.as_bool()).unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── SPEC-06 hemisphere switcher (parse `neoth provider list --output json`) ──

/// Extract the IMPLEMENTED provider ids from `neoth provider list --output json`
/// (`[{id, description, implemented}]`) — the options for the per-role provider
/// picker. PURE + robust (malformed → empty; stub/unimplemented providers
/// excluded so the operator can't bind a role to a non-functional adapter).
/// This is a fixed adapter set, NOT a model whitelist — it stays
/// model-version-agnostic (the model id is a separate free-form field).
pub fn parse_provider_ids(json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter(|p| p.get("implemented").and_then(|i| i.as_bool()).unwrap_or(true))
        .filter_map(|p| p.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .collect()
}

/// MV-01c — extract the non-deprecated model ids for `provider` from
/// `neoth catalog list --provider <p> --output json` (shape
/// `{providers:{<p>:{models:[{id,deprecated},…]}}}`). PURE + robust (malformed
/// JSON or an absent provider → empty) so the per-role model picker offers the
/// LIVE catalog ids without ever hard-failing the GUI on a subprocess hiccup.
/// Stays model-version-agnostic — surfaces whatever the catalog holds, no
/// whitelist (a new model id appears the moment `catalog refresh` sees it).
// MV-01c headless half (50b826c): the Slint model-picker consumer isn't
// wired yet — only the unit tests call this, so the bin target flags it
// dead. Exempt until the GUI half lands; remove the allow with that wiring.
#[allow(dead_code)]
pub fn parse_catalog_model_ids(json: &str, provider: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(models) = v
        .get("providers")
        .and_then(|p| p.get(provider))
        .and_then(|pc| pc.get("models"))
        .and_then(|m| m.as_array())
    else {
        return Vec::new();
    };
    models
        .iter()
        .filter(|m| !m.get("deprecated").and_then(|d| d.as_bool()).unwrap_or(false))
        .filter_map(|m| m.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MV-01c catalog model-id parser ────────────────────────────────────
    #[test]
    fn parse_catalog_model_ids_happy_path_preserves_order() {
        let json = r#"{"providers":{"anthropic_api":{"models":[
            {"id":"claude-opus-4-8","deprecated":false},
            {"id":"claude-sonnet-4-6"}
        ]}}}"#;
        assert_eq!(
            parse_catalog_model_ids(json, "anthropic_api"),
            vec!["claude-opus-4-8".to_string(), "claude-sonnet-4-6".to_string()]
        );
    }

    #[test]
    fn parse_catalog_model_ids_excludes_deprecated_and_other_providers() {
        let json = r#"{"providers":{
            "anthropic_api":{"models":[{"id":"old","deprecated":true},{"id":"new","deprecated":false}]},
            "gemini_api":{"models":[{"id":"g"}]}
        }}"#;
        assert_eq!(parse_catalog_model_ids(json, "anthropic_api"), vec!["new".to_string()]);
        assert_eq!(parse_catalog_model_ids(json, "gemini_api"), vec!["g".to_string()]);
    }

    #[test]
    fn parse_catalog_model_ids_empty_on_malformed_or_absent() {
        assert!(parse_catalog_model_ids("not json", "anthropic_api").is_empty());
        assert!(parse_catalog_model_ids(r#"{"providers":{}}"#, "anthropic_api").is_empty());
        assert!(parse_catalog_model_ids(r#"{"providers":{"x":{"models":[{"id":"m"}]}}}"#, "absent").is_empty());
    }

    // ── GR-03 trust panel parser ──────────────────────────────────────────
    #[test]
    fn parse_trust_extracts_all_four_sections() {
        let json = r#"{
            "autonomy":{"level":"full","behavior":"boundary asks Allow","gated_examples":["fs write","ProactiveChannelSend"]},
            "privacy_switches":{"omi_ingest":false,"channel_weight_scope":"operator_only","live_delivery_edits":true},
            "recovery":{"hmac_key_present":true,"proof_key_present":false,"transfer_key_present":false},
            "trust_ledger":{"segments":787,"total_frames":780,"bad_frames":1,"size_bytes":496628}
        }"#;
        let t = parse_trust(json);
        assert_eq!(t.autonomy_level, "full");
        assert!(t.autonomy_behavior.contains("Allow"));
        assert_eq!(t.gated_examples.len(), 2);
        // privacy: bool→on/off, string verbatim; sorted by key.
        assert_eq!(t.privacy[0], TrustRow { label: "channel_weight_scope".into(), value: "operator_only".into() });
        assert!(t.privacy.iter().any(|r| r.label == "omi_ingest" && r.value == "off"));
        assert!(t.privacy.iter().any(|r| r.label == "live_delivery_edits" && r.value == "on"));
        // recovery: *_present → present/missing.
        assert!(t.recovery.iter().any(|r| r.label == "hmac_key_present" && r.value == "present"));
        assert!(t.recovery.iter().any(|r| r.label == "proof_key_present" && r.value == "missing"));
        // ledger numbers render as strings.
        assert!(t.ledger.iter().any(|r| r.label == "segments" && r.value == "787"));
        assert!(t.ledger.iter().any(|r| r.label == "bad_frames" && r.value == "1"));
    }

    #[test]
    fn parse_trust_is_robust_to_garbage_and_unknown_keys() {
        assert_eq!(parse_trust("not json"), TrustSnapshot::default());
        assert_eq!(parse_trust("{}"), TrustSnapshot::default());
        // A future switch the CLI adds shows up generically (forward-compatible).
        let t = parse_trust(r#"{"privacy_switches":{"some_future_switch":true}}"#);
        assert_eq!(t.privacy, vec![TrustRow { label: "some_future_switch".into(), value: "on".into() }]);
    }

    // ── SL-03 resource panel parser ───────────────────────────────────────
    #[test]
    fn parse_hardware_formats_the_resource_snapshot() {
        let json = r#"{
            "cpu":{"brand":"AMD Ryzen Threadripper PRO 5965WX  ","logical_cores":48,"physical_cores":24,"frequency_mhz":4700},
            "memory":{"total_bytes":274702249984,"available_bytes":241575075840},
            "accelerator":{"picked":"cuda","has_gpu_path":true},
            "vram":{"used_mib":1405,"total_mib":24576},
            "disk":{"home_available_bytes":116186198016,"home_total_bytes":1799240114176,"home_mount":"C:\\"},
            "cached_models":{"qwen2_5_3b":true,"clip_vit_b32":false}
        }"#;
        let h = parse_hardware(json);
        assert_eq!(h.cpu, "AMD Ryzen Threadripper PRO 5965WX — 24c/48t @ 4700 MHz");
        assert_eq!(h.memory, "224 / 255 GiB available");
        assert_eq!(h.accelerator, "cuda — GPU path active");
        assert_eq!(h.vram, "1405 / 24576 MiB used (5%)");
        assert!((h.vram_fraction - 0.057169).abs() < 1e-4);
        assert!(h.disk.starts_with("108 / 1675 GiB free (C:"));
        assert!(h.models.iter().any(|r| r.label == "qwen2_5_3b" && r.value == "cached"));
        assert!(h.models.iter().any(|r| r.label == "clip_vit_b32" && r.value == "not cached"));
    }

    #[test]
    fn parse_hardware_robust_and_no_gpu() {
        assert_eq!(parse_hardware("nope"), HardwareSnapshot::default());
        // No vram node → explicit "(no GPU detected)".
        let h = parse_hardware(r#"{"cpu":{"brand":"x","physical_cores":1,"logical_cores":1,"frequency_mhz":1}}"#);
        assert_eq!(h.vram, "(no GPU detected)");
        assert_eq!(h.accelerator, "");
        // No vram node → fraction 0.0 (meter hidden).
        assert_eq!(h.vram_fraction, 0.0);
    }

    // ── GOLD-PROG-07 VRAM meter fraction ──────────────────────────────────
    #[test]
    fn parse_hardware_vram_fraction_is_ratio_and_safe() {
        // used/total = 1405/24576 ≈ 0.0572.
        let full = parse_hardware(r#"{"vram":{"used_mib":1405,"total_mib":24576}}"#);
        assert!((full.vram_fraction - 0.057169).abs() < 1e-4);
        // total_mib = 0 → 0.0, no divide-by-zero / infinity.
        let zero = parse_hardware(r#"{"vram":{"used_mib":10,"total_mib":0}}"#);
        assert_eq!(zero.vram_fraction, 0.0);
        // Defensive clamp: a stray used>total stays ≤ 1.0 (bar never overruns).
        let over = parse_hardware(r#"{"vram":{"used_mib":99999,"total_mib":1000}}"#);
        assert_eq!(over.vram_fraction, 1.0);
    }

    // ── SL-02 cluster topology parser ─────────────────────────────────────
    #[test]
    fn parse_cluster_topology_empty_peers_is_empty() {
        assert!(parse_cluster_topology(r#"{"peers":[],"local_mode":"single-node"}"#).is_empty());
    }

    #[test]
    fn parse_cluster_topology_malformed_is_empty() {
        assert!(parse_cluster_topology("not json").is_empty());
        assert!(parse_cluster_topology("{}").is_empty()); // no peers key
    }

    #[test]
    fn parse_cluster_topology_formats_full_row() {
        let json = r#"{"peers":[{
            "pub_key_short":"abc123","label":"workstation","addr":"100.64.0.2:7777",
            "status":"recent","rtt_ms":42,"stability_score":0.87,"last_seen_age_secs":130
        }]}"#;
        let rows = parse_cluster_topology(json);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.label, "workstation");
        assert_eq!(r.addr, "100.64.0.2:7777");
        assert_eq!(r.status, "recent");
        assert_eq!(r.rtt_ms, "42 ms");
        assert_eq!(r.stability_pct, "87%");
        assert_eq!(r.last_seen, "2m ago");
    }

    #[test]
    fn parse_cluster_topology_missing_rtt_and_label_fallback() {
        // rtt null → "---", last_seen null → "never", empty label → short key.
        let json = r#"{"peers":[{
            "pub_key_short":"deadbeef","label":"","addr":"x","status":"uncontacted",
            "rtt_ms":null,"stability_score":0.0,"last_seen_age_secs":null
        }]}"#;
        let rows = parse_cluster_topology(json);
        assert_eq!(rows[0].rtt_ms, "---");
        assert_eq!(rows[0].last_seen, "never");
        assert_eq!(rows[0].stability_pct, "0%");
        assert_eq!(rows[0].label, "deadbeef");
    }

    // ── GOLD-PROG-08 usage meter parser ───────────────────────────────────
    #[test]
    fn parse_usage_meter_formats_live_budget() {
        let json = r#"{"events_total":9,"provider_responses":3,"input_tokens_total":1200,"output_tokens_total":450,"lagged_events":0}"#;
        let p = parse_usage_meter(json);
        assert!(p.available);
        assert_eq!(p.responses, "3 provider responses");
        assert_eq!(p.tokens, "1200 in / 450 out tokens");
        assert_eq!(p.note, "council-path only");
    }

    #[test]
    fn parse_usage_meter_absent_or_garbage_is_unavailable() {
        assert!(!parse_usage_meter("not json").available);
        assert!(!parse_usage_meter("{}").available); // no provider_responses key → not live
    }

    #[test]
    fn parse_usage_meter_lag_warns_undercount() {
        let json = r#"{"provider_responses":1,"input_tokens_total":10,"output_tokens_total":5,"lagged_events":4}"#;
        let p = parse_usage_meter(json);
        assert!(p.available);
        assert!(p.note.contains("4 events dropped"));
    }

    // ── KF-08 council budget meter parser ─────────────────────────────────
    #[test]
    fn parse_council_budget_with_and_without_runtime() {
        // No debate yet → headlines set, no runtime rows.
        let b = parse_council_budget(r#"{"configured_cap":15,"daily_usd_cap":null,"runtime":null}"#);
        assert_eq!(b.configured_cap, "15 calls / message");
        assert_eq!(b.daily_usd_cap, "no daily USD cap");
        assert!(b.last_debate.is_empty());

        // With a last-debate runtime + a daily cap.
        let b = parse_council_budget(
            r#"{"configured_cap":3,"daily_usd_cap":5.0,"runtime":{"cap_at_last_debate":3,"used_last_msg":2,"exhausted_last_msg":false,"exhaustions_rolling":1}}"#,
        );
        assert_eq!(b.configured_cap, "3 calls / message");
        assert_eq!(b.daily_usd_cap, "$5.00 / day");
        assert!(b.last_debate.iter().any(|r| r.label == "used last message" && r.value == "2 / 3"));
        assert!(b.last_debate.iter().any(|r| r.label == "exhausted last message" && r.value == "no"));
        assert!(b.last_debate.iter().any(|r| r.label == "exhaustions (rolling)" && r.value == "1"));
    }

    /// GR-061: above the defensive cap the exponent label and the computed
    /// value must agree — before the fix depth=9 displayed "3^9 = 6561"
    /// (label raw, value capped at 3^8).
    #[test]
    fn council_depth_cost_warning_label_and_value_agree_above_cap() {
        let w = council_depth_cost_warning(9);
        assert!(w.contains("3^8"), "{w}");
        assert!(w.contains("6561"), "{w}");
        assert!(w.contains("council depth 9"), "raw depth still named: {w}");
    }

    #[test]
    fn parse_council_budget_robust_to_garbage() {
        assert_eq!(parse_council_budget("nope"), CouncilBudgetPanel::default());
    }

    #[test]
    fn parse_council_budget_surfaces_depth_cost_warning_above_flat() {
        // GOLD-HON-13: flat depth → no warning; depth 4 → 3^4 = 81 callout.
        let flat = parse_council_budget(r#"{"configured_cap":3,"max_recursion_depth":1}"#);
        assert!(flat.depth_cost_warning.is_empty());

        let deep = parse_council_budget(r#"{"configured_cap":3,"max_recursion_depth":4}"#);
        assert!(deep.depth_cost_warning.contains("81"), "{}", deep.depth_cost_warning);
        assert!(deep.depth_cost_warning.contains("council depth 4"));

        // Missing field → no warning (robust default).
        let none = parse_council_budget(r#"{"configured_cap":3}"#);
        assert!(none.depth_cost_warning.is_empty());
    }

    // ── SPEC-05 step5c behavioural-profile selector parser ────────────────
    #[test]
    fn parse_profile_presets_reads_name_desc_recommended_active() {
        let json = r#"[
            {"name":"lowkey","description":"casual","recommended":true,"active":true},
            {"name":"formal","description":"polite","recommended":false,"active":false},
            {"active":true}
        ]"#;
        let rows = parse_profile_presets(json);
        assert_eq!(rows.len(), 2, "name-less entry skipped");
        assert_eq!(rows[0], ProfilePresetRow { name: "lowkey".into(), description: "casual".into(), recommended: true, active: true });
        assert_eq!(rows[1].name, "formal");
        assert!(!rows[1].active && !rows[1].recommended);
    }

    #[test]
    fn parse_profile_presets_robust_to_garbage() {
        assert!(parse_profile_presets("nope").is_empty());
        assert!(parse_profile_presets("{}").is_empty());
    }

    // ── parse ────────────────────────────────────────────────────────────
    #[test]
    fn parse_known_and_unknown() {
        assert_eq!(parse_complexity_level("minimal"), ComplexityLevel::Minimal);
        assert_eq!(parse_complexity_level("  FULL "), ComplexityLevel::Full);
        assert_eq!(parse_complexity_level("standard"), ComplexityLevel::Standard);
        assert_eq!(parse_complexity_level(""), ComplexityLevel::Standard);
        assert_eq!(parse_complexity_level("garbage"), ComplexityLevel::Standard);
    }

    #[test]
    fn default_is_standard() {
        assert_eq!(ComplexityLevel::default(), ComplexityLevel::Standard);
    }

    // ── Minimal: the beginner-safe set ─────────────────────────────────────
    #[test]
    fn minimal_shows_only_beginner_essentials() {
        let p = panels_for(ComplexityLevel::Minimal);
        // Shown: the 3 a beginner needs.
        assert!(p.show_channels, "beginner needs channels to connect Telegram");
        assert!(p.show_privacy, "autonomy level is beginner-critical");
        assert!(p.show_config, "provider choice is beginner-critical");
        // Hidden: everything advanced.
        assert!(!p.show_hemispheres);
        assert!(!p.show_skills);
        assert!(!p.show_plugins);
        assert!(!p.show_memory);
        assert!(!p.show_cluster);
        assert!(!p.show_code_sessions);
        assert!(!p.expand_cluster_advanced);
        assert!(!p.expand_config_advanced);
    }

    // ── Standard: common expanded, advanced collapsed ──────────────────────
    #[test]
    fn standard_shows_common_hides_plugins_collapses_advanced() {
        let p = panels_for(ComplexityLevel::Standard);
        assert!(p.show_hemispheres);
        assert!(p.show_channels);
        assert!(p.show_skills);
        assert!(p.show_memory);
        assert!(p.show_privacy);
        assert!(p.show_cluster);
        assert!(p.show_config);
        assert!(p.show_code_sessions);
        // Plugins is a power-user surface — hidden until Full.
        assert!(!p.show_plugins);
        // Advanced sub-sections collapsed at Standard.
        assert!(!p.expand_cluster_advanced);
        assert!(!p.expand_config_advanced);
    }

    // ── Full: everything ───────────────────────────────────────────────────
    #[test]
    fn full_shows_everything_and_expands_advanced() {
        let p = panels_for(ComplexityLevel::Full);
        assert!(p.show_hemispheres);
        assert!(p.show_channels);
        assert!(p.show_skills);
        assert!(p.show_plugins);
        assert!(p.show_memory);
        assert!(p.show_privacy);
        assert!(p.show_cluster);
        assert!(p.show_config);
        assert!(p.show_code_sessions);
        assert!(p.expand_cluster_advanced);
        assert!(p.expand_config_advanced);
    }

    // ── monotonicity: a higher level never hides what a lower level shows ──
    #[test]
    fn visibility_is_monotonic_across_levels() {
        let m = panels_for(ComplexityLevel::Minimal);
        let s = panels_for(ComplexityLevel::Standard);
        let f = panels_for(ComplexityLevel::Full);
        let fields = |p: &PanelVisibility| {
            [
                p.show_hemispheres,
                p.show_channels,
                p.show_skills,
                p.show_plugins,
                p.show_memory,
                p.show_privacy,
                p.show_cluster,
                p.show_config,
                p.show_code_sessions,
            ]
        };
        let (mf, sf, ff) = (fields(&m), fields(&s), fields(&f));
        for i in 0..mf.len() {
            assert!(!mf[i] || sf[i], "Standard hides a panel Minimal showed (idx {i})");
            assert!(!sf[i] || ff[i], "Full hides a panel Standard showed (idx {i})");
        }
    }

    #[test]
    fn privacy_and_config_visible_at_every_level() {
        // The two safety-critical panels (autonomy + provider) are never hidden.
        for lvl in [
            ComplexityLevel::Minimal,
            ComplexityLevel::Standard,
            ComplexityLevel::Full,
        ] {
            let p = panels_for(lvl);
            assert!(p.show_privacy, "{} must show privacy", lvl.as_str());
            assert!(p.show_config, "{} must show config", lvl.as_str());
        }
    }

    #[test]
    fn read_complexity_from_wizard_state_yaml() {
        let dir = tempfile::tempdir().unwrap();
        // Absent file ⇒ safe default.
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Standard);
        // Top-level complexity_level key (the v2 wizard flattens it there).
        std::fs::write(
            dir.path().join("wizard_state_v2.yaml"),
            "operator_id: alice\ncomplexity_level: full\nprivacy_first: true\n",
        )
        .unwrap();
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Full);
        // Missing field amid other keys ⇒ default.
        std::fs::write(
            dir.path().join("wizard_state_v2.yaml"),
            "operator_id: bob\nautonomy: standard\n",
        )
        .unwrap();
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Standard);
        // Minimal persona round-trips.
        std::fs::write(
            dir.path().join("wizard_state_v2.yaml"),
            "complexity_level: minimal\n",
        )
        .unwrap();
        assert_eq!(read_complexity_level(dir.path()), ComplexityLevel::Minimal);
    }

    #[test]
    fn round_trips_through_string() {
        for lvl in [
            ComplexityLevel::Minimal,
            ComplexityLevel::Standard,
            ComplexityLevel::Full,
        ] {
            assert_eq!(parse_complexity_level(lvl.as_str()), lvl);
        }
    }

    // ── GR-10 parse_safe_mode ────────────────────────────────────────────────

    #[test]
    fn parse_safe_mode_full_payload() {
        let json = r#"{
            "rails": [
                {"name": "autonomy_gate", "engaged": true, "detail": "strict"},
                {"name": "email_llm_tiebreak", "engaged": false, "detail": "off"}
            ],
            "engaged_count": 1,
            "total": 2
        }"#;
        let s = parse_safe_mode(json);
        assert_eq!(s.rails.len(), 2);
        assert_eq!(s.rails[0].name, "autonomy_gate");
        assert!(s.rails[0].engaged);
        assert_eq!(s.rails[0].detail, "strict");
        assert!(!s.rails[1].engaged);
        assert_eq!(s.engaged_count, 1);
        assert_eq!(s.total, 2);
    }

    #[test]
    fn parse_safe_mode_derives_counts_when_absent() {
        // Forward-compat: missing engaged_count/total derive from the rails.
        let json = r#"{"rails":[
            {"name":"a","engaged":true,"detail":""},
            {"name":"b","engaged":true,"detail":""},
            {"name":"c","engaged":false}
        ]}"#;
        let s = parse_safe_mode(json);
        assert_eq!(s.engaged_count, 2, "derived from engaged rails");
        assert_eq!(s.total, 3, "derived from rail count");
        assert_eq!(s.rails[2].detail, "", "missing detail defaults empty");
    }

    #[test]
    fn parse_safe_mode_malformed_is_empty_not_panic() {
        assert_eq!(parse_safe_mode("not json"), SafeModeSnapshot::default());
        assert_eq!(parse_safe_mode(""), SafeModeSnapshot::default());
        // A rail missing its required `name` is skipped, not fatal.
        let s = parse_safe_mode(r#"{"rails":[{"engaged":true},{"name":"ok","engaged":false}]}"#);
        assert_eq!(s.rails.len(), 1);
        assert_eq!(s.rails[0].name, "ok");
    }

    // ── GU-01 parse_hemispheres ───────────────────────────────────────────────

    #[test]
    fn parse_hemispheres_full() {
        let json = r#"{
            "mode": "triplet",
            "single_provider_fallback": "ClaudeCli",
            "roles": [
                {"role":"left","provider":"claude_cli","model":"sonnet","endpoint":null,"has_key":true},
                {"role":"right","provider":"openai_api","model":null,"endpoint":null,"has_key":false},
                {"role":"cerebellum","provider":null,"model":null,"endpoint":null,"has_key":false}
            ]
        }"#;
        let s = parse_hemispheres(json);
        assert_eq!(s.mode, "triplet");
        assert_eq!(s.bindings.len(), 3);
        assert_eq!(s.bindings[0].role, "left");
        assert_eq!(s.bindings[0].provider, "claude_cli");
        assert_eq!(s.bindings[0].model, "sonnet");
        assert!(s.bindings[0].has_key);
        assert_eq!(s.bindings[1].model, "", "null model -> empty");
        assert_eq!(s.bindings[2].provider, "(unset)", "null provider -> (unset)");
    }

    #[test]
    fn parse_hemispheres_malformed_is_empty() {
        assert_eq!(parse_hemispheres("nope"), HemispheresSnapshot::default());
        // role-less entry skipped.
        let s = parse_hemispheres(r#"{"mode":"single","roles":[{"provider":"x"},{"role":"left","provider":"y"}]}"#);
        assert_eq!(s.bindings.len(), 1);
        assert_eq!(s.bindings[0].role, "left");
    }

    // ── GU-01 parse_skills ────────────────────────────────────────────────────

    #[test]
    fn parse_skills_array_with_keywords() {
        let json = r#"[
            {"id":"verification","description":"verify before done","trigger_keywords":["verify","check"],"enabled":true},
            {"id":"research","description":"deep research","trigger_keywords":[]}
        ]"#;
        let rows = parse_skills(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "verification");
        assert_eq!(rows[0].keywords, "verify, check");
        assert!(rows[0].enabled);
        assert!(rows[1].enabled, "missing enabled defaults true");
        assert_eq!(rows[1].keywords, "");
    }

    #[test]
    fn parse_skills_malformed_and_non_array_is_empty() {
        assert!(parse_skills("nope").is_empty());
        assert!(parse_skills(r#"{"id":"x"}"#).is_empty(), "object, not array -> empty");
        // id-less entry skipped.
        let rows = parse_skills(r#"[{"description":"no id"},{"id":"ok"}]"#);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "ok");
    }

    // ── GU-01 parse_plugins ───────────────────────────────────────────────────

    #[test]
    fn parse_plugins_array() {
        let json = r#"[
            {"id":"faccam","name":"FacCam","activation":"enabled"},
            {"id":"x","activation":"pending"}
        ]"#;
        let rows = parse_plugins(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "faccam");
        assert_eq!(rows[0].name, "FacCam");
        assert_eq!(rows[0].activation, "enabled");
        assert_eq!(rows[1].name, "", "missing name -> empty");
        assert_eq!(rows[1].activation, "pending");
    }

    #[test]
    fn parse_plugins_malformed_is_empty() {
        assert!(parse_plugins("nope").is_empty());
        assert!(parse_plugins(r#"{"id":"x"}"#).is_empty(), "object not array");
        assert_eq!(parse_plugins(r#"[{"name":"no id"},{"id":"ok"}]"#).len(), 1);
    }

    // ── GU-01 parse_memory_size ───────────────────────────────────────────────

    #[test]
    fn parse_memory_size_full() {
        let json = r#"{"total_bytes":300,"blocks":[
            {"source":"global","path":"/a/CLAUDE.md","bytes":100},
            {"source":"memory","path":"/b/MEMORY.md","bytes":200}
        ]}"#;
        let s = parse_memory_size(json);
        assert_eq!(s.total_bytes, 300);
        assert_eq!(s.blocks.len(), 2);
        assert_eq!(s.blocks[0].source, "global");
        assert_eq!(s.blocks[1].bytes, 200);
    }

    #[test]
    fn parse_memory_size_derives_total_and_skips_pathless() {
        let s = parse_memory_size(r#"{"blocks":[{"source":"x","path":"/p","bytes":5},{"source":"y","bytes":9}]}"#);
        assert_eq!(s.blocks.len(), 1, "path-less block skipped");
        assert_eq!(s.total_bytes, 5, "derived from present blocks");
        assert_eq!(parse_memory_size("nope"), MemorySnapshot::default());
    }

    // ── GU-01 channel status (secret-safe) ────────────────────────────────────

    #[test]
    fn channel_status_reads_presence_not_values() {
        let yaml = "telegram_token: \"123:abc\"\nslack_bot_token: \"xoxb-x\"\nirc_server: \"irc.libera.chat\"\n";
        let rows = channel_status_from_credentials_yaml(yaml);
        let by = |n: &str| rows.iter().find(|c| c.name == n).unwrap().connected;
        assert!(by("telegram"));
        assert!(by("slack"));
        assert!(by("irc"), "irc_server presence -> connected");
        assert!(!by("whatsapp"), "absent -> disconnected");
        assert!(!by("keet"));
        // Every canonical messaging ChannelKind has a row (whatsapp collapsed).
        for ch in ["telegram", "whatsapp", "slack", "discord", "signal", "matrix",
                   "line", "irc", "mattermost", "twitch", "keet"] {
            assert!(rows.iter().any(|c| c.name == ch), "missing channel row: {ch}");
        }
        // The connected bool is all that's exposed — no token value in the struct.
        assert_eq!(rows.len(), 11);
    }

    #[test]
    fn channel_status_empty_token_is_disconnected_and_malformed_is_all_off() {
        let rows = channel_status_from_credentials_yaml("telegram_token: \"  \"\n");
        assert!(!rows.iter().find(|c| c.name == "telegram").unwrap().connected,
            "whitespace-only token -> disconnected");
        // Malformed YAML -> all disconnected, never a panic.
        let all = channel_status_from_credentials_yaml("%%% not yaml %%%");
        assert!(all.iter().all(|c| !c.connected));
    }

    #[test]
    fn read_channel_status_missing_file_is_all_off() {
        let dir = tempfile::tempdir().unwrap();
        let rows = read_channel_status(dir.path());
        assert_eq!(rows.len(), 11);
        assert!(rows.iter().all(|c| !c.connected));
    }

    // ── SPEC-05 parse_presets ─────────────────────────────────────────────────

    #[test]
    fn parse_presets_marks_active() {
        let json = r#"{"presets":[{"name":"frugal","active":false},{"name":"weekend","active":true}],"active":"weekend"}"#;
        let rows = parse_presets(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "frugal");
        assert!(!rows[0].active);
        assert_eq!(rows[1].name, "weekend");
        assert!(rows[1].active);
    }

    #[test]
    fn parse_presets_malformed_and_nameless_skipped() {
        assert!(parse_presets("nope").is_empty());
        assert!(parse_presets(r#"{"presets":[]}"#).is_empty());
        let rows = parse_presets(r#"{"presets":[{"active":true},{"name":"ok"}]}"#);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "ok");
    }

    // ── SPEC-06 parse_provider_ids ────────────────────────────────────────────

    #[test]
    fn parse_provider_ids_keeps_implemented_only() {
        let json = r#"[
            {"id":"claude_cli","description":"x","implemented":true},
            {"id":"aws_bedrock","description":"y","implemented":false},
            {"id":"openai_api","description":"z","implemented":true}
        ]"#;
        let ids = parse_provider_ids(json);
        assert_eq!(ids, vec!["claude_cli", "openai_api"], "stub provider excluded");
    }

    #[test]
    fn parse_provider_ids_malformed_and_missing_flag() {
        assert!(parse_provider_ids("nope").is_empty());
        assert!(parse_provider_ids(r#"{"id":"x"}"#).is_empty(), "object not array");
        // Missing `implemented` defaults to included (forward-compat).
        let ids = parse_provider_ids(r#"[{"id":"a"},{"description":"no id"}]"#);
        assert_eq!(ids, vec!["a"]);
    }
}
