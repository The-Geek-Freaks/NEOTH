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
    let engaged_count =
        v.get("engaged_count")
            .and_then(|c| c.as_i64())
            .unwrap_or_else(|| rails.iter().filter(|r| r.engaged).count() as i64) as i32;
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
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        })
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
            value: if r.value == "on" {
                "cached".to_string()
            } else {
                "not cached".to_string()
            },
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
                let score = p
                    .get("stability_score")
                    .and_then(|x| x.as_f64())
                    .unwrap_or(0.0);
                format!("{:.0}%", (score * 100.0).clamp(0.0, 100.0))
            };
            let last_seen =
                fmt_peer_last_seen(p.get("last_seen_age_secs").and_then(|x| x.as_i64()));
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
        format!("⚠ {lagged} events dropped (token totals undercount)")
    } else {
        "live token budget".to_string()
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
                    value: if r
                        .get("exhausted_last_msg")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false)
                    {
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
    /// GOLD-ADAPT-AOS-01 — manifest `tags`; first tag = index domain group.
    pub tags: Vec<String>,
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
            let tags = s
                .get("tags")
                .and_then(|t| t.as_array())
                .map(|ts| {
                    ts.iter()
                        .filter_map(|w| w.as_str())
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Some(SkillSummary {
                id,
                description,
                enabled,
                keywords,
                tags,
            })
        })
        .collect()
}

// ── GOLD-ADAPT-AOS-01 — domain-grouped, searchable skills index ──────────────
// Pure shaping: skills in, a FLAT display list out (Slint structs can't nest
// models, so group headers ride inline as `is_header` rows).

/// One row of the grouped skills index — either a domain header or a skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillIndexRow {
    pub id: String,
    pub description: String,
    pub enabled: bool,
    pub keywords: String,
    pub tags: String,
    pub is_header: bool,
}

/// Group skills by their first tag ("general" when untagged), alphabetical
/// groups + ids, filtered case-insensitively over id/description/keywords/
/// tags. Headers for empty (filtered-out) groups are dropped.
pub fn group_skill_rows(skills: &[SkillSummary], filter: &str) -> Vec<SkillIndexRow> {
    let needle = filter.trim().to_lowercase();
    let matches = |s: &SkillSummary| {
        needle.is_empty()
            || s.id.to_lowercase().contains(&needle)
            || s.description.to_lowercase().contains(&needle)
            || s.keywords.to_lowercase().contains(&needle)
            || s.tags.iter().any(|t| t.to_lowercase().contains(&needle))
    };
    let mut groups: std::collections::BTreeMap<String, Vec<&SkillSummary>> =
        std::collections::BTreeMap::new();
    for s in skills.iter().filter(|s| matches(s)) {
        let domain = s
            .tags
            .first()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "general".to_string());
        groups.entry(domain).or_default().push(s);
    }
    let mut out = Vec::new();
    for (domain, mut members) in groups {
        members.sort_by(|a, b| a.id.cmp(&b.id));
        out.push(SkillIndexRow {
            id: domain.to_uppercase(),
            description: String::new(),
            enabled: true,
            keywords: String::new(),
            tags: String::new(),
            is_header: true,
        });
        out.extend(members.into_iter().map(|s| SkillIndexRow {
            id: s.id.clone(),
            description: s.description.clone(),
            enabled: s.enabled,
            keywords: s.keywords.clone(),
            tags: s.tags.join(", "),
            is_header: false,
        }));
    }
    out
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
        nostr_secret_key: Option<String>,
        bluebubbles_url: Option<String>,
        gchat_subscription: Option<String>,
    }
    let creds: MinimalCreds = serde_yaml::from_str(yaml).unwrap_or_default();
    let present = |o: &Option<String>| o.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    let row = |name: &str, connected: bool| ChannelStatus {
        name: name.into(),
        connected,
    };
    vec![
        row("telegram", present(&creds.telegram_token)),
        row("whatsapp", present(&creds.whatsapp_token)),
        row("slack", present(&creds.slack_bot_token)),
        row("discord", present(&creds.discord_bot_token)),
        row("signal", present(&creds.signal_phone_number)),
        row(
            "matrix",
            present(&creds.matrix_access_token) || present(&creds.matrix_password),
        ),
        row("line", present(&creds.line_channel_access_token)),
        row("irc", present(&creds.irc_server)),
        row("mattermost", present(&creds.mattermost_token)),
        row("twitch", present(&creds.twitch_oauth_token)),
        row("keet", present(&creds.keet_seed_phrase)),
        row("nostr", present(&creds.nostr_secret_key)),
        row("imessage", present(&creds.bluebubbles_url)),
        row("gchat", present(&creds.gchat_subscription)),
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
    /// True for the four built-ins (full-auto / balanced / essentials / local-sovereign).
    /// Old daemons that omit the field produce false (manual parse default).
    pub builtin: bool,
    /// Human-readable summary shown under the preset name.
    /// Old daemons that omit the field produce an empty string.
    pub description: String,
}

/// Parse `neoth preset list --json`
/// (`{presets:[{name,active,builtin?,description?}], active}`).
/// PURE + robust: malformed → empty; name-less entries skipped.
/// New `builtin` and `description` fields have serde defaults so old daemons
/// that omit them still parse correctly.
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
                    let builtin = p.get("builtin").and_then(|b| b.as_bool()).unwrap_or(false);
                    let description = p
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(PresetEntry { name, active, builtin, description })
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── SPEC-05 preset apply plan (parse `neoth preset apply <name> --dry-run`) ──

/// A single changed field reported by the dry-run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WarnChange {
    pub path: String,
    pub old: String,
    pub new: String,
}

/// Parsed result of `neoth preset apply <name> --dry-run --json`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplyPlan {
    pub name: String,
    /// "full" when the preset requests operator-autonomy=full; None otherwise.
    pub autonomy_requested: Option<String>,
    pub warn_changes: Vec<WarnChange>,
    pub fields_changed_count: usize,
}

/// Parse `neoth preset apply <name> --dry-run` JSON output.
///
/// Expected shape:
/// ```json
/// {
///   "name": "full-auto",
///   "fields_changed": ["autonomy", "provider"],
///   "autonomy_requested": "full",        // omitted when not full
///   "warn_changes": [
///     {"path": "autonomy.level", "old": "standard", "new": "full"}
///   ]
/// }
/// ```
/// PURE + robust: malformed or missing JSON → `None`.
pub fn parse_apply_plan(json: &str) -> Option<ApplyPlan> {
    let v = serde_json::from_str::<serde_json::Value>(json).ok()?;
    let name = v.get("name")?.as_str()?.to_string();
    let fields_changed_count = v
        .get("fields_changed")
        .and_then(|f| f.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let autonomy_requested = v
        .get("autonomy_requested")
        .and_then(|a| a.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let warn_changes = v
        .get("warn_changes")
        .and_then(|w| w.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let path = c.get("path")?.as_str()?.to_string();
                    let old = c.get("old").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let new = c.get("new").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    Some(WarnChange { path, old, new })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ApplyPlan { name, autonomy_requested, warn_changes, fields_changed_count })
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
                        recommended: p
                            .get("recommended")
                            .and_then(|r| r.as_bool())
                            .unwrap_or(false),
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
        .filter(|p| {
            p.get("implemented")
                .and_then(|i| i.as_bool())
                .unwrap_or(true)
        })
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
// MV-01c: wired into the Hemispheres per-role model picker (GOLD-GUI-OVERHAUL)
// via fetch_hemisphere_model_ids — the cloud-provider half of the combo list.
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
        .filter(|m| {
            !m.get("deprecated")
                .and_then(|d| d.as_bool())
                .unwrap_or(false)
        })
        .filter_map(|m| m.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .collect()
}

/// Parse `neoth models recommend --class <c> --output json` (a JSON array of
/// `{rank, param_b, quant, est_vram_gb, repo, class, pull_ref, …}`) into the
/// list of `pull_ref` model ids — the local GGUF refs (e.g.
/// `hf.co/bartowski/Qwen2.5-…-abliterated-GGUF:Q4_K_M`) that fit this PC's VRAM.
/// These feed the local half of the Hemispheres per-role model picker so the
/// operator can SELECT a fitting local/abliterated model (GOLD-GUI-OVERHAUL).
/// PURE + robust: malformed JSON → empty (never hard-fails the GUI).
pub fn parse_model_recommend_refs(json: &str) -> Vec<String> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(json)
    else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|m| {
            m.get("pull_ref")
                .or_else(|| m.get("repo"))
                .and_then(|r| r.as_str())
                .map(|s| s.to_string())
        })
        .collect()
}

// ── GOLD-LOOP-03 — loop-run record views (mirror of loop_engine JSON) ──
// The GUI never links the engine crate; it reads the `LoopRunRecord`
// files the engine writes to `~/.neoth/loops/<loop_id>.json`.

/// One outer round, as rendered in the Loop panel timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopRoundView {
    pub round_num: u32,
    pub iterations: u32,
    pub ok_calls: u32,
    pub fail_calls: u32,
    pub stop_approved: bool,
    pub refine_fired: bool,
    /// Pre-formatted round duration ("12s" / "3m04s").
    pub duration: String,
}

/// One `LoopRunRecord`, shaped for the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopRunView {
    pub id: String,
    /// Raw epoch seconds — the sort key (review B8: sorting the formatted
    /// string was correct only by accident of the format).
    pub ts_start: i64,
    /// Pre-formatted start time ("2026-07-03 14:22").
    pub started: String,
    pub rounds_run: u32,
    pub stop_reason: String,
    pub total_tool_calls: u64,
    pub per_round: Vec<LoopRoundView>,
    pub final_text: String,
}

fn format_secs(total: i64) -> String {
    if total < 0 {
        return "—".into();
    }
    if total < 60 {
        return format!("{total}s");
    }
    format!("{}m{:02}s", total / 60, total % 60)
}

/// Epoch seconds → "YYYY-MM-DD HH:MM" (UTC, no chrono dep — the civil-date
/// arithmetic is the classic days-to-ymd conversion, exact for 1970..9999).
fn format_epoch_utc(ts: i64) -> String {
    // `<= 0` on purpose: parse sites use `unwrap_or(0)`, so 0 means
    // "field absent", not "midnight 1970" — render the missing marker.
    if ts <= 0 {
        return "—".into();
    }
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Parse one `LoopRunRecord` JSON blob into the panel view. Returns `None`
/// on malformed input (a truncated `.tmp` survivor must not kill the list).
pub fn parse_loop_record(json: &str) -> Option<LoopRunView> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let id = v.get("loop_id")?.as_str()?.to_string();
    let per_round = v
        .get("per_round")
        .and_then(|r| r.as_array())
        .map(|rounds| {
            rounds
                .iter()
                .filter_map(|r| {
                    Some(LoopRoundView {
                        round_num: r.get("round_num")?.as_u64()? as u32,
                        iterations: r.get("iterations").and_then(|x| x.as_u64()).unwrap_or(0)
                            as u32,
                        ok_calls: r
                            .get("successful_calls")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0) as u32,
                        fail_calls: r.get("failed_calls").and_then(|x| x.as_u64()).unwrap_or(0)
                            as u32,
                        stop_approved: r
                            .get("stop_approved")
                            .and_then(|x| x.as_bool())
                            .unwrap_or(false),
                        refine_fired: r
                            .get("refine_fired")
                            .and_then(|x| x.as_bool())
                            .unwrap_or(false),
                        duration: format_secs(
                            r.get("ts_end").and_then(|x| x.as_i64()).unwrap_or(0)
                                - r.get("ts_start").and_then(|x| x.as_i64()).unwrap_or(0),
                        ),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let ts_start = v.get("ts_start").and_then(|x| x.as_i64()).unwrap_or(0);
    Some(LoopRunView {
        id,
        ts_start,
        started: format_epoch_utc(ts_start),
        rounds_run: v.get("rounds_run").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        stop_reason: v
            .get("stop_reason")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string(),
        total_tool_calls: v
            .get("total_tool_calls")
            .or_else(|| v.get("total_tokens_used"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        per_round,
        final_text: v
            .get("final_text")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Load the newest `limit` loop-run records from `<neoth_home>/loops/`,
/// newest-first (by the record's own `ts_start`).
pub fn load_loop_history(neoth_home: &std::path::Path, limit: usize) -> Vec<LoopRunView> {
    let dir = neoth_home.join("loops");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut runs: Vec<LoopRunView> = entries
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|json| parse_loop_record(&json))
        .collect();
    runs.sort_by_key(|r| std::cmp::Reverse(r.ts_start));
    runs.truncate(limit);
    runs
}

/// Read `loop.max_rounds` + `loop.tool_call_budget` from freedom.yaml —
/// the panel's convergence denominator + budget-meter cap. Missing keys
/// fall back to the engine defaults (3 rounds, no cap).
pub fn parse_loop_budget(freedom_yaml: &str) -> (u32, u64) {
    let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(freedom_yaml) else {
        return (3, 0);
    };
    let lp = v.get("loop");
    let max_rounds = lp
        .and_then(|l| l.get("max_rounds"))
        .and_then(|x| x.as_u64())
        .unwrap_or(3) as u32;
    let budget = lp
        .and_then(|l| l.get("tool_call_budget"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    (max_rounds, budget)
}

// ── GOLD-ADAPT-ODY-01 — chat-sidebar session history ────────────────────
// GUI-decoupled mirror of `memory/hindsight.rs::HindsightCard` (the GUI
// never links the daemon crate; it reads `~/.neoth/hindsight/*.json`).
// Only the fields the sidebar renders are mirrored — serde ignores the rest.

#[derive(Debug, Clone, serde::Deserialize)]
pub struct HindsightCardMini {
    pub session_id: String,
    #[serde(default)]
    pub ended_at_unix: i64,
    #[serde(default)]
    pub one_line_summary: String,
    /// GOLD-ADOPT-21 optional LLM session title — preferred label.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// One sidebar row, display-ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEntry {
    pub id: String,
    pub label: String,
    pub meta: String,
}

impl HindsightCardMini {
    fn label(&self) -> String {
        match self.display_name.as_deref() {
            Some(n) if !n.trim().is_empty() => n.trim().to_string(),
            _ if !self.one_line_summary.trim().is_empty() => {
                self.one_line_summary.trim().to_string()
            }
            _ => self.session_id.clone(),
        }
    }
}

/// Load the newest `limit` session cards from `<home>/hindsight/`,
/// newest-first (same ordering contract as `hindsight::list_cards`).
/// Malformed files skip — a torn write must not empty the sidebar.
pub fn load_session_history(neoth_home: &std::path::Path, limit: usize) -> Vec<SessionEntry> {
    let dir = neoth_home.join("hindsight");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut cards: Vec<HindsightCardMini> = entries
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|json| serde_json::from_str::<HindsightCardMini>(&json).ok())
        .collect();
    cards.sort_by_key(|c| std::cmp::Reverse(c.ended_at_unix));
    cards.truncate(limit);
    cards
        .into_iter()
        .map(|c| SessionEntry {
            label: c.label(),
            meta: format_epoch_utc(c.ended_at_unix),
            id: c.session_id,
        })
        .collect()
}

// ── GOLD-ADAPT-ODY-02/05 — per-message metrics chip formatting ──────────
// Pure: sentinel stats in, (chip, popup-detail) strings out. `None` when
// the sentinel carried no token data (older daemon / recall early-return).

fn fmt_k(n: u64) -> String {
    if n >= 10_000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

pub fn format_stream_metrics(
    used_tokens: u64,
    limit_tokens: u64,
    input_tokens: u64,
    output_tokens: u64,
    elapsed_ms: u64,
) -> Option<(String, String)> {
    if used_tokens == 0 && output_tokens == 0 {
        return None;
    }
    let mut chip_parts: Vec<String> = Vec::new();
    let mut detail: Vec<String> = Vec::new();
    if limit_tokens > 0 {
        let pct = ((used_tokens as f64 / limit_tokens as f64) * 100.0).round() as u64;
        chip_parts.push(format!("ctx {pct}%"));
        detail.push(format!(
            "context: {} / {} tokens ({pct}%)",
            fmt_k(used_tokens),
            fmt_k(limit_tokens)
        ));
    }
    if elapsed_ms > 0 && output_tokens > 0 {
        let tps = output_tokens as f64 * 1000.0 / elapsed_ms as f64;
        chip_parts.push(format!("{tps:.0} tok/s"));
    }
    detail.push(format!(
        "in: {} · out: {}",
        fmt_k(input_tokens),
        fmt_k(output_tokens)
    ));
    if elapsed_ms > 0 {
        detail.push(format!("wall: {:.1}s", elapsed_ms as f64 / 1000.0));
    }
    if chip_parts.is_empty() {
        chip_parts.push(format!("{} tok", fmt_k(used_tokens.max(output_tokens))));
    }
    Some((chip_parts.join(" · "), detail.join("\n")))
}

// ── GOLD-ADAPT-AOS-03 — project-context persistence ─────────────────────
// Three optional wizard answers, stored as JSON at
// `<home>/.project-context` (own file — freedom.yaml stays daemon-owned).

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProjectContext {
    #[serde(default)]
    pub building: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub stack: String,
}

pub fn read_project_context(neoth_home: &std::path::Path) -> ProjectContext {
    std::fs::read_to_string(neoth_home.join(".project-context"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Atomic-enough single-file write (tmp+rename like the daemon's small
/// state files). Errors return `false` — the wizard step is optional.
pub fn write_project_context(neoth_home: &std::path::Path, ctx: &ProjectContext) -> bool {
    let Ok(json) = serde_json::to_string_pretty(ctx) else {
        return false;
    };
    let tmp = neoth_home.join(".project-context.tmp");
    let dst = neoth_home.join(".project-context");
    std::fs::create_dir_all(neoth_home).ok();
    if std::fs::write(&tmp, json).is_err() {
        return false;
    }
    std::fs::rename(&tmp, &dst).is_ok()
}

// ── GOLD-ADAPT-AOS-06 — spec-shape description composition ─────────────

/// Compose the `--description` body for `neoth kanban add` from the
/// New-Spec pane's goal + acceptance fields. `None` when both are empty.
pub fn compose_spec_description(goal: &str, acceptance: &str) -> Option<String> {
    let goal = goal.trim();
    let acceptance = acceptance.trim();
    match (goal.is_empty(), acceptance.is_empty()) {
        (true, true) => None,
        (false, true) => Some(format!("Goal: {goal}")),
        (true, false) => Some(format!("Done when: {acceptance}")),
        (false, false) => Some(format!("Goal: {goal}\n\nDone when: {acceptance}")),
    }
}

// ── GOLD-ADAPT-GUI-05 — TypedStatus footer ticker ──────────────────────
// Pure frame function: the Rust timer feeds a monotonic tick; each frame
// is the current message typed up to N chars, then held, then the next
// message. Keeping the math here (not in the Timer closure) makes the
// typing cadence unit-testable without a Slint window.

/// Brand-true footer lines. Machine-truth register, no marketing voice.
pub const TICKER_MESSAGES: &[&str] = &[
    "hippocampus indexing — 3 tiers live",
    "WAL sealed · audit chain clean",
    "hemispheres synced · council idle",
    "consent boundaries armed",
    "local-first · your compute, your memory",
    "skills router warm · triggers loaded",
];

/// Ticks a character is "held" after a message is fully typed before the
/// ticker moves on (at ~80ms/tick ≈ 4s hold).
const TICKER_HOLD_TICKS: u64 = 50;

/// Render the ticker frame for `tick` (monotonic, one per timer fire).
/// Types one char per tick, holds the full line, then advances.
pub fn ticker_frame(tick: u64) -> &'static str {
    ticker_frame_over(TICKER_MESSAGES, tick)
}

fn ticker_frame_over(messages: &[&'static str], tick: u64) -> &'static str {
    if messages.is_empty() {
        return "";
    }
    // Per-message cycle length = chars to type + hold.
    let total: u64 = messages
        .iter()
        .map(|m| m.chars().count() as u64 + TICKER_HOLD_TICKS)
        .sum();
    let mut pos = tick % total.max(1);
    for m in messages {
        let len = m.chars().count() as u64;
        let cycle = len + TICKER_HOLD_TICKS;
        if pos < cycle {
            let shown = pos.min(len) as usize;
            // Byte-index of the char boundary (messages contain non-ASCII "·").
            let end = m
                .char_indices()
                .nth(shown)
                .map(|(i, _)| i)
                .unwrap_or(m.len());
            return &m[..end];
        }
        pos -= cycle;
    }
    messages[0]
}

// ── Wave-1 toast helpers ─────────────────────────────────────────────────────
// Pure functions so they are unit-testable without a Slint display or an event
// loop. The Slint-facing plumbing (push_toast / Timer) lives in main.rs.

/// Remove the toast with the given `id` from `toasts`. Returns the new vec.
/// Called from the event-loop callback after the 6 s lifetime expires.
pub fn prune_toast(toasts: Vec<(i32, String, String, String)>, id: i32)
    -> Vec<(i32, String, String, String)>
{
    toasts.into_iter().filter(|(tid, _, _, _)| *tid != id).collect()
}

/// Allocate a fresh toast id that does not collide with any id in `toasts`.
/// Deterministic: starts at 1, increments until a gap is found.
pub fn next_toast_id(toasts: &[(i32, String, String, String)]) -> i32 {
    let max = toasts.iter().map(|(id, _, _, _)| *id).max().unwrap_or(0);
    max + 1
}

// ── Wave-2 activity helpers ──────────────────────────────────────────────────
// Pure, Slint-free functions — the ActivitySidecar plumbing (push_activity,
// settle_activity) lives in main.rs and calls these for id allocation + cap.

/// One activity row tuple: (id, ts, kind, title, detail, active).
pub type ActivityTuple = (i32, String, String, String, String, bool);

/// Allocate the next activity id (monotonic, no collision with existing rows).
pub fn next_activity_id(rows: &[ActivityTuple]) -> i32 {
    let max = rows.iter().map(|(id, _, _, _, _, _)| *id).max().unwrap_or(0);
    max + 1
}

/// Enforce the session-scoped cap. Keeps the NEWEST `max` rows (rows are stored
/// newest-first in main.rs). Called after every push.
pub fn cap_activity(mut rows: Vec<ActivityTuple>, max: usize) -> Vec<ActivityTuple> {
    rows.truncate(max);
    rows
}

/// Mark all rows whose `kind` equals `kind` as `active = false`.
/// Returns the modified vec. Called on completion events to settle a burst.
pub fn settle_activity(rows: Vec<ActivityTuple>, kind: &str) -> Vec<ActivityTuple> {
    rows.into_iter()
        .map(|(id, ts, k, title, detail, active)| {
            let settled = if k == kind { false } else { active };
            (id, ts, k, title, detail, settled)
        })
        .collect()
}

// GAP-04 — Format the raw stdout+stderr of `neoth recall <query>` into a
// display string for the GUI. Pure: no I/O, no allocation from caller.
//
// Rules:
//   - Concatenate stdout + stderr (stderr appended with a newline separator
//     when non-empty); this mirrors the pattern used in the doctor/status
//     probe workers in main.rs.
//   - Trim the final result; if empty, substitute a "no results" sentinel so
//     the text area never shows a blank rectangle.
//   - Never panics: all inputs are `&str`.
pub fn format_recall_output(stdout: &str, stderr: &str, query: &str) -> String {
    let mut s = stdout.to_owned();
    let err = stderr.trim();
    if !err.is_empty() {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str(err);
    }
    let trimmed = s.trim().to_owned();
    if trimmed.is_empty() {
        format!("No results for \"{query}\".")
    } else {
        trimmed
    }
}

// ── Overview / Mission Control parse helpers (Design Wave 3) ──────────────────
//
// Each function is PURE: takes raw JSON &str, returns a typed result. Tolerant
// of missing keys / malformed payloads — always returns a degraded-but-valid
// value so the GUI renders a "unavailable" state instead of panicking.

/// Parse `neoth status --output json` into (mode, autonomy, channel_health,
/// wal_bytes, tier_counts, daemon_state).
/// `daemon_state` is "live" | "connecting" | "error" for the Led widget.
pub fn parse_overview_status(
    json: &str,
) -> (String, String, String, String, String, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();

    let mode = v
        .get("operating_mode")
        .or_else(|| v.get("mode"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    let autonomy = v
        .get("autonomy")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    // Channel health: try "channel_health" string, fall back to counting active channels.
    let channel_health = if let Some(s) = v.get("channel_health").and_then(|x| x.as_str()) {
        s.to_string()
    } else if let Some(arr) = v.get("channels").and_then(|x| x.as_array()) {
        let active = arr
            .iter()
            .filter(|c| {
                c.get("status")
                    .and_then(|s| s.as_str())
                    .map(|s| s == "active" || s == "connected")
                    .unwrap_or(false)
            })
            .count();
        format!("{active}/{} active", arr.len())
    } else {
        String::new()
    };

    let wal_bytes = v
        .get("wal")
        .and_then(|w| w.get("bytes"))
        .or_else(|| v.get("wal_bytes"))
        .and_then(|x| x.as_u64())
        .map(|b| format!("{b} B"))
        .unwrap_or_default();

    let tier_counts = if let Some(tiers) = v.get("tier_counts").and_then(|x| x.as_object()) {
        tiers
            .iter()
            .map(|(k, val)| {
                let n = val.as_u64().unwrap_or(0);
                format!("{k}={n}")
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        String::new()
    };

    // Daemon liveness: a valid JSON reply means the daemon responded → "live".
    // Callers set "error" when the subprocess exits non-zero.
    let daemon_state = if json.trim().is_empty() || json.starts_with("unavailable") {
        "error".to_string()
    } else {
        "live".to_string()
    };

    (mode, autonomy, channel_health, wal_bytes, tier_counts, daemon_state)
}

/// Parse `neoth meter --format json` into (tokens_in, tokens_out, responses, cost, fraction).
/// `fraction` is 0.0..1.0 — tokens_in / daily_cap if the cap is known, else 0.0.
pub fn parse_meter(json: &str) -> (String, String, String, String, f32) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();

    let fmt_count = |key: &str| -> String {
        v.get(key)
            .and_then(|x| x.as_u64())
            .map(|n| {
                if n >= 1_000_000 {
                    format!("{:.1}M", n as f64 / 1_000_000.0)
                } else if n >= 1_000 {
                    format!("{:.1}K", n as f64 / 1_000.0)
                } else {
                    n.to_string()
                }
            })
            .unwrap_or_default()
    };

    let tokens_in = fmt_count("input_tokens_total");
    let tokens_out = fmt_count("output_tokens_total");
    let responses = v
        .get("provider_responses")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_default();

    let cost = v
        .get("cost_usd")
        .and_then(|x| x.as_f64())
        .map(|c| format!("${c:.4}"))
        .unwrap_or_default();

    // fraction vs daily cap
    let fraction = if let (Some(used), Some(cap)) = (
        v.get("input_tokens_total").and_then(|x| x.as_u64()),
        v.get("daily_cap_tokens").and_then(|x| x.as_u64()),
    ) {
        if cap > 0 {
            (used as f32 / cap as f32).clamp(0.0, 1.0)
        } else {
            0.0
        }
    } else {
        0.0
    };

    (tokens_in, tokens_out, responses, cost, fraction)
}

/// Parse `neoth hemispheres show --output json` into a Vec of (role, provider, model, ok).
pub fn parse_overview_hemispheres(json: &str) -> Vec<(String, String, String, bool)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();

    // Expected shape: [ { "role": "left", "provider": "claude_cli", "model": "claude-opus-4-7", "status": "active" }, … ]
    // Also tolerate { "hemispheres": [ … ] }.
    let arr = v
        .as_array()
        .or_else(|| v.get("hemispheres").and_then(|x| x.as_array()))
        .cloned()
        .unwrap_or_default();

    arr.iter()
        .filter_map(|item| {
            let role = item.get("role").and_then(|x| x.as_str())?.to_string();
            let provider = item
                .get("provider")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let model = item
                .get("model")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let ok = item
                .get("status")
                .and_then(|x| x.as_str())
                .map(|s| s == "active" || s == "ok")
                .unwrap_or(!provider.is_empty());
            Some((role, provider, model, ok))
        })
        .collect()
}

/// Parse `neoth agents list --output json` into (count_str, names).
pub fn parse_agents(json: &str) -> (String, Vec<String>) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();

    let arr = v
        .as_array()
        .or_else(|| v.get("agents").and_then(|x| x.as_array()))
        .cloned()
        .unwrap_or_default();

    let names: Vec<String> = arr
        .iter()
        .filter_map(|item| {
            item.get("name")
                .or_else(|| item.get("id"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .take(8)
        .collect();

    let count = if arr.is_empty() {
        String::new()
    } else {
        arr.len().to_string()
    };

    (count, names)
}

/// Parse `neoth skills list --output json` into (active_count_str, top_names).
pub fn parse_overview_skills(json: &str) -> (String, Vec<String>) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();

    let arr = v
        .as_array()
        .or_else(|| v.get("skills").and_then(|x| x.as_array()))
        .cloned()
        .unwrap_or_default();

    let active: Vec<_> = arr
        .iter()
        .filter(|item| {
            item.get("enabled")
                .or_else(|| item.get("active"))
                .and_then(|x| x.as_bool())
                .unwrap_or(true)
        })
        .collect();

    let names: Vec<String> = active
        .iter()
        .filter_map(|item| {
            item.get("name")
                .or_else(|| item.get("id"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .take(4)
        .collect();

    let count = if active.is_empty() {
        String::new()
    } else {
        active.len().to_string()
    };

    (count, names)
}

/// Parse `neoth calendar list --output json` into (configured, events).
/// Events are (time_str, summary). Returns (false, []) when the payload
/// indicates CalDAV is not configured (error field present / count == 0 with
/// empty events).
pub fn parse_calendar_next(json: &str, n: usize) -> (bool, Vec<(String, String)>) {
    // A subprocess error string (not JSON) means "not configured".
    let v = match serde_json::from_str::<serde_json::Value>(json) {
        Ok(v) => v,
        Err(_) => return (false, vec![]),
    };

    // Error key → not configured.
    if v.get("error").is_some() {
        return (false, vec![]);
    }

    let events = v
        .get("events")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    let parsed: Vec<(String, String)> = events
        .iter()
        .take(n)
        .filter_map(|ev| {
            let summary = ev
                .get("summary")
                .or_else(|| ev.get("title"))
                .and_then(|x| x.as_str())
                .unwrap_or("(no title)")
                .to_string();
            // Try ISO time, fall back to "start" field.
            let time = ev
                .get("start")
                .and_then(|x| x.as_str())
                .or_else(|| ev.get("time").and_then(|x| x.as_str()))
                .map(|s| {
                    // Abbreviate ISO datetime to HH:MM if possible.
                    if s.len() >= 16 && s.contains('T') {
                        s[11..16].to_string()
                    } else {
                        s[..s.len().min(10)].to_string()
                    }
                })
                .unwrap_or_else(|| "—".to_string());
            Some((time, summary))
        })
        .collect();

    (true, parsed)
}

/// Parse `neoth consent list --output json` into Vec<(provider, granted)>.
/// Also returns a smart-approve hint string (empty if not set).
pub fn parse_consent(json: &str) -> (Vec<(String, bool)>, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();

    let arr = v
        .as_array()
        .or_else(|| v.get("consents").and_then(|x| x.as_array()))
        .cloned()
        .unwrap_or_default();

    let entries: Vec<(String, bool)> = arr
        .iter()
        .filter_map(|item| {
            let provider = item
                .get("provider")
                .or_else(|| item.get("name"))
                .and_then(|x| x.as_str())?
                .to_string();
            // Try "granted" bool field first; fall back to "status" == "granted".
            let granted = if let Some(b) = item.get("granted").and_then(|x| x.as_bool()) {
                b
            } else {
                item.get("status")
                    .and_then(|s| s.as_str())
                    .map(|s| s == "granted")
                    .unwrap_or(false)
            };
            Some((provider, granted))
        })
        .collect();

    let smart_approve = v
        .get("smart_approve")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    (entries, smart_approve)
}

// ── Design Wave 4a helpers ────────────────────────────────────────────────────

/// UTC HH:MM:SS timestamp for refresh footers.
pub fn now_hhmm() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let hh = (secs / 3600) % 24;
    let mm = (secs / 60) % 60;
    let ss = secs % 60;
    format!("{hh:02}:{mm:02}:{ss:02} UTC")
}

// ── n8n parse fns ─────────────────────────────────────────────────────────────

/// Parse `neoth n8n status --output json` → (installed, webhook_base, path).
///
/// Expected shape: `{"n8n_installed":true,"webhook_base":"http://localhost:5678",
///   "n8n_path":"/usr/local/bin/n8n","bundled_workflows":[]}`
pub fn parse_n8n_status(json: &str) -> (bool, String, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let installed    = v.get("n8n_installed").and_then(|x| x.as_bool()).unwrap_or(false);
    let webhook_base = v.get("webhook_base").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let path         = v.get("n8n_path").and_then(|x| x.as_str()).unwrap_or("").to_string();
    (installed, webhook_base, path)
}

/// Parse `neoth n8n workflows --output json` → Vec<(name, description)>.
///
/// Expected shape: `{"workflows":[{"name":"...", "description":"..."},...]}`
/// Also tolerates a top-level array `[{...},...]`.
pub fn parse_n8n_workflows(json: &str) -> Vec<(String, String)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("workflows")
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .filter_map(|item| {
            let name = item.get("name").and_then(|x| x.as_str())?.to_string();
            let desc = item
                .get("description")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((name, desc))
        })
        .collect()
}

// ── Babel parse fns ───────────────────────────────────────────────────────────

/// Parse `neoth babel status --output json`.
///
/// Returns `(enabled, threshold, epsilon, federate, total_windows,
///           collapse_flagged, gran_rows)` where `gran_rows` is
/// `Vec<(window_secs_i32, count_i32, last_ts_end)>`.
pub fn parse_babel_status(
    json: &str,
) -> (bool, String, String, bool, i32, i32, Vec<(i32, i32, String)>) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let enabled   = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    let threshold = v.get("threshold").map(|x| x.to_string()).unwrap_or_default();
    let epsilon   = v
        .get("epsilon_calibrated")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let federate  = v.get("federate").and_then(|x| x.as_bool()).unwrap_or(false);
    let total     = v.get("total_windows").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let collapse  = v.get("collapse_flagged").and_then(|x| x.as_i64()).unwrap_or(0) as i32;

    let gran_rows: Vec<(i32, i32, String)> = v
        .get("windows_by_granularity")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|item| {
            let ws  = item.get("window_secs").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
            let cnt = item.get("count").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
            let last = item
                .get("last_ts_end")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            (ws, cnt, last)
        })
        .collect();

    (enabled, threshold, epsilon, federate, total, collapse, gran_rows)
}

/// Parse `neoth babel windows --n 12 --output json`.
///
/// Returns `Vec<(id, window_secs, ts_start, ts_end, b_log, b_mult,
///               b_bottleneck, collapse_kind)>`.
pub fn parse_babel_windows(
    json: &str,
) -> Vec<(String, i32, String, String, f32, f32, f32, String)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("windows")
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let ws = item.get("window_secs").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
            let ts_start = item.get("ts_start").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let ts_end   = item.get("ts_end").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let b_log    = item.get("b_log").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
            let b_mult   = item.get("b_mult").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
            let b_bottleneck = item
                .get("b_bottleneck")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0)
                .clamp(0.0, 1.0) as f32;
            let collapse_kind = item
                .get("collapse_kind")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((id, ws, ts_start, ts_end, b_log, b_mult, b_bottleneck, collapse_kind))
        })
        .collect()
}

// ── Calendar parse fns ────────────────────────────────────────────────────────

/// Parse `neoth calendar list --output json` for the calendar panel.
///
/// Returns `(configured, Vec<(datetime_str, summary, location)>)`.
/// `datetime_str` is formatted from the `start` field for display.
/// Non-JSON output (e.g. CalDAV error message) → `(false, [])`.
pub fn parse_calendar_events(json: &str) -> (bool, Vec<(String, String, String)>) {
    let v = match serde_json::from_str::<serde_json::Value>(json) {
        Ok(v) => v,
        Err(_) => return (false, vec![]),
    };
    if v.get("error").is_some() {
        return (false, vec![]);
    }
    let events = v
        .get("events")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let rows: Vec<(String, String, String)> = events
        .iter()
        .filter_map(|item| {
            let summary  = item.get("summary").and_then(|x| x.as_str())?.to_string();
            let start_raw = item.get("start").and_then(|x| x.as_str()).unwrap_or("").to_string();
            // Display: keep first 16 chars of ISO timestamp (YYYY-MM-DDTHH:MM).
            let datetime = if start_raw.len() >= 16 {
                start_raw[..16].replace('T', " ")
            } else {
                start_raw.clone()
            };
            let location = item
                .get("location")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((datetime, summary, location))
        })
        .collect();
    (true, rows)
}

// ── Self-Improve parse fns ────────────────────────────────────────────────────

/// Parse `neoth self-improve status --output json`.
///
/// Returns `(enabled, auto, skillopt_installed, last_run, autonomy)`.
pub fn parse_selfimprove_status(json: &str) -> (bool, bool, bool, String, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let enabled  = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    let auto     = v.get("auto")
        .and_then(|x| x.as_bool())
        .or_else(|| v.get("implied_by_full_auto").and_then(|x| x.as_bool()))
        .unwrap_or(false);
    let skillopt = v.get("skillopt_installed").and_then(|x| x.as_bool()).unwrap_or(false);
    let last     = v.get("last").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let autonomy = v.get("autonomy").and_then(|x| x.as_str()).unwrap_or("").to_string();
    (enabled, auto, skillopt, last, autonomy)
}

/// Parse `neoth self-improve review --output json` → Vec<(id, title, description)>.
///
/// Tolerates `{"proposals":[...]}` or top-level array.
pub fn parse_selfimprove_proposals(json: &str) -> Vec<(String, String, String)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("proposals")
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .filter_map(|item| {
            let id    = item.get("id").and_then(|x| x.as_str())?.to_string();
            let title = item.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let desc  = item
                .get("description")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((id, title, desc))
        })
        .collect()
}

/// Parse `neoth self-improve log --output json` → Vec<(id, title, status, ts)>,
/// capped at 10 entries.
pub fn parse_selfimprove_log(json: &str) -> Vec<(String, String, String, String)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("log")
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .take(10)
        .filter_map(|item| {
            let id     = item.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let title  = item.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let status = item.get("status").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let ts     = item.get("ts")
                .or_else(|| item.get("timestamp"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((id, title, status, ts))
        })
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
            vec![
                "claude-opus-4-8".to_string(),
                "claude-sonnet-4-6".to_string()
            ]
        );
    }

    #[test]
    fn parse_catalog_model_ids_excludes_deprecated_and_other_providers() {
        let json = r#"{"providers":{
            "anthropic_api":{"models":[{"id":"old","deprecated":true},{"id":"new","deprecated":false}]},
            "gemini_api":{"models":[{"id":"g"}]}
        }}"#;
        assert_eq!(
            parse_catalog_model_ids(json, "anthropic_api"),
            vec!["new".to_string()]
        );
        assert_eq!(
            parse_catalog_model_ids(json, "gemini_api"),
            vec!["g".to_string()]
        );
    }

    #[test]
    fn parse_catalog_model_ids_empty_on_malformed_or_absent() {
        assert!(parse_catalog_model_ids("not json", "anthropic_api").is_empty());
        assert!(parse_catalog_model_ids(r#"{"providers":{}}"#, "anthropic_api").is_empty());
        assert!(
            parse_catalog_model_ids(r#"{"providers":{"x":{"models":[{"id":"m"}]}}}"#, "absent")
                .is_empty()
        );
    }

    // ── local model recommend parser (Hemispheres model picker) ───────────
    #[test]
    fn parse_model_recommend_refs_extracts_pull_refs_in_order() {
        let json = r#"[
            {"rank":1,"repo":"bartowski/Qwen2.5-Coder-32B-abliterated-GGUF",
             "pull_ref":"hf.co/bartowski/Qwen2.5-Coder-32B-abliterated-GGUF:Q4_K_M"},
            {"rank":2,"repo":"mradermacher/Qwen2.5-VL-7B-abliterated-GGUF",
             "pull_ref":"hf.co/mradermacher/Qwen2.5-VL-7B-abliterated-GGUF:Q8_0"}
        ]"#;
        assert_eq!(
            parse_model_recommend_refs(json),
            vec![
                "hf.co/bartowski/Qwen2.5-Coder-32B-abliterated-GGUF:Q4_K_M".to_string(),
                "hf.co/mradermacher/Qwen2.5-VL-7B-abliterated-GGUF:Q8_0".to_string(),
            ]
        );
    }

    #[test]
    fn parse_model_recommend_refs_falls_back_to_repo_and_tolerates_garbage() {
        // pull_ref absent → repo is the fallback id.
        assert_eq!(
            parse_model_recommend_refs(r#"[{"repo":"some/Model-GGUF"}]"#),
            vec!["some/Model-GGUF".to_string()]
        );
        assert!(parse_model_recommend_refs("not json").is_empty());
        assert!(parse_model_recommend_refs(r#"{"not":"an array"}"#).is_empty());
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
        assert_eq!(
            t.privacy[0],
            TrustRow {
                label: "channel_weight_scope".into(),
                value: "operator_only".into()
            }
        );
        assert!(
            t.privacy
                .iter()
                .any(|r| r.label == "omi_ingest" && r.value == "off")
        );
        assert!(
            t.privacy
                .iter()
                .any(|r| r.label == "live_delivery_edits" && r.value == "on")
        );
        // recovery: *_present → present/missing.
        assert!(
            t.recovery
                .iter()
                .any(|r| r.label == "hmac_key_present" && r.value == "present")
        );
        assert!(
            t.recovery
                .iter()
                .any(|r| r.label == "proof_key_present" && r.value == "missing")
        );
        // ledger numbers render as strings.
        assert!(
            t.ledger
                .iter()
                .any(|r| r.label == "segments" && r.value == "787")
        );
        assert!(
            t.ledger
                .iter()
                .any(|r| r.label == "bad_frames" && r.value == "1")
        );
    }

    #[test]
    fn parse_trust_is_robust_to_garbage_and_unknown_keys() {
        assert_eq!(parse_trust("not json"), TrustSnapshot::default());
        assert_eq!(parse_trust("{}"), TrustSnapshot::default());
        // A future switch the CLI adds shows up generically (forward-compatible).
        let t = parse_trust(r#"{"privacy_switches":{"some_future_switch":true}}"#);
        assert_eq!(
            t.privacy,
            vec![TrustRow {
                label: "some_future_switch".into(),
                value: "on".into()
            }]
        );
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
        assert_eq!(
            h.cpu,
            "AMD Ryzen Threadripper PRO 5965WX — 24c/48t @ 4700 MHz"
        );
        assert_eq!(h.memory, "224 / 255 GiB available");
        assert_eq!(h.accelerator, "cuda — GPU path active");
        assert_eq!(h.vram, "1405 / 24576 MiB used (5%)");
        assert!((h.vram_fraction - 0.057169).abs() < 1e-4);
        assert!(h.disk.starts_with("108 / 1675 GiB free (C:"));
        assert!(
            h.models
                .iter()
                .any(|r| r.label == "qwen2_5_3b" && r.value == "cached")
        );
        assert!(
            h.models
                .iter()
                .any(|r| r.label == "clip_vit_b32" && r.value == "not cached")
        );
    }

    #[test]
    fn parse_hardware_robust_and_no_gpu() {
        assert_eq!(parse_hardware("nope"), HardwareSnapshot::default());
        // No vram node → explicit "(no GPU detected)".
        let h = parse_hardware(
            r#"{"cpu":{"brand":"x","physical_cores":1,"logical_cores":1,"frequency_mhz":1}}"#,
        );
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
        assert_eq!(p.note, "live token budget");
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
        let b =
            parse_council_budget(r#"{"configured_cap":15,"daily_usd_cap":null,"runtime":null}"#);
        assert_eq!(b.configured_cap, "15 calls / message");
        assert_eq!(b.daily_usd_cap, "no daily USD cap");
        assert!(b.last_debate.is_empty());

        // With a last-debate runtime + a daily cap.
        let b = parse_council_budget(
            r#"{"configured_cap":3,"daily_usd_cap":5.0,"runtime":{"cap_at_last_debate":3,"used_last_msg":2,"exhausted_last_msg":false,"exhaustions_rolling":1}}"#,
        );
        assert_eq!(b.configured_cap, "3 calls / message");
        assert_eq!(b.daily_usd_cap, "$5.00 / day");
        assert!(
            b.last_debate
                .iter()
                .any(|r| r.label == "used last message" && r.value == "2 / 3")
        );
        assert!(
            b.last_debate
                .iter()
                .any(|r| r.label == "exhausted last message" && r.value == "no")
        );
        assert!(
            b.last_debate
                .iter()
                .any(|r| r.label == "exhaustions (rolling)" && r.value == "1")
        );
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
        assert!(
            deep.depth_cost_warning.contains("81"),
            "{}",
            deep.depth_cost_warning
        );
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
        assert_eq!(
            rows[0],
            ProfilePresetRow {
                name: "lowkey".into(),
                description: "casual".into(),
                recommended: true,
                active: true
            }
        );
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
        assert_eq!(
            parse_complexity_level("standard"),
            ComplexityLevel::Standard
        );
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
        assert!(
            p.show_channels,
            "beginner needs channels to connect Telegram"
        );
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
            assert!(
                !mf[i] || sf[i],
                "Standard hides a panel Minimal showed (idx {i})"
            );
            assert!(
                !sf[i] || ff[i],
                "Full hides a panel Standard showed (idx {i})"
            );
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
        assert_eq!(
            s.bindings[2].provider, "(unset)",
            "null provider -> (unset)"
        );
    }

    #[test]
    fn parse_hemispheres_malformed_is_empty() {
        assert_eq!(parse_hemispheres("nope"), HemispheresSnapshot::default());
        // role-less entry skipped.
        let s = parse_hemispheres(
            r#"{"mode":"single","roles":[{"provider":"x"},{"role":"left","provider":"y"}]}"#,
        );
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

    // ── GOLD-ADAPT-AOS-01 — tags + grouped index ───────────────────────
    #[test]
    fn parse_skills_reads_tags() {
        let rows = parse_skills(
            r#"[{"id":"a","tags":["security","net"]},{"id":"b"}]"#,
        );
        assert_eq!(rows[0].tags, vec!["security", "net"]);
        assert!(rows[1].tags.is_empty());
    }

    #[test]
    fn group_skill_rows_groups_by_first_tag_sorted_with_headers() {
        let mk = |id: &str, tags: &[&str], desc: &str| SkillSummary {
            id: id.into(),
            description: desc.into(),
            enabled: true,
            keywords: String::new(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        };
        let skills = vec![
            mk("zeta", &["security"], ""),
            mk("alpha", &["security", "extra"], ""),
            mk("plain", &[], "untagged skill"),
            mk("writer", &["Docs"], ""),
        ];
        let rows = group_skill_rows(&skills, "");
        let shape: Vec<(bool, &str)> =
            rows.iter().map(|r| (r.is_header, r.id.as_str())).collect();
        assert_eq!(
            shape,
            vec![
                (true, "DOCS"),
                (false, "writer"),
                (true, "GENERAL"),
                (false, "plain"),
                (true, "SECURITY"),
                (false, "alpha"),
                (false, "zeta"),
            ]
        );
        // Filter hits description; empty groups drop their headers.
        let filtered = group_skill_rows(&skills, "UNTAGGED");
        let shape: Vec<(bool, &str)> = filtered
            .iter()
            .map(|r| (r.is_header, r.id.as_str()))
            .collect();
        assert_eq!(shape, vec![(true, "GENERAL"), (false, "plain")]);
        // Filter with no match → fully empty (no orphan headers).
        assert!(group_skill_rows(&skills, "zzz-nope").is_empty());
    }

    #[test]
    fn parse_skills_malformed_and_non_array_is_empty() {
        assert!(parse_skills("nope").is_empty());
        assert!(
            parse_skills(r#"{"id":"x"}"#).is_empty(),
            "object, not array -> empty"
        );
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
        assert!(
            parse_plugins(r#"{"id":"x"}"#).is_empty(),
            "object not array"
        );
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
        let s = parse_memory_size(
            r#"{"blocks":[{"source":"x","path":"/p","bytes":5},{"source":"y","bytes":9}]}"#,
        );
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
        for ch in [
            "telegram",
            "whatsapp",
            "slack",
            "discord",
            "signal",
            "matrix",
            "line",
            "irc",
            "mattermost",
            "twitch",
            "keet",
            "nostr",
            "imessage",
            "gchat",
        ] {
            assert!(
                rows.iter().any(|c| c.name == ch),
                "missing channel row: {ch}"
            );
        }
        // The connected bool is all that's exposed — no token value in the struct.
        assert_eq!(rows.len(), 14);
    }

    #[test]
    fn channel_status_empty_token_is_disconnected_and_malformed_is_all_off() {
        let rows = channel_status_from_credentials_yaml("telegram_token: \"  \"\n");
        assert!(
            !rows
                .iter()
                .find(|c| c.name == "telegram")
                .unwrap()
                .connected,
            "whitespace-only token -> disconnected"
        );
        // Malformed YAML -> all disconnected, never a panic.
        let all = channel_status_from_credentials_yaml("%%% not yaml %%%");
        assert!(all.iter().all(|c| !c.connected));
    }

    #[test]
    fn read_channel_status_missing_file_is_all_off() {
        let dir = tempfile::tempdir().unwrap();
        let rows = read_channel_status(dir.path());
        assert_eq!(rows.len(), 14);
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

    #[test]
    fn parse_presets_reads_builtin_and_description_fields() {
        let json = r#"{
            "presets":[
                {"name":"full-auto","active":false,"builtin":true,"description":"Acts without asking"},
                {"name":"balanced","active":true,"builtin":true,"description":"Balanced defaults"},
                {"name":"my-custom","active":false,"builtin":false,"description":""}
            ],
            "active":"balanced"
        }"#;
        let rows = parse_presets(json);
        assert_eq!(rows.len(), 3);
        assert!(rows[0].builtin);
        assert_eq!(rows[0].description, "Acts without asking");
        assert!(rows[1].builtin);
        assert!(rows[1].active);
        assert!(!rows[2].builtin);
        assert_eq!(rows[2].description, "");
    }

    #[test]
    fn parse_presets_builtin_description_default_when_absent() {
        // Old daemon: fields absent — must not panic, defaults to false/"".
        let json = r#"{"presets":[{"name":"frugal","active":false}],"active":null}"#;
        let rows = parse_presets(json);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].builtin, "absent builtin defaults false");
        assert_eq!(rows[0].description, "", "absent description defaults empty");
    }

    // ── SPEC-05 parse_apply_plan ──────────────────────────────────────────────

    #[test]
    fn parse_apply_plan_happy_path_with_warns() {
        let json = r#"{
            "name": "full-auto",
            "fields_changed": ["autonomy", "provider"],
            "autonomy_requested": "full",
            "warn_changes": [
                {"path": "autonomy.level", "old": "standard", "new": "full"},
                {"path": "council.enabled", "old": "false", "new": "true"}
            ]
        }"#;
        let plan = parse_apply_plan(json).expect("valid JSON must parse");
        assert_eq!(plan.name, "full-auto");
        assert_eq!(plan.autonomy_requested, Some("full".to_string()));
        assert_eq!(plan.fields_changed_count, 2);
        assert_eq!(plan.warn_changes.len(), 2);
        assert_eq!(plan.warn_changes[0].path, "autonomy.level");
        assert_eq!(plan.warn_changes[0].old, "standard");
        assert_eq!(plan.warn_changes[0].new, "full");
    }

    #[test]
    fn parse_apply_plan_no_warns_no_autonomy() {
        let json = r#"{"name":"essentials","fields_changed":["provider"],"warn_changes":[]}"#;
        let plan = parse_apply_plan(json).expect("valid JSON must parse");
        assert_eq!(plan.name, "essentials");
        assert_eq!(plan.autonomy_requested, None);
        assert_eq!(plan.fields_changed_count, 1);
        assert!(plan.warn_changes.is_empty());
    }

    #[test]
    fn parse_apply_plan_malformed_json_returns_none() {
        assert!(parse_apply_plan("not json").is_none());
        assert!(parse_apply_plan("{}").is_none(), "missing name field → None");
        assert!(parse_apply_plan("").is_none());
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
        assert_eq!(
            ids,
            vec!["claude_cli", "openai_api"],
            "stub provider excluded"
        );
    }

    #[test]
    fn parse_provider_ids_malformed_and_missing_flag() {
        assert!(parse_provider_ids("nope").is_empty());
        assert!(
            parse_provider_ids(r#"{"id":"x"}"#).is_empty(),
            "object not array"
        );
        // Missing `implemented` defaults to included (forward-compat).
        let ids = parse_provider_ids(r#"[{"id":"a"},{"description":"no id"}]"#);
        assert_eq!(ids, vec!["a"]);
    }

    // ── GOLD-LOOP-03 — loop record parsing ────────────────────────────
    const LOOP_RECORD: &str = r#"{
        "loop_id": "lp-20260703-abc123",
        "prompt_hash": "deadbeef",
        "rounds_run": 2,
        "stop_reason": "converged",
        "total_tool_calls": 17,
        "per_round": [
            {"round_num":1,"iterations":6,"hit_cap":false,"successful_calls":9,
             "failed_calls":1,"stop_approved":false,"refine_fired":true,
             "ts_start":1751500000,"ts_end":1751500042},
            {"round_num":2,"iterations":3,"hit_cap":false,"successful_calls":7,
             "failed_calls":0,"stop_approved":true,"refine_fired":false,
             "ts_start":1751500042,"ts_end":1751500171}
        ],
        "final_text": "done — tests green",
        "ts_start": 1751500000,
        "ts_end": 1751500171
    }"#;

    #[test]
    fn parse_loop_record_maps_rounds_and_headline() {
        let run = parse_loop_record(LOOP_RECORD).expect("record parses");
        assert_eq!(run.id, "lp-20260703-abc123");
        assert_eq!(run.rounds_run, 2);
        assert_eq!(run.stop_reason, "converged");
        assert_eq!(run.total_tool_calls, 17);
        assert_eq!(run.final_text, "done — tests green");
        assert_eq!(run.per_round.len(), 2);
        let r1 = &run.per_round[0];
        assert_eq!(
            (r1.round_num, r1.iterations, r1.ok_calls, r1.fail_calls),
            (1, 6, 9, 1)
        );
        assert!(r1.refine_fired && !r1.stop_approved);
        assert_eq!(r1.duration, "42s");
        let r2 = &run.per_round[1];
        assert!(r2.stop_approved && !r2.refine_fired);
        assert_eq!(r2.duration, "2m09s");
        // Epoch 1751500000 = 2025-07-02 23:46 UTC (civil-from-days exact).
        assert_eq!(run.started, "2025-07-02 23:46");
    }

    #[test]
    fn parse_loop_record_tolerates_old_alias_and_garbage() {
        // Older records used `total_tokens_used`.
        let old = LOOP_RECORD.replace("total_tool_calls", "total_tokens_used");
        assert_eq!(parse_loop_record(&old).unwrap().total_tool_calls, 17);
        // Truncated `.tmp` survivor must not panic the list.
        assert!(parse_loop_record("{\"loop_id\": \"x\"").is_none());
        assert!(parse_loop_record("null").is_none());
    }

    #[test]
    fn load_loop_history_sorts_newest_first_and_skips_broken() {
        let dir = tempfile::tempdir().unwrap();
        let loops = dir.path().join("loops");
        std::fs::create_dir_all(&loops).unwrap();
        let older = LOOP_RECORD
            .replace("lp-20260703-abc123", "lp-older")
            .replace("\"ts_start\": 1751500000", "\"ts_start\": 1751400000");
        std::fs::write(loops.join("a.json"), older).unwrap();
        std::fs::write(loops.join("b.json"), LOOP_RECORD).unwrap();
        std::fs::write(loops.join("broken.json"), "{oops").unwrap();
        let runs = load_loop_history(dir.path(), 20);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].id, "lp-20260703-abc123");
        assert_eq!(runs[1].id, "lp-older");
        // Limit applies after the sort.
        assert_eq!(load_loop_history(dir.path(), 1).len(), 1);
        // Missing dir → empty, not an error.
        assert!(load_loop_history(&dir.path().join("nope"), 5).is_empty());
    }

    #[test]
    fn parse_loop_budget_reads_keys_with_engine_defaults() {
        assert_eq!(
            parse_loop_budget("loop:\n  max_rounds: 5\n  tool_call_budget: 40\n"),
            (5, 40)
        );
        assert_eq!(parse_loop_budget("loop:\n  enabled: true\n"), (3, 0));
        assert_eq!(parse_loop_budget("not yaml: ["), (3, 0));
        assert_eq!(parse_loop_budget(""), (3, 0));
    }

    // ── GOLD-ADAPT-ODY-01 — session history loader ─────────────────────
    #[test]
    fn load_session_history_prefers_display_name_and_sorts_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let hs = dir.path().join("hindsight");
        std::fs::create_dir_all(&hs).unwrap();
        std::fs::write(
            hs.join("s-old.json"),
            r#"{"session_id":"s-old","ended_at_unix":1751400000,
                "one_line_summary":"12 turns over 30 min on rust, wal",
                "display_name":null}"#,
        )
        .unwrap();
        std::fs::write(
            hs.join("s-new.json"),
            r#"{"session_id":"s-new","ended_at_unix":1751500000,
                "one_line_summary":"3 turns over 5 min on gui",
                "display_name":"GUI polish session"}"#,
        )
        .unwrap();
        std::fs::write(hs.join("torn.json"), "{oops").unwrap();
        let rows = load_session_history(dir.path(), 20);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "s-new");
        assert_eq!(rows[0].label, "GUI polish session");
        assert_eq!(rows[1].label, "12 turns over 30 min on rust, wal");
        assert!(rows[0].meta.starts_with("2025-07-02"), "{}", rows[0].meta);
        assert_eq!(load_session_history(dir.path(), 1).len(), 1);
        assert!(load_session_history(&dir.path().join("none"), 5).is_empty());
    }

    #[test]
    fn session_label_falls_back_summary_then_id() {
        let c = |dn: Option<&str>, s: &str| HindsightCardMini {
            session_id: "sid".into(),
            ended_at_unix: 0,
            one_line_summary: s.into(),
            display_name: dn.map(Into::into),
        };
        assert_eq!(c(Some("Title"), "sum").label(), "Title");
        assert_eq!(c(Some("  "), "sum").label(), "sum");
        assert_eq!(c(None, "").label(), "sid");
    }

    // ── GOLD-ADAPT-ODY-02/05 — metrics chip formatting ─────────────────
    #[test]
    fn format_stream_metrics_full_stats() {
        let (chip, detail) =
            format_stream_metrics(12_400, 200_000, 12_000, 400, 10_000).unwrap();
        assert_eq!(chip, "ctx 6% · 40 tok/s");
        assert!(detail.contains("context: 12.4k / 200.0k tokens (6%)"), "{detail}");
        assert!(detail.contains("in: 12.0k · out: 400"), "{detail}");
        assert!(detail.contains("wall: 10.0s"), "{detail}");
    }

    #[test]
    fn format_stream_metrics_no_data_is_none_and_partial_degrades() {
        assert!(format_stream_metrics(0, 0, 0, 0, 0).is_none());
        // No limit (cap 0) → no ctx part, still a chip.
        let (chip, _) = format_stream_metrics(500, 0, 400, 100, 2_000).unwrap();
        assert_eq!(chip, "50 tok/s");
        // No timing → token count fallback.
        let (chip, _) = format_stream_metrics(500, 0, 400, 100, 0).unwrap();
        assert_eq!(chip, "500 tok");
    }

    // ── GOLD-ADAPT-AOS-03 — project context round-trip ─────────────────
    #[test]
    fn project_context_roundtrip_and_missing_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_project_context(dir.path()), ProjectContext::default());
        let ctx = ProjectContext {
            building: "AI companion".into(),
            domain: "security research".into(),
            stack: "Rust + Slint".into(),
        };
        assert!(write_project_context(dir.path(), &ctx));
        assert_eq!(read_project_context(dir.path()), ctx);
        // Corrupt file degrades to default, never panics.
        std::fs::write(dir.path().join(".project-context"), "{oops").unwrap();
        assert_eq!(read_project_context(dir.path()), ProjectContext::default());
    }

    // ── GOLD-ADAPT-AOS-06 — spec description ───────────────────────────
    #[test]
    fn compose_spec_description_shapes() {
        assert_eq!(compose_spec_description("", "  "), None);
        assert_eq!(
            compose_spec_description("fix auth", "").as_deref(),
            Some("Goal: fix auth")
        );
        assert_eq!(
            compose_spec_description("", "tests green").as_deref(),
            Some("Done when: tests green")
        );
        assert_eq!(
            compose_spec_description("fix auth", "tests green").as_deref(),
            Some("Goal: fix auth\n\nDone when: tests green")
        );
    }

    // ── GOLD-ADAPT-GUI-05 — ticker frame math ──────────────────────────
    #[test]
    fn ticker_frame_types_then_holds_then_advances() {
        let first = TICKER_MESSAGES[0];
        let len = first.chars().count() as u64;
        // Mid-typing: a strict prefix by char count.
        let mid = ticker_frame(len / 2);
        assert!(first.starts_with(mid));
        assert_eq!(mid.chars().count(), (len / 2) as usize);
        // Fully typed + held.
        assert_eq!(ticker_frame(len), first);
        assert_eq!(ticker_frame(len + 10), first);
        // After the hold the SECOND message starts typing.
        let second_start = ticker_frame(len + 50);
        assert!(TICKER_MESSAGES[1].starts_with(second_start));
        // Never panics across a full wrap (non-ASCII "·" boundaries).
        let total: u64 = TICKER_MESSAGES
            .iter()
            .map(|m| m.chars().count() as u64 + 50)
            .sum();
        for t in 0..(total * 2) {
            let _ = ticker_frame(t);
        }
    }

    // ── GAP-04 format_recall_output ───────────────────────────────────────
    #[test]
    fn format_recall_output_returns_stdout_when_no_stderr() {
        let out = format_recall_output("episode 1\nepisode 2", "", "topic");
        assert_eq!(out, "episode 1\nepisode 2");
    }

    #[test]
    fn format_recall_output_appends_stderr_when_present() {
        let out = format_recall_output("result line", "  warn: tier miss  ", "q");
        assert_eq!(out, "result line\nwarn: tier miss");
    }

    #[test]
    fn format_recall_output_uses_sentinel_when_both_empty() {
        let out = format_recall_output("", "", "my query");
        assert_eq!(out, "No results for \"my query\".");
    }

    #[test]
    fn format_recall_output_uses_sentinel_when_only_whitespace() {
        let out = format_recall_output("  \n  ", "   ", "blank");
        assert_eq!(out, "No results for \"blank\".");
    }

    #[test]
    fn format_recall_output_stderr_only_shows_without_leading_newline() {
        // stdout empty → no leading \n before stderr content
        let out = format_recall_output("", "daemon not running", "x");
        assert_eq!(out, "daemon not running");
    }

    #[test]
    fn format_recall_output_trims_trailing_whitespace_from_result() {
        let out = format_recall_output("found it  \n\n", "", "q");
        assert_eq!(out, "found it");
    }

    // ── Wave-2 activity helpers ──────────────────────────────────────────
    fn make_row(id: i32, kind: &str, active: bool) -> ActivityTuple {
        (id, "12:00".to_string(), kind.to_string(), "T".to_string(), "D".to_string(), active)
    }

    #[test]
    fn next_activity_id_monotonic_and_no_collision() {
        assert_eq!(next_activity_id(&[]), 1);
        let rows = vec![make_row(1, "plan", true), make_row(5, "loop", false)];
        assert_eq!(next_activity_id(&rows), 6);
    }

    #[test]
    fn cap_activity_keeps_newest_n_rows() {
        let rows = vec![make_row(3, "plan", true), make_row(2, "kanban", false), make_row(1, "loop", false)];
        let capped = cap_activity(rows.clone(), 2);
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0].0, 3);
        assert_eq!(capped[1].0, 2);
        // cap larger than vec → unchanged
        let full = cap_activity(rows, 10);
        assert_eq!(full.len(), 3);
    }

    #[test]
    fn settle_activity_marks_matching_kind_inactive() {
        let rows = vec![
            make_row(1, "plan", true),
            make_row(2, "kanban", true),
            make_row(3, "plan", true),
        ];
        let settled = settle_activity(rows, "plan");
        // plan rows → inactive
        assert!(!settled[0].5);
        assert!(!settled[2].5);
        // kanban row unchanged
        assert!(settled[1].5);
    }

    #[test]
    fn settle_activity_noop_on_unknown_kind() {
        let rows = vec![make_row(1, "plan", true)];
        let settled = settle_activity(rows, "skill");
        assert!(settled[0].5, "unmatched kind must stay active");
    }

    // ── Wave-1 toast helpers ─────────────────────────────────────────────
    type Toasts = Vec<(i32, String, String, String)>;

    fn make_toast(id: i32, kind: &str, title: &str, body: &str) -> (i32, String, String, String) {
        (id, kind.to_string(), title.to_string(), body.to_string())
    }

    #[test]
    fn prune_toast_removes_matching_id() {
        let toasts: Toasts = vec![
            make_toast(1, "info", "A", ""),
            make_toast(2, "success", "B", ""),
            make_toast(3, "warn", "C", ""),
        ];
        let result = prune_toast(toasts, 2);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|(id, _, _, _)| *id != 2));
    }

    #[test]
    fn prune_toast_noop_when_id_absent() {
        let toasts: Toasts = vec![make_toast(1, "info", "A", "")];
        let result = prune_toast(toasts.clone(), 99);
        assert_eq!(result, toasts);
    }

    #[test]
    fn prune_toast_empty_input_stays_empty() {
        let result = prune_toast(vec![], 1);
        assert!(result.is_empty());
    }

    #[test]
    fn next_toast_id_returns_one_on_empty() {
        let result = next_toast_id(&[]);
        assert_eq!(result, 1);
    }

    #[test]
    fn next_toast_id_increments_past_max() {
        let toasts = vec![make_toast(3, "info", "A", ""), make_toast(7, "warn", "B", "")];
        assert_eq!(next_toast_id(&toasts), 8);
    }

    #[test]
    fn next_toast_id_no_collision_single_item() {
        let toasts = vec![make_toast(1, "info", "X", "")];
        assert_eq!(next_toast_id(&toasts), 2);
    }

    // ── Overview parse helper tests ───────────────────────────────────────────

    #[test]
    fn parse_overview_status_full_payload() {
        let json = r#"{"operating_mode":"chat","autonomy":"standard","wal":{"bytes":1024},"tier_counts":{"hot":3,"warm":12},"channels":[{"status":"active"},{"status":"active"},{"status":"idle"}]}"#;
        let (mode, autonomy, ch, wal, tiers, state) = super::parse_overview_status(json);
        assert_eq!(mode, "chat");
        assert_eq!(autonomy, "standard");
        assert!(ch.contains("2/3"), "channel health: {ch}");
        assert_eq!(wal, "1024 B");
        assert!(tiers.contains("hot=3"), "tiers: {tiers}");
        assert_eq!(state, "live");
    }

    #[test]
    fn parse_overview_status_empty_yields_defaults() {
        let (mode, autonomy, ch, wal, tiers, state) = super::parse_overview_status("{}");
        assert!(mode.is_empty());
        assert!(autonomy.is_empty());
        assert!(ch.is_empty());
        assert!(wal.is_empty());
        assert!(tiers.is_empty());
        assert_eq!(state, "live"); // valid JSON → live
    }

    #[test]
    fn parse_overview_status_malformed_returns_error_state() {
        let (_, _, _, _, _, state) = super::parse_overview_status("unavailable — binary not found");
        assert_eq!(state, "error");
    }

    #[test]
    fn parse_meter_formats_large_counts() {
        let json = r#"{"input_tokens_total":1500000,"output_tokens_total":250000,"provider_responses":42,"cost_usd":0.1234}"#;
        let (tin, tout, resp, cost, fraction) = super::parse_meter(json);
        assert_eq!(tin, "1.5M");
        assert_eq!(tout, "250.0K");
        assert_eq!(resp, "42");
        assert_eq!(cost, "$0.1234");
        assert_eq!(fraction, 0.0); // no daily cap → 0
    }

    #[test]
    fn parse_meter_fraction_computed_when_cap_present() {
        let json = r#"{"input_tokens_total":500,"output_tokens_total":100,"provider_responses":1,"daily_cap_tokens":1000}"#;
        let (_, _, _, _, fraction) = super::parse_meter(json);
        assert!((fraction - 0.5).abs() < 0.01, "fraction={fraction}");
    }

    #[test]
    fn parse_hemispheres_three_roles() {
        let json = r#"[{"role":"left","provider":"claude_cli","model":"claude-opus-4-7","status":"active"},{"role":"right","provider":"gemini","model":"gemini-2-5","status":"active"},{"role":"cerebellum","provider":"codex","model":"o3","status":"idle"}]"#;
        let hemis = super::parse_overview_hemispheres(json);
        assert_eq!(hemis.len(), 3);
        assert_eq!(hemis[0].0, "left");
        assert!(hemis[0].3, "left should be ok");
        assert_eq!(hemis[2].0, "cerebellum");
        assert!(!hemis[2].3, "idle should be not-ok");
    }

    #[test]
    fn parse_hemispheres_empty_json() {
        assert!(super::parse_overview_hemispheres("[]").is_empty());
        assert!(super::parse_overview_hemispheres("not json").is_empty());
    }

    #[test]
    fn parse_agents_counts_and_names() {
        let json = r#"[{"name":"archon"},{"name":"worker-1"},{"name":"worker-2"}]"#;
        let (count, names) = super::parse_agents(json);
        assert_eq!(count, "3");
        assert_eq!(names, vec!["archon", "worker-1", "worker-2"]);
    }

    #[test]
    fn parse_agents_empty_array() {
        let (count, names) = super::parse_agents("[]");
        assert!(count.is_empty());
        assert!(names.is_empty());
    }

    #[test]
    fn parse_skills_counts_active_only() {
        let json = r#"[{"name":"ponytail","enabled":true},{"name":"caveman","enabled":true},{"name":"stale","enabled":false}]"#;
        let (count, names) = super::parse_overview_skills(json);
        assert_eq!(count, "2");
        assert!(names.contains(&"ponytail".to_string()));
        assert!(!names.contains(&"stale".to_string()));
    }

    #[test]
    fn parse_calendar_next_three_events() {
        let json = r#"{"events":[{"start":"2026-07-04T09:00:00Z","summary":"Standup"},{"start":"2026-07-04T14:30:00Z","summary":"Review"},{"start":"2026-07-04T17:00:00Z","summary":"Ship"}]}"#;
        let (configured, evs) = super::parse_calendar_next(json, 3);
        assert!(configured);
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].0, "09:00");
        assert_eq!(evs[0].1, "Standup");
    }

    #[test]
    fn parse_calendar_next_not_configured_on_error_key() {
        let json = r#"{"error":"CalDAV not configured"}"#;
        let (configured, evs) = super::parse_calendar_next(json, 3);
        assert!(!configured);
        assert!(evs.is_empty());
    }

    #[test]
    fn parse_calendar_next_not_configured_on_non_json() {
        let (configured, _) = super::parse_calendar_next("unavailable", 3);
        assert!(!configured);
    }

    #[test]
    fn parse_consent_entries_and_smart_approve() {
        let json = r#"{"consents":[{"provider":"claude_cli","granted":true},{"provider":"gemini","granted":false}],"smart_approve":"standard"}"#;
        let (entries, sa) = super::parse_consent(json);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].1, "claude_cli should be granted");
        assert!(!entries[1].1, "gemini should be pending");
        assert_eq!(sa, "standard");
    }

    #[test]
    fn parse_consent_empty() {
        let (entries, sa) = super::parse_consent("{}");
        assert!(entries.is_empty());
        assert!(sa.is_empty());
    }

    // ── Wave 4a: parse_n8n_status ─────────────────────────────────────────────

    #[test]
    fn parse_n8n_status_happy_path() {
        let json = r#"{"n8n_installed":true,"webhook_base":"http://localhost:5678","n8n_path":"/usr/bin/n8n","bundled_workflows":[]}"#;
        let (installed, webhook, path) = super::parse_n8n_status(json);
        assert!(installed);
        assert_eq!(webhook, "http://localhost:5678");
        assert_eq!(path, "/usr/bin/n8n");
    }

    #[test]
    fn parse_n8n_status_not_installed_empty_fields() {
        let (installed, webhook, path) = super::parse_n8n_status(r#"{"n8n_installed":false}"#);
        assert!(!installed);
        assert!(webhook.is_empty());
        assert!(path.is_empty());
    }

    #[test]
    fn parse_n8n_status_malformed_returns_defaults() {
        let (installed, _, _) = super::parse_n8n_status("not json");
        assert!(!installed);
    }

    // ── Wave 4a: parse_n8n_workflows ──────────────────────────────────────────

    #[test]
    fn parse_n8n_workflows_wrapped_array() {
        let json = r#"{"workflows":[{"name":"daily-digest","description":"Sends a summary"},{"name":"alert-hook","description":""}]}"#;
        let wfs = super::parse_n8n_workflows(json);
        assert_eq!(wfs.len(), 2);
        assert_eq!(wfs[0].0, "daily-digest");
        assert_eq!(wfs[0].1, "Sends a summary");
        assert_eq!(wfs[1].1, "");
    }

    #[test]
    fn parse_n8n_workflows_empty_and_malformed() {
        assert!(super::parse_n8n_workflows("{}").is_empty());
        assert!(super::parse_n8n_workflows("not json").is_empty());
        assert!(super::parse_n8n_workflows(r#"{"workflows":[]}"#).is_empty());
    }

    // ── Wave 4a: parse_babel_status ───────────────────────────────────────────

    #[test]
    fn parse_babel_status_happy_path() {
        let json = r#"{"enabled":true,"threshold":0.42,"epsilon_calibrated":"calibrated","federate":false,"total_windows":120,"collapse_flagged":3,"windows_by_granularity":[{"window_secs":300,"count":60,"last_ts_end":"2026-07-04T10:00:00Z"}]}"#;
        let (enabled, threshold, epsilon, federate, total, collapse, gran) =
            super::parse_babel_status(json);
        assert!(enabled);
        assert!(!threshold.is_empty());
        assert_eq!(epsilon, "calibrated");
        assert!(!federate);
        assert_eq!(total, 120);
        assert_eq!(collapse, 3);
        assert_eq!(gran.len(), 1);
        assert_eq!(gran[0].0, 300);
        assert_eq!(gran[0].1, 60);
    }

    #[test]
    fn parse_babel_status_malformed_returns_defaults() {
        let (enabled, _, _, _, total, _, gran) = super::parse_babel_status("not json");
        assert!(!enabled);
        assert_eq!(total, 0);
        assert!(gran.is_empty());
    }

    // ── Wave 4a: parse_babel_windows ──────────────────────────────────────────

    #[test]
    fn parse_babel_windows_happy_path() {
        let json = r#"{"windows":[{"id":"w1","window_secs":300,"ts_start":"T1","ts_end":"T2","b_log":0.5,"b_mult":1.2,"b_bottleneck":0.8,"collapse_kind":"5m"},{"id":"w2","window_secs":1800,"ts_start":"T3","ts_end":"T4","b_log":0.1,"b_mult":1.0,"b_bottleneck":0.2,"collapse_kind":""}]}"#;
        let rows = super::parse_babel_windows(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "w1");
        assert!((rows[0].6 - 0.8).abs() < 0.01);
        assert_eq!(rows[0].7, "5m");
        assert_eq!(rows[1].7, "");
    }

    #[test]
    fn parse_babel_windows_bottleneck_clamped() {
        let json = r#"{"windows":[{"id":"x","window_secs":60,"ts_start":"","ts_end":"","b_log":0.0,"b_mult":1.0,"b_bottleneck":1.5,"collapse_kind":""}]}"#;
        let rows = super::parse_babel_windows(json);
        assert!((rows[0].6 - 1.0).abs() < 0.01, "bottleneck must clamp to 1.0");
    }

    #[test]
    fn parse_babel_windows_empty_and_malformed() {
        assert!(super::parse_babel_windows("not json").is_empty());
        assert!(super::parse_babel_windows(r#"{"windows":[]}"#).is_empty());
    }

    // ── Wave 4a: parse_calendar_events ────────────────────────────────────────

    #[test]
    fn parse_calendar_events_happy_path() {
        let json = r#"{"events":[{"start":"2026-07-04T09:00:00Z","summary":"Standup","location":"Zoom"},{"start":"2026-07-04T14:00:00Z","summary":"Review"}]}"#;
        let (configured, evs) = super::parse_calendar_events(json);
        assert!(configured);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].0, "2026-07-04 09:00");
        assert_eq!(evs[0].1, "Standup");
        assert_eq!(evs[0].2, "Zoom");
        assert_eq!(evs[1].2, "");
    }

    #[test]
    fn parse_calendar_events_not_configured_on_error_key() {
        let json = r#"{"error":"CalDAV not configured"}"#;
        let (configured, evs) = super::parse_calendar_events(json);
        assert!(!configured);
        assert!(evs.is_empty());
    }

    #[test]
    fn parse_calendar_events_not_configured_on_non_json() {
        let (configured, _) = super::parse_calendar_events("unavailable — binary not found");
        assert!(!configured);
    }

    // ── Wave 4a: parse_selfimprove_status ─────────────────────────────────────

    #[test]
    fn parse_selfimprove_status_happy_path() {
        let json = r#"{"enabled":true,"auto":false,"skillopt_installed":true,"last":"2026-07-04T08:00:00Z","autonomy":"elevated"}"#;
        let (enabled, auto, skillopt, last, autonomy) = super::parse_selfimprove_status(json);
        assert!(enabled);
        assert!(!auto);
        assert!(skillopt);
        assert_eq!(last, "2026-07-04T08:00:00Z");
        assert_eq!(autonomy, "elevated");
    }

    #[test]
    fn parse_selfimprove_status_malformed_returns_defaults() {
        let (enabled, auto, skillopt, last, autonomy) = super::parse_selfimprove_status("{}");
        assert!(!enabled);
        assert!(!auto);
        assert!(!skillopt);
        assert!(last.is_empty());
        assert!(autonomy.is_empty());
    }

    // ── Wave 4a: parse_selfimprove_proposals ──────────────────────────────────

    #[test]
    fn parse_selfimprove_proposals_happy_path() {
        let json = r#"{"proposals":[{"id":"p1","title":"Add retry logic","description":"Retries failed ops"},{"id":"p2","title":"Cache headers","description":""}]}"#;
        let props = super::parse_selfimprove_proposals(json);
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].0, "p1");
        assert_eq!(props[0].1, "Add retry logic");
        assert_eq!(props[1].2, "");
    }

    #[test]
    fn parse_selfimprove_proposals_empty_and_malformed() {
        assert!(super::parse_selfimprove_proposals("not json").is_empty());
        assert!(super::parse_selfimprove_proposals(r#"{"proposals":[]}"#).is_empty());
    }

    // ── Wave 4a: parse_selfimprove_log ────────────────────────────────────────

    #[test]
    fn parse_selfimprove_log_happy_path_capped_10() {
        // Build 12 entries; only 10 should survive.
        let entries: Vec<String> = (0..12)
            .map(|i| format!(r#"{{"id":"e{i}","title":"item {i}","status":"accepted","ts":"2026-07-0{n}T00:00:00Z"}}"#, n = i % 9 + 1))
            .collect();
        let json = format!(r#"{{"log":[{}]}}"#, entries.join(","));
        let rows = super::parse_selfimprove_log(&json);
        assert_eq!(rows.len(), 10, "log must be capped at 10");
        assert_eq!(rows[0].2, "accepted");
    }

    #[test]
    fn parse_selfimprove_log_malformed_returns_empty() {
        assert!(super::parse_selfimprove_log("not json").is_empty());
        assert!(super::parse_selfimprove_log("{}").is_empty());
    }
}
