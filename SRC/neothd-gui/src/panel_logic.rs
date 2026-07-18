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

use zeroize::Zeroizing;

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

/// Parsed `neoth omi status --output json`. Existing secrets are represented
/// only by presence booleans; the GUI never reads secret values back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmiSnapshot {
    pub enabled: bool,
    pub mode: String,
    pub endpoint: String,
    pub listen_addr: String,
    pub configuration_valid: bool,
    pub configuration_error: String,
    pub developer_credential_present: bool,
    pub native_credential_present: bool,
    pub runtime_state: String,
    pub runtime_detail: String,
    pub pending_audits: u64,
    pub retention_days: u64,
    pub retain_transcripts: bool,
    pub audio_enabled: bool,
    pub visual_enabled: bool,
    pub video_enabled: bool,
    pub allow_cloud_api: bool,
    pub allow_cloud_summary: bool,
    pub create_actions: bool,
    pub seed_groundtruth: bool,
    pub summary_enabled: bool,
}

impl Default for OmiSnapshot {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "developer_api".to_string(),
            endpoint: "http://127.0.0.1:8002".to_string(),
            listen_addr: "127.0.0.1:8003".to_string(),
            configuration_valid: false,
            configuration_error: String::new(),
            developer_credential_present: false,
            native_credential_present: false,
            runtime_state: "unknown".to_string(),
            runtime_detail: String::new(),
            pending_audits: 0,
            retention_days: 30,
            retain_transcripts: false,
            audio_enabled: false,
            visual_enabled: false,
            video_enabled: false,
            allow_cloud_api: false,
            allow_cloud_summary: false,
            create_actions: true,
            seed_groundtruth: true,
            summary_enabled: true,
        }
    }
}

pub fn parse_omi_status(json: &str) -> OmiSnapshot {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return OmiSnapshot::default();
    };
    let defaults = OmiSnapshot::default();
    let string = |key: &str, fallback: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or(fallback)
            .to_string()
    };
    let boolean = |key: &str, fallback: bool| {
        value
            .get(key)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(fallback)
    };
    OmiSnapshot {
        enabled: boolean("enabled", defaults.enabled),
        mode: string("mode", &defaults.mode),
        endpoint: string("endpoint", &defaults.endpoint),
        listen_addr: string("listen_addr", &defaults.listen_addr),
        configuration_valid: boolean("configuration_valid", defaults.configuration_valid),
        configuration_error: string("configuration_error", &defaults.configuration_error),
        developer_credential_present: boolean(
            "developer_api_credential_present",
            defaults.developer_credential_present,
        ),
        native_credential_present: boolean(
            "native_ingest_credential_present",
            defaults.native_credential_present,
        ),
        runtime_state: string("runtime_state", &defaults.runtime_state),
        runtime_detail: string("runtime_detail", &defaults.runtime_detail),
        pending_audits: value
            .get("pending_audits")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(defaults.pending_audits),
        retention_days: value
            .get("retention_days")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(defaults.retention_days),
        retain_transcripts: boolean("retain_transcripts", defaults.retain_transcripts),
        audio_enabled: boolean("audio_enabled", defaults.audio_enabled),
        visual_enabled: boolean("visual_enabled", defaults.visual_enabled),
        video_enabled: boolean("video_enabled", defaults.video_enabled),
        allow_cloud_api: boolean("allow_cloud_api", defaults.allow_cloud_api),
        allow_cloud_summary: boolean("allow_cloud_summary", defaults.allow_cloud_summary),
        create_actions: boolean("create_actions", defaults.create_actions),
        seed_groundtruth: boolean("seed_groundtruth", defaults.seed_groundtruth),
        summary_enabled: boolean("summary_enabled", defaults.summary_enabled),
    }
}

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
    // ── GUI-HARDWARE-RESOURCES-01 — runtime load metrics ─────────────────
    /// CPU aggregate utilization %. `None` when absent from JSON (CPU-only
    /// host, old firmware, or sysinfo failure).
    pub cpu_load_pct: Option<f64>,
    /// GPU compute utilization %. `None` when `nvidia-smi` is absent/failed.
    pub gpu_util_pct: Option<f64>,
    /// GPU core temperature in °C. `None` when `nvidia-smi` is absent/failed.
    pub gpu_temp_c: Option<f64>,
    /// GPU power draw in W. `None` when `nvidia-smi` is absent/failed.
    pub gpu_power_w: Option<f64>,
    /// Pre-formatted one-line load readout consumed by the Slint label, e.g.
    /// `"CPU 23% · GPU 41% · 62°C · 118W"`. Empty when all four are `None`.
    pub load_readout: String,
}

/// Bytes → whole GiB (rounded) as a display string.
fn gib(bytes: u64) -> u64 {
    bytes / (1024 * 1024 * 1024)
}

// Type alias to avoid tuple-soup signatures in build_load_readout.
type LoadMetric = Option<f64>;

/// Build the compact one-line load readout for the hardware panel, e.g.
/// `"CPU 23% · GPU 41% · 62°C · 118W"`. Absent values render as `"—"`.
/// Returns an empty string when all four metrics are `None`.
fn build_load_readout(
    cpu: LoadMetric,
    gpu_util: LoadMetric,
    temp: LoadMetric,
    power: LoadMetric,
) -> String {
    if cpu.is_none() && gpu_util.is_none() && temp.is_none() && power.is_none() {
        return String::new();
    }
    let fmt_cpu = cpu.map_or_else(|| "—".to_string(), |v| format!("{:.0}%", v));
    let fmt_gpu = gpu_util.map_or_else(|| "—".to_string(), |v| format!("{:.0}%", v));
    let fmt_temp = temp.map_or_else(|| "—".to_string(), |v| format!("{:.0}°C", v));
    let fmt_power = power.map_or_else(|| "—".to_string(), |v| format!("{:.0}W", v));
    format!("CPU {fmt_cpu} · GPU {fmt_gpu} · {fmt_temp} · {fmt_power}")
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

    // GUI-HARDWARE-RESOURCES-01 — runtime load metrics. All are optional;
    // absent fields (old JSON, CPU-only host) silently produce `None`.
    let f = |p: &str| v.pointer(p).and_then(|x| x.as_f64());
    let cpu_load_pct = f("/cpu_load_pct");
    let gpu_util_pct = f("/gpu_load/util_pct");
    let gpu_temp_c = f("/gpu_load/temp_c");
    let gpu_power_w = f("/gpu_load/power_w");
    let load_readout = build_load_readout(cpu_load_pct, gpu_util_pct, gpu_temp_c, gpu_power_w);

    HardwareSnapshot {
        cpu,
        memory,
        accelerator,
        vram,
        vram_fraction,
        disk,
        models,
        cpu_load_pct,
        gpu_util_pct,
        gpu_temp_c,
        gpu_power_w,
        load_readout,
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
    pub activation: String, // "active" | "pending" | "disabled" | "reconsent_required"
    pub requested_permission: String,
    /// True when the plugin's manifest declares a `ui_surface` object.
    pub has_ui_surface: bool,
    /// The `ui_surface.title` value, or "" when absent.
    pub ui_title: String,
}

/// Parse `neoth plugin list --output json` (array of
/// `{id,name,activation,requested_permission,ui_surface?}`).
/// PURE + robust (malformed/non-array → empty; id-less entries skipped).
/// `ui_surface` is optional — absent or non-object → has_ui_surface=false, ui_title="".
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
            let requested_permission = p
                .get("requested_permission")
                .and_then(|permission| permission.as_str())
                .unwrap_or("none")
                .to_string();
            // ui_surface is optional; tolerant — missing or wrong type → false / "".
            let (has_ui_surface, ui_title) = match p.get("ui_surface").and_then(|s| s.as_object()) {
                Some(surf) => {
                    let title = surf
                        .get("title")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();
                    (true, title)
                }
                None => (false, String::new()),
            };
            Some(PluginSummary {
                id,
                name,
                activation,
                requested_permission,
                has_ui_surface,
                ui_title,
            })
        })
        .collect()
}

/// One WAL-feed event row from `neoth plugin events <id> --output json --last 30`.
/// Fields: event kind (opaque string), payload byte count, unix timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PluginEventRow {
    pub kind: String,
    pub payload_bytes: u64,
    pub ts_unix: u64,
}

/// Parse `neoth plugin events <id> --output json --last 30`.
/// Shape: `{"id":"...","events":[{"kind":"...","payload_bytes":N,"ts_unix":T}]}`.
/// PURE + tolerant: not-found / no-events / malformed → empty Vec.
pub fn parse_plugin_events(json: &str) -> Vec<PluginEventRow> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let events = match v.get("events").and_then(|e| e.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };
    events
        .iter()
        .filter_map(|e| {
            // kind must be present; payload_bytes + ts_unix default to 0 if absent/wrong type.
            let kind = e.get("kind")?.as_str()?.to_string();
            let payload_bytes = e.get("payload_bytes").and_then(|b| b.as_u64()).unwrap_or(0);
            let ts_unix = e.get("ts_unix").and_then(|t| t.as_u64()).unwrap_or(0);
            Some(PluginEventRow {
                kind,
                payload_bytes,
                ts_unix,
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

// ── GU-01 / GOLD-R3-04 channels panel (canonical CLI probe contract) ─────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum GuiSetupRequirement {
    Required,
    Optional,
    OneOf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuiSetupField {
    key: &'static str,
    requirement: GuiSetupRequirement,
    one_of_group: Option<&'static str>,
}

const fn gui_required(key: &'static str) -> GuiSetupField {
    GuiSetupField {
        key,
        requirement: GuiSetupRequirement::Required,
        one_of_group: None,
    }
}

const fn gui_optional(key: &'static str) -> GuiSetupField {
    GuiSetupField {
        key,
        requirement: GuiSetupRequirement::Optional,
        one_of_group: None,
    }
}

const fn gui_one_of(key: &'static str, group: &'static str) -> GuiSetupField {
    GuiSetupField {
        key,
        requirement: GuiSetupRequirement::OneOf,
        one_of_group: Some(group),
    }
}

const GUI_TELEGRAM_SETUP: &[GuiSetupField] = &[
    gui_required("telegram_token"),
    gui_required("telegram_user_id"),
];
const GUI_SLACK_SETUP: &[GuiSetupField] = &[
    gui_required("slack_bot_token"),
    gui_required("slack_app_token"),
    gui_required("slack_allowed_user_id"),
];
const GUI_WHATSAPP_BUSINESS_SETUP: &[GuiSetupField] = &[
    gui_required("whatsapp_token"),
    gui_required("whatsapp_phone_id"),
    gui_required("whatsapp_verify_token"),
    gui_required("whatsapp_app_secret"),
    gui_required("whatsapp_allowed_sender"),
];
const GUI_WHATSAPP_BAILEYS_SETUP: &[GuiSetupField] = &[
    gui_required("whatsapp_baileys_url"),
    gui_required("whatsapp_baileys_token"),
    gui_required("whatsapp_baileys_allowed_senders"),
    gui_optional("whatsapp_baileys_allowed_groups"),
];
const GUI_KEET_SETUP: &[GuiSetupField] = &[
    gui_required("keet_bridge_url"),
    gui_required("keet_bridge_bearer_token"),
    gui_required("keet_topic"),
    gui_required("keet_allowed_senders"),
];
const GUI_DISCORD_SETUP: &[GuiSetupField] = &[
    gui_required("discord_bot_token"),
    gui_required("discord_allowed_user_id"),
];
const GUI_SIGNAL_SETUP: &[GuiSetupField] = &[
    gui_required("signal_cli_url"),
    gui_required("signal_phone_number"),
    gui_required("signal_allowed_sender"),
];
const GUI_LINE_SETUP: &[GuiSetupField] = &[
    gui_required("line_channel_access_token"),
    gui_optional("line_channel_secret"),
    gui_required("line_allowed_sender"),
];
const GUI_IRC_SETUP: &[GuiSetupField] = &[
    gui_required("irc_server"),
    gui_required("irc_nick"),
    gui_optional("irc_password"),
    gui_optional("irc_channels"),
    gui_required("irc_allowed_account"),
];
const GUI_BLUEBUBBLES_SETUP: &[GuiSetupField] = &[
    gui_required("bluebubbles_url"),
    gui_required("bluebubbles_password"),
    gui_required("imessage_allowed_sender"),
    gui_optional("bluebubbles_chat_guid"),
];
const GUI_MATTERMOST_SETUP: &[GuiSetupField] = &[
    gui_required("mattermost_url"),
    gui_required("mattermost_token"),
    gui_required("mattermost_allowed_user_id"),
];
const GUI_GCHAT_SETUP: &[GuiSetupField] = &[
    gui_required("gchat_service_account_json"),
    gui_required("gchat_subscription"),
    gui_required("gchat_allowed_sender"),
];
const GUI_MATRIX_SETUP: &[GuiSetupField] = &[
    gui_required("matrix_homeserver"),
    gui_required("matrix_user_id"),
    gui_one_of("matrix_access_token", "matrix_auth"),
    gui_one_of("matrix_password", "matrix_auth"),
    gui_one_of("matrix_allowed_user_id", "matrix_inbound_policy"),
    gui_one_of("matrix_allowed_room_ids", "matrix_inbound_policy"),
    gui_optional("matrix_require_encryption"),
];
const GUI_TWITCH_SETUP: &[GuiSetupField] = &[
    gui_required("twitch_username"),
    gui_required("twitch_oauth_token"),
    gui_required("twitch_channels"),
];
const GUI_NOSTR_SETUP: &[GuiSetupField] = &[
    gui_required("nostr_secret_key"),
    gui_required("nostr_relays"),
    gui_required("nostr_allowed_pubkey"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuiChannelForm {
    Telegram,
    Slack,
    WhatsAppBusiness,
    WhatsAppBaileys,
    Keet,
    Discord,
    Signal,
    Line,
    Irc,
    BlueBubbles,
    Mattermost,
    GoogleChat,
    Matrix,
    Twitch,
    Nostr,
}

#[derive(Debug, Clone, Copy)]
struct GuiChannelContract {
    form: GuiChannelForm,
    setup_fields: &'static [GuiSetupField],
}

/// The GUI has behavior-specific form/flag wiring, but not an independent
/// inventory. The daemon's serialized registry is iterated at runtime and every
/// descriptor must resolve here with an identical setup schema or the panel
/// fails closed instead of presenting a broken Add action.
fn gui_channel_contract(channel_id: &str) -> Option<GuiChannelContract> {
    let (form, setup_fields) = match channel_id {
        "telegram" => (GuiChannelForm::Telegram, GUI_TELEGRAM_SETUP),
        "slack" => (GuiChannelForm::Slack, GUI_SLACK_SETUP),
        "whatsapp_business" => (
            GuiChannelForm::WhatsAppBusiness,
            GUI_WHATSAPP_BUSINESS_SETUP,
        ),
        "whatsapp_baileys" => (GuiChannelForm::WhatsAppBaileys, GUI_WHATSAPP_BAILEYS_SETUP),
        "keet" => (GuiChannelForm::Keet, GUI_KEET_SETUP),
        "discord" => (GuiChannelForm::Discord, GUI_DISCORD_SETUP),
        "signal" => (GuiChannelForm::Signal, GUI_SIGNAL_SETUP),
        "line" => (GuiChannelForm::Line, GUI_LINE_SETUP),
        "irc" => (GuiChannelForm::Irc, GUI_IRC_SETUP),
        "imessage_bluebubbles" => (GuiChannelForm::BlueBubbles, GUI_BLUEBUBBLES_SETUP),
        "mattermost" => (GuiChannelForm::Mattermost, GUI_MATTERMOST_SETUP),
        "gchat" => (GuiChannelForm::GoogleChat, GUI_GCHAT_SETUP),
        "matrix" => (GuiChannelForm::Matrix, GUI_MATRIX_SETUP),
        "twitch" => (GuiChannelForm::Twitch, GUI_TWITCH_SETUP),
        "nostr" => (GuiChannelForm::Nostr, GUI_NOSTR_SETUP),
        _ => return None,
    };
    Some(GuiChannelContract { form, setup_fields })
}

fn zeroize_json_strings(value: &mut serde_json::Value) {
    use zeroize::Zeroize as _;

    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_strings(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_strings(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// Build the strict private-stdin credential envelope for one
/// registry-projected GUI form. This stays pure so every canonical registry ID
/// is regression-tested without ever translating secret values into argv.
pub fn build_channel_credential_request(
    channel_id: &str,
    fields: [&str; 6],
    flag: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let [f1, f2, f3, f4, _f5, _f6] = fields;
    let [n1, n2, n3, n4, n5, n6] = fields.map(str::trim);
    let secret_present = |value: &str| !value.trim().is_empty();
    let contract = gui_channel_contract(channel_id)
        .ok_or_else(|| format!("channel `{channel_id}` has no GUI setup binding"))?;

    let request_fields = match contract.form {
        GuiChannelForm::Telegram => {
            if !secret_present(f1) || n2.is_empty() {
                return Err("telegram needs: --token and --telegram-user-id".into());
            }
            let user_id = n2
                .parse::<u64>()
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| "telegram user ID must be a positive integer".to_string())?;
            serde_json::json!({
                "token": f1,
                "telegram_user_id": user_id,
            })
        }
        GuiChannelForm::Slack => {
            if !secret_present(f1) || !secret_present(f2) || n3.is_empty() {
                return Err("slack needs: --bot-token, --app-token, and --allowed-sender".into());
            }
            serde_json::json!({
                "bot_token": f1,
                "app_token": f2,
                "allowed_sender": n3,
            })
        }
        GuiChannelForm::WhatsAppBusiness => {
            if !secret_present(f1)
                || n2.is_empty()
                || !secret_present(f3)
                || !secret_present(f4)
                || n5.is_empty()
            {
                return Err(
                    "whatsapp_business needs: --token, --phone-id, --verify-token, --app-secret, and --allowed-sender"
                        .into(),
                );
            }
            serde_json::json!({
                "token": f1,
                "phone_id": n2,
                "verify_token": f3,
                "app_secret": f4,
                "allowed_sender": n5,
            })
        }
        GuiChannelForm::WhatsAppBaileys => {
            if n1.is_empty() || !secret_present(f2) || n3.is_empty() {
                return Err("whatsapp_baileys needs: --url, --token, and --allowed-sender".into());
            }
            serde_json::json!({
                "url": n1,
                "token": f2,
                "allowed_sender": n3,
                "allowed_rooms_csv": (!n4.is_empty()).then_some(n4),
            })
        }
        GuiChannelForm::Keet => {
            if n1.is_empty() || !secret_present(f2) || !secret_present(f3) || n4.is_empty() {
                return Err(
                    "keet needs: --url, --token, --server (topic), and --allowed-sender".into(),
                );
            }
            serde_json::json!({
                "url": n1,
                "token": f2,
                "server": f3,
                "allowed_sender": n4,
            })
        }
        GuiChannelForm::Discord => {
            if !secret_present(f1) || n2.is_empty() {
                return Err("discord needs: --token and --allowed-sender (numeric user ID)".into());
            }
            if !n2.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("Discord allowed sender id must be a numeric user snowflake".into());
            }
            let parsed = n2
                .parse::<u64>()
                .map_err(|_| "Discord allowed sender id exceeds the snowflake range")?;
            if parsed == 0 || parsed.to_string() != n2 {
                return Err(
                    "Discord allowed sender id must be a canonical positive user snowflake".into(),
                );
            }
            serde_json::json!({ "token": f1, "allowed_sender": n2 })
        }
        GuiChannelForm::Signal => {
            if n1.is_empty() || n2.is_empty() || n3.is_empty() {
                return Err("signal needs: --url, --phone, and --allowed-sender".into());
            }
            serde_json::json!({ "url": n1, "phone": n2, "allowed_sender": n3 })
        }
        GuiChannelForm::Line => {
            if !secret_present(f1) || n3.is_empty() {
                return Err("line needs: --token and --allowed-sender".into());
            }
            serde_json::json!({
                "token": f1,
                "password": secret_present(f2).then_some(f2),
                "allowed_sender": n3,
            })
        }
        GuiChannelForm::Irc => {
            if n1.is_empty() || n2.is_empty() || n5.is_empty() {
                return Err(
                    "irc needs: --server, --nick, and --allowed-sender (services account)".into(),
                );
            }
            serde_json::json!({
                "server": n1,
                "nick": n2,
                "password": secret_present(f3).then_some(f3),
                "channels_csv": (!n4.is_empty()).then_some(n4),
                "allowed_sender": n5,
            })
        }
        GuiChannelForm::BlueBubbles => {
            if n1.is_empty() || !secret_present(f2) || n3.is_empty() {
                return Err(
                    "imessage_bluebubbles needs: --url, --password, and --allowed-sender".into(),
                );
            }
            serde_json::json!({
                "url": n1,
                "password": f2,
                "allowed_sender": n3,
                "channels_csv": (!n4.is_empty()).then_some(n4),
            })
        }
        GuiChannelForm::Mattermost => {
            if n1.is_empty() || !secret_present(f2) || n3.is_empty() {
                return Err(
                    "mattermost needs: --url, --token, and --allowed-sender (user ID)".into(),
                );
            }
            serde_json::json!({ "url": n1, "token": f2, "allowed_sender": n3 })
        }
        GuiChannelForm::GoogleChat => {
            if n1.is_empty() || n2.is_empty() || n3.is_empty() {
                return Err(
                    "gchat needs: --url (service-account JSON path), --server (subscription), and --allowed-sender"
                        .into(),
                );
            }
            serde_json::json!({ "url": n1, "server": n2, "allowed_sender": n3 })
        }
        GuiChannelForm::Matrix => {
            if n1.is_empty()
                || n2.is_empty()
                || (!secret_present(f3) && !secret_present(f4))
                || (n5.is_empty() && n6.is_empty())
            {
                return Err("matrix needs: --url, --nick, either --token or --password, and at least one sender/room allowlist".into());
            }
            serde_json::json!({
                "url": n1,
                "nick": n2,
                "token": secret_present(f3).then_some(f3),
                "password": secret_present(f4).then_some(f4),
                "allowed_sender": (!n5.is_empty()).then_some(n5),
                "allowed_rooms_csv": (!n6.is_empty()).then_some(n6),
                "allow_plaintext": flag,
            })
        }
        GuiChannelForm::Twitch => {
            if n1.is_empty() || !secret_present(f2) || n3.is_empty() {
                return Err("twitch needs: --nick, --token, and --channels-csv".into());
            }
            serde_json::json!({
                "nick": n1,
                "token": f2,
                "channels_csv": n3,
            })
        }
        GuiChannelForm::Nostr => {
            if !secret_present(f1) || n2.is_empty() || n3.is_empty() {
                return Err("nostr needs: --token, --channels-csv (relay URLs), and --allowed-sender (64-char hex pubkey)".into());
            }
            serde_json::json!({
                "token": f1,
                "channels_csv": n2,
                "allowed_sender": n3,
            })
        }
    };

    let mut request = serde_json::json!({
        "schema_version": 1,
        "channel": channel_id,
        "fields": request_fields,
    });
    let mut body = Zeroizing::new(Vec::new());
    let encoded = serde_json::to_writer(&mut *body, &request)
        .map(|()| body)
        .map_err(|error| format!("encode private channel credential request: {error}"));
    zeroize_json_strings(&mut request);
    encoded
}

/// One channel row from `neoth channel list --output json`.
///
/// The GUI deliberately consumes the daemon's canonical probe result instead
/// of reparsing `credentials.yaml`. That keeps file/keychain credentials,
/// feature availability, partial configuration, and validation errors aligned
/// across CLI and GUI without ever returning a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    pub name: String,
    pub status: String,
    pub configured: bool,
    pub detail: String,
    /// Secret flags for the six text-entry slots, projected directly from the
    /// daemon registry. Slint binds every actual input widget to these flags.
    pub setup_secret_mask: [bool; 6],
}

/// Parse the authoritative channel inventory. Malformed, empty, duplicated, or
/// future-unknown status values are explicit errors; silently rendering them as
/// "disconnected" would hide damaged operator state.
pub fn parse_channel_status(json: &str) -> Result<Vec<ChannelStatus>, String> {
    #[derive(serde::Deserialize)]
    struct Payload {
        registry: Registry,
        channels: Vec<Row>,
        configured: usize,
        total: usize,
    }
    #[derive(serde::Deserialize)]
    struct Registry {
        schema_version: u32,
        channels: Vec<RegistryRow>,
    }
    #[derive(serde::Deserialize)]
    struct RegistryRow {
        id: String,
        aliases: Vec<String>,
        migration_aliases: Vec<String>,
        setup_fields: Vec<RegistrySetupField>,
    }
    #[derive(serde::Deserialize)]
    struct RegistrySetupField {
        key: String,
        secret: bool,
        requirement: GuiSetupRequirement,
        #[serde(default)]
        one_of_group: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Row {
        name: String,
        status: String,
        configured: bool,
        detail: String,
    }

    let payload: Payload = serde_json::from_str(json)
        .map_err(|error| format!("invalid channel inventory JSON: {error}"))?;
    if payload.registry.schema_version != 1 {
        return Err(format!(
            "unsupported channel registry schema version {} (expected 1)",
            payload.registry.schema_version
        ));
    }
    if payload.registry.channels.is_empty() {
        return Err("channel registry projection is empty".to_string());
    }
    if payload.total != payload.channels.len() {
        return Err(format!(
            "channel inventory total {} does not match {} rows",
            payload.total,
            payload.channels.len()
        ));
    }
    let configured_rows = payload
        .channels
        .iter()
        .filter(|channel| channel.configured)
        .count();
    if payload.configured != configured_rows {
        return Err(format!(
            "channel inventory configured count {} does not match {} configured rows",
            payload.configured, configured_rows
        ));
    }

    let valid_token = |token: &str| {
        !token.is_empty()
            && token
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    };
    let mut registry_ids = std::collections::BTreeSet::new();
    let mut setup_secret_masks = std::collections::BTreeMap::new();
    for descriptor in &payload.registry.channels {
        if !valid_token(&descriptor.id) {
            return Err(format!(
                "channel registry contains invalid canonical id `{}`",
                descriptor.id
            ));
        }
        if !registry_ids.insert(descriptor.id.as_str()) {
            return Err(format!(
                "channel registry contains duplicate canonical id `{}`",
                descriptor.id
            ));
        }
        let contract = gui_channel_contract(&descriptor.id).ok_or_else(|| {
            format!(
                "channel `{}` has no GUI setup/form binding; refusing a partially wired inventory",
                descriptor.id
            )
        })?;
        let setup_matches = descriptor.setup_fields.len() == contract.setup_fields.len()
            && descriptor
                .setup_fields
                .iter()
                .zip(contract.setup_fields)
                .all(|(actual, expected)| {
                    actual.key == expected.key
                        && actual.requirement == expected.requirement
                        && actual.one_of_group.as_deref() == expected.one_of_group
                });
        if !setup_matches {
            return Err(format!(
                "channel `{}` GUI setup binding differs from the registry setup schema",
                descriptor.id
            ));
        }
        if descriptor
            .setup_fields
            .iter()
            .skip(6)
            .any(|field| field.secret)
        {
            return Err(format!(
                "channel `{}` has a secret setup field without a GUI password slot",
                descriptor.id
            ));
        }
        let mut secret_mask = [false; 6];
        for (slot, field) in descriptor.setup_fields.iter().take(6).enumerate() {
            secret_mask[slot] = field.secret;
        }
        setup_secret_masks.insert(descriptor.id.clone(), secret_mask);
    }

    let mut operator_names = registry_ids.clone();
    let mut migration_names = registry_ids.clone();
    for descriptor in &payload.registry.channels {
        for (namespace, aliases, names) in [
            ("operator", &descriptor.aliases, &mut operator_names),
            (
                "migration",
                &descriptor.migration_aliases,
                &mut migration_names,
            ),
        ] {
            for alias in aliases {
                if !valid_token(alias) {
                    return Err(format!(
                        "channel `{}` contains invalid {namespace} alias `{alias}`",
                        descriptor.id
                    ));
                }
                if !names.insert(alias.as_str()) {
                    return Err(format!(
                        "channel registry contains duplicate {namespace} name `{alias}`"
                    ));
                }
            }
        }
    }

    if payload.total != payload.registry.channels.len() {
        return Err(format!(
            "channel inventory total {} does not match {} registry descriptors",
            payload.total,
            payload.registry.channels.len()
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut channels = Vec::with_capacity(payload.channels.len());
    for row in payload.channels {
        let name = row.name.trim();
        if name.is_empty() {
            return Err("channel inventory contains an empty channel id".to_string());
        }
        if !seen.insert(name.to_string()) {
            return Err(format!("channel inventory contains duplicate id `{name}`"));
        }
        if !matches!(
            row.status.as_str(),
            "ok" | "warn" | "error" | "unavailable" | "not_configured"
        ) {
            return Err(format!(
                "channel `{name}` returned unknown status `{}`",
                row.status
            ));
        }
        // Defer an unknown row to the set comparison below so one diagnostic
        // reports the complete missing/unknown drift instead of stopping at
        // the first foreign ID. The placeholder is never returned to the UI:
        // unequal sets fail before `Ok(channels)`.
        let setup_secret_mask = setup_secret_masks.get(name).copied().unwrap_or([false; 6]);
        channels.push(ChannelStatus {
            name: name.to_string(),
            status: row.status,
            configured: row.configured,
            detail: row.detail,
            setup_secret_mask,
        });
    }

    let expected = registry_ids;
    let actual = seen
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
        let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
        return Err(format!(
            "channel registry drift (missing: {}; unknown: {})",
            if missing.is_empty() {
                "none".to_string()
            } else {
                missing.join(", ")
            },
            if unknown.is_empty() {
                "none".to_string()
            } else {
                unknown.join(", ")
            },
        ));
    }
    let projected_order = payload
        .registry
        .channels
        .iter()
        .map(|descriptor| descriptor.id.as_str())
        .collect::<Vec<_>>();
    let actual_order = channels
        .iter()
        .map(|channel| channel.name.as_str())
        .collect::<Vec<_>>();
    if actual_order != projected_order {
        return Err("channel inventory order differs from registry projection".to_string());
    }
    Ok(channels)
}

/// Typed result from `neoth channel test <id> --output json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelTestStatus {
    pub status: String,
    pub detail: String,
}

/// Parse one canonical channel-test result and bind it to the channel the GUI
/// requested. A process exit code alone is insufficient because the CLI emits
/// typed `fail`, `skipped`, and `unavailable` results with structured detail.
pub fn parse_channel_test_status(
    json: &str,
    expected_channel: &str,
) -> Result<ChannelTestStatus, String> {
    #[derive(serde::Deserialize)]
    struct Payload {
        channel: String,
        status: String,
        detail: String,
    }

    let result: Payload = serde_json::from_str(json)
        .map_err(|error| format!("invalid channel test JSON: {error}"))?;
    if result.channel != expected_channel {
        return Err(format!(
            "channel test returned `{}` while `{expected_channel}` was requested",
            result.channel
        ));
    }
    if !matches!(
        result.status.as_str(),
        "ok" | "fail" | "skipped" | "unavailable"
    ) {
        return Err(format!(
            "channel `{expected_channel}` returned unknown test status `{}`",
            result.status
        ));
    }
    let detail = result.detail.trim();
    if detail.is_empty()
        || detail
            .chars()
            .any(|character| character.is_control() && !character.is_whitespace())
    {
        return Err(format!(
            "channel `{expected_channel}` returned invalid test detail"
        ));
    }
    Ok(ChannelTestStatus {
        status: result.status,
        detail: detail.to_string(),
    })
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
                    Some(PresetEntry {
                        name,
                        active,
                        builtin,
                        description,
                    })
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
                    let old = c
                        .get("old")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let new = c
                        .get("new")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(WarnChange { path, old, new })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ApplyPlan {
        name,
        autonomy_requested,
        warn_changes,
        fields_changed_count,
    })
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
pub fn format_epoch_utc(ts: i64) -> String {
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
pub fn prune_toast(
    toasts: Vec<(i32, String, String, String)>,
    id: i32,
) -> Vec<(i32, String, String, String)> {
    toasts
        .into_iter()
        .filter(|(tid, _, _, _)| *tid != id)
        .collect()
}

/// Allocate a fresh toast id that does not collide with any id in `toasts`.
/// Deterministic: starts at 1, increments until a gap is found.
pub fn next_toast_id(toasts: &[(i32, String, String, String)]) -> i32 {
    let max = toasts.iter().map(|(id, _, _, _)| *id).max().unwrap_or(0);
    max + 1
}

// ── Chat code blocks (H19-lite) ──────────────────────────────────────────────

/// Extract fenced code blocks from a chat reply. Returns (joined blocks,
/// first language tag). Multiple blocks join with a blank line; an
/// unterminated fence swallows to end-of-text (streaming tail).
pub fn extract_code_blocks(text: &str) -> (String, String) {
    let mut blocks: Vec<String> = Vec::new();
    let mut lang = String::new();
    let mut rest = text;
    while let Some(open) = rest.find("```") {
        let after = &rest[open + 3..];
        let nl = after.find('\n');
        let (tag, body_start) = match nl {
            Some(n) => (after[..n].trim(), n + 1),
            None => break, // fence at EOF with no body
        };
        let body = &after[body_start..];
        let (block, next) = match body.find("```") {
            Some(close) => (&body[..close], &body[close + 3..]),
            None => (body, ""),
        };
        let trimmed = block.trim_end_matches('\n');
        if !trimmed.trim().is_empty() {
            if lang.is_empty() && !tag.is_empty() {
                lang = tag.to_string();
            }
            blocks.push(trimmed.to_string());
        }
        rest = next;
    }
    (blocks.join("\n\n"), lang)
}

// ── Permissions matrix (C2) ──────────────────────────────────────────────────

/// One per-action permission row for the Privacy matrix.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PermRowData {
    pub action: String,
    pub decision: String, // "allow" | "confirm" | "deny"
    pub overridden: bool,
}

/// Parse `neoth permissions show --output json`: rows come from the
/// ACTIVE level's decisions with `active_custom_overrides` applied on
/// top (those mark `overridden`). Returns (rows, active_level).
pub fn parse_permissions_show(json: &str) -> (Vec<PermRowData>, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let level = v
        .get("active_level")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let overrides = v
        .get("active_custom_overrides")
        .and_then(|x| x.as_object())
        .cloned()
        .unwrap_or_default();
    let Some(matrix) = v.get("matrix").and_then(|x| x.as_array()) else {
        return (Vec::new(), level);
    };
    let active = matrix
        .iter()
        .find(|m| m.get("level").and_then(|x| x.as_str()) == Some(level.as_str()))
        .or_else(|| matrix.first());
    let Some(decisions) = active
        .and_then(|m| m.get("decisions"))
        .and_then(|x| x.as_array())
    else {
        return (Vec::new(), level);
    };
    let rows = decisions
        .iter()
        .map(|d| {
            let action = d
                .get("action")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let base = d
                .get("decision")
                .and_then(|x| x.as_str())
                .unwrap_or("confirm")
                .to_string();
            match overrides.get(&action).and_then(|x| x.as_str()) {
                Some(o) => PermRowData {
                    action,
                    decision: o.to_lowercase(),
                    overridden: true,
                },
                None => PermRowData {
                    action,
                    decision: base.to_lowercase(),
                    overridden: false,
                },
            }
        })
        .collect();
    (rows, level)
}

// ── Regenerate with model (H18) ──────────────────────────────────────────────

/// Parse the models-catalog JSON into the picker list for one provider:
/// non-deprecated model ids, provider order, capped at 8. Unknown
/// provider (or empty kind) falls back to every provider's models
/// merged in catalog order — still filtered, never invented.
pub fn parse_models_catalog(json: &str, provider_kind: &str) -> Vec<String> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(providers) = v.get("providers").and_then(|x| x.as_object()) else {
        return Vec::new();
    };
    fn ids(pc: &serde_json::Value) -> Vec<String> {
        pc.get("models")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|m| {
                        !m.get("deprecated")
                            .and_then(|d| d.as_bool())
                            .unwrap_or(false)
                    })
                    .filter_map(|m| m.get("id").and_then(|i| i.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
    let picked: Vec<String> = match providers.get(provider_kind) {
        Some(pc) if !ids(pc).is_empty() => ids(pc),
        _ => providers.values().flat_map(ids).collect(),
    };
    picked.into_iter().take(8).collect()
}

// ── Cost & usage (C7) ────────────────────────────────────────────────────────

/// One top-session cost row for the overview card.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CostSessionData {
    pub session: String,
    pub provider: String,
    pub tokens: String,
    pub cost: String,
}

/// Parse `neoth cost top-sessions --output json` (array of row objects;
/// tolerant of field-name drift by probing common keys).
pub fn parse_cost_sessions(json: &str) -> Vec<CostSessionData> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(rows) = v.as_array().cloned().or_else(|| {
        v.get("sessions")
            .or_else(|| v.get("rows"))
            .and_then(|x| x.as_array())
            .cloned()
    }) else {
        return Vec::new();
    };
    fn s(v: &serde_json::Value, keys: &[&str]) -> String {
        for k in keys {
            if let Some(x) = v.get(k) {
                if let Some(t) = x.as_str() {
                    return t.to_string();
                }
                if x.is_number() {
                    return x.to_string();
                }
            }
        }
        String::new()
    }
    rows.iter()
        .map(|r| {
            // `models` is an array; surface the first (usually only) one.
            let model = r
                .get("models")
                .and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| s(r, &["provider", "model"]));
            CostSessionData {
                session: s(r, &["session", "session_id", "id"])
                    .chars()
                    .take(18)
                    .collect(),
                provider: model,
                tokens: s(r, &["total_tokens", "tokens", "output_tokens"]),
                // top-sessions ranks by tokens, not currency — show the
                // response count in the cost column (honest, not a fake $).
                cost: match s(r, &["responses"]).as_str() {
                    "" => s(r, &["cost", "total_eur", "eur"]),
                    n => format!("{n} resp"),
                },
            }
        })
        .take(8)
        .collect()
}

/// Parse one `neoth usage … --format json` rollup → (cost_usd, tokens).
pub fn parse_usage_rollup(json: &str) -> Option<(f64, u64)> {
    let v = serde_json::from_str::<serde_json::Value>(json).ok()?;
    let cost = v.get("total_cost_usd")?.as_f64()?;
    let tokens = v
        .get("total_input_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(0)
        + v.get("total_output_tokens")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
    Some((cost, tokens))
}

// ── Memory graph (H2) — parse + deterministic force layout ───────────────────

/// One node of the Hebbian association graph, positioned 0..1.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GraphNodeData {
    pub id: i64,
    pub label: String,
    pub tier: String,
    pub degree: i32,
    pub community: i32,
    pub x: f32,
    pub y: f32,
    pub r: f32, // 0..1 relative radius (degree-scaled)
}

/// One positioned edge (endpoints 0..1) with normalized weight.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GraphEdgeData {
    pub x1: f32,
    pub y1: f32,
    pub x2: f32,
    pub y2: f32,
    pub w: f32,
}

/// Parse `neoth memory --graph --output json` and lay the graph out with
/// a deterministic Fruchterman–Reingold pass (nodes start on a circle by
/// index — no RNG, so the layout is stable across refreshes). Returns
/// (nodes, edges, communities).
pub fn layout_memory_graph(json: &str) -> (Vec<GraphNodeData>, Vec<GraphEdgeData>, i32) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let communities = v.get("communities").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let Some(jnodes) = v.get("nodes").and_then(|x| x.as_array()) else {
        return (Vec::new(), Vec::new(), 0);
    };
    let jedges = v
        .get("edges")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    let n = jnodes.len();
    if n == 0 {
        return (Vec::new(), Vec::new(), communities);
    }
    let mut nodes: Vec<GraphNodeData> = jnodes
        .iter()
        .enumerate()
        .map(|(i, jn)| {
            let ang = std::f32::consts::TAU * (i as f32) / (n as f32);
            GraphNodeData {
                id: jn.get("id").and_then(|x| x.as_i64()).unwrap_or(0),
                label: jn
                    .get("label")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                tier: jn
                    .get("tier")
                    .and_then(|x| x.as_str())
                    .unwrap_or("fact")
                    .to_string(),
                degree: jn.get("degree").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
                community: jn.get("community").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
                x: 0.5 + 0.4 * ang.cos(),
                y: 0.5 + 0.4 * ang.sin(),
                r: 0.0,
            }
        })
        .collect();
    let index_of: std::collections::HashMap<i64, usize> =
        nodes.iter().enumerate().map(|(i, nd)| (nd.id, i)).collect();
    let raw_edges: Vec<(usize, usize, f32)> = jedges
        .iter()
        .filter_map(|je| {
            let a = *index_of.get(&je.get("a")?.as_i64()?)?;
            let b = *index_of.get(&je.get("b")?.as_i64()?)?;
            let w = je.get("w").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
            Some((a, b, w))
        })
        .collect();

    // Fruchterman–Reingold, 60 iterations, cooling step. O(n²) repulsion
    // is fine at the 400-link export cap (≤ ~300 nodes).
    // ponytail: O(n²), grid-bucket it if graphs ever exceed ~1k nodes.
    let k = (1.0 / n as f32).sqrt();
    let mut temp = 0.10_f32;
    for _ in 0..60 {
        let mut disp = vec![(0.0_f32, 0.0_f32); n];
        for i in 0..n {
            for j in (i + 1)..n {
                let dx = nodes[i].x - nodes[j].x;
                let dy = nodes[i].y - nodes[j].y;
                let d2 = (dx * dx + dy * dy).max(1e-6);
                let d = d2.sqrt();
                let rep = k * k / d;
                disp[i].0 += dx / d * rep;
                disp[i].1 += dy / d * rep;
                disp[j].0 -= dx / d * rep;
                disp[j].1 -= dy / d * rep;
            }
        }
        for (a, b, w) in &raw_edges {
            let dx = nodes[*a].x - nodes[*b].x;
            let dy = nodes[*a].y - nodes[*b].y;
            let d = (dx * dx + dy * dy).max(1e-6).sqrt();
            let att = d * d / k * (0.5 + w.clamp(0.0, 1.0));
            disp[*a].0 -= dx / d * att;
            disp[*a].1 -= dy / d * att;
            disp[*b].0 += dx / d * att;
            disp[*b].1 += dy / d * att;
        }
        for (i, nd) in nodes.iter_mut().enumerate() {
            let (dx, dy) = disp[i];
            let d = (dx * dx + dy * dy).max(1e-9).sqrt();
            let step = d.min(temp);
            nd.x = (nd.x + dx / d * step).clamp(0.02, 0.98);
            nd.y = (nd.y + dy / d * step).clamp(0.02, 0.98);
        }
        temp *= 0.94;
    }

    // Normalize into 0.05..0.95 with aspect preserved by the caller.
    let (mut min_x, mut max_x, mut min_y, mut max_y) = (1.0_f32, 0.0_f32, 1.0_f32, 0.0_f32);
    for nd in &nodes {
        min_x = min_x.min(nd.x);
        max_x = max_x.max(nd.x);
        min_y = min_y.min(nd.y);
        max_y = max_y.max(nd.y);
    }
    let sx = (max_x - min_x).max(1e-6);
    let sy = (max_y - min_y).max(1e-6);
    let max_deg = nodes.iter().map(|nd| nd.degree).max().unwrap_or(1).max(1) as f32;
    for nd in &mut nodes {
        nd.x = 0.05 + 0.90 * (nd.x - min_x) / sx;
        nd.y = 0.05 + 0.90 * (nd.y - min_y) / sy;
        nd.r = (nd.degree as f32 / max_deg).clamp(0.1, 1.0);
    }

    let edges: Vec<GraphEdgeData> = raw_edges
        .iter()
        .map(|(a, b, w)| GraphEdgeData {
            x1: nodes[*a].x,
            y1: nodes[*a].y,
            x2: nodes[*b].x,
            y2: nodes[*b].y,
            w: w.clamp(0.0, 1.0),
        })
        .collect();
    (nodes, edges, communities)
}

// ── Agents tab — structured card data ─────────────────────────────────────────

/// One agent card parsed from `neoth agents list --output json`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AgentRowData {
    pub name: String,
    pub hemisphere: String, // source label: "built-in" | "operator"
    pub provider: String,
    pub model: String,
    pub state: String, // "idle" | "off"
    pub current_task: String,
    pub tasks_done: i32,
}

/// Tolerant parse; empty vec on any shape mismatch (caller falls back to
/// the raw mono dump so nothing regresses).
pub fn parse_agents_list(json: &str) -> Vec<AgentRowData> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(rows) = v.get("agents").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    rows.iter()
        .map(|a| AgentRowData {
            name: a
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string(),
            hemisphere: a
                .get("source")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            provider: String::new(),
            model: a
                .get("model")
                .and_then(|x| x.as_str())
                .unwrap_or("(default)")
                .to_string(),
            state: if a.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) {
                "idle".to_string()
            } else {
                "off".to_string()
            },
            current_task: a
                .get("description")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            tasks_done: 0,
        })
        .collect()
}

// ── WAL inspector ─────────────────────────────────────────────────────────────

/// One row parsed from `neoth wal show --output json` for the inspector.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WalRowData {
    pub seq: i32,
    pub ts: String,
    pub ts_ns: u64,
    pub opcode: String,
    pub kind: String,
    pub summary: String,
    pub tint: String,
    pub detail_json: String,
}

/// One timeline bucket: per-band frame counts inside an equal time slice.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WalBucketData {
    pub label: String,
    pub memory_n: i32,
    pub audit_n: i32,
    pub consent_n: i32,
    pub warning_n: i32,
    pub plain_n: i32,
}

/// Slice the cached rows into `n` equal time buckets (oldest first) for
/// the timeline scrubber. Rows with ts_ns == 0 are skipped. Returns the
/// buckets plus each bucket's (start_ns, end_ns) so a click can filter
/// the row list to that slice.
pub fn bucket_wal_rows(rows: &[WalRowData], n: usize) -> (Vec<WalBucketData>, Vec<(u64, u64)>) {
    let stamps: Vec<u64> = rows.iter().map(|r| r.ts_ns).filter(|t| *t > 0).collect();
    let (Some(&min), Some(&max)) = (stamps.iter().min(), stamps.iter().max()) else {
        return (Vec::new(), Vec::new());
    };
    let n = n.max(1);
    let span = (max - min).max(1);
    let step = span.div_ceil(n as u64).max(1);
    let mut buckets = vec![WalBucketData::default(); n];
    let mut ranges = Vec::with_capacity(n);
    for (i, b) in buckets.iter_mut().enumerate() {
        let lo = min + step * i as u64;
        ranges.push((lo, lo + step));
        b.label = format_epoch_utc((lo / 1_000_000_000) as i64);
    }
    for r in rows {
        if r.ts_ns == 0 {
            continue;
        }
        let idx = (((r.ts_ns - min) / step) as usize).min(n - 1);
        let b = &mut buckets[idx];
        match r.tint.as_str() {
            "memory" => b.memory_n += 1,
            "audit" => b.audit_n += 1,
            "consent" => b.consent_n += 1,
            "warning" => b.warning_n += 1,
            _ => b.plain_n += 1,
        }
    }
    (buckets, ranges)
}

/// Semantic tint per opcode band — mirrors the WAL registry's band map
/// (events.rs header table) onto the GUI's meaning colours.
pub fn wal_tint_for(event_type: u8) -> &'static str {
    match event_type {
        0x10..=0x2F => "memory",  // memory / recall / self-dev
        0x30..=0x3F => "audit",   // channels / ingress-egress
        0x40..=0x4F => "warning", // cron (amber = in-progress)
        0x60..=0x6F => "audit",   // council / decisions
        0x70..=0x7F => "warning", // coding workflow + loops
        0xC0..=0xCF => "consent", // caps / denials / security
        0xF0..=0xFF => "memory",  // dreaming / high band
        _ => "plain",
    }
}

/// Parse the `wal show` JSON envelope into inspector rows (already
/// newest-first from the CLI). Returns (rows, frames_matched).
pub fn parse_wal_show(json: &str) -> (Vec<WalRowData>, i32) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let matched = v
        .get("frames_matched")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;
    let Some(frames) = v.get("frames").and_then(|x| x.as_array()) else {
        return (Vec::new(), matched);
    };
    let rows = frames
        .iter()
        .map(|f| {
            let opcode = f
                .get("event_type")
                .and_then(|x| x.as_str())
                .unwrap_or("0x??")
                .to_string();
            let et = u8::from_str_radix(opcode.trim_start_matches("0x"), 16).unwrap_or(0);
            let ts_ns = f.get("ts_ns").and_then(|x| x.as_u64()).unwrap_or(0);
            let payload_len = f.get("payload_len").and_then(|x| x.as_u64()).unwrap_or(0);
            let importance = f.get("importance").and_then(|x| x.as_f64()).unwrap_or(0.0);
            WalRowData {
                seq: f.get("event_id").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
                ts: format_epoch_utc((ts_ns / 1_000_000_000) as i64),
                ts_ns,
                opcode,
                kind: f
                    .get("event_name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                summary: format!("{} B · imp {:.2}", payload_len, importance),
                tint: wal_tint_for(et).to_string(),
                detail_json: serde_json::to_string_pretty(f).unwrap_or_default(),
            }
        })
        .collect();
    (rows, matched)
}

/// Client-side filter for the inspector: free-text over kind/opcode plus
/// an opcode-band index matching `WAL_BAND_OPTIONS`.
pub const WAL_BAND_OPTIONS: &[(&str, Option<(u8, u8)>)] = &[
    ("all bands", None),
    ("memory 0x10–0x2F", Some((0x10, 0x2F))),
    ("channels 0x30–0x3F", Some((0x30, 0x3F))),
    ("cron 0x40–0x4F", Some((0x40, 0x4F))),
    ("council 0x60–0x6F", Some((0x60, 0x6F))),
    ("coding+loops 0x70–0x7F", Some((0x70, 0x7F))),
    ("security 0xC0–0xCF", Some((0xC0, 0xCF))),
    ("dreaming 0xF0–0xFF", Some((0xF0, 0xFF))),
];

pub fn filter_wal_rows(rows: &[WalRowData], text: &str, band_idx: usize) -> Vec<WalRowData> {
    let q = text.trim().to_lowercase();
    let band = WAL_BAND_OPTIONS.get(band_idx).and_then(|(_, range)| *range);
    rows.iter()
        .filter(|r| {
            let et = u8::from_str_radix(r.opcode.trim_start_matches("0x"), 16).unwrap_or(0);
            let band_ok = band.is_none_or(|(lo, hi)| et >= lo && et <= hi);
            let text_ok = q.is_empty()
                || r.kind.to_lowercase().contains(&q)
                || r.opcode.to_lowercase().contains(&q);
            band_ok && text_ok
        })
        .cloned()
        .collect()
}

// ── Mesh fleet dashboard — swarm resource snapshots ──────────────────────────

/// One node row parsed from `neoth cluster swarm --output json`
/// (top-level `{ "sampling": …, "nodes": [ … ] }`). Fractions are 0..1
/// ready for SegBar meters.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SwarmNodeData {
    pub node_id: String,
    pub cpu_frac: f32,
    pub ram_frac: f32,
    pub vram_frac: f32,
    pub age_secs: i32,
}

/// Parse the swarm dashboard JSON. Tolerant: bad JSON / missing fields
/// yield an empty vec / zeroed fractions (meters render empty).
pub fn parse_swarm_nodes(json: &str) -> Vec<SwarmNodeData> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(nodes) = v.get("nodes").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    fn frac(used: Option<f64>, total: Option<f64>) -> f32 {
        match (used, total) {
            (Some(u), Some(t)) if t > 0.0 => (u / t).clamp(0.0, 1.0) as f32,
            _ => 0.0,
        }
    }
    nodes
        .iter()
        .map(|n| SwarmNodeData {
            node_id: n
                .get("node_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            cpu_frac: (n.get("cpu_pct").and_then(|x| x.as_f64()).unwrap_or(0.0) / 100.0)
                .clamp(0.0, 1.0) as f32,
            ram_frac: frac(
                n.get("ram_used_mb").and_then(|x| x.as_f64()),
                n.get("ram_total_mb").and_then(|x| x.as_f64()),
            ),
            vram_frac: frac(
                n.get("vram_used_mb").and_then(|x| x.as_f64()),
                n.get("vram_total_mb").and_then(|x| x.as_f64()),
            ),
            age_secs: n.get("age_s").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        })
        .collect()
}

/// Render `cluster events --output json` rows as mono log lines for the
/// mesh tab's gossip stream, newest first, capped. Tolerant of shape
/// drift: rows missing fields render with placeholders.
pub fn format_gossip_lines(json: &str, cap: usize) -> Vec<String> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(rows) = v.as_array() else {
        return Vec::new();
    };
    let mut lines: Vec<(i64, String)> = rows
        .iter()
        .map(|r| {
            let ts = r.get("received_at").and_then(|x| x.as_i64()).unwrap_or(0);
            let peer = r
                .get("origin_peer_pk")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let peer8: String = peer.chars().take(8).collect();
            let et = r.get("event_type").and_then(|x| x.as_u64()).unwrap_or(0);
            let bytes = r.get("payload_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
            (
                ts,
                format!(
                    "{}  {}  0x{:02X}  {}",
                    format_epoch_utc(ts),
                    peer8,
                    et,
                    format_backup_bytes(bytes)
                ),
            )
        })
        .collect();
    lines.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
    lines.into_iter().take(cap).map(|(_, l)| l).collect()
}

// ── Companion overlay position persistence ──────────────────────────────────

/// Parse the "x,y" dotfile written on overlay hide/restore. Whitespace
/// tolerant; anything malformed yields None (default position applies).
pub fn parse_overlay_pos(s: &str) -> Option<(i32, i32)> {
    let (x, y) = s.trim().split_once(',')?;
    Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
}

// ── Command palette (Ctrl+K) ─────────────────────────────────────────────────
// Pure catalog + filter; the Slint plumbing lives in main.rs.

/// One palette entry: (label, glyph, tab-key, group-hint). Mirrors the
/// sidebar nav in app_shell.slint — keep the two in sync when a tab is
/// added or renamed.
pub type PaletteEntry = (&'static str, &'static str, &'static str, &'static str);

/// Every nav destination the palette can jump to. Complexity gating is
/// deliberately NOT applied here: the palette is the power-user surface,
/// so it always reaches everything (Raycast grammar).
pub const PALETTE_CATALOG: &[PaletteEntry] = &[
    ("Chat", "💬", "chat", "CORE"),
    ("Overview", "◎", "overview", "CORE"),
    ("Coding", "⌘", "coding", "WORK"),
    ("Agents", "⚇", "agents", "WORK"),
    ("Automation", "⟳", "automation", "WORK"),
    ("Loops", "∞", "loops", "WORK"),
    ("n8n", "⇶", "n8n", "WORK"),
    ("Calendar", "◷", "calendar", "WORK"),
    ("Evolve", "✦", "evolve", "WORK"),
    ("Self-Dev", "⊞", "selfdev", "WORK"),
    ("Dreaming", "☽", "dreaming", "WORK"),
    ("Buddy Config", "⊙", "buddyconfig", "WORK"),
    ("Memory", "◈", "memory", "SYSTEM"),
    ("Memory Graph", "❋", "memgraph", "SYSTEM"),
    ("Groundtruth", "⊨", "groundtruth", "SYSTEM"),
    ("Hemispheres", "◐", "hemispheres", "SYSTEM"),
    ("Channels", "⇄", "channels", "SYSTEM"),
    ("Privacy", "⛨", "privacy", "SYSTEM"),
    ("Plugins", "⧉", "plugins", "SYSTEM"),
    ("MCP", "⧟", "mcp", "SYSTEM"),
    ("Hooks", "⋔", "hooks", "SYSTEM"),
    ("Model Catalog", "⊚", "catalog", "SYSTEM"),
    ("Quota", "⊘", "quota", "SYSTEM"),
    ("Tweaks", "⚗", "tweaks", "SYSTEM"),
    ("Cluster", "⬡", "cluster", "SYSTEM"),
    ("Resources", "▦", "resources", "SYSTEM"),
    ("Babel", "◬", "babel", "SYSTEM"),
    ("Obsidian", "◉", "obsidian", "SYSTEM"),
    ("Wiki", "⌗", "wiki", "SYSTEM"),
    ("Companion", "⊕", "companion", "SYSTEM"),
    ("Mesh", "◇", "mesh", "SYSTEM"),
    ("WAL", "≣", "wal", "SYSTEM"),
    ("Doctor", "✚", "doctor", "SYSTEM"),
    ("Config", "⚙", "config", "SYSTEM"),
];

/// Case-insensitive substring filter over the catalog. Empty query
/// returns the full catalog (palette opens showing everything).
/// Matches on label first, then tab key ("selfdev" finds Self-Dev).
pub fn filter_palette(query: &str) -> Vec<PaletteEntry> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return PALETTE_CATALOG.to_vec();
    }
    PALETTE_CATALOG
        .iter()
        .filter(|(label, _, tab, _)| label.to_lowercase().contains(&q) || tab.contains(&q))
        .copied()
        .collect()
}

// ── Wave-2 activity helpers ──────────────────────────────────────────────────
// Pure, Slint-free functions — the ActivitySidecar plumbing (push_activity,
// settle_activity) lives in main.rs and calls these for id allocation + cap.

/// One activity row tuple: (id, ts, kind, title, detail, active).
pub type ActivityTuple = (i32, String, String, String, String, bool);

/// Allocate the next activity id (monotonic, no collision with existing rows).
pub fn next_activity_id(rows: &[ActivityTuple]) -> i32 {
    let max = rows
        .iter()
        .map(|(id, _, _, _, _, _)| *id)
        .max()
        .unwrap_or(0);
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
pub fn parse_overview_status(json: &str) -> (String, String, String, String, String, String) {
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

    (
        mode,
        autonomy,
        channel_health,
        wal_bytes,
        tier_counts,
        daemon_state,
    )
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
        .map(|ev| {
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
                    if s.as_bytes().get(10) == Some(&b'T')
                        && let Some(time) = s.get(11..16)
                    {
                        return time.to_string();
                    }
                    s.chars().take(10).collect()
                })
                .unwrap_or_else(|| "—".to_string());
            (time, summary)
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

// ── I13 bg-jobs parse ────────────────────────────────────────────────────────

/// Parse `neoth jobs --bg --output json` → (id, status, exit_code_string) rows.
///
/// Expected shape: `[{"id":"build-1721...","status":"completed","exit_code":0}]`.
/// `exit_code` is null while running → rendered as "". Malformed input or a
/// non-array yields an empty Vec (panel shows its empty state, never crashes).
pub fn parse_bg_jobs(json: &str) -> Vec<(String, String, String)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let id = row.get("id")?.as_str()?.to_string();
            let status = row
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            let exit = row
                .get("exit_code")
                .and_then(|c| c.as_i64())
                .map(|c| c.to_string())
                .unwrap_or_default();
            Some((id, status, exit))
        })
        .collect()
}

// ── H16 kanban bulk-selection store ──────────────────────────────────────────

/// Selected kanban task ids ("#42" display form). Plain set semantics —
/// the GUI layer owns one instance behind a Mutex and re-stamps the board
/// model's `selected` flags after every mutation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KanbanSelection(std::collections::HashSet<String>);

impl KanbanSelection {
    pub fn toggle(&mut self, id: &str) {
        let id = id.trim();
        if id.is_empty() {
            return;
        }
        if !self.0.remove(id) {
            self.0.insert(id.to_string());
        }
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn contains(&self, id: &str) -> bool {
        self.0.contains(id.trim())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Ids in deterministic order for the bulk-mutation loop.
    pub fn sorted_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.0.iter().cloned().collect();
        ids.sort();
        ids
    }

    /// Drop ids that no longer exist on the board (stale after refresh).
    pub fn retain_known(&mut self, known: &[String]) {
        let known: std::collections::HashSet<&str> =
            known.iter().map(String::as_str).collect();
        self.0.retain(|id| known.contains(id.as_str()));
    }
}

#[cfg(test)]
mod kanban_selection_tests {
    use super::KanbanSelection;

    #[test]
    fn toggle_clear_retain_roundtrip() {
        let mut sel = KanbanSelection::default();
        sel.toggle("#1");
        sel.toggle("#2");
        sel.toggle("#1"); // off again
        assert!(!sel.contains("#1"));
        assert!(sel.contains("#2"));
        assert_eq!(sel.len(), 1);
        sel.toggle("  "); // ignored
        assert_eq!(sel.len(), 1);
        sel.toggle("#3");
        sel.retain_known(&["#2".into()]);
        assert_eq!(sel.sorted_ids(), vec!["#2".to_string()]);
        sel.clear();
        assert!(sel.is_empty());
    }
}

// ── F2 mesh sync-state parse ─────────────────────────────────────────────────

/// One display row from `neoth cluster sync-state --output json`
/// (`durable_sync::MeshPeerStatus`). All fields pre-formatted for Slint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSyncData {
    pub peer_short: String,
    pub acked: String,
    pub pending: String,
    pub inbound_next: String,
    pub cursor: String,
    pub request: String,
    pub last_error: String,
}

/// Parse the sync-state JSON array. Optional u64s render as "-";
/// `pending` folds attempts in ("12 (3×)"); cursor shows the segment file
/// name plus offset. Malformed input yields an empty Vec.
pub fn parse_mesh_sync(json: &str) -> Vec<MeshSyncData> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    let opt = |row: &serde_json::Value, key: &str| -> String {
        row.get(key)
            .and_then(|x| x.as_u64())
            .map(|x| x.to_string())
            .unwrap_or_else(|| "-".to_string())
    };
    arr.iter()
        .filter_map(|row| {
            let pk = row.get("peer_pk")?.as_str()?;
            let peer_short = if pk.len() > 16 {
                format!("{}…", &pk[..16])
            } else {
                pk.to_string()
            };
            let pending = match (
                row.get("pending_origin_seq").and_then(|x| x.as_u64()),
                row.get("pending_attempts").and_then(|x| x.as_u64()),
            ) {
                (Some(seq), Some(att)) if att > 1 => format!("{seq} ({att}×)"),
                (Some(seq), _) => seq.to_string(),
                (None, _) => "-".to_string(),
            };
            let cursor = match (
                row.get("cursor_segment").and_then(|x| x.as_str()),
                row.get("cursor_offset").and_then(|x| x.as_u64()),
            ) {
                (Some(seg), off) => {
                    let name = std::path::Path::new(seg)
                        .file_name()
                        .and_then(std::ffi::OsStr::to_str)
                        .unwrap_or(seg);
                    format!("{name}:{}", off.unwrap_or(0))
                }
                (None, Some(off)) => off.to_string(),
                (None, None) => "-".to_string(),
            };
            Some(MeshSyncData {
                peer_short,
                acked: opt(row, "acked_origin_seq"),
                pending,
                inbound_next: opt(row, "inbound_next_expected_seq"),
                cursor,
                request: row
                    .get("request_state")
                    .and_then(|x| x.as_str())
                    .unwrap_or("-")
                    .to_string(),
                last_error: row
                    .get("request_last_error")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod mesh_sync_parse_tests {
    use super::parse_mesh_sync;

    #[test]
    fn parses_full_and_sparse_rows() {
        let json = r#"[
            {"peer_pk":"abcdef0123456789deadbeef","cursor_segment":"C:\\wal\\seg-0007.wal",
             "cursor_offset":4096,"acked_origin_seq":120,"pending_origin_seq":121,
             "pending_attempts":3,"inbound_next_expected_seq":88,
             "request_state":"pending","request_last_error":"peer unreachable"},
            {"peer_pk":"short","cursor_segment":null,"cursor_offset":0,
             "acked_origin_seq":0,"pending_origin_seq":null,"pending_attempts":null,
             "inbound_next_expected_seq":null,"request_state":null,"request_last_error":null}
        ]"#;
        let rows = parse_mesh_sync(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].peer_short, "abcdef0123456789…");
        assert_eq!(rows[0].pending, "121 (3×)");
        assert_eq!(rows[0].cursor, "seg-0007.wal:4096");
        assert_eq!(rows[0].request, "pending");
        assert_eq!(rows[0].last_error, "peer unreachable");
        assert_eq!(rows[1].peer_short, "short");
        assert_eq!(rows[1].pending, "-");
        assert_eq!(rows[1].cursor, "0");
        assert_eq!(rows[1].request, "-");
    }

    #[test]
    fn malformed_input_yields_empty() {
        assert!(parse_mesh_sync("not json").is_empty());
        assert!(parse_mesh_sync("{}").is_empty());
    }
}

// ── I14 slash-command parse ──────────────────────────────────────────────────

/// Parse `neoth slash list --output json` → (name, source, description,
/// enabled) rows. Expected shape:
/// `{"count":24,"commands":[{"name":"/help","source":"builtin",
///   "description":"…","enabled":true}]}`.
/// Malformed input yields an empty Vec (panel shows its empty state).
pub fn parse_slash_cmds(json: &str) -> Vec<(String, String, String, bool)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let Some(arr) = v.get("commands").and_then(|c| c.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|row| {
            let name = row.get("name")?.as_str()?.to_string();
            let source = row
                .get("source")
                .and_then(|s| s.as_str())
                .unwrap_or("builtin")
                .to_string();
            let description = row
                .get("description")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();
            let enabled = row
                .get("enabled")
                .and_then(|e| e.as_bool())
                .unwrap_or(true);
            Some((name, source, description, enabled))
        })
        .collect()
}

#[cfg(test)]
mod slash_cmds_parse_tests {
    use super::parse_slash_cmds;

    #[test]
    fn parses_builtin_and_operator_rows() {
        let json = r#"{"count":2,"commands":[
            {"name":"/help","source":"builtin","description":"list commands","enabled":true},
            {"name":"/deploy","source":"operator","description":"","enabled":false}
        ]}"#;
        let rows = parse_slash_cmds(json);
        assert_eq!(
            rows,
            vec![
                (
                    "/help".into(),
                    "builtin".into(),
                    "list commands".into(),
                    true
                ),
                ("/deploy".into(), "operator".into(), String::new(), false),
            ]
        );
    }

    #[test]
    fn malformed_input_yields_empty() {
        assert!(parse_slash_cmds("not json").is_empty());
        assert!(parse_slash_cmds("[]").is_empty());
        assert!(parse_slash_cmds("{\"count\":0}").is_empty());
    }
}

#[cfg(test)]
mod bg_jobs_parse_tests {
    use super::parse_bg_jobs;

    #[test]
    fn parses_running_and_completed_rows() {
        let json = r#"[
            {"id":"build-1","status":"completed","exit_code":0},
            {"id":"scan-2","status":"running","exit_code":null},
            {"id":"fail-3","status":"completed","exit_code":101}
        ]"#;
        let rows = parse_bg_jobs(json);
        assert_eq!(
            rows,
            vec![
                ("build-1".into(), "completed".into(), "0".into()),
                ("scan-2".into(), "running".into(), String::new()),
                ("fail-3".into(), "completed".into(), "101".into()),
            ]
        );
    }

    #[test]
    fn malformed_input_yields_empty() {
        assert!(parse_bg_jobs("not json").is_empty());
        assert!(parse_bg_jobs("{}").is_empty());
        assert!(parse_bg_jobs("[{\"status\":\"running\"}]").is_empty());
    }
}

// ── n8n parse fns ─────────────────────────────────────────────────────────────

/// Parse `neoth n8n status --output json` → (installed, webhook_base, path).
///
/// Expected shape: `{"n8n_installed":true,"webhook_base":"http://localhost:5678",
///   "n8n_path":"/usr/local/bin/n8n","bundled_workflows":[]}`
pub fn parse_n8n_status(json: &str) -> (bool, String, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let installed = v
        .get("n8n_installed")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let webhook_base = v
        .get("webhook_base")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let path = v
        .get("n8n_path")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
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
/// Row shape for the babel granularity table: `(window_secs, count, last_ts_end)`.
pub type BabelGranRow = (i32, i32, String);

#[derive(Debug, Default, PartialEq)]
pub struct BabelStatus {
    pub enabled: bool,
    pub threshold: String,
    pub epsilon: String,
    pub federate: bool,
    pub total_windows: i32,
    pub collapse_flagged: i32,
    pub memory_signals: String,
    pub skill_signals: String,
    pub k_d: String,
    pub gran_rows: Vec<BabelGranRow>,
}

pub fn parse_babel_status(json: &str) -> BabelStatus {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    let threshold = v
        .get("threshold")
        .map(|x| x.to_string())
        .unwrap_or_default();
    let epsilon = match v.get("epsilon_calibrated") {
        Some(serde_json::Value::Number(value)) => value.to_string(),
        Some(serde_json::Value::String(value)) => value.clone(),
        _ => String::new(),
    };
    let federate = v.get("federate").and_then(|x| x.as_bool()).unwrap_or(false);
    let total = v.get("total_windows").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
    let collapse = v
        .get("collapse_flagged")
        .and_then(|x| x.as_i64())
        .unwrap_or(0) as i32;

    let signal_status = |key: &str| {
        let Some(signal) = v.get(key) else {
            return String::new();
        };
        let enabled = signal
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let mapping = signal
            .get("mapping_version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("mapping unavailable");
        format!(
            "{} ({mapping})",
            if enabled { "enabled" } else { "disabled" }
        )
    };
    let memory_signals = signal_status("memory_signals");
    let skill_signals = signal_status("skill_signals");
    let k_d = v
        .get("k_d")
        .map(|posture| {
            let mode = posture
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let requested = posture
                .get("requested_model")
                .and_then(serde_json::Value::as_str);
            let degraded = posture
                .get("last_window_posture")
                .and_then(|last| last.get("degraded_reason"))
                .and_then(serde_json::Value::as_str);
            let mut status =
                requested.map_or_else(|| mode.to_string(), |model| format!("{mode} / {model}"));
            if let Some(reason) = degraded {
                status.push_str(" / degraded: ");
                status.push_str(reason);
            }
            status
        })
        .unwrap_or_default();

    let gran_rows: Vec<BabelGranRow> = v
        .get("windows_by_granularity")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|item| {
            let ws = item
                .get("window_secs")
                .and_then(|x| x.as_i64())
                .unwrap_or(0) as i32;
            let cnt = item.get("count").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
            let last = item
                .get("last_ts_end")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            (ws, cnt, last)
        })
        .collect();

    BabelStatus {
        enabled,
        threshold,
        epsilon,
        federate,
        total_windows: total,
        collapse_flagged: collapse,
        memory_signals,
        skill_signals,
        k_d,
        gran_rows,
    }
}

/// Parse `neoth babel windows --n 12 --output json`.
///
/// Returns `Vec<(id, window_secs, ts_start, ts_end, b_log, b_mult,
///               b_bottleneck, collapse_kind)>`.
/// Row shape for the babel windows table:
/// `(id, window_secs, ts_start, ts_end, b_log, b_mult, b_bottleneck, collapse_kind)`.
pub type BabelWindowRow = (String, i32, String, String, f32, f32, f32, String);

pub fn parse_babel_windows(json: &str) -> Vec<BabelWindowRow> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("windows")
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .map(|item| {
            let id = item
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let ws = item
                .get("window_secs")
                .and_then(|x| x.as_i64())
                .unwrap_or(0) as i32;
            let ts_start = item
                .get("ts_start")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let ts_end = item
                .get("ts_end")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let b_log = item.get("b_log").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
            let b_mult = item.get("b_mult").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
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
            (
                id,
                ws,
                ts_start,
                ts_end,
                b_log,
                b_mult,
                b_bottleneck,
                collapse_kind,
            )
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
            let summary = item.get("summary").and_then(|x| x.as_str())?.to_string();
            let start_raw = item
                .get("start")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            // Display: keep first 16 chars of ISO timestamp (YYYY-MM-DDTHH:MM).
            let datetime = start_raw
                .chars()
                .take(16)
                .collect::<String>()
                .replace('T', " ");
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
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    let auto = v
        .get("auto")
        .and_then(|x| x.as_bool())
        .or_else(|| v.get("implied_by_full_auto").and_then(|x| x.as_bool()))
        .unwrap_or(false);
    let skillopt = v
        .get("skillopt_installed")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let last = v
        .get("last")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let autonomy = v
        .get("autonomy")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
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
            let id = item.get("id").and_then(|x| x.as_str())?.to_string();
            let title = item
                .get("title")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let desc = item
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
        .map(|item| {
            let id = item
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let title = item
                .get("title")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let status = item
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let ts = item
                .get("ts")
                .or_else(|| item.get("timestamp"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            (id, title, status, ts)
        })
        .collect()
}

// ── FEAT-05 — Self-Dev Proposal Review parse ─────────────────────────────────

/// One decoded proposal from `neoth self-dev review --output json`.
///
/// `patch_path`, `diff_sha256`, and `target_paths` are only populated for
/// `kind == "source_edit"` proposals (GUI-DES-SELFDEV-APPLY-01). They are
/// empty/default for all other proposal kinds.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SelfDevProposalData {
    pub id: String,
    pub kind: String,
    pub confidence: f64,
    pub target: String,
    pub reason: String,
    /// Raw status string from the daemon: "pending" | "accepted" | "declined".
    pub status: String,
    /// Absolute path to the `.patch` file — only set for `kind == "source_edit"`.
    pub patch_path: String,
    /// SHA-256 hex digest of the patch file — TOCTOU guard for the apply subprocess.
    pub diff_sha256: String,
    /// Files the patch touches — display hint for the confirm dialog.
    pub target_paths: Vec<String>,
}

/// Parse `neoth self-dev review --output json` → `Vec<SelfDevProposalData>`.
///
/// Accepts a top-level JSON array `[{id, kind, confidence, target, reason, status, ...}]`
/// or an object with a `"proposals"` key.  Pure + tolerant: missing / malformed
/// input yields an empty vec; unknown extra fields are ignored.
///
/// For `kind == "source_edit"` entries the additional fields `patch_path`,
/// `diff_sha256`, and `target_paths` are extracted; all other kinds leave them
/// as default (empty string / empty vec).
pub fn parse_selfdev_proposals(json: &str) -> Vec<SelfDevProposalData> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("proposals")
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(|x| x.as_str())?.to_string();
            let kind = item
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            let confidence = item
                .get("confidence")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0);
            let target = item
                .get("target")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let reason = item
                .get("reason")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let status = item
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("pending")
                .to_string();
            // SourceEdit-specific fields (null / absent for other kinds).
            let patch_path = item
                .get("patch_path")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let diff_sha256 = item
                .get("diff_sha256")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let target_paths = item
                .get("target_paths")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            Some(SelfDevProposalData {
                id,
                kind,
                confidence,
                target,
                reason,
                status,
                patch_path,
                diff_sha256,
                target_paths,
            })
        })
        .collect()
}

// ── I10 kanban card helpers ───────────────────────────────────────────────────
//
// Pre-format rich task fields into strings/bools that Slint can bind
// directly (no arithmetic in .slint). Both the cold path (`kanban show`)
// and the warm path (`gui-stream board`) call the same helpers so their
// `KanbanTaskRow` values are identical — see the equivalence comment in
// `board_json_to_snapshot`.

/// Format the passing/total test chip text for a kanban card.
///
/// Derives the denominator from the explicit `total` when available,
/// otherwise falls back to `passing + failing` (the two fields we always
/// receive). Returns `""` when `passing` is `None` (no test data yet).
///
/// Single canonical derivation — call this from BOTH cold and warm paths.
pub fn format_tests_string(
    passing: Option<u32>,
    failing: Option<u32>,
    total: Option<u32>,
) -> String {
    let Some(p) = passing else {
        return String::new();
    };
    // Prefer the explicit total the daemon wrote; fall back to sum of known
    // counts so we never show a denominator smaller than the numerator.
    let denom = total.unwrap_or_else(|| p + failing.unwrap_or(0));
    format!("{p}/{denom}")
}

/// Humanize an ETA for a kanban card chip. Pure (takes `now_ns`) so
/// tests can pin the clock without mocking `SystemTime`.
///
/// `eta_ns` is a **duration in nanoseconds** (see `store::assign_task`
/// and the 60-second assertion in `store`'s tests — not an epoch
/// timestamp). When `started_ns` is present the remaining time is
/// `(started_ns + eta_ns) - now_ns`; otherwise the full duration is
/// shown as-is ("how long it will take").
///
/// Returns `""` when `eta_ns` is `None`, the task appears already
/// complete (`started + eta ≤ now`), or the remaining time rounds to 0.
pub fn format_eta_at(eta_ns: Option<u64>, started_ns: Option<u64>, now_ns: u64) -> String {
    let Some(dur) = eta_ns else {
        return String::new();
    };
    let remaining = if let Some(st) = started_ns {
        let end = st.saturating_add(dur);
        if end <= now_ns {
            return String::new(); // already past ETA
        }
        end - now_ns
    } else {
        dur // not started yet — show the planned duration
    };
    let secs = remaining / 1_000_000_000;
    if secs == 0 {
        return String::new();
    }
    if secs < 60 {
        format!("~{secs}s")
    } else if secs < 3_600 {
        format!("~{}m", secs / 60)
    } else {
        format!("~{}h", secs / 3_600)
    }
}

/// Wrapper around [`format_eta_at`] that supplies the current unix time
/// from `SystemTime`. Use in production; use `format_eta_at` in tests.
pub fn format_eta(eta_ns: Option<u64>, started_ns: Option<u64>) -> String {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    format_eta_at(eta_ns, started_ns, now_ns)
}

#[cfg(test)]
mod kanban_card_helpers_tests {
    use super::{format_eta_at, format_tests_string};

    // ── format_tests_string ──────────────────────────────────────────

    #[test]
    fn tests_string_no_data_returns_empty() {
        assert_eq!(format_tests_string(None, None, None), "");
    }

    #[test]
    fn tests_string_passing_only_uses_passing_as_denom() {
        // When only passing is known, denom = passing + 0.
        assert_eq!(format_tests_string(Some(5), None, None), "5/5");
    }

    #[test]
    fn tests_string_with_failing_derives_total() {
        // No explicit total → denom = passing + failing.
        assert_eq!(format_tests_string(Some(8), Some(2), None), "8/10");
    }

    #[test]
    fn tests_string_with_explicit_total_uses_total() {
        // Explicit total wins over the derived sum.
        assert_eq!(format_tests_string(Some(8), Some(2), Some(15)), "8/15");
    }

    #[test]
    fn tests_string_all_zero_passes() {
        assert_eq!(format_tests_string(Some(0), Some(0), Some(0)), "0/0");
    }

    // ── format_eta_at ────────────────────────────────────────────────

    #[test]
    fn eta_none_returns_empty() {
        assert_eq!(format_eta_at(None, None, 0), "");
    }

    #[test]
    fn eta_no_start_shows_full_duration_seconds() {
        // 30 seconds, no start → "~30s"
        assert_eq!(format_eta_at(Some(30_000_000_000), None, 0), "~30s");
    }

    #[test]
    fn eta_no_start_shows_full_duration_minutes() {
        // 5 minutes → "~5m"
        assert_eq!(format_eta_at(Some(5 * 60 * 1_000_000_000), None, 0), "~5m");
    }

    #[test]
    fn eta_no_start_shows_full_duration_hours() {
        // 2 hours → "~2h"
        assert_eq!(
            format_eta_at(Some(2 * 3_600 * 1_000_000_000), None, 0),
            "~2h"
        );
    }

    #[test]
    fn eta_with_start_remaining_minutes() {
        // started at t=0, duration 5min, now at 2min → 3 min left
        let start: u64 = 0;
        let dur: u64 = 5 * 60 * 1_000_000_000;
        let now: u64 = 2 * 60 * 1_000_000_000;
        assert_eq!(format_eta_at(Some(dur), Some(start), now), "~3m");
    }

    #[test]
    fn eta_past_deadline_returns_empty() {
        // started at t=0, 1min duration, now at 90s → past ETA
        let start: u64 = 0;
        let dur: u64 = 60 * 1_000_000_000;
        let now: u64 = 90 * 1_000_000_000;
        assert_eq!(format_eta_at(Some(dur), Some(start), now), "");
    }

    #[test]
    fn eta_warm_cold_equivalence_no_fields() {
        // Both paths with None fields produce ""
        assert_eq!(format_eta_at(None, None, u64::MAX), "");
    }

    // ── backward compat: missing fields → empty/false (parse test) ──

    /// Proves that a warm-channel JSON row without the I10 fields still
    /// produces empty/false chip values after serde(default) parsing.
    /// Uses JSON directly to stay independent of daemon build version.
    #[test]
    fn backward_compat_missing_rich_fields_give_empty_chips() {
        // Simulate an old daemon that sends only the four base fields.
        // The new GuiBoardTaskJson serde(default) annotations must fill
        // in safe zero-values so the chip row stays invisible.
        #[derive(serde::Deserialize)]
        struct MinGuiBoardTask {
            task_id: i64,
            #[serde(default)]
            task_type: String,
            #[serde(default)]
            worker: Option<String>,
            #[serde(default)]
            tests_passing: Option<u32>,
            #[serde(default)]
            tests_failing: Option<u32>,
            #[serde(default)]
            tests_total: Option<u32>,
            #[serde(default)]
            has_patch: bool,
            #[serde(default)]
            parent_task_id: Option<i64>,
            #[serde(default)]
            eta_ns: Option<u64>,
            #[serde(default)]
            started_ns: Option<u64>,
        }
        let json = r#"{"task_id":1,"title":"foo","hemisphere":"left","status":"todo"}"#;
        let t: MinGuiBoardTask = serde_json::from_str(json).expect("parse");
        assert_eq!(t.task_id, 1);
        assert_eq!(t.task_type, "");
        assert!(t.worker.is_none());
        assert!(t.tests_passing.is_none());
        assert!(!t.has_patch);
        assert!(t.parent_task_id.is_none());
        // chip helpers return "" for all-None → chip row stays hidden
        assert_eq!(format_tests_string(t.tests_passing, t.tests_failing, t.tests_total), "");
        assert_eq!(format_eta_at(t.eta_ns, t.started_ns, 9_999_999_999_999_999_999), "");
    }
}

#[cfg(test)]
mod selfdev_tests {
    use super::parse_selfdev_proposals;

    #[test]
    fn parse_selfdev_proposals_happy_path() {
        let json = r#"[
            {"id":"p-001","kind":"refactor","confidence":0.83,"target":"src/foo.rs","reason":"unused import","status":"pending"},
            {"id":"p-002","kind":"lint","confidence":0.91,"target":"src/bar.rs","reason":"dead code"}
        ]"#;
        let rows = parse_selfdev_proposals(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "p-001");
        assert_eq!(rows[0].kind, "refactor");
        assert!((rows[0].confidence - 0.83).abs() < 1e-9);
        assert_eq!(rows[0].target, "src/foo.rs");
        assert_eq!(rows[0].reason, "unused import");
        assert_eq!(rows[0].status, "pending");
        assert_eq!(rows[1].id, "p-002");
        // Missing status field defaults to "pending".
        assert_eq!(rows[1].status, "pending");
    }

    #[test]
    fn parse_selfdev_proposals_malformed_yields_empty() {
        assert!(parse_selfdev_proposals("").is_empty());
        assert!(parse_selfdev_proposals("not json").is_empty());
        assert!(parse_selfdev_proposals("{}").is_empty());
        assert!(parse_selfdev_proposals("[]").is_empty());
        // Entry missing required `id` field → skipped, not fatal.
        let json = r#"[{"kind":"lint","confidence":0.5}]"#;
        assert!(parse_selfdev_proposals(json).is_empty());
    }

    #[test]
    fn parse_selfdev_proposals_source_edit_populates_extra_fields() {
        let json = r#"[{
            "id": "source_edit-deadbeef",
            "kind": "source_edit",
            "confidence": 0.95,
            "target": "src/cli/mod.rs",
            "reason": "performance",
            "status": "accepted",
            "patch_path": "/tmp/edit.patch",
            "diff_sha256": "abc123def456",
            "target_paths": ["src/cli/mod.rs", "src/cli/obsidian.rs"]
        }]"#;
        let rows = parse_selfdev_proposals(json);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.kind, "source_edit");
        assert_eq!(r.status, "accepted");
        assert_eq!(r.patch_path, "/tmp/edit.patch");
        assert_eq!(r.diff_sha256, "abc123def456");
        assert_eq!(
            r.target_paths,
            vec!["src/cli/mod.rs", "src/cli/obsidian.rs"]
        );
    }

    #[test]
    fn parse_selfdev_proposals_unit_variant_has_empty_source_edit_fields() {
        let json = r#"[{
            "id": "switch_preset-aabbccdd",
            "kind": "switch_preset",
            "confidence": 0.8,
            "target": "formal",
            "reason": "drift",
            "status": "pending",
            "patch_path": null,
            "diff_sha256": null,
            "target_paths": null
        }]"#;
        let rows = parse_selfdev_proposals(json);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.kind, "switch_preset");
        assert!(r.patch_path.is_empty());
        assert!(r.diff_sha256.is_empty());
        assert!(r.target_paths.is_empty());
    }
}

// ── Wave 4b parse types ───────────────────────────────────────────────────────

/// One row in the wiki / capability map.
#[derive(Debug, Default)]
pub struct WikiRowData {
    pub id: String,
    pub kind: String,
    pub description: String,
    pub gate: String,
}

/// Snapshot from `neoth buddy status --output json`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuddyStatusSnap {
    pub sovereign_buddy: bool,
    pub self_activation_enabled: bool,
    pub self_activation_skills: Vec<String>,
    pub smart_approve_any: bool,
    pub autonomy: String,
    pub proactive_enabled: bool,
}

/// One peer from `neoth cluster status --output json`.
#[derive(Debug, Default)]
pub struct MeshPeerData {
    pub id: String,
    pub last_seen: String,
    pub reachable: bool,
}

/// Snapshot from `neoth cluster status --output json`.
#[derive(Debug, Default)]
pub struct MeshStatusSnap {
    pub node_id: String,
    pub listen_port: String,
    pub mdns_enabled: bool,
    pub trusted_ssids: String,
    pub peers: Vec<MeshPeerData>,
    pub conflict_count: usize,
    pub gossip_note: String,
}

// ── Wave 4b parse fns ─────────────────────────────────────────────────────────

/// Parse `neoth obsidian status --output json`.
///
/// Expected shape: `{"vault_path":"...", "subdir":"...", "status":"..."}`
/// Returns `(vault_path, subdir, result_text)`.
pub fn parse_obsidian_status(json: &str) -> (String, String, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let vault_path = v
        .get("vault_path")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let subdir = v
        .get("subdir")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let result_text = v
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    (vault_path, subdir, result_text)
}

/// Parse `neoth dream list --output json`.
///
/// Expected shape: `{"days":[{"day":"2026-07-04","entries":3,"path":"..."},...]}`
/// Returns `(Vec<(day, path, entries_i32)>, refreshed_at)`.
pub fn parse_dream_days(json: &str) -> (Vec<(String, String, i32)>, String) {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let refreshed_at = v
        .get("refreshed_at")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let arr = v
        .get("days")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let days = arr
        .iter()
        .filter_map(|item| {
            let day = item.get("day").and_then(|x| x.as_str())?.to_string();
            let path = item
                .get("path")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let entries = item.get("entries").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
            Some((day, path, entries))
        })
        .collect();
    (days, refreshed_at)
}

/// Parse `neoth dream show <day> --output json`.
///
/// Expected shape: `{"entries":[{"day":"...","title":"...","body":"..."},...]}`
/// Returns `Vec<(day, title, body)>`.
pub fn parse_dream_entries(json: &str) -> Vec<(String, String, String)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("entries")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    arr.iter()
        .filter_map(|item| {
            let day = item
                .get("day")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let title = item.get("title").and_then(|x| x.as_str())?.to_string();
            let body = item
                .get("body")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((day, title, body))
        })
        .collect()
}

/// Parse `neoth capabilities --output json` into a list of `WikiRowData`.
///
/// Expected shape: `{"capabilities":[{"id":"...","kind":"...","description":"...","gate":"..."},...]}`
pub fn parse_wiki_rows(json: &str) -> Vec<WikiRowData> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .get("capabilities")
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.iter()
        .map(|item| WikiRowData {
            id: item
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            kind: item
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            description: item
                .get("description")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            gate: item
                .get("gate")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect()
}

/// Filter wiki rows by search text and/or kind — pure, client-side.
pub fn filter_wiki_rows(rows: Vec<WikiRowData>, search: &str, kind: &str) -> Vec<WikiRowData> {
    let search = search.to_lowercase();
    let kind_lc = kind.to_lowercase();
    rows.into_iter()
        .filter(|r| {
            let kind_ok = kind_lc.is_empty() || r.kind.to_lowercase() == kind_lc;
            let search_ok = search.is_empty()
                || r.id.to_lowercase().contains(&search)
                || r.description.to_lowercase().contains(&search)
                || r.kind.to_lowercase().contains(&search);
            kind_ok && search_ok
        })
        .collect()
}

/// Parse `neoth buddy status --output json` → `BuddyStatusSnap`.
///
/// Expected shape: `{"sovereign_buddy":true,"self_activation_enabled":true,
///   "self_activation_skills":["sk1","sk2"],"smart_approve_any":false,
///   "autonomy":"standard","proactive_enabled":true}`
pub fn parse_buddy_status(json: &str) -> Result<BuddyStatusSnap, String> {
    let snapshot: BuddyStatusSnap = serde_json::from_str(json)
        .map_err(|error| format!("invalid Buddy status JSON: {error}"))?;
    if !matches!(
        snapshot.autonomy.as_str(),
        "strict" | "standard" | "elevated" | "full" | "custom"
    ) {
        return Err(format!(
            "Buddy status returned unknown autonomy `{}`",
            snapshot.autonomy
        ));
    }
    if snapshot
        .self_activation_skills
        .iter()
        .any(|skill| skill.trim().is_empty())
    {
        return Err("Buddy status contains an empty self-activation skill id".to_string());
    }
    Ok(snapshot)
}

/// Parse `neoth cluster status --output json` → `MeshStatusSnap`.
///
/// Expected shape: `{"node_id":"...","listen_port":7700,"mdns_enabled":true,
///   "trusted_ssids":["HomeNet"],"conflict_count":0,"gossip":{...},
///   "peers":[{"id":"...","last_seen":"3s ago","reachable":true}]}`
/// On parse failure all fields are empty / defaults (the cluster feature may not be built).
pub fn parse_mesh_status(json: &str) -> MeshStatusSnap {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let node_id = v
        .get("node_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let listen_port = v
        .get("listen_port")
        .map(|x| x.to_string().replace('"', ""))
        .unwrap_or_default();
    let mdns_enabled = v
        .get("mdns_enabled")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let trusted_ssids = v
        .get("trusted_ssids")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let peers = v
        .get("peers")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .map(|p| MeshPeerData {
                    id: p
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    last_seen: p
                        .get("last_seen")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    reachable: p
                        .get("reachable")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();
    let conflict_count = v
        .get("conflict_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as usize;
    let gossip_note = v
        .get("gossip")
        .map(|gossip| {
            let raw = gossip
                .get("replicate_raw_ingress")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let days = gossip
                .get("replay_budget_days")
                .and_then(|x| x.as_u64())
                .unwrap_or(30);
            format!(
                "raw ingress {} · replay window {days} days",
                if raw { "enabled" } else { "disabled" }
            )
        })
        .unwrap_or_default();
    MeshStatusSnap {
        node_id,
        listen_port,
        mdns_enabled,
        trusted_ssids,
        peers,
        conflict_count,
        gossip_note,
    }
}

/// DES-13 — one origin-peer's aggregated backup summary for the Mesh
/// redundancy panel.
#[derive(Debug, Clone, PartialEq)]
pub struct ForeignBackupPeer {
    pub peer: String, // origin peer pubkey (truncated for display)
    pub count: u64,
    pub bytes: u64,
    pub latest_at: i64, // latest received_at unix secs
}

/// DES-13 — aggregate of `neoth cluster events --output json` for the Mesh tab.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ForeignBackupSummary {
    pub peers: Vec<ForeignBackupPeer>,
    pub total_events: u64,
    pub total_bytes: u64,
}

/// DES-13 — parse + aggregate `neoth cluster events --output json`
/// (`idx_foreign_events`) into a per-peer backup summary. The input is a JSON
/// array of `{origin_peer_pk, origin_seq, event_type, payload_bytes,
/// received_at}`. On any parse failure the summary is empty (cluster feature
/// may not be built / no peers paired) — never panics.
pub fn parse_foreign_backup(json: &str) -> ForeignBackupSummary {
    let arr = match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Array(a)) => a,
        _ => return ForeignBackupSummary::default(),
    };
    // Preserve first-seen peer order; aggregate count/bytes/latest per peer.
    let mut order: Vec<String> = Vec::new();
    let mut by_peer: std::collections::HashMap<String, ForeignBackupPeer> =
        std::collections::HashMap::new();
    let mut total_events = 0u64;
    let mut total_bytes = 0u64;
    for e in &arr {
        let peer = e
            .get("origin_peer_pk")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if peer.is_empty() {
            continue;
        }
        let bytes = e.get("payload_bytes").and_then(|x| x.as_u64()).unwrap_or(0);
        let received = e.get("received_at").and_then(|x| x.as_i64()).unwrap_or(0);
        total_events += 1;
        total_bytes += bytes;
        let entry = by_peer.entry(peer.clone()).or_insert_with(|| {
            order.push(peer.clone());
            ForeignBackupPeer {
                peer: peer.clone(),
                count: 0,
                bytes: 0,
                latest_at: 0,
            }
        });
        entry.count += 1;
        entry.bytes += bytes;
        entry.latest_at = entry.latest_at.max(received);
    }
    let peers = order
        .into_iter()
        .filter_map(|k| by_peer.remove(&k))
        .collect();
    ForeignBackupSummary {
        peers,
        total_events,
        total_bytes,
    }
}

/// DES-13 — human byte formatter for the backup panel (B / KB / MB).
pub fn format_backup_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

// ── Chat-surface consent strip helpers ───────────────────────────────────────

/// Parse `neoth autonomy show --output json` → operating-mode string for the
/// chat consent strip pill.
/// JSON shape: `{"mode":"<mode>","autonomy":"<level>","skills_enable_all_bundled":<bool>}`
/// Returns the `mode` field, falling back to the `autonomy` field, then "".
pub fn parse_autonomy_mode(json: &str) -> String {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    v.get("mode")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| v.get("autonomy").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string()
}

/// Parse `neoth consent list --output json` → Vec<(provider, granted)> for the
/// chat consent strip popover.
/// JSON shape: array of `{"provider":"<slug>","granted_unix_ts":<ts>}`.
/// A row is "granted" when it appears in the array (any `granted_unix_ts` value).
/// Also handles the generic `{"granted":bool}` field shape used by `parse_consent`.
pub fn parse_chat_consent_grants(json: &str) -> Vec<(String, bool)> {
    let v = serde_json::from_str::<serde_json::Value>(json).unwrap_or_default();
    let arr = v
        .as_array()
        .or_else(|| v.get("grants").and_then(|x| x.as_array()))
        .cloned()
        .unwrap_or_default();
    arr.iter()
        .filter_map(|item| {
            let provider = item
                .get("provider")
                .or_else(|| item.get("name"))
                .and_then(|x| x.as_str())?
                .to_string();
            // `granted_unix_ts` present → the marker file exists → granted.
            // Fall back to explicit `"granted": bool` for the show-single shape.
            let granted = if item.get("granted_unix_ts").is_some() {
                true
            } else if let Some(b) = item.get("granted").and_then(|x| x.as_bool()) {
                b
            } else {
                item.get("status")
                    .and_then(|s| s.as_str())
                    .map(|s| s == "granted")
                    .unwrap_or(false)
            };
            Some((provider, granted))
        })
        .collect()
}

// ── GAP-01 Cron panel parse helper ───────────────────────────────────────────
//
// Pure function: takes raw JSON from `neoth cron list --output json` and
// returns a typed Vec ready for the Slint model. Tolerant of missing keys,
// wrong types, and non-JSON input (returns empty Vec gracefully).
//
// JSON shape per cli/cron.rs:
//   [{id, name, enabled, cron, tz, role, timeout_seconds, channel, recipient}]
//
// Return tuple per row: (id, name, enabled, cron, tz, role, timeout, channel, recipient)
// where `timeout` is `timeout_seconds` as a display string (empty if 0/absent).
/// Row shape for the cron jobs table:
/// `(id, name, enabled, cron, tz, role, timeout, channel, recipient)`.
pub type CronJobRow = (
    String,
    String,
    bool,
    String,
    String,
    String,
    String,
    String,
    String,
);

pub fn parse_cron_jobs(json: &str) -> Vec<CronJobRow> {
    let arr = match serde_json::from_str::<serde_json::Value>(json) {
        Ok(v) => v.as_array().cloned().unwrap_or_default(),
        Err(_) => return vec![],
    };
    arr.iter()
        .filter_map(|item| {
            let id = item
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                return None; // id is required
            }
            let name = item
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let enabled = item
                .get("enabled")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let cron = item
                .get("cron")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let tz = item
                .get("tz")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let role = item
                .get("role")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let timeout_secs = item
                .get("timeout_seconds")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            let timeout = if timeout_secs > 0 {
                timeout_secs.to_string()
            } else {
                String::new()
            };
            let channel = item
                .get("channel")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let recipient = item
                .get("recipient")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((
                id, name, enabled, cron, tz, role, timeout, channel, recipient,
            ))
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
    fn parse_omi_status_keeps_secrets_presence_only_and_all_consent_switches() {
        let snapshot = parse_omi_status(
            r#"{
                "enabled":true,"mode":"both","endpoint":"https://api.omi.me",
                "listen_addr":"127.0.0.1:8003","configuration_valid":true,
                "developer_api_credential_present":true,"native_ingest_credential_present":true,
                "runtime_state":"healthy","runtime_detail":"ready","pending_audits":2,
                "retention_days":14,"retain_transcripts":true,"audio_enabled":true,
                "visual_enabled":false,"video_enabled":true,"allow_cloud_api":true,
                "allow_cloud_summary":false,"create_actions":true,
                "seed_groundtruth":false,"summary_enabled":true
            }"#,
        );
        assert!(snapshot.enabled);
        assert_eq!(snapshot.mode, "both");
        assert_eq!(snapshot.runtime_state, "healthy");
        assert_eq!(snapshot.pending_audits, 2);
        assert!(snapshot.developer_credential_present);
        assert!(snapshot.native_credential_present);
        assert!(snapshot.retain_transcripts);
        assert!(snapshot.audio_enabled);
        assert!(!snapshot.visual_enabled);
        assert!(snapshot.video_enabled);
        assert!(snapshot.allow_cloud_api);
        assert!(!snapshot.allow_cloud_summary);
        assert!(snapshot.create_actions);
        assert!(!snapshot.seed_groundtruth);
        assert!(snapshot.summary_enabled);
    }

    #[test]
    fn parse_omi_status_rejects_malformed_payload() {
        assert_eq!(parse_omi_status("not json"), OmiSnapshot::default());
    }

    #[test]
    fn parse_omi_status_sparse_payload_keeps_safe_manual_defaults() {
        let snapshot = parse_omi_status(r#"{"enabled":true}"#);
        assert!(snapshot.enabled);
        assert_eq!(snapshot.mode, "developer_api");
        assert_eq!(snapshot.endpoint, "http://127.0.0.1:8002");
        assert_eq!(snapshot.listen_addr, "127.0.0.1:8003");
        assert_eq!(snapshot.runtime_state, "unknown");
        assert_eq!(snapshot.retention_days, 30);
        assert!(snapshot.create_actions);
        assert!(snapshot.seed_groundtruth);
        assert!(snapshot.summary_enabled);
        assert!(!snapshot.audio_enabled);
        assert!(!snapshot.allow_cloud_api);
    }

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

    // ── GUI-HARDWARE-RESOURCES-01: load metrics + backward compat ─────────

    #[test]
    fn parse_hardware_backward_compat_no_load_fields() {
        // Old JSON without cpu_load_pct / gpu_load must parse cleanly with
        // all new fields as None and load_readout empty.
        let json =
            r#"{"cpu":{"brand":"x","physical_cores":1,"logical_cores":1,"frequency_mhz":1}}"#;
        let h = parse_hardware(json);
        assert_eq!(h.cpu_load_pct, None);
        assert_eq!(h.gpu_util_pct, None);
        assert_eq!(h.gpu_temp_c, None);
        assert_eq!(h.gpu_power_w, None);
        assert_eq!(h.load_readout, "");
    }

    #[test]
    fn parse_hardware_load_fields_when_present() {
        let json = r#"{
            "cpu":{"brand":"x","physical_cores":1,"logical_cores":1,"frequency_mhz":1},
            "cpu_load_pct": 23.4,
            "gpu_load": {"util_pct": 41, "temp_c": 62, "power_w": 118}
        }"#;
        let h = parse_hardware(json);
        assert!((h.cpu_load_pct.unwrap() - 23.4).abs() < 1e-6);
        assert_eq!(h.gpu_util_pct, Some(41.0));
        assert_eq!(h.gpu_temp_c, Some(62.0));
        assert_eq!(h.gpu_power_w, Some(118.0));
        assert_eq!(h.load_readout, "CPU 23% · GPU 41% · 62°C · 118W");
    }

    #[test]
    fn parse_hardware_cpu_only_no_gpu_fields() {
        // CPU present, no gpu_load node → GPU slots render "—".
        let json = r#"{"cpu_load_pct": 5.0}"#;
        let h = parse_hardware(json);
        assert_eq!(h.cpu_load_pct, Some(5.0));
        assert_eq!(h.gpu_util_pct, None);
        assert_eq!(h.load_readout, "CPU 5% · GPU — · — · —");
    }

    #[test]
    fn build_load_readout_all_none_is_empty() {
        assert_eq!(build_load_readout(None, None, None, None), "");
    }

    #[test]
    fn build_load_readout_full_values() {
        let r = build_load_readout(Some(23.0), Some(41.0), Some(62.0), Some(118.0));
        assert_eq!(r, "CPU 23% · GPU 41% · 62°C · 118W");
    }

    #[test]
    fn build_load_readout_partial_gpu_absent() {
        let r = build_load_readout(Some(10.0), None, None, None);
        assert_eq!(r, "CPU 10% · GPU — · — · —");
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
        let rows = parse_skills(r#"[{"id":"a","tags":["security","net"]},{"id":"b"}]"#);
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
        let shape: Vec<(bool, &str)> = rows.iter().map(|r| (r.is_header, r.id.as_str())).collect();
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
            {"id":"faccam","name":"FacCam","activation":"active","requested_permission":"read_only"},
            {"id":"x","activation":"reconsent_required","requested_permission":"dangerous","approval_error":"manifest changed"}
        ]"#;
        let rows = parse_plugins(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "faccam");
        assert_eq!(rows[0].name, "FacCam");
        assert_eq!(rows[0].activation, "active");
        assert_eq!(rows[0].requested_permission, "read_only");
        assert_eq!(rows[1].name, "", "missing name -> empty");
        assert_eq!(rows[1].activation, "reconsent_required");
        assert_eq!(rows[1].requested_permission, "dangerous");
    }

    #[test]
    fn parse_plugins_malformed_is_empty() {
        assert!(parse_plugins("nope").is_empty());
        assert!(
            parse_plugins(r#"{"id":"x"}"#).is_empty(),
            "object not array"
        );
        let rows = parse_plugins(r#"[{"name":"no id"},{"id":"ok"}]"#);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requested_permission, "none");
    }

    #[test]
    fn parse_plugins_ui_surface_present() {
        let json = r#"[
            {"id":"feed","name":"Feed","activation":"active",
             "ui_surface":{"kind":"wal_feed","title":"Live Feed"}},
            {"id":"plain","name":"Plain","activation":"disabled"}
        ]"#;
        let rows = parse_plugins(json);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].has_ui_surface);
        assert_eq!(rows[0].ui_title, "Live Feed");
        assert!(!rows[1].has_ui_surface);
        assert_eq!(rows[1].ui_title, "");
    }

    #[test]
    fn parse_plugins_ui_surface_missing_title_defaults_empty() {
        let json = r#"[{"id":"x","activation":"active","ui_surface":{"kind":"wal_feed"}}]"#;
        let rows = parse_plugins(json);
        assert!(rows[0].has_ui_surface);
        assert_eq!(rows[0].ui_title, "");
    }

    #[test]
    fn parse_plugins_ui_surface_not_object_ignored() {
        // ui_surface is a scalar — should treat as absent
        let json = r#"[{"id":"x","activation":"active","ui_surface":"bad"}]"#;
        let rows = parse_plugins(json);
        assert!(!rows[0].has_ui_surface);
    }

    // ── DES-12 parse_plugin_events ────────────────────────────────────────────

    #[test]
    fn parse_plugin_events_happy_path() {
        let json = r#"{"id":"feed","events":[
            {"kind":"wal::commit","payload_bytes":128,"ts_unix":1700000000},
            {"kind":"wal::read","payload_bytes":0,"ts_unix":1700000060}
        ]}"#;
        let rows = parse_plugin_events(json);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, "wal::commit");
        assert_eq!(rows[0].payload_bytes, 128);
        assert_eq!(rows[0].ts_unix, 1700000000);
        assert_eq!(rows[1].kind, "wal::read");
        assert_eq!(rows[1].payload_bytes, 0);
    }

    #[test]
    fn parse_plugin_events_empty_array() {
        let json = r#"{"id":"feed","events":[]}"#;
        assert!(parse_plugin_events(json).is_empty());
    }

    #[test]
    fn parse_plugin_events_no_events_key() {
        // not-found / daemon returns {"id":"x"} with no "events" field
        assert!(parse_plugin_events(r#"{"id":"x"}"#).is_empty());
    }

    #[test]
    fn parse_plugin_events_malformed_json() {
        assert!(parse_plugin_events("not json").is_empty());
        assert!(parse_plugin_events("[]").is_empty()); // array at root, no "events" key
    }

    #[test]
    fn parse_plugin_events_kind_less_entries_skipped() {
        // entry without "kind" must be skipped; entry with kind survives
        let json = r#"{"id":"x","events":[
            {"payload_bytes":10,"ts_unix":1},
            {"kind":"ok","payload_bytes":20,"ts_unix":2}
        ]}"#;
        let rows = parse_plugin_events(json);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "ok");
    }

    #[test]
    fn parse_plugin_events_missing_numeric_fields_default_zero() {
        let json = r#"{"id":"x","events":[{"kind":"evt"}]}"#;
        let rows = parse_plugin_events(json);
        assert_eq!(rows[0].payload_bytes, 0);
        assert_eq!(rows[0].ts_unix, 0);
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

    // ── GOLD-R3-04 canonical channel status ──────────────────────────────────

    fn registry_row(channel_id: &str, aliases: &[&str]) -> serde_json::Value {
        let contract = gui_channel_contract(channel_id).expect("test channel has GUI contract");
        let descriptor = neothd::channels::registry::channel_descriptors()
            .iter()
            .find(|descriptor| descriptor.id.as_str() == channel_id)
            .expect("test channel has core registry descriptor");
        let setup_fields = contract
            .setup_fields
            .iter()
            .zip(descriptor.setup_fields)
            .map(|(field, descriptor_field)| {
                let requirement = match field.requirement {
                    GuiSetupRequirement::Required => "required",
                    GuiSetupRequirement::Optional => "optional",
                    GuiSetupRequirement::OneOf => "one_of",
                };
                serde_json::json!({
                    "key": field.key,
                    "secret": descriptor_field.secret,
                    "requirement": requirement,
                    "one_of_group": field.one_of_group,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "id": channel_id,
            "aliases": aliases,
            "migration_aliases": [],
            "setup_fields": setup_fields,
        })
    }

    #[test]
    fn parse_channel_status_preserves_probe_states_and_detail() {
        let states = ["ok", "warn", "error", "unavailable", "not_configured"];
        let ids = ["telegram", "slack", "discord", "keet", "gchat"];
        let channel_rows = ids
            .iter()
            .enumerate()
            .map(|(index, name)| {
                serde_json::json!({
                    "name": name,
                    "status": states[index % states.len()],
                    "configured": index % states.len() < 3,
                    "detail": format!("probe detail {index}"),
                })
            })
            .collect::<Vec<_>>();
        let registry_rows = ids
            .iter()
            .map(|id| registry_row(id, &[]))
            .collect::<Vec<_>>();
        let payload = serde_json::json!({
            "registry": { "schema_version": 1, "channels": registry_rows },
            "channels": channel_rows,
            "configured": 3,
            "total": ids.len(),
        });
        let rows = parse_channel_status(&payload.to_string()).unwrap();
        assert_eq!(rows.len(), ids.len());
        assert_eq!(rows[0].status, "ok");
        assert_eq!(rows[1].status, "warn");
        assert_eq!(rows[2].name, "discord");
        assert!(rows[2].configured);
        assert_eq!(rows[2].detail, "probe detail 2");
        assert_eq!(rows[3].status, "unavailable");
        assert_eq!(rows[4].status, "not_configured");
    }

    #[test]
    fn real_core_registry_has_gui_schema_and_private_builder_for_every_canonical_id() {
        let descriptors = neothd::channels::registry::channel_descriptors();
        let channel_rows = descriptors
            .iter()
            .map(|descriptor| {
                serde_json::json!({
                    "name": descriptor.id.as_str(),
                    "status": "not_configured",
                    "configured": false,
                    "detail": "not configured",
                })
            })
            .collect::<Vec<_>>();
        let payload = serde_json::json!({
            "registry": {
                "schema_version": neothd::channels::registry::CHANNEL_REGISTRY_SCHEMA_VERSION,
                "channels": descriptors,
            },
            "channels": channel_rows,
            "configured": 0,
            "total": descriptors.len(),
        });

        let rows = parse_channel_status(&payload.to_string()).unwrap();
        assert_eq!(rows.len(), descriptors.len());
        for (row, descriptor) in rows.iter().zip(descriptors) {
            let mut expected_secret_mask = [false; 6];
            for (slot, field) in descriptor.setup_fields.iter().take(6).enumerate() {
                expected_secret_mask[slot] = field.secret;
            }
            assert_eq!(
                row.setup_secret_mask,
                expected_secret_mask,
                "{} secret mask must come from the core descriptor",
                descriptor.id.as_str()
            );
            let request = build_channel_credential_request(descriptor.id.as_str(), ["1"; 6], true)
                .unwrap_or_else(|error| panic!("{}: {error}", descriptor.id.as_str()));
            let envelope: serde_json::Value = serde_json::from_slice(request.as_slice()).unwrap();
            assert_eq!(envelope["schema_version"], 1);
            assert_eq!(envelope["channel"], descriptor.id.as_str());
            assert!(
                envelope["fields"]
                    .as_object()
                    .is_some_and(|fields| !fields.is_empty()),
                "{} must emit private credential fields",
                descriptor.id.as_str()
            );
        }
    }

    #[test]
    fn private_channel_builder_preserves_typed_fields_without_cli_flags() {
        let telegram = build_channel_credential_request(
            "telegram",
            ["bot-secret", "123456789", "", "", "", ""],
            false,
        )
        .unwrap();
        let telegram: serde_json::Value = serde_json::from_slice(telegram.as_slice()).unwrap();
        assert_eq!(telegram["channel"], "telegram");
        assert_eq!(telegram["fields"]["token"], "bot-secret");
        assert_eq!(telegram["fields"]["telegram_user_id"], 123_456_789);

        let discord = build_channel_credential_request(
            "discord",
            ["discord-secret", "123456789012345678", "", "", "", ""],
            false,
        )
        .unwrap();
        let discord: serde_json::Value = serde_json::from_slice(discord.as_slice()).unwrap();
        assert_eq!(discord["fields"]["token"], "discord-secret");
        assert_eq!(discord["fields"]["allowed_sender"], "123456789012345678");
        for invalid in ["0", "01", "owner", "18446744073709551616"] {
            assert!(
                build_channel_credential_request(
                    "discord",
                    ["discord-secret", invalid, "", "", "", ""],
                    false,
                )
                .is_err(),
                "Discord identity `{invalid}` must fail closed",
            );
        }

        let slack = build_channel_credential_request(
            "slack",
            ["xoxb-secret", "xapp-secret", "U123456", "", "", ""],
            false,
        )
        .unwrap();
        let slack: serde_json::Value = serde_json::from_slice(slack.as_slice()).unwrap();
        assert_eq!(slack["fields"]["allowed_sender"], "U123456");

        let whatsapp = build_channel_credential_request(
            "whatsapp_business",
            [
                "meta-token",
                "12345",
                "verify",
                "secret",
                "+491701234567",
                "",
            ],
            false,
        )
        .unwrap();
        let whatsapp: serde_json::Value = serde_json::from_slice(whatsapp.as_slice()).unwrap();
        assert_eq!(whatsapp["fields"]["allowed_sender"], "+491701234567");

        let signal = build_channel_credential_request(
            "signal",
            [
                "http://127.0.0.1:8080",
                "+491701111111",
                "+491702222222",
                "",
                "",
                "",
            ],
            false,
        )
        .unwrap();
        let signal: serde_json::Value = serde_json::from_slice(signal.as_slice()).unwrap();
        assert_eq!(signal["fields"]["allowed_sender"], "+491702222222");

        let line = build_channel_credential_request(
            "line",
            ["line-token", "line-secret", "U123456", "", "", ""],
            false,
        )
        .unwrap();
        let line: serde_json::Value = serde_json::from_slice(line.as_slice()).unwrap();
        assert_eq!(line["fields"]["allowed_sender"], "U123456");

        let matrix = build_channel_credential_request(
            "matrix",
            [
                "https://matrix.example.org",
                "@neoth:example.org",
                "matrix-secret",
                "",
                "@owner:example.org",
                "!room:example.org",
            ],
            true,
        )
        .unwrap();
        let matrix: serde_json::Value = serde_json::from_slice(matrix.as_slice()).unwrap();
        assert_eq!(matrix["fields"]["token"], "matrix-secret");
        assert_eq!(matrix["fields"]["password"], serde_json::Value::Null);
        assert_eq!(matrix["fields"]["allow_plaintext"], true);
    }

    #[test]
    fn private_channel_builder_preserves_secret_bytes_and_normalizes_public_fields() {
        let secret = " \tSëcret value\n ";
        let request = build_channel_credential_request(
            "matrix",
            [
                "  https://matrix.example.org  ",
                "  @neoth:example.org  ",
                secret,
                "",
                "  @owner:example.org  ",
                "  !room:example.org  ",
            ],
            false,
        )
        .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(request.as_slice()).unwrap();
        let fields = &envelope["fields"];
        assert_eq!(fields["url"], "https://matrix.example.org");
        assert_eq!(fields["nick"], "@neoth:example.org");
        assert_eq!(fields["allowed_sender"], "@owner:example.org");
        assert_eq!(fields["allowed_rooms_csv"], "!room:example.org");
        assert_eq!(
            fields["token"].as_str().unwrap().as_bytes(),
            secret.as_bytes()
        );

        let irc = build_channel_credential_request(
            "irc",
            [
                " irc.example.org ",
                " neoth ",
                secret,
                " #neoth ",
                " operator ",
                "",
            ],
            false,
        )
        .unwrap();
        let irc: serde_json::Value = serde_json::from_slice(irc.as_slice()).unwrap();
        assert_eq!(
            irc["fields"]["password"].as_str().unwrap().as_bytes(),
            secret.as_bytes()
        );
        assert_eq!(irc["fields"]["server"], "irc.example.org");
        assert_eq!(irc["fields"]["channels_csv"], "#neoth");
    }

    #[test]
    fn private_channel_builder_rejects_whitespace_only_required_secrets() {
        assert!(
            build_channel_credential_request("discord", [" \t\n ", "", "", "", "", ""], false,)
                .is_err()
        );
        assert!(
            build_channel_credential_request(
                "matrix",
                [
                    "https://matrix.example.org",
                    "@neoth:example.org",
                    "  ",
                    "\t",
                    "@owner:example.org",
                    "",
                ],
                false,
            )
            .is_err()
        );
        assert!(
            build_channel_credential_request(
                "imessage_bluebubbles",
                ["https://blue.example.org", "  ", "+491234", "", "", ""],
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn parse_channel_status_binds_descriptor_secrets_and_rejects_unknown_form() {
        let mut telegram = registry_row("telegram", &[]);
        telegram["setup_fields"][1]["secret"] = serde_json::json!(true);
        let descriptor_secret = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [telegram] },
            "channels": [{
                "name": "telegram",
                "status": "not_configured",
                "configured": false,
                "detail": "off",
            }],
            "configured": 0,
            "total": 1,
        });
        let rows = parse_channel_status(&descriptor_secret.to_string()).unwrap();
        assert_eq!(
            rows[0].setup_secret_mask,
            [true, true, false, false, false, false]
        );

        let mut matrix = registry_row("matrix", &[]);
        matrix["setup_fields"][6]["secret"] = serde_json::json!(true);
        let unrenderable_secret = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [matrix] },
            "channels": [{
                "name": "matrix",
                "status": "not_configured",
                "configured": false,
                "detail": "off",
            }],
            "configured": 0,
            "total": 1,
        });
        assert!(
            parse_channel_status(&unrenderable_secret.to_string())
                .unwrap_err()
                .contains("secret setup field without a GUI password slot")
        );

        let unknown_form = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [{
                "id": "future_chat",
                "aliases": [],
                "migration_aliases": [],
                "setup_fields": [{
                    "key": "future_token",
                    "secret": true,
                    "requirement": "required",
                }],
            }] },
            "channels": [{
                "name": "future_chat",
                "status": "not_configured",
                "configured": false,
                "detail": "off",
            }],
            "configured": 0,
            "total": 1,
        });
        assert!(
            parse_channel_status(&unknown_form.to_string())
                .unwrap_err()
                .contains("no GUI setup/form binding")
        );
    }

    #[test]
    fn parse_channel_status_rejects_malformed_empty_duplicate_and_unknown() {
        assert!(parse_channel_status("not json").is_err());
        assert!(parse_channel_status(r#"{"channels":[],"total":0}"#).is_err());
        assert!(
            parse_channel_status(
                r#"{"registry":{"schema_version":1,"channels":[{"id":"keet","aliases":[],"migration_aliases":[]}]},"channels":[
                {"name":"keet","status":"ok","configured":true,"detail":"a"},
                {"name":"keet","status":"warn","configured":true,"detail":"b"}
            ],"configured":2,"total":2}"#
            )
            .is_err()
        );
        assert!(parse_channel_status(
            r#"{"registry":{"schema_version":1,"channels":[{"id":"telegram","aliases":[],"migration_aliases":[]}]},"channels":[{"name":"telegram","status":"maybe","configured":true,"detail":"?"}],"configured":1,"total":1}"#
        )
        .is_err());
    }

    #[test]
    fn parse_channel_status_rejects_partial_unknown_and_mismatched_inventory() {
        let partial = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [
                registry_row("telegram", &[]),
                registry_row("slack", &[]),
            ]},
            "channels": [
                { "name": "telegram", "status": "ok", "configured": true, "detail": "live" },
                { "name": "future_chat", "status": "not_configured", "configured": false, "detail": "off" },
            ],
            "configured": 1,
            "total": 2,
        });
        let error = parse_channel_status(&partial.to_string()).unwrap_err();
        assert!(error.contains("registry drift"));
        assert!(error.contains("slack"));
        assert!(error.contains("future_chat"));

        let mismatch = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [
                registry_row("telegram", &[]),
                registry_row("slack", &[]),
            ]},
            "channels": [{
                "name": "telegram",
                "status": "ok",
                "configured": true,
                "detail": "live",
            }],
            "configured": 1,
            "total": 2,
        });
        assert!(
            parse_channel_status(&mismatch.to_string())
                .unwrap_err()
                .contains("does not match")
        );
    }

    #[test]
    fn parse_channel_status_rejects_registry_alias_drift_and_order_drift() {
        let duplicate_alias = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [
                registry_row("telegram", &["chat"]),
                registry_row("slack", &["chat"]),
            ]},
            "channels": [
                { "name": "telegram", "status": "not_configured", "configured": false, "detail": "off" },
                { "name": "slack", "status": "not_configured", "configured": false, "detail": "off" },
            ],
            "configured": 0,
            "total": 2,
        });
        assert!(
            parse_channel_status(&duplicate_alias.to_string())
                .unwrap_err()
                .contains("duplicate operator name")
        );

        let wrong_order = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [
                registry_row("telegram", &[]),
                registry_row("slack", &[]),
            ]},
            "channels": [
                { "name": "slack", "status": "not_configured", "configured": false, "detail": "off" },
                { "name": "telegram", "status": "not_configured", "configured": false, "detail": "off" },
            ],
            "configured": 0,
            "total": 2,
        });
        assert!(
            parse_channel_status(&wrong_order.to_string())
                .unwrap_err()
                .contains("order differs")
        );

        let summary_drift = serde_json::json!({
            "registry": { "schema_version": 1, "channels": [
                registry_row("telegram", &[]),
            ]},
            "channels": [
                { "name": "telegram", "status": "ok", "configured": true, "detail": "ready" },
            ],
            "configured": 0,
            "total": 1,
        });
        assert!(
            parse_channel_status(&summary_drift.to_string())
                .unwrap_err()
                .contains("configured count")
        );
    }

    #[test]
    fn parse_channel_test_status_preserves_non_success_verdicts() {
        let failed = parse_channel_test_status(
            r#"{"channel":"keet","status":"fail","detail":"bridge offline"}"#,
            "keet",
        )
        .unwrap();
        assert_eq!(failed.status, "fail");
        assert_eq!(failed.detail, "bridge offline");

        let skipped = parse_channel_test_status(
            r#"{"channel":"matrix","status":"skipped","detail":"no live probe"}"#,
            "matrix",
        )
        .unwrap();
        assert_eq!(skipped.status, "skipped");

        let unavailable = parse_channel_test_status(
            r#"{"channel":"irc","status":"unavailable","detail":"no safe auth probe"}"#,
            "irc",
        )
        .unwrap();
        assert_eq!(unavailable.status, "unavailable");
        assert_eq!(unavailable.detail, "no safe auth probe");

        let multiline = parse_channel_test_status(
            r#"{"channel":"signal","status":"fail","detail":"Connection refused\n\tverify signal-cli with neoth doctor"}"#,
            "signal",
        )
        .unwrap();
        assert_eq!(
            multiline.detail,
            "Connection refused\n\tverify signal-cli with neoth doctor"
        );
    }

    #[test]
    fn parse_channel_test_status_rejects_mismatch_unknown_and_bad_detail() {
        assert!(
            parse_channel_test_status(
                r#"{"channel":"slack","status":"ok","detail":"live"}"#,
                "telegram"
            )
            .is_err()
        );
        assert!(
            parse_channel_test_status(
                r#"{"channel":"keet","status":"maybe","detail":"live"}"#,
                "keet"
            )
            .is_err()
        );
        assert!(
            parse_channel_test_status(r#"{"channel":"keet","status":"ok","detail":""}"#, "keet")
                .is_err()
        );
        assert!(
            parse_channel_test_status(
                r#"{"channel":"keet","status":"fail","detail":"bad\u0007detail"}"#,
                "keet"
            )
            .is_err()
        );
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
        assert!(
            parse_apply_plan("{}").is_none(),
            "missing name field → None"
        );
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
        let (chip, detail) = format_stream_metrics(12_400, 200_000, 12_000, 400, 10_000).unwrap();
        assert_eq!(chip, "ctx 6% · 40 tok/s");
        assert!(
            detail.contains("context: 12.4k / 200.0k tokens (6%)"),
            "{detail}"
        );
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
        (
            id,
            "12:00".to_string(),
            kind.to_string(),
            "T".to_string(),
            "D".to_string(),
            active,
        )
    }

    #[test]
    fn next_activity_id_monotonic_and_no_collision() {
        assert_eq!(next_activity_id(&[]), 1);
        let rows = vec![make_row(1, "plan", true), make_row(5, "loop", false)];
        assert_eq!(next_activity_id(&rows), 6);
    }

    #[test]
    fn cap_activity_keeps_newest_n_rows() {
        let rows = vec![
            make_row(3, "plan", true),
            make_row(2, "kanban", false),
            make_row(1, "loop", false),
        ];
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
        let toasts = vec![
            make_toast(3, "info", "A", ""),
            make_toast(7, "warn", "B", ""),
        ];
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
    fn parse_calendar_next_fallback_is_utf8_boundary_safe() {
        let json = r#"{"events":[{"start":"日本語予定","summary":"祝日"}]}"#;
        let (configured, events) = super::parse_calendar_next(json, 1);
        assert!(configured);
        assert_eq!(events, vec![("日本語予定".to_string(), "祝日".to_string())]);
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
        let json = r#"{"enabled":true,"threshold":0.42,"epsilon_calibrated":0.01,"federate":false,"total_windows":120,"collapse_flagged":3,"memory_signals":{"enabled":true,"mapping_version":"BabelSignalMap_v1"},"skill_signals":{"enabled":false,"mapping_version":"BabelSignalMap_v1"},"k_d":{"mode":"embedding_v1","requested_model":"org/embed","last_window_posture":{"degraded_reason":"provider_error"}},"windows_by_granularity":[{"window_secs":300,"count":60,"last_ts_end":"2026-07-04T10:00:00Z"}]}"#;
        let status = super::parse_babel_status(json);
        assert!(status.enabled);
        assert!(!status.threshold.is_empty());
        assert_eq!(status.epsilon, "0.01");
        assert!(!status.federate);
        assert_eq!(status.total_windows, 120);
        assert_eq!(status.collapse_flagged, 3);
        assert_eq!(status.memory_signals, "enabled (BabelSignalMap_v1)");
        assert_eq!(status.skill_signals, "disabled (BabelSignalMap_v1)");
        assert_eq!(
            status.k_d,
            "embedding_v1 / org/embed / degraded: provider_error"
        );
        assert_eq!(status.gran_rows.len(), 1);
        assert_eq!(status.gran_rows[0].0, 300);
        assert_eq!(status.gran_rows[0].1, 60);
    }

    #[test]
    fn parse_babel_status_malformed_returns_defaults() {
        let status = super::parse_babel_status("not json");
        assert!(!status.enabled);
        assert_eq!(status.total_windows, 0);
        assert!(status.gran_rows.is_empty());
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
        assert!(
            (rows[0].6 - 1.0).abs() < 0.01,
            "bottleneck must clamp to 1.0"
        );
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
    fn parse_calendar_events_unicode_start_is_boundary_safe() {
        let json = r#"{"events":[{"summary":"Holiday","start":"日本語予定🌍abcdefghijklmnop","location":"Home"}]}"#;
        let (configured, events) = super::parse_calendar_events(json);
        assert!(configured);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0.chars().count(), 16);
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

    // ── Wave 4b: parse_obsidian_status ────────────────────────────────────────

    #[test]
    fn parse_obsidian_status_happy_path() {
        let json = r#"{"vault_path":"/home/alex/vault","subdir":"notes","status":"synced"}"#;
        let (vp, sub, st) = super::parse_obsidian_status(json);
        assert_eq!(vp, "/home/alex/vault");
        assert_eq!(sub, "notes");
        assert_eq!(st, "synced");
    }

    #[test]
    fn parse_obsidian_status_malformed_returns_empty() {
        let (vp, sub, st) = super::parse_obsidian_status("not json");
        assert!(vp.is_empty());
        assert!(sub.is_empty());
        assert!(st.is_empty());
    }

    // ── Wave 4b: parse_dream_days ─────────────────────────────────────────────

    #[test]
    fn parse_dream_days_happy_path() {
        let json = r#"{"days":[{"day":"2026-07-04","path":"/dreams/2026-07-04.md","entries":3}],"refreshed_at":"10:00"}"#;
        let (days, ts) = super::parse_dream_days(json);
        assert_eq!(days.len(), 1);
        assert_eq!(days[0].0, "2026-07-04");
        assert_eq!(days[0].2, 3);
        assert_eq!(ts, "10:00");
    }

    #[test]
    fn parse_dream_days_malformed_returns_empty() {
        let (days, _) = super::parse_dream_days("not json");
        assert!(days.is_empty());
    }

    // ── Wave 4b: parse_dream_entries ─────────────────────────────────────────

    #[test]
    fn parse_dream_entries_happy_path() {
        let json = r#"{"entries":[{"day":"2026-07-04","title":"Dream of code","body":"I wrote Rust all night"}]}"#;
        let entries = super::parse_dream_entries(json);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, "Dream of code");
        assert_eq!(entries[0].2, "I wrote Rust all night");
    }

    #[test]
    fn parse_dream_entries_malformed_returns_empty() {
        assert!(super::parse_dream_entries("not json").is_empty());
        assert!(super::parse_dream_entries(r#"{"entries":[]}"#).is_empty());
    }

    // ── Wave 4b: parse_wiki_rows + filter_wiki_rows ───────────────────────────

    #[test]
    fn parse_wiki_rows_happy_path() {
        let json =
            r#"{"capabilities":[{"id":"CAP-01","kind":"tool","description":"A tool","gate":""}]}"#;
        let rows = super::parse_wiki_rows(json);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "CAP-01");
        assert_eq!(rows[0].kind, "tool");
    }

    #[test]
    fn parse_wiki_rows_malformed_returns_empty() {
        assert!(super::parse_wiki_rows("not json").is_empty());
        assert!(super::parse_wiki_rows("{}").is_empty());
    }

    #[test]
    fn filter_wiki_rows_by_kind() {
        let rows = vec![
            super::WikiRowData {
                id: "A".into(),
                kind: "tool".into(),
                description: "desc".into(),
                gate: "".into(),
            },
            super::WikiRowData {
                id: "B".into(),
                kind: "skill".into(),
                description: "desc".into(),
                gate: "".into(),
            },
        ];
        let filtered = super::filter_wiki_rows(rows, "", "tool");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "A");
    }

    #[test]
    fn filter_wiki_rows_by_search() {
        let rows = vec![
            super::WikiRowData {
                id: "CAP-01".into(),
                kind: "tool".into(),
                description: "compiler".into(),
                gate: "".into(),
            },
            super::WikiRowData {
                id: "CAP-02".into(),
                kind: "tool".into(),
                description: "debugger".into(),
                gate: "".into(),
            },
        ];
        let filtered = super::filter_wiki_rows(rows, "comp", "");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "CAP-01");
    }

    // ── Wave 4b: parse_buddy_status ───────────────────────────────────────────

    #[test]
    fn parse_buddy_status_happy_path() {
        let json = r#"{"sovereign_buddy":true,"self_activation_enabled":true,"self_activation_skills":["code","review"],"smart_approve_any":true,"autonomy":"standard","proactive_enabled":true}"#;
        let snap = super::parse_buddy_status(json).expect("valid Buddy status");
        assert!(snap.sovereign_buddy);
        assert!(snap.self_activation_enabled);
        assert_eq!(snap.self_activation_skills.len(), 2);
        assert_eq!(snap.self_activation_skills[0], "code");
        assert!(snap.smart_approve_any);
        assert_eq!(snap.autonomy, "standard");
        assert!(snap.proactive_enabled);
    }

    #[test]
    fn parse_buddy_status_rejects_malformed_or_lossy_payloads() {
        assert!(super::parse_buddy_status("not json").is_err());
        assert!(
            super::parse_buddy_status(
                r#"{"sovereign_buddy":false,"self_activation_enabled":false,"self_activation_skills":[],"smart_approve_any":false,"autonomy":"standard"}"#
            )
            .is_err(),
            "missing proactive_enabled must not render as false"
        );
        assert!(
            super::parse_buddy_status(
                r#"{"sovereign_buddy":false,"self_activation_enabled":"false","self_activation_skills":[],"smart_approve_any":false,"autonomy":"standard","proactive_enabled":false}"#
            )
            .is_err(),
            "wrong-typed booleans must not render as false"
        );
        assert!(
            super::parse_buddy_status(
                r#"{"sovereign_buddy":false,"self_activation_enabled":false,"self_activation_skills":[],"smart_approve_any":false,"autonomy":"future","proactive_enabled":false}"#
            )
            .is_err(),
            "unknown autonomy must be explicit"
        );
    }

    // ── Wave 4b: parse_mesh_status ────────────────────────────────────────────

    #[test]
    fn parse_mesh_status_happy_path() {
        let json = r#"{"node_id":"node-abc","listen_port":7700,"mdns_enabled":true,"trusted_ssids":["HomeNet"],"conflict_count":2,"gossip":{"replicate_raw_ingress":false,"replay_budget_days":14},"peers":[{"id":"peer-1","last_seen":"3s ago","reachable":true}]}"#;
        let snap = super::parse_mesh_status(json);
        assert_eq!(snap.node_id, "node-abc");
        assert!(snap.listen_port.contains("7700"));
        assert!(snap.mdns_enabled);
        assert!(snap.trusted_ssids.contains("HomeNet"));
        assert_eq!(snap.peers.len(), 1);
        assert!(snap.peers[0].reachable);
        assert_eq!(snap.conflict_count, 2);
        assert_eq!(
            snap.gossip_note,
            "raw ingress disabled · replay window 14 days"
        );
    }

    #[test]
    fn parse_mesh_status_malformed_returns_empty() {
        let snap = super::parse_mesh_status("not json");
        assert!(snap.node_id.is_empty());
        assert!(snap.peers.is_empty());
    }

    // ── parse_autonomy_mode ──────────────────────────────────────────────────

    #[test]
    fn parse_autonomy_mode_mode_field_preferred() {
        let json = r#"{"mode":"gated","autonomy":"standard","skills_enable_all_bundled":false}"#;
        assert_eq!(super::parse_autonomy_mode(json), "gated");
    }

    #[test]
    fn parse_autonomy_mode_full_auto() {
        let json = r#"{"mode":"full-auto","autonomy":"full","skills_enable_all_bundled":true}"#;
        assert_eq!(super::parse_autonomy_mode(json), "full-auto");
    }

    #[test]
    fn parse_autonomy_mode_falls_back_to_autonomy_field() {
        // Missing "mode" key — fall back to "autonomy".
        let json = r#"{"autonomy":"elevated"}"#;
        assert_eq!(super::parse_autonomy_mode(json), "elevated");
    }

    #[test]
    fn parse_autonomy_mode_malformed_returns_empty() {
        assert_eq!(super::parse_autonomy_mode("not json"), "");
        assert_eq!(super::parse_autonomy_mode("{}"), "");
    }

    // ── parse_chat_consent_grants ────────────────────────────────────────────

    #[test]
    fn parse_chat_consent_grants_granted_unix_ts_means_granted() {
        let json = r#"[{"provider":"anthropic_api","granted_unix_ts":1720000000},{"provider":"openai","granted_unix_ts":1720001000}]"#;
        let grants = super::parse_chat_consent_grants(json);
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].0, "anthropic_api");
        assert!(grants[0].1);
        assert_eq!(grants[1].0, "openai");
        assert!(grants[1].1);
    }

    #[test]
    fn parse_chat_consent_grants_explicit_bool_field() {
        // `granted: false` row — marker absent, so not granted.
        let json =
            r#"[{"provider":"gemini","granted":false},{"provider":"mistral","granted":true}]"#;
        let grants = super::parse_chat_consent_grants(json);
        assert_eq!(grants.len(), 2);
        assert!(!grants[0].1);
        assert!(grants[1].1);
    }

    #[test]
    fn parse_chat_consent_grants_empty_array() {
        assert!(super::parse_chat_consent_grants("[]").is_empty());
    }

    #[test]
    fn parse_chat_consent_grants_malformed_returns_empty() {
        assert!(super::parse_chat_consent_grants("not json").is_empty());
    }

    // ── GAP-01 parse_cron_jobs ────────────────────────────────────────────────

    #[test]
    fn parse_cron_jobs_happy_path() {
        let json = r#"[
            {"id":"daily-summary","name":"Daily Summary","enabled":true,
             "cron":"0 7 * * *","tz":"UTC","role":"","timeout_seconds":120,
             "channel":"telegram","recipient":"12345"},
            {"id":"weekly-report","name":"Weekly Report","enabled":false,
             "cron":"0 9 * * 1","tz":"Europe/Berlin","role":"","timeout_seconds":0,
             "channel":"","recipient":""}
        ]"#;
        let rows = super::parse_cron_jobs(json);
        assert_eq!(rows.len(), 2);
        let (id, name, enabled, cron, tz, _role, timeout, channel, recipient) = &rows[0];
        assert_eq!(id, "daily-summary");
        assert_eq!(name, "Daily Summary");
        assert!(enabled);
        assert_eq!(cron, "0 7 * * *");
        assert_eq!(tz, "UTC");
        assert_eq!(timeout, "120");
        assert_eq!(channel, "telegram");
        assert_eq!(recipient, "12345");
        let (id2, _name, enabled2, _cron, _tz, _role, timeout2, channel2, _rcpt) = &rows[1];
        assert_eq!(id2, "weekly-report");
        assert!(!enabled2);
        assert_eq!(timeout2, "", "timeout_seconds=0 → empty string");
        assert_eq!(channel2, "");
    }

    #[test]
    fn parse_cron_jobs_empty_array() {
        assert!(super::parse_cron_jobs("[]").is_empty());
    }

    #[test]
    fn parse_cron_jobs_malformed_non_json() {
        assert!(super::parse_cron_jobs("unavailable — binary not found").is_empty());
    }

    #[test]
    fn parse_cron_jobs_skips_rows_without_id() {
        let json = r#"[
            {"name":"no-id","enabled":true,"cron":"* * * * *"},
            {"id":"has-id","enabled":false,"cron":"0 0 * * *"}
        ]"#;
        let rows = super::parse_cron_jobs(json);
        assert_eq!(rows.len(), 1, "row without id must be skipped");
        assert_eq!(rows[0].0, "has-id");
    }

    #[test]
    fn parse_cron_jobs_tolerates_missing_optional_fields() {
        let json = r#"[{"id":"minimal","cron":"*/5 * * * *","enabled":true}]"#;
        let rows = super::parse_cron_jobs(json);
        assert_eq!(rows.len(), 1);
        let (id, name, enabled, cron, tz, _role, timeout, channel, recipient) = &rows[0];
        assert_eq!(id, "minimal");
        assert_eq!(name, "", "missing name → empty string");
        assert!(enabled);
        assert_eq!(cron, "*/5 * * * *");
        assert_eq!(tz, "");
        assert_eq!(timeout, "");
        assert_eq!(channel, "");
        assert_eq!(recipient, "");
    }

    // ── DES-13 foreign-backup aggregation ─────────────────────────────────
    #[test]
    fn parse_foreign_backup_aggregates_per_peer() {
        let json = r#"[
            {"origin_peer_pk":"aaaa1111","origin_seq":1,"event_type":"0x32","payload_bytes":100,"received_at":1000},
            {"origin_peer_pk":"aaaa1111","origin_seq":2,"event_type":"0x33","payload_bytes":50,"received_at":1500},
            {"origin_peer_pk":"bbbb2222","origin_seq":1,"event_type":"0x32","payload_bytes":200,"received_at":1200}
        ]"#;
        let s = parse_foreign_backup(json);
        assert_eq!(s.total_events, 3);
        assert_eq!(s.total_bytes, 350);
        assert_eq!(s.peers.len(), 2);
        // First-seen order preserved.
        assert_eq!(s.peers[0].peer, "aaaa1111");
        assert_eq!(s.peers[0].count, 2);
        assert_eq!(s.peers[0].bytes, 150);
        assert_eq!(s.peers[0].latest_at, 1500, "latest = max received_at");
        assert_eq!(s.peers[1].peer, "bbbb2222");
        assert_eq!(s.peers[1].count, 1);
    }

    #[test]
    fn parse_foreign_backup_empty_and_malformed() {
        assert_eq!(parse_foreign_backup("[]"), ForeignBackupSummary::default());
        assert_eq!(
            parse_foreign_backup("not json"),
            ForeignBackupSummary::default()
        );
        // Object (not array) → empty (cluster feature returns array).
        assert_eq!(parse_foreign_backup("{}"), ForeignBackupSummary::default());
        // Rows missing origin_peer_pk are skipped.
        let s = parse_foreign_backup(r#"[{"payload_bytes":10,"received_at":1}]"#);
        assert_eq!(s.total_events, 0);
        assert!(s.peers.is_empty());
    }

    #[test]
    fn format_backup_bytes_scales() {
        assert_eq!(format_backup_bytes(512), "512 B");
        assert_eq!(format_backup_bytes(1536), "1.5 KB");
        assert_eq!(format_backup_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn extract_code_blocks_single_multi_and_unterminated() {
        let (code, lang) = extract_code_blocks("hi\n```rust\nfn a() {}\n```\nbye");
        assert_eq!(code, "fn a() {}");
        assert_eq!(lang, "rust");

        let (code, lang) = extract_code_blocks("```py\nx = 1\n```\ntext\n```\ny = 2\n```");
        assert_eq!(code, "x = 1\n\ny = 2");
        assert_eq!(lang, "py", "first tag wins");

        // streaming tail: open fence, no close — swallow to end
        let (code, _) = extract_code_blocks("```sh\necho hi");
        assert_eq!(code, "echo hi");

        assert_eq!(extract_code_blocks("no fences here").0, "");
        assert_eq!(extract_code_blocks("").0, "");
        // empty block is dropped
        assert_eq!(extract_code_blocks("```\n\n```").0, "");
    }

    #[test]
    fn parse_permissions_show_merges_overrides() {
        let json = r#"{"active_level":"standard",
            "active_custom_overrides":{"exec_arbitrary":"deny"},
            "matrix":[
              {"level":"strict","decisions":[{"action":"exec_arbitrary","decision":"deny","reason":""}]},
              {"level":"standard","decisions":[
                {"action":"exec_arbitrary","decision":"confirm","reason":"r"},
                {"action":"channel_send","decision":"allow","reason":""}]}]}"#;
        let (rows, level) = parse_permissions_show(json);
        assert_eq!(level, "standard");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].action, "exec_arbitrary");
        assert_eq!(rows[0].decision, "deny", "override wins over base confirm");
        assert!(rows[0].overridden);
        assert_eq!(rows[1].decision, "allow");
        assert!(!rows[1].overridden);
        assert!(parse_permissions_show("garbage").0.is_empty());
    }

    #[test]
    fn parse_models_catalog_filters_and_falls_back() {
        let json = r#"{"version":1,"providers":{
            "claude_cli":{"fetched_at_unix":1,"models":[
                {"id":"model-alpha"},{"id":"old-model","deprecated":true},{"id":"model-beta"}]},
            "openai_compat":{"fetched_at_unix":1,"models":[{"id":"other-model"}]}}}"#;
        let m = parse_models_catalog(json, "claude_cli");
        assert_eq!(m, vec!["model-alpha", "model-beta"]);
        // unknown provider falls back to the merged set, still filtered
        let all = parse_models_catalog(json, "nope");
        assert!(all.contains(&"other-model".to_string()));
        assert!(!all.contains(&"old-model".to_string()));
        assert!(parse_models_catalog("junk", "x").is_empty());
    }

    #[test]
    fn parse_usage_rollup_reads_cost_and_tokens() {
        let json = r#"{"since_unix":0,"until_unix":1,"total_call_count":3,
            "total_ok_count":3,"total_err_count":0,"total_input_tokens":100,
            "total_output_tokens":50,"total_cost_usd":0.12}"#;
        assert_eq!(parse_usage_rollup(json), Some((0.12, 150)));
        assert_eq!(parse_usage_rollup("junk"), None);
        assert_eq!(parse_usage_rollup("{}"), None);
    }

    #[test]
    fn parse_cost_sessions_tolerates_shapes() {
        let arr = r#"[{"session_id":"abcdef1234567890XYZ","models":["claude_cli/opus"],
            "input_tokens":1000,"output_tokens":234,"total_tokens":1234,
            "responses":7,"last_ts_unix":1}]"#;
        let rows = parse_cost_sessions(arr);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session.chars().count(), 18, "session id capped");
        assert_eq!(rows[0].provider, "claude_cli/opus");
        assert_eq!(rows[0].tokens, "1234");
        assert_eq!(rows[0].cost, "7 resp");
        assert!(parse_cost_sessions("{}").is_empty());
        assert!(parse_cost_sessions("junk").is_empty());
    }

    #[test]
    fn layout_memory_graph_positions_and_normalizes() {
        let json = r#"{"communities":2,"nodes":[
            {"id":1,"label":"alpha","tier":"hot","degree":2,"community":0},
            {"id":2,"label":"beta","tier":"cold","degree":1,"community":0},
            {"id":3,"label":"gamma","tier":"fact","degree":1,"community":1}],
            "edges":[{"a":1,"b":2,"w":0.8},{"a":1,"b":3,"w":0.2}]}"#;
        let (nodes, edges, comms) = layout_memory_graph(json);
        assert_eq!(nodes.len(), 3);
        assert_eq!(edges.len(), 2);
        assert_eq!(comms, 2);
        for nd in &nodes {
            assert!((0.05..=0.95).contains(&nd.x), "x in bounds: {}", nd.x);
            assert!((0.05..=0.95).contains(&nd.y), "y in bounds: {}", nd.y);
            assert!((0.1..=1.0).contains(&nd.r));
        }
        assert_eq!(nodes[0].r, 1.0, "highest degree gets full radius");
        // determinism — identical input, identical layout
        let (again, _, _) = layout_memory_graph(json);
        assert_eq!(nodes, again);
        // degenerate inputs
        assert!(layout_memory_graph("").0.is_empty());
        assert!(layout_memory_graph(r#"{"nodes":[]}"#).0.is_empty());
    }

    #[test]
    fn parse_agents_list_maps_fields_and_tolerates_garbage() {
        let json = r#"{"count":1,"agents":[{"name":"reviewer","source":"built-in",
            "description":"reviews code","model":"qwen2","tool_count":3,"enabled":true}]}"#;
        let rows = parse_agents_list(json);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "reviewer");
        assert_eq!(rows[0].hemisphere, "built-in");
        assert_eq!(rows[0].state, "idle");
        assert_eq!(rows[0].current_task, "reviews code");
        assert!(parse_agents_list("nope").is_empty());
        assert!(parse_agents_list("{}").is_empty());
    }

    #[test]
    fn bucket_wal_rows_counts_bands_and_ranges() {
        let mk = |ts_ns: u64, tint: &str| WalRowData {
            ts_ns,
            tint: tint.into(),
            ..Default::default()
        };
        let rows = vec![
            mk(1_000_000_000, "memory"),
            mk(2_000_000_000, "warning"),
            mk(9_000_000_000, "consent"),
            mk(10_000_000_000, "consent"),
            mk(0, "audit"), // ts 0 skipped
        ];
        let (buckets, ranges) = bucket_wal_rows(&rows, 4);
        assert_eq!(buckets.len(), 4);
        assert_eq!(ranges.len(), 4);
        let total: i32 = buckets
            .iter()
            .map(|b| b.memory_n + b.audit_n + b.consent_n + b.warning_n + b.plain_n)
            .sum();
        assert_eq!(total, 4, "ts 0 row must be skipped");
        assert_eq!(buckets[0].memory_n, 1);
        assert_eq!(buckets[3].consent_n, 2, "newest slice holds both consents");
        assert!(bucket_wal_rows(&[], 4).0.is_empty());
    }

    #[test]
    fn parse_wal_show_rows_and_tints() {
        let json = r#"{"frames_matched":3,"frames":[
            {"event_type":"0x40","event_name":"job_fired","event_subtype":0,
             "payload_len":120,"importance":0.5,"ts_ns":1000000000,"event_id":7,"payload_hash":"00"},
            {"event_type":"0xC7","event_name":"plugin_cap_denied","event_subtype":0,
             "payload_len":8,"importance":0.9,"ts_ns":2000000000,"event_id":8,"payload_hash":"01"}]}"#;
        let (rows, matched) = parse_wal_show(json);
        assert_eq!(matched, 3);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].seq, 7);
        assert_eq!(rows[0].tint, "warning", "cron band = amber");
        assert_eq!(rows[1].tint, "consent", "security band = pink");
        assert!(rows[0].detail_json.contains("job_fired"));
        assert!(parse_wal_show("garbage").0.is_empty());
    }

    #[test]
    fn filter_wal_rows_by_text_and_band() {
        let (rows, _) = parse_wal_show(
            r#"{"frames_matched":2,"frames":[
            {"event_type":"0x40","event_name":"job_fired","payload_len":1,"importance":0.1,"ts_ns":0,"event_id":1},
            {"event_type":"0x62","event_name":"council_vote","payload_len":1,"importance":0.1,"ts_ns":0,"event_id":2}]}"#,
        );
        assert_eq!(filter_wal_rows(&rows, "", 0).len(), 2);
        assert_eq!(filter_wal_rows(&rows, "council", 0).len(), 1);
        assert_eq!(filter_wal_rows(&rows, "0x40", 0).len(), 1);
        // band 3 = cron 0x40–0x4F
        let cron = filter_wal_rows(&rows, "", 3);
        assert_eq!(cron.len(), 1);
        assert_eq!(cron[0].kind, "job_fired");
        assert!(filter_wal_rows(&rows, "zzz", 0).is_empty());
    }

    #[test]
    fn format_gossip_lines_newest_first_and_capped() {
        let json = r#"[
            {"origin_peer_pk":"aabbccddeeff0011","origin_seq":1,"event_type":50,"payload_bytes":100,"received_at":1000},
            {"origin_peer_pk":"1122334455667788","origin_seq":2,"event_type":64,"payload_bytes":2048,"received_at":2000}]"#;
        let lines = format_gossip_lines(json, 10);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("11223344"), "newest first: {lines:?}");
        assert!(lines[0].contains("0x40"));
        assert!(lines[1].contains("aabbccdd"));
        assert_eq!(format_gossip_lines(json, 1).len(), 1);
        assert!(format_gossip_lines("garbage", 5).is_empty());
        assert!(format_gossip_lines("{}", 5).is_empty());
    }

    #[test]
    fn parse_swarm_nodes_full_and_degenerate() {
        let json = r#"{"sampling":{"enabled":true},"nodes":[
            {"node_id":"abc","hostname":"cube","cpu_pct":42.5,
             "ram_used_mb":8000,"ram_total_mb":16000,
             "vram_used_mb":0,"vram_total_mb":0,"ts_unix":1,"age_s":7}]}"#;
        let nodes = parse_swarm_nodes(json);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "abc");
        assert!((nodes[0].cpu_frac - 0.425).abs() < 1e-6);
        assert!((nodes[0].ram_frac - 0.5).abs() < 1e-6);
        assert_eq!(nodes[0].vram_frac, 0.0, "zero-total VRAM must not divide");
        assert_eq!(nodes[0].age_secs, 7);

        assert!(parse_swarm_nodes("").is_empty());
        assert!(parse_swarm_nodes("{}").is_empty());
        assert!(parse_swarm_nodes(r#"{"nodes":"nope"}"#).is_empty());
        // cpu over 100 clamps to 1.0
        let hot = parse_swarm_nodes(r#"{"nodes":[{"node_id":"x","cpu_pct":250.0}]}"#);
        assert_eq!(hot[0].cpu_frac, 1.0);
    }

    #[test]
    fn parse_overlay_pos_roundtrip_and_garbage() {
        assert_eq!(parse_overlay_pos("120,340"), Some((120, 340)));
        assert_eq!(parse_overlay_pos(" -5 , 0 \n"), Some((-5, 0)));
        assert_eq!(parse_overlay_pos(""), None);
        assert_eq!(parse_overlay_pos("120"), None);
        assert_eq!(parse_overlay_pos("a,b"), None);
    }

    #[test]
    fn filter_palette_empty_query_returns_full_catalog() {
        assert_eq!(filter_palette("").len(), PALETTE_CATALOG.len());
        assert_eq!(filter_palette("   ").len(), PALETTE_CATALOG.len());
    }

    #[test]
    fn filter_palette_matches_label_case_insensitive() {
        let hits = filter_palette("MEM");
        assert!(hits.iter().any(|(l, _, _, _)| *l == "Memory"));
        assert!(
            hits.iter()
                .all(|(l, _, tab, _)| l.to_lowercase().contains("mem") || tab.contains("mem"))
        );
    }

    #[test]
    fn filter_palette_matches_tab_key() {
        // "selfdev" only exists as the tab key (label is "Self-Dev").
        let hits = filter_palette("selfdev");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, "selfdev");
    }

    #[test]
    fn filter_palette_no_match_returns_empty() {
        assert!(filter_palette("zzz-not-a-tab").is_empty());
    }

    #[test]
    fn palette_catalog_tab_keys_are_unique() {
        let mut keys: Vec<&str> = PALETTE_CATALOG.iter().map(|(_, _, t, _)| *t).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate tab key in PALETTE_CATALOG");
    }
}
