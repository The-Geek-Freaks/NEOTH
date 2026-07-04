//! Config-file doctor checks (GOLD-ARCH-06): freedom.yaml,
//! credentials.yaml (+age), policy.yaml, tweaks.toml, profile extensions.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus, is_mode_0600};

pub(crate) fn check_freedom_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: format!("missing at {}; run `neoth init`", path.display()),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Warn,
            detail: format!("mode > 0600 — run `chmod 0600 {}`", path.display()),
        };
    }
    // Cheap parse check — full parse happens in serve.
    let Ok(body) = std::fs::read_to_string(&path) else {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: "unreadable".into(),
        };
    };
    if serde_yaml::from_str::<serde_yaml::Value>(&body).is_err() {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: "YAML parse error".into(),
        };
    }
    CheckOutcome {
        name: "freedom.yaml",
        status: CheckStatus::Pass,
        detail: format!("ok ({} bytes)", body.len()),
    }
}

pub(crate) fn check_credentials_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("credentials.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Pass,
            detail: "absent (claude-cli OAuth flow doesn't need it)".into(),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Fail,
            detail: format!(
                "mode > 0600 — secrets leak; run `chmod 0600 {}`",
                path.display()
            ),
        };
    }
    if let Err(e) = crate::config::credentials::Credentials::load_or_default(&path) {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        };
    }
    CheckOutcome {
        name: "credentials.yaml",
        status: CheckStatus::Pass,
        detail: "present, mode 0600, parseable".into(),
    }
}

/// Warn past 180 days, fail past 365 days since `credentials.yaml` was
/// last touched. Audit 2026-05-19 — Telegram/Slack tokens get rotated
/// server-side without any signal to NEOTH; without this check a
/// revoked token reads as a generic 401 deep inside a channel handler.
pub(crate) const CREDENTIAL_AGE_WARN_DAYS: u64 = 180;

pub(crate) const CREDENTIAL_AGE_FAIL_DAYS: u64 = 365;

pub(crate) const SECONDS_PER_DAY: u64 = 86_400;

pub(crate) fn check_credential_age(home: &Path) -> CheckOutcome {
    let path = home.join("credentials.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: "no credentials.yaml — skipping age check".into(),
        };
    }
    // Only warn when there's actually a secret to rotate. A bare file
    // with every Option<SecretString> set to None can sit for years
    // without operator risk.
    let creds = match crate::config::credentials::Credentials::load_or_default(&path) {
        Ok(c) => c,
        Err(_) => {
            // credentials.yaml parse errors are already surfaced by
            // `check_credentials_yaml`; don't double-fail here.
            return CheckOutcome {
                name: "credentials age",
                status: CheckStatus::Pass,
                detail: "credentials.yaml parse error — see credentials.yaml check".into(),
            };
        }
    };
    if creds.is_empty() {
        return CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: "credentials.yaml present but holds no secrets to age-check".into(),
        };
    }
    let modified = match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(m) => m,
        Err(e) => {
            return CheckOutcome {
                name: "credentials age",
                status: CheckStatus::Warn,
                detail: format!("cannot read credentials.yaml mtime: {e}"),
            };
        }
    };
    let age_secs = std::time::SystemTime::now()
        .duration_since(modified)
        .map(|d| d.as_secs())
        // mtime in the future (clock skew or operator `touch -t`) — treat as fresh.
        .unwrap_or(0);
    let age_days = age_secs / SECONDS_PER_DAY;
    if age_days >= CREDENTIAL_AGE_FAIL_DAYS {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Fail,
            detail: format!(
                "credentials.yaml is {age_days} days old (>= {CREDENTIAL_AGE_FAIL_DAYS}d) — rotate Telegram/Slack/provider keys and `touch` the file"
            ),
        }
    } else if age_days >= CREDENTIAL_AGE_WARN_DAYS {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Warn,
            detail: format!(
                "credentials.yaml is {age_days} days old (>= {CREDENTIAL_AGE_WARN_DAYS}d) — consider rotating before tokens expire silently"
            ),
        }
    } else {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: format!("credentials.yaml is {age_days} days old"),
        }
    }
}

pub(crate) fn check_policy_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("policy.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Pass,
            detail: "absent (no dangerous-target deny list configured)".into(),
        };
    }
    match crate::policy::PolicyConfig::load_or_default(&path) {
        Ok(p) => CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Pass,
            detail: format!(
                "{} dangerous target(s), {} pattern(s)",
                p.dangerous_targets.len(),
                p.dangerous_patterns.len()
            ),
        },
        Err(e) => CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

pub(crate) fn check_profile_extensions(home: &Path) -> CheckOutcome {
    let path = home.join("profile_extensions.toml");
    if !path.exists() {
        return CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Pass,
            detail: "absent (only base profile taxonomy allowed)".into(),
        };
    }
    match crate::profile::extension_registry::TypedExtensionRegistry::load_from(&path) {
        Ok(reg) => CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Pass,
            detail: format!(
                "{} operator-registered profile category extension(s)",
                reg.registered_count()
            ),
        },
        Err(e) => CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

pub(crate) fn check_tweaks_toml(home: &Path) -> CheckOutcome {
    let path = home.join("tweaks.toml");
    if !path.exists() {
        return CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Pass,
            detail: "absent (built-in defaults)".into(),
        };
    }
    match crate::tweaks::Tweaks::load_or_default(&path) {
        Ok(t) => CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Pass,
            detail: format!("{} prompt snippet(s) configured", t.prompts.len()),
        },
        Err(e) => CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

/// Advisory hint: `council.groundtruth_injection` is off.
///
/// When enabled, the daemon reads verified facts from `idx_groundtruth`
/// (rows with `fact_state = 'verified'`) and prepends them as a tagged
/// context block before each council debate — improving factual accuracy
/// without adding provider round-trips. The default is `true`; this check
/// fires only when the operator has explicitly set it to `false` in
/// `freedom.yaml`, which is easy to miss and rarely intentional.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_groundtruth_injection(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        // freedom.yaml missing is already a Fail in check_freedom_yaml; skip here.
        return CheckOutcome {
            name: "advisable: groundtruth injection",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => {
            // Parse errors are already surfaced by check_freedom_yaml.
            CheckOutcome {
                name: "advisable: groundtruth injection",
                status: CheckStatus::Pass,
                detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
            }
        }
        Ok(cfg) => {
            if cfg.council.groundtruth_injection {
                CheckOutcome {
                    name: "advisable: groundtruth injection",
                    status: CheckStatus::Pass,
                    detail: "council.groundtruth_injection = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: groundtruth injection",
                    status: CheckStatus::Warn,
                    detail: "council.groundtruth_injection is false — enabling injects \
                             verified facts into council debates, improving factual accuracy. \
                             Set `council.groundtruth_injection: true` in freedom.yaml, \
                             or apply a built-in preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `consolidation_sweep.enabled` is off.
///
/// When enabled, the daemon runs a background cron that consolidates fragmented
/// memory entries — merging near-duplicates, promoting high-recall candidates,
/// and expiring stale facts — so that recall quality improves over time without
/// any user action. Defaults to `false` (opt-in); operators frequently miss this
/// toggle during initial setup.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_consolidation_sweep(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: consolidation sweep",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: consolidation sweep",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.consolidation_sweep.enabled {
                CheckOutcome {
                    name: "advisable: consolidation sweep",
                    status: CheckStatus::Pass,
                    detail: "consolidation_sweep.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: consolidation sweep",
                    status: CheckStatus::Warn,
                    detail: "consolidation_sweep.enabled is false — background memory \
                             consolidation is off; recall quality degrades over long \
                             sessions as near-duplicate facts accumulate. \
                             Set `consolidation_sweep.enabled: true` in freedom.yaml, \
                             or apply a built-in preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `watchdog.enabled` is off.
///
/// When enabled, the daemon probes supervised local services (n8n, Ollama) on a
/// configurable interval and restarts them when they are found unresponsive. The
/// watchdog manages those external processes only — it does not restart neothd
/// itself. Useful for operators running long-lived agentic workflows where n8n or
/// Ollama may crash silently. Requires Elevated+ autonomy to perform restarts.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_watchdog(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: watchdog",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: watchdog",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.watchdog.enabled {
                CheckOutcome {
                    name: "advisable: watchdog",
                    status: CheckStatus::Pass,
                    detail: "watchdog.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: watchdog",
                    status: CheckStatus::Warn,
                    detail: "watchdog.enabled is false — supervised local services (n8n, Ollama) \
                             will not be automatically restarted when they go down. Set \
                             `watchdog.enabled: true` in freedom.yaml to enable probe-and-restart \
                             at Elevated+ autonomy, or apply a preset: \
                             `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `dreaming.enabled` is off.
///
/// When enabled, the daemon runs a nightly memory clustering and theme-composition
/// pipeline that groups related episodes, distills recurring themes, and promotes
/// high-signal facts to long-term recall — improving memory quality over time without
/// any user action. No network egress by default (`allow_cloud_fallback = false`).
/// Note: the dreaming pipeline invokes the configured local provider once per nightly
/// run, so it carries a small but non-zero LLM compute cost.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_dreaming(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: dreaming",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: dreaming",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.dreaming.enabled {
                CheckOutcome {
                    name: "advisable: dreaming",
                    status: CheckStatus::Pass,
                    detail: "dreaming.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: dreaming",
                    status: CheckStatus::Warn,
                    detail: "dreaming.enabled is false — nightly memory clustering and theme \
                             composition are off; recall quality degrades over long sessions as \
                             related episodes remain unlinked. Note: enabling this incurs one \
                             LLM provider call per nightly run. Set `dreaming.enabled: true` in \
                             freedom.yaml, or apply a preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `proactive.enabled` is off.
///
/// When enabled, the daemon generates and delivers scheduled briefings and check-ins
/// via the configured messenger channels. Pairs naturally with `checkin_cron` for
/// timed outbound messages. The companion `quiet_hours_utc` tunable suppresses
/// delivery during operator sleep windows. Default is off (opt-in due to outbound
/// messaging impact).
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_proactive(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: proactive",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: proactive",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.proactive.enabled {
                CheckOutcome {
                    name: "advisable: proactive",
                    status: CheckStatus::Pass,
                    detail: "proactive.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: proactive",
                    status: CheckStatus::Warn,
                    detail: "proactive.enabled is false — scheduled briefings and check-ins will \
                             not be delivered. Consider also setting `checkin_cron.enabled: true` \
                             and configuring `proactive.quiet_hours_utc` to suppress messages \
                             during sleep windows. Set `proactive.enabled: true` in freedom.yaml, \
                             or apply a preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `checkin_cron.enabled` is off.
///
/// When enabled, the daemon runs a scheduled cron job that generates a personalised
/// check-in message body via a provider call and delivers it through the active
/// messenger. Useful for operators who want periodic context-aware nudges. Note:
/// each tick triggers one LLM provider call, so enabling this carries a recurring
/// LLM cost at the configured cron interval.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_checkin_cron(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: checkin cron",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: checkin cron",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.checkin_cron.enabled {
                CheckOutcome {
                    name: "advisable: checkin cron",
                    status: CheckStatus::Pass,
                    detail: "checkin_cron.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: checkin cron",
                    status: CheckStatus::Warn,
                    detail: "checkin_cron.enabled is false — scheduled check-in message \
                             generation is off. Note: enabling this incurs one LLM provider call \
                             per cron tick. Set `checkin_cron.enabled: true` in freedom.yaml, \
                             or apply a preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `skill_curator.enabled` is off.
///
/// When enabled, the daemon runs a weekly background job that promotes
/// operator-reviewed skill proposals from `~/.neoth/proposals/` into
/// `~/.neoth/skills/`. Only proposals that the operator has explicitly accepted
/// are promoted — no unsupervised changes to the skill library occur. Safe by
/// design; the weekly cadence avoids noisy churn.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_skill_curator(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: skill curator",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: skill curator",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.skill_curator.enabled {
                CheckOutcome {
                    name: "advisable: skill curator",
                    status: CheckStatus::Pass,
                    detail: "skill_curator.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: skill curator",
                    status: CheckStatus::Warn,
                    detail: "skill_curator.enabled is false — accepted skill proposals in \
                             ~/.neoth/proposals/ will not be promoted automatically to \
                             ~/.neoth/skills/. Set `skill_curator.enabled: true` in \
                             freedom.yaml, or apply a preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `monitor.enabled` is off.
///
/// When enabled, the daemon runs background alerting for WAL CRC failures,
/// crash.log growth, and channel silence anomalies. Purely advisory — no egress,
/// no LLM cost — and high-value for long-running deployments where silent failures
/// are otherwise invisible. Alerts are delivered via the configured messenger.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_monitor(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: monitor",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: monitor",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.monitor.enabled {
                CheckOutcome {
                    name: "advisable: monitor",
                    status: CheckStatus::Pass,
                    detail: "monitor.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: monitor",
                    status: CheckStatus::Warn,
                    detail: "monitor.enabled is false — WAL CRC alerting, crash.log monitoring, \
                             and channel silence detection are off; failures on long-running \
                             deployments will be silent. No egress or LLM cost. Set \
                             `monitor.enabled: true` in freedom.yaml, or apply a preset: \
                             `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `loop_config.enabled` is off.
///
/// When enabled, the multi-round autonomous loop engine is available for agentic
/// workflows that run N dispatch rounds with structural stop criteria. High-value
/// for power users driving automated pipelines. Note: each loop activation costs
/// up to `loop_config.max_rounds` provider round-trips; tune that value to manage
/// LLM spend.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_loop_config(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: loop config",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: loop config",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.loop_config.enabled {
                CheckOutcome {
                    name: "advisable: loop config",
                    status: CheckStatus::Pass,
                    detail: "loop_config.enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: loop config",
                    status: CheckStatus::Warn,
                    detail: "loop_config.enabled is false — the multi-round autonomous loop \
                             engine is unavailable; agentic workflows run only a single dispatch \
                             round. Note: enabling this costs up to `loop_config.max_rounds` \
                             provider round-trips per activation. Set `loop_config.enabled: true` \
                             in freedom.yaml, or apply a preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Advisory hint: `media.dictation_enabled` is off.
///
/// When enabled, the daemon activates push-to-talk mic capture for voice dictation.
/// A consent notice fires on first use regardless of this setting. Useful discovery
/// nudge for operators who are unaware the capability exists. The feature is purely
/// opt-in; no audio is captured without explicit user action.
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_dictation(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "advisable: dictation",
            status: CheckStatus::Pass,
            detail: "freedom.yaml absent — skipping advisable check".into(),
        };
    }
    match crate::config::FreedomConfig::load_from_path(&path) {
        Err(_) => CheckOutcome {
            name: "advisable: dictation",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable — see freedom.yaml check".into(),
        },
        Ok(cfg) => {
            if cfg.media.dictation_enabled {
                CheckOutcome {
                    name: "advisable: dictation",
                    status: CheckStatus::Pass,
                    detail: "media.dictation_enabled = true".into(),
                }
            } else {
                CheckOutcome {
                    name: "advisable: dictation",
                    status: CheckStatus::Warn,
                    detail: "media.dictation_enabled is false — push-to-talk voice dictation is \
                             unavailable. A consent notice fires on first use regardless. Set \
                             `media.dictation_enabled: true` in freedom.yaml to enable the \
                             feature, or apply a preset: `neoth preset apply balanced`."
                        .into(),
                }
            }
        }
    }
}

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[
    check_freedom_yaml,
    check_credentials_yaml,
    check_credential_age,
    check_policy_yaml,
    check_tweaks_toml,
    check_profile_extensions,
    check_advisable_groundtruth_injection,
    check_advisable_consolidation_sweep,
    // ZF-08 new advisable hints:
    check_advisable_watchdog,
    check_advisable_dreaming,
    check_advisable_proactive,
    check_advisable_checkin_cron,
    check_advisable_skill_curator,
    check_advisable_monitor,
    check_advisable_loop_config,
    check_advisable_dictation,
];

/// Operator runbook entries for this domain (the `--explain` surface).
pub(crate) const DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "freedom.yaml",
        purpose: "Operator configuration lives in `~/.neoth/freedom.yaml`. \
                  Doctor verifies the file exists, parses cleanly via \
                  `FreedomConfig::load_from_path`, and (on unix) is mode \
                  0600 so secrets at rest survive multi-user systems.",
        common_failures: "Missing file (operator hasn't run `neoth init`); \
                         parse error (hand-edited typo); permissions broader \
                         than 0600 (unix).",
        fix: "Missing → `neoth init` (or `neoth init --force` for a clean \
              wipe).\nParse error → diff against `freedom.yaml.example` in \
              the repo / install root.\nPermissions → `chmod 600 ~/.neoth/freedom.yaml`.",
    },
    CheckDoc {
        name: "credentials.yaml",
        purpose: "Secret store at `~/.neoth/credentials.yaml`. Holds API \
                  keys + bot tokens that should NEVER be in freedom.yaml. \
                  Doctor checks existence (warn if missing — daemon can \
                  start without it for local_qwen-only deployments), parse \
                  cleanly, and 0600 mode.",
        common_failures: "Secrets pasted into freedom.yaml instead (creates \
                         a leak path through `neoth export`); world-readable \
                         mode; corrupt YAML.",
        fix: "Edit by hand: keys at the top level (`provider_key`, \
              `telegram_token`). `chmod 600 ~/.neoth/credentials.yaml`.",
    },
    CheckDoc {
        name: "credentials age",
        purpose: "Age of `~/.neoth/credentials.yaml`. Telegram bot tokens, \
                  Slack tokens, and provider API keys quietly expire or \
                  get rotated server-side. Doctor reads the file's \
                  modification time and warns past 180 days, fails past \
                  365. The check skips when the file is absent or holds \
                  only `None` secret slots (local_qwen-only setups).",
        common_failures: "Long-lived deployment without rotation; Slack \
                         workspace revoked the bot token; Telegram \
                         BotFather rotated the secret.",
        fix: "Re-run the relevant wizard step (`neoth init --step \
              credentials`) or edit `~/.neoth/credentials.yaml` and \
              `touch` the file to reset the age clock once the new \
              token is in.",
    },
    CheckDoc {
        name: "policy.yaml",
        purpose: "Optional autonomy policy override at \
                  `~/.neoth/policy.yaml`. When present, overrides the \
                  freedom.yaml-level `autonomy` field per-action category. \
                  Doctor verifies parse + schema.",
        common_failures: "Missing is fine (operator just hasn't customised). \
                         Parse error blocks daemon startup.",
        fix: "Missing → no action needed. Parse error → diff against the \
              schema in `docs/policy.md`, or delete to fall back to \
              freedom.yaml's autonomy field.",
    },
    CheckDoc {
        name: "tweaks.toml",
        purpose: "tweakcc-style customisation at `~/.neoth/tweaks.toml`. \
                  Operator overrides for prompts, persona, slash-command \
                  aliases. Doctor parses + flags unknown keys.",
        common_failures: "Hand-edited YAML where TOML is expected; \
                         malformed `[[prompts]]` array.",
        fix: "Diff against `assets/tweaks.toml.example`. Or delete to \
              fall back to bundled defaults.",
    },
    CheckDoc {
        name: "profile_extensions.toml",
        purpose: "Typed extension registry at \
                  `~/.neoth/profile_extensions.toml`. Operator-defined \
                  custom profile fields outside the base taxonomy (e.g. \
                  `operator.preferences.editor`). Doctor parses + warns on \
                  unknown reserved keys.",
        common_failures: "Empty file (use the bundled example as a start); \
                         TOML syntax error.",
        fix: "Missing → use defaults. Syntax error → diff against \
              `assets/profile_extensions.toml.example`.",
    },
    CheckDoc {
        name: "advisable: groundtruth injection",
        purpose: "Advisory hint that fires when `council.groundtruth_injection` \
                  is explicitly set to `false` in `freedom.yaml`. When enabled, \
                  the daemon reads verified facts from `idx_groundtruth` \
                  (rows with `fact_state = 'verified'`) and prepends them as \
                  a tagged context block before council debates, improving \
                  factual accuracy without additional provider round-trips. \
                  The check is informational only — daemon starts either way.",
        common_failures: "Operator disabled the flag during debugging and \
                         forgot to re-enable it; old freedom.yaml from before \
                         GOLD-G02-COUNCIL-01 that pre-dates the field (serde \
                         default = true, so absence is fine — explicit false \
                         is the only trigger).",
        fix: "Set `council.groundtruth_injection: true` in \
              `~/.neoth/freedom.yaml`, or run \
              `neoth preset apply balanced` to restore recommended defaults.",
    },
    CheckDoc {
        name: "advisable: consolidation sweep",
        purpose: "Advisory hint that fires when `consolidation_sweep.enabled` \
                  is `false` (the default). When enabled, the daemon runs a \
                  background cron that merges near-duplicate memory entries, \
                  promotes high-recall candidates, and expires stale facts. \
                  Recall quality improves over long sessions without any user \
                  action. The check is informational only — daemon starts \
                  either way.",
        common_failures: "Fresh install — the field defaults to `false` and \
                         the wizard does not flip it unless the operator \
                         chooses a preset that includes memory consolidation.",
        fix: "Set `consolidation_sweep.enabled: true` in \
              `~/.neoth/freedom.yaml`, or run \
              `neoth preset apply balanced` to restore recommended defaults.",
    },
    // ZF-08 new advisable hints ────────────────────────────────────────────
    CheckDoc {
        name: "advisable: watchdog",
        purpose: "Advisory hint that fires when `watchdog.enabled` is `false`. \
                  When enabled, the daemon probes supervised local services \
                  (n8n, Ollama) on a configurable interval and restarts them \
                  when unresponsive. The watchdog manages those external \
                  processes only — it does NOT restart neothd itself. Requires \
                  Elevated+ autonomy to perform restarts. The check is \
                  informational only — daemon starts either way.",
        common_failures: "Fresh install — defaults to `false`. Operator running \
                         n8n or Ollama and finding them silently dead after \
                         overnight runs.",
        fix: "Set `watchdog.enabled: true` in `~/.neoth/freedom.yaml`, or run \
              `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: dreaming",
        purpose: "Advisory hint that fires when `dreaming.enabled` is `false`. \
                  When enabled, the daemon runs a nightly memory clustering and \
                  theme-composition pipeline — grouping related episodes, \
                  distilling recurring themes, and promoting high-signal facts \
                  to long-term recall. No network egress by default \
                  (`allow_cloud_fallback = false`). Note: incurs one LLM \
                  provider call per nightly run. The check is informational \
                  only — daemon starts either way.",
        common_failures: "Fresh install — defaults to `false`. Operator noticing \
                         that recall quality does not improve over time despite \
                         active use.",
        fix: "Set `dreaming.enabled: true` in `~/.neoth/freedom.yaml`, or run \
              `neoth preset apply balanced`. Be aware of the nightly LLM call.",
    },
    CheckDoc {
        name: "advisable: proactive",
        purpose: "Advisory hint that fires when `proactive.enabled` is `false`. \
                  When enabled, the daemon delivers scheduled briefings and \
                  check-ins via configured messenger channels. Pairs with \
                  `checkin_cron`; the companion `proactive.quiet_hours_utc` \
                  tunable suppresses delivery during operator sleep windows. \
                  Default is off (opt-in due to outbound messaging impact). \
                  The check is informational only — daemon starts either way.",
        common_failures: "Operator expecting proactive briefings but not seeing \
                         them; `checkin_cron.enabled` is true but `proactive` \
                         is false so no messages are sent.",
        fix: "Set `proactive.enabled: true` in `~/.neoth/freedom.yaml`. \
              Configure `proactive.quiet_hours_utc` to suppress night messages. \
              Or run `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: checkin cron",
        purpose: "Advisory hint that fires when `checkin_cron.enabled` is \
                  `false`. When enabled, the daemon generates a personalised \
                  check-in message body via a provider call on a schedule and \
                  delivers it through the active messenger. Each tick triggers \
                  one LLM provider call — enabling this carries a recurring \
                  LLM cost at the configured interval. The check is \
                  informational only — daemon starts either way.",
        common_failures: "Operator wanting periodic context-aware nudges but \
                         not receiving them; LLM cost surprise on high-frequency \
                         cron intervals.",
        fix: "Set `checkin_cron.enabled: true` in `~/.neoth/freedom.yaml`. \
              Tune the cron expression to manage LLM spend. Or run \
              `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: skill curator",
        purpose: "Advisory hint that fires when `skill_curator.enabled` is \
                  `false`. When enabled, the daemon runs a weekly background \
                  job that promotes operator-reviewed skill proposals from \
                  `~/.neoth/proposals/` into `~/.neoth/skills/`. Only \
                  explicitly accepted proposals are promoted — no unsupervised \
                  changes occur. The check is informational only — daemon \
                  starts either way.",
        common_failures: "Fresh install — defaults to `false`. Operator finding \
                         that accepted proposals accumulate in ~/.neoth/proposals/ \
                         without being promoted.",
        fix: "Set `skill_curator.enabled: true` in `~/.neoth/freedom.yaml`, \
              or run `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: monitor",
        purpose: "Advisory hint that fires when `monitor.enabled` is `false`. \
                  When enabled, the daemon runs background alerting for WAL CRC \
                  failures, crash.log growth, and channel silence anomalies. No \
                  egress, no LLM cost — purely a local health watchdog. High \
                  value for long-running deployments where silent failures \
                  would otherwise go unnoticed. The check is informational \
                  only — daemon starts either way.",
        common_failures: "Fresh install — defaults to `false`. Long-running \
                         deployments where WAL corruption or channel drops \
                         are only noticed when operator manually checks.",
        fix: "Set `monitor.enabled: true` in `~/.neoth/freedom.yaml`, or run \
              `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: loop config",
        purpose: "Advisory hint that fires when `loop_config.enabled` is \
                  `false`. When enabled, the multi-round autonomous loop engine \
                  is available, running up to `loop_config.max_rounds` dispatch \
                  rounds with structural stop criteria. High-value for power \
                  users running agentic workflows. Note: each activation costs \
                  up to `max_rounds` LLM provider calls. The check is \
                  informational only — daemon starts either way.",
        common_failures: "Fresh install — defaults to `false`. Power users \
                         wanting autonomous multi-round loops finding single-shot \
                         dispatch only.",
        fix: "Set `loop_config.enabled: true` in `~/.neoth/freedom.yaml`. \
              Tune `loop_config.max_rounds` to manage LLM spend. Or run \
              `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: dictation",
        purpose: "Advisory hint that fires when `media.dictation_enabled` is \
                  `false`. When enabled, push-to-talk mic capture for voice \
                  dictation becomes available. A consent notice fires on first \
                  use regardless of this setting. The feature is purely opt-in; \
                  no audio is captured without explicit user action. The check \
                  is informational only — daemon starts either way.",
        common_failures: "Fresh install — defaults to `false`. Operator unaware \
                         the push-to-talk dictation capability exists.",
        fix: "Set `media.dictation_enabled: true` in `~/.neoth/freedom.yaml`, \
              or apply a preset: `neoth preset apply balanced`.",
    },
];
