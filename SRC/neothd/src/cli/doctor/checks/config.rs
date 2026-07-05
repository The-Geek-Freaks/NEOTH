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

// ── ZF-08 advisable hints: remaining meaningful default-OFF groups ────────

/// Shared preamble used by every `advisable:*` check that reads a single
/// `enabled` bool from `freedom.yaml` via `FreedomConfig`.
///
/// Returns `None` when freedom.yaml is absent or unreadable (those cases are
/// already surfaced by `check_freedom_yaml`; we don't duplicate the noise here).
fn load_cfg_for_advisable(home: &Path) -> Option<crate::config::FreedomConfig> {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return None;
    }
    crate::config::FreedomConfig::load_from_path(&path).ok()
}

/// Builds the standard Pass outcome when a group is already enabled.
fn advisable_pass(name: &'static str, key: &str) -> CheckOutcome {
    CheckOutcome {
        name,
        status: CheckStatus::Pass,
        detail: format!("{key}.enabled = true"),
    }
}

/// Builds the standard Pass outcome when freedom.yaml is absent/unreadable.
fn advisable_skip(name: &'static str) -> CheckOutcome {
    CheckOutcome {
        name,
        status: CheckStatus::Pass,
        detail: "freedom.yaml absent or unreadable — skipping advisable check".into(),
    }
}

/// Advisory hint: `proactive.enabled` is off.
///
/// When enabled, the daemon's cron may post outbound briefings and follow-ups
/// on its own — the "proactive channel messaging" feature (C-16). Operators
/// who want NEOTH to reach out without being asked need this toggle. Default
/// `false` per the AGENTER rule "no destructive auto-action without operator GO".
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_proactive(home: &Path) -> CheckOutcome {
    const NAME: &str = "advisable: proactive messaging";
    let Some(cfg) = load_cfg_for_advisable(home) else {
        return advisable_skip(NAME);
    };
    if cfg.proactive.enabled {
        return advisable_pass(NAME, "proactive");
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: "proactive.enabled is false — the daemon will not send outbound \
                 briefings or follow-ups on its own. Enable if you want NEOTH to \
                 reach out proactively. \
                 Set `proactive.enabled: true` in freedom.yaml, \
                 or apply a built-in preset: `neoth preset apply balanced`."
            .into(),
    }
}

/// Advisory hint: `dreaming.enabled` is off.
///
/// When enabled, the daemon runs a background dream-synthesis pass that clusters
/// recent memories into themes, surfaces patterns, and writes synthesis notes
/// to `~/.neoth/dreams/`. Improves long-horizon recall without requiring
/// operator action. Default `false` (opt-in).
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_dreaming(home: &Path) -> CheckOutcome {
    const NAME: &str = "advisable: dreaming";
    let Some(cfg) = load_cfg_for_advisable(home) else {
        return advisable_skip(NAME);
    };
    if cfg.dreaming.enabled {
        return advisable_pass(NAME, "dreaming");
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: "dreaming.enabled is false — background dream-synthesis is off; \
                 long-horizon pattern recognition and theme clustering are inactive. \
                 Set `dreaming.enabled: true` in freedom.yaml, \
                 or apply a built-in preset: `neoth preset apply balanced`."
            .into(),
    }
}

/// Advisory hint: `ecology.enabled` is off.
///
/// The ecology layer (F4-01) is the self-adaptation auto-scheduler: when
/// enabled, it periodically correlates operator feedback signals and adjusts
/// response weights accordingly. The read-only `neoth ecology correlation`
/// diagnostic works regardless — this hint is about the live adaptation cron.
/// Default `false` (opt-in).
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_ecology(home: &Path) -> CheckOutcome {
    const NAME: &str = "advisable: ecology";
    let Some(cfg) = load_cfg_for_advisable(home) else {
        return advisable_skip(NAME);
    };
    if cfg.ecology.enabled {
        return advisable_pass(NAME, "ecology");
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: "ecology.enabled is false — the self-adaptation scheduler is off; \
                 NEOTH will not auto-tune response weights from operator feedback. \
                 Set `ecology.enabled: true` in freedom.yaml, \
                 or apply a built-in preset: `neoth preset apply balanced`."
            .into(),
    }
}

/// Advisory hint: `companion.enabled` is off.
///
/// The companion server (loopback port 9745) exposes a local HTTP API so that
/// a paired mobile client (`neoth companion qr`) can reach the daemon without
/// going through a messenger channel. Useful for operators who want a dedicated
/// NEOTH mobile client. Default `false` (opt-in, loopback-only).
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_companion(home: &Path) -> CheckOutcome {
    const NAME: &str = "advisable: companion server";
    let Some(cfg) = load_cfg_for_advisable(home) else {
        return advisable_skip(NAME);
    };
    if cfg.companion.enabled {
        return advisable_pass(NAME, "companion");
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: "companion.enabled is false — the local companion HTTP server is off; \
                 mobile pairing via `neoth companion qr` will not work. \
                 Set `companion.enabled: true` in freedom.yaml, \
                 or run `neoth companion start` to enable it interactively."
            .into(),
    }
}

/// Advisory hint: `synthesis_cron.enabled` is off.
///
/// The synthesis cron periodically reconciles contradictions across memory
/// entries, writes a structured synthesis note as an `idx_groundtruth` row,
/// and optionally archives it to `~/.neoth/synthesis/YYYY-WW.md`. Improves
/// factual coherence without operator action. Default `false` (opt-in).
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_synthesis_cron(home: &Path) -> CheckOutcome {
    const NAME: &str = "advisable: synthesis cron";
    let Some(cfg) = load_cfg_for_advisable(home) else {
        return advisable_skip(NAME);
    };
    if cfg.synthesis_cron.enabled {
        return advisable_pass(NAME, "synthesis_cron");
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: "synthesis_cron.enabled is false — periodic memory synthesis and \
                 contradiction reconciliation are off; factual coherence degrades \
                 over long sessions without it. \
                 Set `synthesis_cron.enabled: true` in freedom.yaml, \
                 or apply a built-in preset: `neoth preset apply balanced`."
            .into(),
    }
}

/// Advisory hint: `skill_curator.enabled` is off.
///
/// The skill curator cron auto-promotes mature operator-accepted skill proposals
/// from `~/.neoth/proposals/` to `~/.neoth/skills/`. Without it, accepted
/// proposals sit in the queue indefinitely until promoted manually.
/// Default `false` (opt-in).
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_skill_curator(home: &Path) -> CheckOutcome {
    const NAME: &str = "advisable: skill curator";
    let Some(cfg) = load_cfg_for_advisable(home) else {
        return advisable_skip(NAME);
    };
    if cfg.skill_curator.enabled {
        return advisable_pass(NAME, "skill_curator");
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: "skill_curator.enabled is false — accepted skill proposals in \
                 `~/.neoth/proposals/` will not be auto-promoted to `~/.neoth/skills/`. \
                 Set `skill_curator.enabled: true` in freedom.yaml, \
                 or apply a built-in preset: `neoth preset apply balanced`."
            .into(),
    }
}

/// Advisory hint: `auto_skill_extract.enabled` is off.
///
/// When enabled, after turns with enough tool calls NEOTH distils a structured
/// skill block (`{title, steps, tags, confidence}`) and stages high-confidence
/// computer-executable extractions in the proactive review queue
/// (`~/.neoth/proposals/`). Feeds the skill curator pipeline.
/// Default `false` (opt-in; requires usage data before proposals are meaningful).
///
/// Severity: Warn (advisory only — daemon starts and runs correctly either way).
pub(crate) fn check_advisable_auto_skill_extract(home: &Path) -> CheckOutcome {
    const NAME: &str = "advisable: auto skill extract";
    let Some(cfg) = load_cfg_for_advisable(home) else {
        return advisable_skip(NAME);
    };
    if cfg.auto_skill_extract.enabled {
        return advisable_pass(NAME, "auto_skill_extract");
    }
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: "auto_skill_extract.enabled is false — NEOTH will not distil \
                 reusable skill steps from agent runs into the proposals queue. \
                 Set `auto_skill_extract.enabled: true` in freedom.yaml, \
                 or apply a built-in preset: `neoth preset apply balanced`."
            .into(),
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
    // ZF-08: remaining meaningful default-OFF groups.
    check_advisable_proactive,
    check_advisable_dreaming,
    check_advisable_ecology,
    check_advisable_companion,
    check_advisable_synthesis_cron,
    check_advisable_skill_curator,
    check_advisable_auto_skill_extract,
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
    // ── ZF-08 advisable hints ─────────────────────────────────────────────
    CheckDoc {
        name: "advisable: proactive messaging",
        purpose: "Advisory hint that fires when `proactive.enabled` is `false` \
                  (the default). When enabled, the daemon's cron may post \
                  outbound briefings and follow-ups on its own without a user \
                  trigger — the C-16 proactive channel messaging feature. \
                  The check is informational only — daemon starts either way.",
        common_failures: "Default-off by design per the AGENTER operator-GO \
                         rule; operator missed the toggle during initial setup.",
        fix: "Set `proactive.enabled: true` in `~/.neoth/freedom.yaml`, \
              or run `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: dreaming",
        purpose: "Advisory hint that fires when `dreaming.enabled` is `false` \
                  (the default). When enabled, the daemon runs background \
                  dream-synthesis passes that cluster recent memories into \
                  themes and write synthesis notes to `~/.neoth/dreams/`. \
                  Improves long-horizon recall. The check is informational \
                  only — daemon starts either way.",
        common_failures: "Default-off; operator missed the toggle at setup.",
        fix: "Set `dreaming.enabled: true` in `~/.neoth/freedom.yaml`, \
              or run `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: ecology",
        purpose: "Advisory hint that fires when `ecology.enabled` is `false` \
                  (the default). The ecology layer (F4-01) is the \
                  self-adaptation auto-scheduler: it periodically correlates \
                  operator feedback and adjusts response weights. The \
                  read-only `neoth ecology correlation` diagnostic still works \
                  without it. The check is informational only.",
        common_failures: "Default-off; the cron is separate from the \
                         read-only correlation scan which always runs.",
        fix: "Set `ecology.enabled: true` in `~/.neoth/freedom.yaml`, \
              or run `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: companion server",
        purpose: "Advisory hint that fires when `companion.enabled` is \
                  `false` (the default). When enabled, a loopback HTTP server \
                  on port 9745 (configurable) allows a paired mobile client \
                  to reach the daemon. Needed for `neoth companion qr` mobile \
                  pairing. The check is informational only.",
        common_failures: "Default-off; operator has not set up mobile pairing.",
        fix: "Set `companion.enabled: true` in `~/.neoth/freedom.yaml`, \
              or run `neoth companion start` for an interactive setup.",
    },
    CheckDoc {
        name: "advisable: synthesis cron",
        purpose: "Advisory hint that fires when `synthesis_cron.enabled` is \
                  `false` (the default). When enabled, a background cron \
                  reconciles contradictions across memory entries and writes \
                  structured synthesis notes to `idx_groundtruth` and \
                  optionally to `~/.neoth/synthesis/YYYY-WW.md`. Improves \
                  factual coherence over time. The check is informational only.",
        common_failures: "Default-off; operator missed the toggle at setup.",
        fix: "Set `synthesis_cron.enabled: true` in `~/.neoth/freedom.yaml`, \
              or run `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: skill curator",
        purpose: "Advisory hint that fires when `skill_curator.enabled` is \
                  `false` (the default). When enabled, a background cron \
                  auto-promotes mature, operator-accepted skill proposals from \
                  `~/.neoth/proposals/` to `~/.neoth/skills/`. Without it, \
                  accepted proposals accumulate unacted upon. The check is \
                  informational only.",
        common_failures: "Default-off; operator hasn't opted into automatic \
                         skill promotion yet.",
        fix: "Set `skill_curator.enabled: true` in `~/.neoth/freedom.yaml`, \
              or run `neoth preset apply balanced`.",
    },
    CheckDoc {
        name: "advisable: auto skill extract",
        purpose: "Advisory hint that fires when `auto_skill_extract.enabled` \
                  is `false` (the default). When enabled, after turns with \
                  enough tool calls NEOTH distils a structured skill block \
                  and stages high-confidence extractions in the proactive \
                  review queue for curator promotion. Feeds the skill pipeline. \
                  The check is informational only.",
        common_failures: "Default-off; requires accumulated usage data before \
                         proposals are meaningful.",
        fix: "Set `auto_skill_extract.enabled: true` in \
              `~/.neoth/freedom.yaml`, or run `neoth preset apply balanced`.",
    },
];
