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

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[
    check_freedom_yaml,
    check_credentials_yaml,
    check_credential_age,
    check_policy_yaml,
    check_tweaks_toml,
    check_profile_extensions,
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
];
