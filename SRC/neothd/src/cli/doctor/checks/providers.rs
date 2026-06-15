//! Provider-health doctor checks (GOLD-ARCH-06): n8n API token, local
//! qwen weights, refusal recovery, provider flapping, circuit breakers,
//! usage/cost today.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

/// SC-08 n8n API bearer-token at-rest protection. When the n8n API is
/// enabled, its bearer token lives at `~/.neoth/n8n_api_token`. On
/// Windows it must be DPAPI-wrapped (a stolen file is useless outside the
/// operator's account); on Unix it must be mode-0600. PASS when n8n is
/// disabled (no token to protect), the token isn't minted yet (created
/// on next `neoth serve`), or it's protected. WARN when an enabled
/// deployment has a plaintext (Windows) / world-readable (Unix) token.
pub(crate) fn check_n8n_api_token(home: &Path) -> CheckOutcome {
    let name = "n8n_api_token";
    let enabled = crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml"))
        .map(|c| c.n8n_api.enabled)
        .unwrap_or(false);
    if !enabled {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "n8n API disabled (freedom.yaml::n8n_api.enabled=false) — token check skipped"
                .to_string(),
        };
    }
    let path = home.join("n8n_api_token");
    if !path.exists() {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "n8n API enabled; token not yet minted (created on next `neoth serve`)"
                .to_string(),
        };
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: format!("n8n_api_token unreadable at {}", path.display()),
        };
    };
    #[cfg(windows)]
    {
        if crate::wal::dpapi::is_wrapped(&bytes) {
            CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: "n8n_api_token present + DPAPI-wrapped (machine/user-bound)".to_string(),
            }
        } else {
            CheckOutcome {
                name,
                status: CheckStatus::Warn,
                detail: format!(
                    "n8n_api_token at {} is PLAINTEXT — delete it; `neoth serve` re-mints it DPAPI-wrapped",
                    path.display()
                ),
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o777);
        if mode == 0o600 {
            CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: format!("n8n_api_token present + mode 0600 ({} bytes)", bytes.len()),
            }
        } else {
            CheckOutcome {
                name,
                status: CheckStatus::Warn,
                detail: format!(
                    "n8n_api_token at {} is mode {mode:o} — should be 0600 (chmod 600 it)",
                    path.display()
                ),
            }
        }
    }
}

/// SPEC-04 local_qwen profile-extraction readiness. When `profile.
/// learn_provider` is set to the on-device `local_qwen` path, profile
/// extraction runs locally ONLY if the Qwen weights are cached;
/// otherwise `from_config_for_learn` fails the build and (with
/// `allow_cloud_fallback=false`, the privacy-floor default) extraction
/// is SKIPPED — profile learning silently stops. This check surfaces
/// that gap before it bites.
///
/// PASS: `learn_provider` is not `local_qwen` (cache irrelevant), or the
/// weights are cached, or freedom.yaml is unreadable (owned by the
/// freedom.yaml check, not double-reported here).
/// WARN: configured `local_qwen` but the weights are absent → the
/// operator must `neoth model fetch`.
pub(crate) fn check_local_qwen_weights(home: &Path) -> CheckOutcome {
    let name = "local_qwen weights";
    let cfg = match crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml")) {
        Ok(c) => c,
        Err(_) => {
            return CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: "freedom.yaml unreadable — skipping local_qwen cache check".to_string(),
            };
        }
    };
    let learn = cfg.profile.learn_provider.as_deref().unwrap_or("");
    if learn != "local_qwen" {
        let shown = if learn.is_empty() { "(unset)" } else { learn };
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: format!(
                "learn_provider `{shown}` is not local_qwen — Qwen weight cache not required"
            ),
        };
    }
    let model = crate::installers::qwen_weights::DEFAULT_QWEN_MODEL_ID;
    if crate::installers::qwen_weights::check_weights_cached(model) {
        CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: format!("local_qwen weights cached ({model})"),
        }
    } else {
        CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: format!(
                "learn_provider=local_qwen but {model} weights not cached → profile \
                 extraction will SKIP (privacy floor). Run `neoth model fetch` or \
                 `neoth init` step 5c."
            ),
        }
    }
}

/// SPEC-10 refusal-recovery health. Recovery reframes + retries when the
/// model refuses a legitimate request. The footgun this catches: a
/// config where recovery is left ENABLED but can never actually fire —
/// every applicable LOWKEY reframing disabled, or `max_attempts = 0` —
/// so refusals silently surface verbatim despite recovery "being on".
///
/// PASS: recovery off by operator choice (deliberate); recovery active
/// with ≥1 reframing enabled + max_attempts ≥ 1; freedom.yaml unreadable
/// (recovery falls back to healthy defaults — the missing-config WARN is
/// owned by `check_freedom_yaml`, not duplicated here).
/// WARN: enabled but a no-op (all reframings disabled, or max_attempts=0).
pub(crate) fn check_refusal_recovery(home: &Path) -> CheckOutcome {
    let name = "refusal recovery";
    let cfg = match crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml")) {
        Ok(c) => c,
        Err(_) => {
            return CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: "freedom.yaml unreadable — recovery uses defaults \
                         (enabled, 0 reframings disabled, max_attempts=2)"
                    .to_string(),
            };
        }
    };
    let rr = &cfg.refusal_recovery;
    let catalogue = crate::security::refusal_reframings::default_catalogue();
    let total = catalogue.len();
    let enabled_count = catalogue
        .iter()
        .filter(|r| !rr.disabled_reframings.iter().any(|d| d == r.id()))
        .count();

    if !rr.enabled {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "off by operator config (refusal_recovery.enabled=false) — \
                     refusals surface verbatim"
                .to_string(),
        };
    }
    if rr.max_attempts == 0 {
        return CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: "ENABLED but max_attempts=0 → recovery never retries \
                     (silent no-op). Set refusal_recovery.max_attempts ≥ 1."
                .to_string(),
        };
    }
    if enabled_count == 0 {
        return CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: format!(
                "ENABLED but all {total} LOWKEY reframings disabled → silent \
                 no-op. Re-enable via `neoth refusal enable <id>`."
            ),
        };
    }
    CheckOutcome {
        name,
        status: CheckStatus::Pass,
        detail: format!(
            "active — {enabled_count}/{total} reframings enabled, max_attempts={}",
            rr.max_attempts
        ),
    }
}

/// Flapping detection for channel-routing providers (Slack outbound +
/// WhatsApp Graph API). Reads the last 24h of usage_log entries and
/// surfaces a warning when error rate per channel-related provider
/// crosses `FLAPPING_THRESHOLD_PCT`. Pass on insufficient samples
/// (<5 calls) or below threshold.
pub(crate) const FLAPPING_THRESHOLD_PCT: f64 = 20.0;

pub(crate) const FLAPPING_MIN_SAMPLES: u64 = 5;

pub(crate) fn check_provider_flapping(home: &Path) -> CheckOutcome {
    let now = crate::time::now_unix_i64();
    let since = now - 86_400;
    let roll = crate::daemon::usage_log::aggregate(home, since, now);
    // Look for providers whose names suggest channel egress. We
    // can't filter perfectly without per-call channel labels in
    // usage_log (Phase 2 work), so the heuristic surfaces ANY
    // provider with a >20% error rate over the last 24h — the
    // detail string tags channel-suspect providers explicitly
    // for operator interpretation.
    if roll.per_provider.is_empty() {
        return CheckOutcome {
            name: "provider flapping",
            status: CheckStatus::Pass,
            detail: "no provider calls in last 24h to analyse".to_string(),
        };
    }
    let mut warnings = Vec::new();
    for p in &roll.per_provider {
        if p.call_count < FLAPPING_MIN_SAMPLES {
            continue;
        }
        let err_pct = (p.err_count as f64 / p.call_count as f64) * 100.0;
        if err_pct >= FLAPPING_THRESHOLD_PCT {
            warnings.push(format!(
                "{provider}: {err}/{total} errors ({pct:.0}%)",
                provider = p.provider,
                err = p.err_count,
                total = p.call_count,
                pct = err_pct,
            ));
        }
    }
    if warnings.is_empty() {
        return CheckOutcome {
            name: "provider flapping",
            status: CheckStatus::Pass,
            detail: format!(
                "every provider with ≥{FLAPPING_MIN_SAMPLES} samples is below {:.0}% errors",
                FLAPPING_THRESHOLD_PCT,
            ),
        };
    }
    CheckOutcome {
        name: "provider flapping",
        status: CheckStatus::Warn,
        detail: format!("flapping detected — {}", warnings.join("; ")),
    }
}

/// QM-10 Phase 1 doctor surface: render the registered circuit-
/// breaker states. v0.1.x: there's no persisted breaker state across
/// daemon restarts, so this check only has content when a long-running
/// daemon's `BreakerRegistry` is exposed to the doctor via the
/// runtime sidecar (deferred — out of scope here). For now the
/// check is always Pass with an honest "no live registry attached"
/// detail, which matches the rest of the v0.1 daemon-restart story.
/// When the runtime registry is wired (Phase 2), this detail flips
/// to render every registered breaker's state + cooldown.
pub(crate) fn check_circuit_breakers(_home: &Path) -> CheckOutcome {
    // QM-10 Phase 2 wire-in landed: chat dispatch consults the
    // global registry on every provider.complete(). The registry
    // is process-scoped (per the design comment in
    // providers::circuit_breaker::GLOBAL), so a doctor invocation
    // OUTSIDE the running `neoth serve` process sees an empty
    // snapshot — that's expected. When wired into the running
    // daemon's status surface (Phase 3), this reads the live
    // sidecar instead.
    let snaps = crate::providers::circuit_breaker::GLOBAL.snapshot_all();
    if snaps.is_empty() {
        return CheckOutcome {
            name: "circuit breakers",
            status: CheckStatus::Pass,
            detail: "no providers seen yet in this process".to_string(),
        };
    }
    let mut any_open = false;
    let mut any_half_open = false;
    let mut parts = Vec::new();
    for (provider, snap) in snaps {
        match snap.state {
            crate::providers::circuit_breaker::BreakerState::Open => any_open = true,
            crate::providers::circuit_breaker::BreakerState::HalfOpen => any_half_open = true,
            _ => {}
        }
        parts.push(format!(
            "{provider}={state}(fails={f})",
            state = snap.state.as_str(),
            f = snap.consecutive_failures,
        ));
    }
    let detail = parts.join("; ");
    let status = if any_open || any_half_open {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    CheckOutcome {
        name: "circuit breakers",
        status,
        detail,
    }
}

/// QM-9 Phase 1 doctor surface: aggregate the last 24h of
/// `~/.neoth/usage/*.jsonl` and warn when cost crosses the operator's
/// configured daily cap. Pass when no usage dir exists yet (clean
/// install) or when cost is below the cap. The cap defaults to
/// `freedom.yaml::council.daily_usd_cap` (typical value $5).
pub(crate) fn check_usage_today(home: &Path) -> CheckOutcome {
    let now = crate::time::now_unix_i64();
    let since = now - 86_400;
    let roll = crate::daemon::usage_log::aggregate(home, since, now);
    if roll.total_call_count == 0 {
        return CheckOutcome {
            name: "usage today",
            status: CheckStatus::Pass,
            detail: "no calls in last 24h".to_string(),
        };
    }
    // Storage canonical stays USD; render in the operator's chosen
    // currency. Cap stays a USD value (council.daily_usd_cap) so the
    // gate is currency-stable across operator preference changes.
    let cap_usd = freedom_daily_usd_cap(home);
    let currency = crate::cli::usage::resolve_currency(home, None);
    let pct_of_cap = if cap_usd > 0.0 {
        (roll.total_cost_usd / cap_usd) * 100.0
    } else {
        0.0
    };
    let cost_rendered = crate::providers::cost::format_amount(
        crate::providers::cost::convert_from_usd(roll.total_cost_usd, currency),
        currency,
    );
    let cap_rendered = crate::providers::cost::format_amount(
        crate::providers::cost::convert_from_usd(cap_usd, currency),
        currency,
    );
    let detail = format!(
        "{} calls (ok={}, err={}), {} ({:.0}% of {} cap)",
        roll.total_call_count,
        roll.total_ok_count,
        roll.total_err_count,
        cost_rendered,
        pct_of_cap,
        cap_rendered,
    );
    let status = if cap_usd > 0.0 && (roll.total_cost_usd >= cap_usd || pct_of_cap >= 80.0) {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    CheckOutcome {
        name: "usage today",
        status,
        detail,
    }
}

/// Read `freedom.yaml::council.daily_usd_cap`. Returns 5.0 as the
/// sensible default when the field is missing or unparseable —
/// matches the Pick #8 council redesign default in the spec.
pub(crate) fn freedom_daily_usd_cap(home: &Path) -> f64 {
    const DEFAULT_CAP: f64 = 5.0;
    let path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return DEFAULT_CAP;
    };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return DEFAULT_CAP;
    };
    val.get("council")
        .and_then(|c| c.get("daily_usd_cap"))
        .and_then(|v| v.as_f64())
        .unwrap_or(DEFAULT_CAP)
}

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[
    check_usage_today,
    check_circuit_breakers,
    check_provider_flapping,
    check_refusal_recovery,
    check_local_qwen_weights,
    check_n8n_api_token,
];

/// Operator runbook entries for this domain (the `--explain` surface).
pub(crate) const DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "usage today",
        purpose: "QM-9 Phase 1 spend-visibility surface. Aggregates \
                  the last 24h of `~/.neoth/usage/*.jsonl` and warns \
                  when cost crosses `council.daily_usd_cap` (default \
                  $5) or 80% of it. Pass when usage dir is missing \
                  (clean install) or cost is under threshold. Detail \
                  always carries call count + ok/err split + dollars \
                  + percent-of-cap so the operator sees burn rate at \
                  a glance.",
        common_failures: "Spend creeps past the daily cap before the \
                         operator notices. Errors-vs-successes ratio \
                         spikes (provider outage, broken prompt \
                         template).",
        fix: "If the spend is intentional, raise `council.daily_usd_cap` \
              in freedom.yaml. If unexpected, tail \
              `~/.neoth/usage/<today>.jsonl` to find the chatty path. \
              Lower the cap to throttle inadvertent loops by setting \
              `council.max_calls_per_user_message` (default 15) lower.",
    },
    CheckDoc {
        name: "circuit breakers",
        purpose: "QM-10 Phase 2 visibility surface. Reads the global \
                  `BreakerRegistry` snapshot + renders every provider \
                  the chat dispatch has touched in this process, with \
                  current state (closed/half_open/open) + consecutive \
                  failure count. Warn when any breaker is Open or in \
                  the HalfOpen probe state.",
        common_failures: "Provider flap (rate limit / regional outage / \
                          expired token) flips the breaker Open; chat \
                          calls reject immediately with retry_after \
                          until cooldown elapses (default 30s).",
        fix: "Wait the cooldown. Check `~/.neoth/usage/<today>.jsonl` \
              filtered by `ok == false` for the failure pattern. If a \
              specific provider is permanently broken, switch via \
              `neoth hemispheres set --role X --provider Y` or use \
              `neoth preset activate <bundle>` to swap a cloud-heavy \
              preset to a local-only one.",
    },
    CheckDoc {
        name: "provider flapping",
        purpose: "Flapping detection: scans the last 24h of \
                  usage_log entries + warns when any provider with \
                  ≥5 calls has an error rate ≥20%. Catches Slack \
                  rate-limit storms / WhatsApp Graph 5xx waves / \
                  OpenAI 429 spirals before they burn the operator's \
                  daily cap.",
        common_failures: "Slack workspace exceeded the per-app token \
                          rate limit (50 req/min for `chat.postMessage` \
                          on free workspaces); WhatsApp Cloud API \
                          rejecting webhooks because the operator's \
                          verify_token changed; OpenAI 429 from sudden \
                          burst traffic without a paid tier.",
        fix: "Check `~/.neoth/usage/<today>.jsonl` filtered by \
              `ok == false` for the failure shape. For rate-limit \
              flaps, reduce `council.max_calls_per_user_message` or \
              switch to a local-only preset via `neoth preset activate \
              fully-local && neoth preset apply fully-local`. For \
              auth flaps, `neoth doctor channels` shows the credential \
              wiring + a `neoth doctor --explain channels wiring` \
              gives the per-channel fix.",
    },
    CheckDoc {
        name: "refusal recovery",
        purpose: "SPEC-10 LOWKEY refusal-recovery health. When the model \
                  refuses a legitimate request, `try_recover` reframes the \
                  prompt + retries (up to `max_attempts`) per detected \
                  cause. Doctor warns when recovery is ENABLED but can \
                  never fire — every applicable reframing disabled, or \
                  `max_attempts = 0` — i.e. a silent no-op that looks \
                  active but does nothing.",
        common_failures: "All LOWKEY reframings added to \
                         `refusal_recovery.disabled_reframings`; \
                         `max_attempts: 0` set by hand; recovery left \
                         enabled but effectively dead.",
        fix: "Re-enable a reframing: `neoth refusal enable <id>` (list them \
              with `neoth refusal reframings`). Restore retries: set \
              `refusal_recovery.max_attempts: 2` in freedom.yaml. To turn \
              recovery off on purpose, set `refusal_recovery.enabled: \
              false` — doctor then passes quietly. Dry-run a refusal with \
              `neoth refusal test \"<refusal text>\"`.",
    },
    CheckDoc {
        name: "local_qwen weights",
        purpose: "SPEC-04 private-extraction readiness. When \
                  `profile.learn_provider = local_qwen` (the privacy-floor \
                  default), profile facts are extracted ON-DEVICE — but \
                  only if the Qwen weights are cached. If they're missing, \
                  the local provider fails to build and (with \
                  `allow_cloud_fallback = false`) extraction is SKIPPED \
                  rather than leaking the conversation to a cloud model, \
                  so profile learning silently stops.",
        common_failures: "Fresh install where the operator chose local_qwen \
                         in the wizard but skipped the ~3 GB weight download; \
                         a wiped `~/.neoth/models/` cache; an interrupted \
                         download leaving an `.incomplete` marker.",
        fix: "Download the weights: `neoth model fetch` (or re-run `neoth \
              init` and accept step 5c). To extract on a cloud model \
              instead, set `profile.learn_provider` to a cloud slug AND \
              `profile.allow_cloud_fallback: true` in freedom.yaml \
              (understand the privacy trade-off first — see `neoth privacy \
              audit`).",
    },
    CheckDoc {
        name: "n8n_api_token",
        purpose: "SC-08 — when the n8n API is enabled, its bearer token \
                  at `~/.neoth/n8n_api_token` is the key to the localhost \
                  automation surface. On Windows it must be DPAPI-wrapped \
                  (a copied file is useless outside the operator's \
                  account); on Unix it must be mode-0600.",
        common_failures: "A pre-SC-08 plaintext token still on disk \
                         (Windows); a token file whose mode drifted off \
                         0600 (Unix, e.g. restored from a backup).",
        fix: "Delete `~/.neoth/n8n_api_token` and restart `neoth serve` — \
              it re-mints the token DPAPI-wrapped (Windows) / mode-0600 \
              (Unix). On Unix you can also just `chmod 600 \
              ~/.neoth/n8n_api_token`. To remove the surface entirely set \
              `n8n_api.enabled: false`.",
    },
];
