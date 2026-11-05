//! Local operator controls for the same persisted communication-profile owner.
use super::*;
use crate::profile::communication::{self, CommunicationDimension, session};
use sha2::{Digest, Sha256};

fn scoped_audit_payload(
    home: &std::path::Path,
    action: CommunicationControlAction,
    session_id: &str,
    dimension: CommunicationDimension,
    changed: bool,
) -> Result<Vec<u8>> {
    let state = communication::load_state(home)?;
    let payload = communication_control_audit_payload(
        action, changed, COMMUNICATION_OPERATOR_SUBJECT,
        state.subjects.get(COMMUNICATION_OPERATOR_SUBJECT).map(|profile| profile.revision),
        state.revision, crate::time::now_unix_i64(),
    )?;
    let mut payload: serde_json::Value = serde_json::from_slice(&payload)?;
    let mut hash = Sha256::new();
    hash.update(b"neoth.communication.session-control.v1\0");
    hash.update(session_id.as_bytes());
    payload["scope"] = serde_json::json!("session");
    payload["session_sha256"] = serde_json::json!(hex::encode(hash.finalize()));
    payload["dimension"] = serde_json::json!(dimension.as_str());
    serde_json::to_vec(&payload).context("serialize session preference audit")
}

fn set_at(
    home: &std::path::Path,
    policy: &crate::config::CommunicationProfileConfig,
    session_id: &str,
    dimension: CommunicationDimension,
    value: &str,
) -> Result<communication::ObservationOutcome> {
    session::validate_control_id(session_id)?;
    let preference = parse_communication_preference(dimension, value)?;
    // The event identity binds the explicit target and dimension as well as a
    // fresh nonce. No raw value or session id is placed into the WAL receipt.
    let identity = mint_communication_action_identity(
        "session_set",
        &format!("{session_id}\0{}\0{}", dimension.as_str(), preference_value_name(preference)),
    )?;
    let at = crate::time::now_unix_i64();
    let result = session::set(
        home, policy, LocalProfileCommunicationOperator::mint(), session_id,
        preference, identity.event_hash, at, false,
    )?;
    anyhow::ensure!(result.recorded == 1, "session preference was not persisted");
    Ok(result)
}

pub(super) async fn run(
    home: &std::path::Path,
    session_id: &str,
    sub: CommunicationSessionSub,
    output: &OutputFormat,
) -> Result<()> {
    communication::session::validate_control_id(session_id)?;
    let writing = !matches!(&sub, CommunicationSessionSub::Show);
    let policy = load_communication_policy_at(home, writing)?;
    if writing && !policy.enabled {
        anyhow::bail!("communication adaptation is disabled; enable it before changing preferences");
    }
    let (dimension, value, changed, action) = match sub {
        CommunicationSessionSub::Show => {
            let selected = session::inspect(
                home, &policy, LocalProfileCommunicationOperator::mint(), session_id, false,
            )?;
            let overrides = selected.iter().map(|(dimension, value)| serde_json::json!({
                "dimension": dimension.as_str(), "value": preference_value_name(*value)
            })).collect::<Vec<_>>();
            return match output {
                OutputFormat::Json | OutputFormat::Jsonl => emit_communication_json(
                    &serde_json::json!({"scope":"session","session_id":session_id,
                        "enabled":policy.enabled,"overrides":overrides,
                        "fallback":"existing global/channel preferences","device_override":false}),
                    output,
                ),
                OutputFormat::Table => {
                    println!("Session presentation: {session_id}");
                    if !policy.enabled {
                        println!("  Communication adaptation is disabled; no profile was read.");
                    } else if overrides.is_empty() {
                        println!("  No session overrides; existing preferences apply.");
                    } else {
                        for (dimension, value) in selected {
                            println!("  {}: {}", dimension.as_str(), preference_value_name(value));
                        }
                    }
                    Ok(())
                }
            };
        }
        CommunicationSessionSub::Set { dimension, value } => {
            let dimension = dimension.into();
            let parsed = parse_communication_preference(dimension, &value)?;
            set_at(home, &policy, session_id, dimension, &value)?;
            (dimension, Some(preference_value_name(parsed)), true, CommunicationControlAction::SetSessionPreference)
        }
        CommunicationSessionSub::Reset { dimension } => {
            let dimension = dimension.into();
            let changed = session::reset(
                home, &policy, LocalProfileCommunicationOperator::mint(), session_id, dimension, false,
            )?;
            (dimension, None, changed, CommunicationControlAction::ResetSessionPreference)
        }
    };
    let audit = scoped_audit_payload(home, action, session_id, dimension, changed)?;
    append_communication_control_payload_at(home, audit).await
        .context("session preference state committed; required post-commit audit failed")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => emit_communication_json(
            &serde_json::json!({"scope":"session","session_id":session_id,"dimension":dimension.as_str(),
                "value":value,"changed":changed,"wal_audit_persisted":true,
                "persistence":communication::STATE_RELATIVE_PATH}), output,
        ),
        OutputFormat::Table => {
            println!("Session presentation: {session_id}");
            println!("  {}: {}", dimension.as_str(), value.unwrap_or("session override cleared"));
            println!("  WAL audit: persisted; global preferences unchanged.");
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "profile_communication_session_tests.rs"]
mod tests;
