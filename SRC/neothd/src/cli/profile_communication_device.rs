//! Local operator controls for the same persisted communication-profile owner.
use super::*;
use crate::profile::communication::{self, CommunicationDimension, device};
use sha2::{Digest, Sha256};

fn scoped_audit_payload(
    home: &std::path::Path,
    action: CommunicationControlAction,
    device_id: &str,
    dimension: CommunicationDimension,
    changed: bool,
) -> Result<Vec<u8>> {
    let state = communication::load_state(home)?;
    let payload = communication_control_audit_payload(
        action,
        changed,
        COMMUNICATION_OPERATOR_SUBJECT,
        state
            .subjects
            .get(COMMUNICATION_OPERATOR_SUBJECT)
            .map(|profile| profile.revision),
        state.revision,
        crate::time::now_unix_i64(),
    )?;
    let mut payload: serde_json::Value = serde_json::from_slice(&payload)?;
    let mut hash = Sha256::new();
    hash.update(b"neoth.communication.device-control.v1\0");
    hash.update(device_id.as_bytes());
    payload["scope"] = serde_json::json!("device");
    payload["device_sha256"] = serde_json::json!(hex::encode(hash.finalize()));
    payload["dimension"] = serde_json::json!(dimension.as_str());
    serde_json::to_vec(&payload).context("serialize device preference audit")
}

fn set_at(
    home: &std::path::Path,
    policy: &crate::config::CommunicationProfileConfig,
    device_id: &str,
    dimension: CommunicationDimension,
    value: &str,
) -> Result<communication::ObservationOutcome> {
    device::validate_control_id(device_id)?;
    let preference = parse_communication_preference(dimension, value)?;
    // The event identity binds the explicit target and dimension as well as a
    // fresh nonce. No raw value or device id is placed into the WAL receipt.
    let identity = mint_communication_action_identity(
        "device_set",
        &format!(
            "{device_id}\0{}\0{}",
            dimension.as_str(),
            preference_value_name(preference)
        ),
    )?;
    let at = crate::time::now_unix_i64();
    let result = device::set(
        home,
        policy,
        LocalProfileCommunicationOperator::mint(),
        device_id,
        preference,
        identity.event_hash,
        at,
        false,
    )?;
    anyhow::ensure!(result.recorded == 1, "device preference was not persisted");
    Ok(result)
}

fn active_device_scope(
    devices: &[crate::daemon::companion_runtime::CompanionV3DeviceView],
    requested: uuid::Uuid,
) -> Result<String> {
    let mut matching = devices
        .iter()
        .filter(|device| device.device_id.0 == requested);
    let device = matching.next().context("companion device not found")?;
    anyhow::ensure!(matching.next().is_none(), "ambiguous companion device");
    anyhow::ensure!(
        device.grant_state == "active",
        "companion device is not active"
    );
    communication::device::scope_id(requested, device.revision)
}
pub(super) async fn run(
    home: &std::path::Path,
    device_id: &str,
    revision: Option<u64>,
    sub: CommunicationSessionSub,
    output: &OutputFormat,
) -> Result<()> {
    let requested = uuid::Uuid::parse_str(device_id).context("invalid companion device id")?;
    anyhow::ensure!(
        !requested.is_nil() && requested.to_string() == device_id,
        "noncanonical companion device id"
    );
    let epoch = if let Some(revision) = revision {
        anyhow::ensure!(
            !matches!(&sub, CommunicationSessionSub::Set { .. }),
            "an explicit revision permits only show or reset"
        );
        communication::device::scope_id(requested, revision)?
    } else {
        let devices = crate::daemon::audit_rpc::companion_v3_list_devices(home)
            .await
            .map_err(|error| anyhow::anyhow!("read active companion devices: {error}"))?;
        active_device_scope(&devices, requested)?
    };
    let device_id = epoch.as_str();
    communication::device::validate_control_id(device_id)?;
    let writing = !matches!(&sub, CommunicationSessionSub::Show);
    let policy = load_communication_policy_at(home, writing)?;
    if writing && !policy.enabled {
        anyhow::bail!(
            "communication adaptation is disabled; enable it before changing preferences"
        );
    }
    let (dimension, value, changed, action) = match sub {
        CommunicationSessionSub::Show => {
            let selected = device::inspect(
                home,
                &policy,
                LocalProfileCommunicationOperator::mint(),
                device_id,
                false,
            )?;
            let overrides = selected
                .iter()
                .map(|(dimension, value)| {
                    serde_json::json!({
                        "dimension": dimension.as_str(), "value": preference_value_name(*value)
                    })
                })
                .collect::<Vec<_>>();
            return match output {
                OutputFormat::Json | OutputFormat::Jsonl => emit_communication_json(
                    &serde_json::json!({"scope":"device","device_id":device_id,
                        "enabled":policy.enabled,"overrides":overrides,
                        "fallback":"existing global/channel preferences","device_override":true}),
                    output,
                ),
                OutputFormat::Table => {
                    println!("Device presentation: {device_id}");
                    if !policy.enabled {
                        println!("  Communication adaptation is disabled; no profile was read.");
                    } else if overrides.is_empty() {
                        println!("  No device overrides; existing preferences apply.");
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
            set_at(home, &policy, device_id, dimension, &value)?;
            (
                dimension,
                Some(preference_value_name(parsed)),
                true,
                CommunicationControlAction::SetDevicePreference,
            )
        }
        CommunicationSessionSub::Reset { dimension } => {
            let dimension = dimension.into();
            let changed = device::reset(
                home,
                &policy,
                LocalProfileCommunicationOperator::mint(),
                device_id,
                dimension,
                false,
            )?;
            (
                dimension,
                None,
                changed,
                CommunicationControlAction::ResetDevicePreference,
            )
        }
    };
    let audit = scoped_audit_payload(home, action, device_id, dimension, changed)?;
    append_communication_control_payload_at(home, audit)
        .await
        .context("device preference state committed; required post-commit audit failed")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => emit_communication_json(
            &serde_json::json!({"scope":"device","device_id":device_id,"dimension":dimension.as_str(),
                "value":value,"changed":changed,"wal_audit_persisted":true,
                "persistence":communication::STATE_RELATIVE_PATH}),
            output,
        ),
        OutputFormat::Table => {
            println!("Device presentation: {device_id}");
            println!(
                "  {}: {}",
                dimension.as_str(),
                value.unwrap_or("device override cleared")
            );
            println!("  WAL audit: persisted; global preferences unchanged.");
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "profile_communication_device_tests.rs"]
mod tests;
