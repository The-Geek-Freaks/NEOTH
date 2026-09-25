//! Isolated restore-candidate identity, construction, and inspect boundary.
//!
//! A restore candidate remains inert while recovered n8n state is copied and
//! checked. It has no network or published ports and bypasses the image's
//! normal n8n entrypoint with a fixed Node keepalive.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{valid_container_id, MANAGED_LABEL_KEY, MANAGED_LABEL_VALUE};
use crate::{installers::n8n::N8N_OCI_REFERENCE, integrations::state::JobId};

pub(crate) const RESTORE_CANDIDATE_TMPFS_BYTES: u64 = 64 * 1024 * 1024;
const RESTORE_SCHEMA: &str = "1";
const INERT_ENTRYPOINT: &str = "node";
const INERT_KEEPALIVE_ARGUMENT: &str = "setInterval(() => {}, 2147483647);";
const TMPFS_OPTIONS: &str = "rw,noexec,nosuid,nodev,size=67108864";

pub(crate) const CANDIDATE_INSPECT_FORMAT: &str = r#"[{"Id":{{json .Id}},"State":{"Running":{{json .State.Running}}},"Config":{"Image":{{json .Config.Image}},"Labels":{{json .Config.Labels}},"Entrypoint":{{json .Config.Entrypoint}},"Cmd":{{json .Config.Cmd}}},"HostConfig":{"NetworkMode":{{json .HostConfig.NetworkMode}},"RestartPolicy":{"Name":{{json .HostConfig.RestartPolicy.Name}}},"PortBindings":{{json .HostConfig.PortBindings}},"Tmpfs":{{json .HostConfig.Tmpfs}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}},"Mounts":{{json .Mounts}}}]"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RestoreCandidateSpec<'a> {
    pub restore_job_id: &'a JobId,
    pub image: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedRestoreCandidate {
    pub id: String,
    pub running: bool,
    pub image: String,
    pub restore_job_id: String,
    pub volume: String,
    /// Daemon-owned mount point observed in Docker's actual named-volume
    /// receipt. It is not synthesized from the volume name.
    pub volume_source: String,
    pub network_mode: String,
    pub tmpfs_options: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InspectRestoreCandidateOutcome {
    Absent,
    Found(ObservedRestoreCandidate),
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreCandidateContentReceipt {
    pub workflow_count: u32,
    pub credential_count: u32,
    pub credential_decryption_proven: bool,
    pub evidence_sha256: String,
}

fn compact(job: &JobId) -> String {
    job.as_str().replace('-', "")
}

pub(crate) fn restore_volume_name(job: &JobId) -> String {
    format!("neoth_n8n_{}", compact(job))
}

pub(crate) fn restore_candidate_name(job: &JobId) -> String {
    format!("neoth-n8n-restore-{}", compact(job))
}

pub(crate) fn valid_restore_volume_name(value: &str, job: &JobId) -> bool {
    value == restore_volume_name(job)
}

pub(crate) fn restore_volume_command(job: &JobId) -> Vec<String> {
    vec![
        "docker".into(),
        "volume".into(),
        "create".into(),
        "--label".into(),
        format!("{MANAGED_LABEL_KEY}={MANAGED_LABEL_VALUE}"),
        "--label".into(),
        format!("io.neoth.n8n-restore={}", job.as_str()),
        "--label".into(),
        format!("io.neoth.n8n-restore-schema={RESTORE_SCHEMA}"),
        restore_volume_name(job),
    ]
}

pub(crate) fn restore_candidate_command(
    spec: RestoreCandidateSpec<'_>,
) -> Result<Vec<String>, &'static str> {
    if spec.image != N8N_OCI_REFERENCE {
        return Err("n8n_restore_candidate_image_invalid");
    }
    Ok(vec![
        "docker".into(),
        "create".into(),
        "--name".into(),
        restore_candidate_name(spec.restore_job_id),
        "--label".into(),
        format!("{MANAGED_LABEL_KEY}={MANAGED_LABEL_VALUE}"),
        "--label".into(),
        format!("io.neoth.n8n-restore={}", spec.restore_job_id.as_str()),
        "--label".into(),
        format!("io.neoth.n8n-restore-schema={RESTORE_SCHEMA}"),
        "--network".into(),
        "none".into(),
        "--restart".into(),
        "no".into(),
        "--tmpfs".into(),
        format!("/tmp:{TMPFS_OPTIONS}"),
        "--mount".into(),
        format!(
            "type=volume,source={},target=/home/node/.n8n",
            restore_volume_name(spec.restore_job_id)
        ),
        "--entrypoint".into(),
        INERT_ENTRYPOINT.into(),
        spec.image.into(),
        "-e".into(),
        INERT_KEEPALIVE_ARGUMENT.into(),
    ])
}

#[derive(Deserialize)]
struct Inspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "State")]
    state: State,
    #[serde(rename = "Config")]
    config: Config,
    #[serde(rename = "HostConfig")]
    host: Host,
    #[serde(rename = "NetworkSettings")]
    network_settings: NetworkSettings,
    #[serde(rename = "Mounts")]
    mounts: Vec<Mount>,
}

#[derive(Deserialize)]
struct State {
    #[serde(rename = "Running")]
    running: bool,
}

#[derive(Deserialize)]
struct Config {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    command: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Host {
    #[serde(rename = "NetworkMode")]
    network_mode: String,
    #[serde(rename = "RestartPolicy")]
    restart_policy: RestartPolicy,
    #[serde(rename = "PortBindings")]
    port_bindings: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(rename = "Tmpfs")]
    tmpfs: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct RestartPolicy {
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Deserialize)]
struct NetworkSettings {
    #[serde(rename = "Ports")]
    ports: Option<BTreeMap<String, Option<Vec<serde_json::Value>>>>,
}

#[derive(Deserialize)]
struct Mount {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Source")]
    source: String,
    #[serde(rename = "Destination")]
    destination: String,
}

pub(crate) fn parse_observed_restore_candidate_json(
    data: &[u8],
) -> Result<ObservedRestoreCandidate, &'static str> {
    let mut rows: Vec<Inspect> =
        serde_json::from_slice(data).map_err(|_| "n8n_restore_candidate_inspect_invalid")?;
    if rows.len() != 1 {
        return Err("n8n_restore_candidate_inspect_invalid");
    }
    let observed = rows.pop().expect("length checked");
    if !valid_container_id(&observed.id)
        || observed.config.image != N8N_OCI_REFERENCE
        || observed.host.network_mode != "none"
        || observed.host.restart_policy.name != "no"
        || !has_fixed_inert_process(&observed.config)
        || !no_host_port_bindings(&observed.host.port_bindings)
        || !no_published_ports(&observed.network_settings.ports)
    {
        return Err("n8n_restore_candidate_inspect_invalid");
    }
    let labels = observed
        .config
        .labels
        .ok_or("n8n_restore_candidate_inspect_invalid")?;
    let restore_job_id = labels
        .get("io.neoth.n8n-restore")
        .cloned()
        .ok_or("n8n_restore_candidate_inspect_invalid")?;
    if JobId::parse(restore_job_id.clone()).is_err()
        || labels.get(MANAGED_LABEL_KEY).map(String::as_str) != Some(MANAGED_LABEL_VALUE)
        || labels.get("io.neoth.n8n-restore-schema").map(String::as_str) != Some(RESTORE_SCHEMA)
        || labels.contains_key("io.neoth.n8n-job")
    {
        return Err("n8n_restore_candidate_inspect_invalid");
    }
    let tmpfs = observed
        .host
        .tmpfs
        .ok_or("n8n_restore_candidate_inspect_invalid")?;
    let tmpfs_options = tmpfs
        .get("/tmp")
        .cloned()
        .ok_or("n8n_restore_candidate_inspect_invalid")?;
    if tmpfs.len() != 1 || !valid_tmpfs(&tmpfs_options) {
        return Err("n8n_restore_candidate_inspect_invalid");
    }
    // Moby keeps legacy --tmpfs only in HostConfig.Tmpfs. .Mounts contains
    // the named volume (with populated Source), not a second tmpfs mount.
    if observed.mounts.len() != 1 {
        return Err("n8n_restore_candidate_inspect_invalid");
    }
    let mount = &observed.mounts[0];
    let volume = mount
        .name
        .as_deref()
        .ok_or("n8n_restore_candidate_inspect_invalid")?;
    let restore_job = JobId::parse(restore_job_id.clone())
        .map_err(|_| "n8n_restore_candidate_inspect_invalid")?;
    if mount.kind != "volume"
        || mount.source.is_empty()
        || mount.destination != "/home/node/.n8n"
        || !valid_restore_volume_name(volume, &restore_job)
    {
        return Err("n8n_restore_candidate_inspect_invalid");
    }
    Ok(ObservedRestoreCandidate {
        id: observed.id,
        running: observed.state.running,
        image: observed.config.image,
        restore_job_id,
        volume: volume.into(),
        volume_source: mount.source.clone(),
        network_mode: observed.host.network_mode,
        tmpfs_options,
    })
}

fn no_host_port_bindings(bindings: &Option<BTreeMap<String, serde_json::Value>>) -> bool {
    bindings.as_ref().map_or(true, BTreeMap::is_empty)
}

fn has_fixed_inert_process(config: &Config) -> bool {
    config.entrypoint.as_ref().map_or(false, |entrypoint| {
        entrypoint.len() == 1 && entrypoint[0] == INERT_ENTRYPOINT
    }) && config.command.as_ref().map_or(false, |command| {
        command.len() == 2
            && command[0] == "-e"
            && command[1] == INERT_KEEPALIVE_ARGUMENT
    })
}

fn no_published_ports(ports: &Option<BTreeMap<String, Option<Vec<serde_json::Value>>>>) -> bool {
    match ports {
        None => true,
        Some(ports) if ports.is_empty() => true,
        // n8n exposes 5678/tcp in its image. Docker represents this unbound
        // declaration as null, never a host binding.
        Some(ports) => ports.len() == 1 && matches!(ports.get("5678/tcp"), Some(None)),
    }
}

fn valid_tmpfs(value: &str) -> bool {
    value == TMPFS_OPTIONS
}

#[cfg(test)]
mod tests {
    use super::*;
    const JOB: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn job() -> JobId {
        JobId::parse(JOB.into()).expect("fixed valid UUID")
    }

    fn inspected_candidate() -> String {
        format!(
            r#"[{{"Id":"{ID}","State":{{"Running":false}},"Config":{{"Image":"{N8N_OCI_REFERENCE}","Labels":{{"{MANAGED_LABEL_KEY}":"{MANAGED_LABEL_VALUE}","io.neoth.n8n-restore":"{JOB}","io.neoth.n8n-restore-schema":"1"}},"Entrypoint":["node"],"Cmd":["-e","{INERT_KEEPALIVE_ARGUMENT}"]}},"HostConfig":{{"NetworkMode":"none","RestartPolicy":{{"Name":"no"}},"PortBindings":{{}},"Tmpfs":{{"/tmp":"{TMPFS_OPTIONS}"}}}},"NetworkSettings":{{"Ports":{{"5678/tcp":null}}}},"Mounts":[{{"Type":"volume","Name":"neoth_n8n_123e4567e89b12d3a456426614174000","Source":"/var/lib/docker/volumes/neoth_n8n_123e4567e89b12d3a456426614174000/_data","Destination":"/home/node/.n8n"}}]}}]"#
        )
    }

    #[test]
    fn restore_names_are_exact_and_not_generic() {
        let job = job();
        assert_eq!(restore_volume_name(&job), "neoth_n8n_123e4567e89b12d3a456426614174000");
        assert_eq!(restore_candidate_name(&job), "neoth-n8n-restore-123e4567e89b12d3a456426614174000");
        assert!(valid_restore_volume_name(&restore_volume_name(&job), &job));
        assert!(!valid_restore_volume_name("neoth_n8n_data", &job));
    }

    #[test]
    fn restore_candidate_command_is_inert_and_uses_fixed_immutable_identity() {
        let job = job();
        let command = restore_candidate_command(RestoreCandidateSpec {
            restore_job_id: &job,
            image: N8N_OCI_REFERENCE,
        })
        .expect("pinned image");
        assert!(command.windows(2).any(|pair| pair == ["--network", "none"]));
        assert!(command.windows(2).any(|pair| pair == ["--restart", "no"]));
        assert!(command.windows(2).any(|pair| pair == ["--entrypoint", "node"]));
        assert!(command.windows(2).any(|pair| pair == ["-e", INERT_KEEPALIVE_ARGUMENT]));
        assert!(command.iter().any(|part| part == N8N_OCI_REFERENCE));
        assert!(!command.iter().any(|part| part == "-p" || part == "--publish"));
        assert!(restore_candidate_command(RestoreCandidateSpec {
            restore_job_id: &job,
            image: "docker.io/n8nio/n8n@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        })
        .is_err());
    }
    #[test]
    fn parse_restore_candidate_accepts_real_docker_volume_mount_shape() {
        let found = parse_observed_restore_candidate_json(inspected_candidate().as_bytes())
            .expect("isolated candidate receipt");
        assert_eq!(found.id, ID);
        assert_eq!(found.restore_job_id, JOB);
        assert_eq!(found.volume, restore_volume_name(&job()));
        assert_eq!(
            found.volume_source,
            "/var/lib/docker/volumes/neoth_n8n_123e4567e89b12d3a456426614174000/_data"
        );
        assert_eq!(found.image, N8N_OCI_REFERENCE);
        assert!(!found.running);
        let running = inspected_candidate().replacen(r#""Running":false"#, r#""Running":true"#, 1);
        assert!(parse_observed_restore_candidate_json(running.as_bytes()).unwrap().running);
    }

    #[test]
    fn parse_restore_candidate_rejects_each_non_inert_or_ambiguous_shape() {
        let baseline = inspected_candidate();
        for (from, to) in [
            (r#""NetworkMode":"none"#, r#""NetworkMode":"bridge"#),
            (r#""Name":"no"#, r#""Name":"unless-stopped"#),
            (r#""PortBindings":{}"#, r#""PortBindings":{"5678/tcp":[{"HostIp":"127.0.0.1","HostPort":"5678"}]}"#),
            (r#""Entrypoint":["node"]"#, r#""Entrypoint":["n8n"]"#),
            (INERT_KEEPALIVE_ARGUMENT, "process.exit(0)"),
            (TMPFS_OPTIONS, "rw,nosuid,nodev,size=67108864"),
            (r#""Name":"neoth_n8n_123e4567e89b12d3a456426614174000"#, r#""Name":"neoth_n8n_data"#),
            (r#""Source":"/var/lib/docker/volumes/neoth_n8n_123e4567e89b12d3a456426614174000/_data"#, r#""Source":""#),
        ] {
            let invalid = baseline.replacen(from, to, 1);
            assert!(parse_observed_restore_candidate_json(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn parse_restore_candidate_rejects_duplicate_mounts_and_tmpfs() {
        let baseline = inspected_candidate();
        let duplicated_mount = baseline.replacen(
            "]}]",
            r#",{"Type":"volume","Name":"neoth_n8n_123e4567e89b12d3a456426614174000","Source":"/var/lib/docker/volumes/other/_data","Destination":"/home/node/.n8n"}]}]"#,
            1,
        );
        assert!(parse_observed_restore_candidate_json(duplicated_mount.as_bytes()).is_err());
        let duplicate_tmpfs = baseline.replacen(
            r#""Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=67108864"}"#,
            r#""Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=67108864","/scratch":"rw,noexec,nosuid,nodev,size=67108864"}"#,
            1,
        );
        assert!(parse_observed_restore_candidate_json(duplicate_tmpfs.as_bytes()).is_err());
    }
}
