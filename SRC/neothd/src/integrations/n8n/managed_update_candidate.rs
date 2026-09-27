//! Exact, isolated candidate identities for the managed Update custody.
//!
//! The source-image seed is only an offline export host. The target candidate
//! is a separately named normal n8n process on the same copied volume. The
//! two parsers intentionally cannot accept one another.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::{MANAGED_LABEL_KEY, MANAGED_LABEL_VALUE, valid_container_id};
use crate::integrations::state::JobId;

pub(crate) const UPDATE_CANDIDATE_INSPECT_FORMAT: &str = r#"[{"Id":{{json .Id}},"Name":{{json .Name}},"State":{"Running":{{json .State.Running}}},"Config":{"Image":{{json .Config.Image}},"Labels":{{json .Config.Labels}},"Entrypoint":{{json .Config.Entrypoint}},"Cmd":{{json .Config.Cmd}}},"HostConfig":{"NetworkMode":{{json .HostConfig.NetworkMode}},"RestartPolicy":{"Name":{{json .HostConfig.RestartPolicy.Name}}},"PortBindings":{{json .HostConfig.PortBindings}},"Tmpfs":{{json .HostConfig.Tmpfs}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}},"Mounts":{{json .Mounts}}}]"#;

const UPDATE_SCHEMA: &str = "1";
const INERT_ENTRYPOINT: &str = "node";
const INERT_KEEPALIVE_ARGUMENT: &str = "setInterval(() => {}, 2147483647);";
const TMPFS_OPTIONS: &str = "rw,noexec,nosuid,nodev,size=67108864";
const N8N_IMAGE_PREFIX: &str = "docker.io/n8nio/n8n@sha256:";
// Published normal n8n 2.40.7 image defaults. The candidate keeps these
// image defaults intact; inspection rejects every other command shape.
const NORMAL_ENTRYPOINT: [&str; 3] = ["tini", "--", "/docker-entrypoint.sh"];
// The admitted OCI config has no Cmd; Docker projects that absence as null.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdateVolumeSpec<'a> {
    pub update_job_id: &'a JobId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdateSeedSpec<'a> {
    pub update_job_id: &'a JobId,
    pub image: &'a str,
    pub volume: &'a str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdateServerCandidateSpec<'a> {
    pub update_job_id: &'a JobId,
    pub image: &'a str,
    pub volume: &'a str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedUpdateSeed {
    pub id: String,
    pub running: bool,
    pub image: String,
    pub update_job_id: String,
    pub volume: String,
    pub volume_source: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedUpdateServerCandidate {
    pub id: String,
    pub running: bool,
    pub image: String,
    pub update_job_id: String,
    pub volume: String,
    pub volume_source: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InspectUpdateSeedOutcome {
    Absent,
    Found(ObservedUpdateSeed),
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InspectUpdateServerCandidateOutcome {
    Absent,
    Found(ObservedUpdateServerCandidate),
    Unknown,
}

fn compact(job: &JobId) -> String {
    job.as_str().replace('-', "")
}
pub(crate) fn update_volume_name(job: &JobId) -> String {
    format!("neoth_n8n_update_{}", compact(job))
}
pub(crate) fn update_seed_name(job: &JobId) -> String {
    format!("neoth-n8n-update-seed-{}", compact(job))
}
pub(crate) fn update_server_candidate_name(job: &JobId) -> String {
    format!("neoth-n8n-update-candidate-{}", compact(job))
}
pub(crate) fn valid_update_volume_name(value: &str, job: &JobId) -> bool {
    value == update_volume_name(job)
}
pub(crate) fn valid_update_volume_labels(labels: &BTreeMap<String, String>, job: &JobId) -> bool {
    labels.len() == 3
        && labels.get(MANAGED_LABEL_KEY).map(String::as_str) == Some(MANAGED_LABEL_VALUE)
        && labels.get("io.neoth.n8n-update").map(String::as_str) == Some(job.as_str())
        && labels.get("io.neoth.n8n-update-schema").map(String::as_str) == Some(UPDATE_SCHEMA)
}
pub(crate) fn update_volume_command(spec: UpdateVolumeSpec<'_>) -> Vec<String> {
    vec![
        "docker".into(),
        "volume".into(),
        "create".into(),
        "--label".into(),
        format!("{MANAGED_LABEL_KEY}={MANAGED_LABEL_VALUE}"),
        "--label".into(),
        format!("io.neoth.n8n-update={}", spec.update_job_id.as_str()),
        "--label".into(),
        format!("io.neoth.n8n-update-schema={UPDATE_SCHEMA}"),
        update_volume_name(spec.update_job_id),
    ]
}
fn candidate_prefix(job: &JobId, name: String, volume: &str) -> Vec<String> {
    vec![
        "docker".into(),
        "create".into(),
        "--name".into(),
        name,
        "--label".into(),
        format!("{MANAGED_LABEL_KEY}={MANAGED_LABEL_VALUE}"),
        "--label".into(),
        format!("io.neoth.n8n-update={}", job.as_str()),
        "--label".into(),
        format!("io.neoth.n8n-update-schema={UPDATE_SCHEMA}"),
        "--network".into(),
        "none".into(),
        "--restart".into(),
        "no".into(),
        "--tmpfs".into(),
        format!("/tmp:{TMPFS_OPTIONS}"),
        "--mount".into(),
        format!("type=volume,source={volume},target=/home/node/.n8n"),
    ]
}
pub(crate) fn update_seed_command(spec: UpdateSeedSpec<'_>) -> Result<Vec<String>, &'static str> {
    if !valid_target_image(spec.image) || !valid_update_volume_name(spec.volume, spec.update_job_id)
    {
        return Err("n8n_update_seed_input_invalid");
    }
    let mut command = candidate_prefix(
        spec.update_job_id,
        update_seed_name(spec.update_job_id),
        spec.volume,
    );
    command.extend([
        "--entrypoint".into(),
        INERT_ENTRYPOINT.into(),
        spec.image.into(),
        "-e".into(),
        INERT_KEEPALIVE_ARGUMENT.into(),
    ]);
    Ok(command)
}
pub(crate) fn update_server_candidate_command(
    spec: UpdateServerCandidateSpec<'_>,
) -> Result<Vec<String>, &'static str> {
    if !valid_target_image(spec.image) || !valid_update_volume_name(spec.volume, spec.update_job_id)
    {
        return Err("n8n_update_server_candidate_input_invalid");
    }
    let mut command = candidate_prefix(
        spec.update_job_id,
        update_server_candidate_name(spec.update_job_id),
        spec.volume,
    );
    command.push(spec.image.into());
    Ok(command)
}

#[derive(Deserialize)]
struct Inspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "State")]
    state: State,
    #[serde(rename = "Config")]
    config: Config,
    #[serde(rename = "HostConfig")]
    host: Host,
    #[serde(rename = "NetworkSettings")]
    network: Network,
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
    restart: Restart,
    #[serde(rename = "PortBindings")]
    bindings: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(rename = "Tmpfs")]
    tmpfs: Option<BTreeMap<String, String>>,
}
#[derive(Deserialize)]
struct Restart {
    #[serde(rename = "Name")]
    name: String,
}
#[derive(Deserialize)]
struct Network {
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

fn parse(data: &[u8]) -> Result<Inspect, &'static str> {
    let mut rows: Vec<Inspect> =
        serde_json::from_slice(data).map_err(|_| "n8n_update_candidate_inspect_invalid")?;
    if rows.len() != 1 {
        return Err("n8n_update_candidate_inspect_invalid");
    }
    Ok(rows.pop().expect("length checked"))
}
fn common(row: &Inspect) -> Result<(JobId, String, String), &'static str> {
    if !valid_container_id(&row.id)
        || !valid_target_image(&row.config.image)
        || row.host.network_mode != "none"
        || row.host.restart.name != "no"
        || !no_host_port_bindings(&row.host.bindings)
        || !no_published_ports(&row.network.ports)
        || !has_exact_tmpfs(&row.host.tmpfs)
        || row.mounts.len() != 1
    {
        return Err("n8n_update_candidate_inspect_invalid");
    }
    let labels = row
        .config
        .labels
        .as_ref()
        .ok_or("n8n_update_candidate_inspect_invalid")?;
    // Docker inherits the admitted image's OCI/DHI metadata labels. Only the
    // NEOTH custody namespace is closed; image metadata is not another owner.
    if labels
        .keys()
        .filter(|key| key.starts_with("io.neoth."))
        .count()
        != 3
        || labels.get(MANAGED_LABEL_KEY).map(String::as_str) != Some(MANAGED_LABEL_VALUE)
        || labels.get("io.neoth.n8n-update-schema").map(String::as_str) != Some(UPDATE_SCHEMA)
        || labels.contains_key("io.neoth.n8n-job")
    {
        return Err("n8n_update_candidate_inspect_invalid");
    }
    let raw = labels
        .get("io.neoth.n8n-update")
        .ok_or("n8n_update_candidate_inspect_invalid")?;
    let job = JobId::parse(raw.clone()).map_err(|_| "n8n_update_candidate_inspect_invalid")?;
    let mount = &row.mounts[0];
    let volume = mount
        .name
        .clone()
        .ok_or("n8n_update_candidate_inspect_invalid")?;
    if mount.kind != "volume"
        || mount.source.is_empty()
        || mount.destination != "/home/node/.n8n"
        || !valid_update_volume_name(&volume, &job)
    {
        return Err("n8n_update_candidate_inspect_invalid");
    }
    Ok((job, volume, mount.source.clone()))
}
pub(crate) fn parse_observed_update_seed_json(
    data: &[u8],
) -> Result<ObservedUpdateSeed, &'static str> {
    let row = parse(data)?;
    let (job, volume, source) = common(&row)?;
    if row.name != format!("/{}", update_seed_name(&job)) || !has_inert_process(&row.config) {
        return Err("n8n_update_seed_inspect_invalid");
    }
    Ok(ObservedUpdateSeed {
        id: row.id,
        running: row.state.running,
        image: row.config.image,
        update_job_id: job.to_string(),
        volume,
        volume_source: source,
    })
}
pub(crate) fn parse_observed_update_server_candidate_json(
    data: &[u8],
) -> Result<ObservedUpdateServerCandidate, &'static str> {
    let row = parse(data)?;
    let (job, volume, source) = common(&row)?;
    if row.name != format!("/{}", update_server_candidate_name(&job))
        || !has_normal_process(&row.config)
    {
        return Err("n8n_update_server_candidate_inspect_invalid");
    }
    Ok(ObservedUpdateServerCandidate {
        id: row.id,
        running: row.state.running,
        image: row.config.image,
        update_job_id: job.to_string(),
        volume,
        volume_source: source,
    })
}
fn has_exact_tmpfs(tmpfs: &Option<BTreeMap<String, String>>) -> bool {
    tmpfs.as_ref().is_some_and(|value| {
        value.len() == 1 && value.get("/tmp").map(String::as_str) == Some(TMPFS_OPTIONS)
    })
}
fn has_inert_process(config: &Config) -> bool {
    config
        .entrypoint
        .as_ref()
        .is_some_and(|value| value.as_slice() == [INERT_ENTRYPOINT])
        && config
            .command
            .as_ref()
            .is_some_and(|value| value.as_slice() == ["-e", INERT_KEEPALIVE_ARGUMENT])
}
fn has_normal_process(config: &Config) -> bool {
    config
        .entrypoint
        .as_ref()
        .is_some_and(|value| value.as_slice() == NORMAL_ENTRYPOINT)
        && config.command.is_none()
}
fn no_host_port_bindings(bindings: &Option<BTreeMap<String, serde_json::Value>>) -> bool {
    bindings.as_ref().is_none_or(BTreeMap::is_empty)
}
fn no_published_ports(ports: &Option<BTreeMap<String, Option<Vec<serde_json::Value>>>>) -> bool {
    match ports {
        None => true,
        Some(value) => value
            .values()
            .all(|binding| binding.as_ref().is_none_or(Vec::is_empty)),
    }
}
fn valid_target_image(value: &str) -> bool {
    value.strip_prefix(N8N_IMAGE_PREFIX).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn job() -> JobId {
        JobId::parse("018f713e-2abc-7def-8abc-0123456789ab").unwrap()
    }
    fn image() -> String {
        format!("{N8N_IMAGE_PREFIX}{}", "a".repeat(64))
    }
    fn inspect(entrypoint: serde_json::Value, command: serde_json::Value) -> Vec<u8> {
        let job = job();
        serde_json::to_vec(&serde_json::json!([{"Id": "b".repeat(64), "Name": format!("/{}", update_server_candidate_name(&job)), "State": {"Running": false}, "Config": {"Image": image(), "Labels": {MANAGED_LABEL_KEY: MANAGED_LABEL_VALUE, "io.neoth.n8n-update": job.as_str(), "io.neoth.n8n-update-schema": UPDATE_SCHEMA, "org.opencontainers.image.title": "n8n", "com.docker.dhi.entitlement": "public"}, "Entrypoint": entrypoint, "Cmd": command}, "HostConfig": {"NetworkMode": "none", "RestartPolicy": {"Name": "no"}, "PortBindings": {}, "Tmpfs": {"/tmp": TMPFS_OPTIONS}}, "NetworkSettings": {"Ports": {"5678/tcp": null}}, "Mounts": [{"Type":"volume", "Name": update_volume_name(&job), "Source":"/var/lib/docker/volumes/x/_data", "Destination":"/home/node/.n8n"}]}])).unwrap()
    }
    #[test]
    fn target_candidate_is_networkless_normal_and_hardened() {
        let job = job();
        let volume = update_volume_name(&job);
        let image = image();
        let command = update_server_candidate_command(UpdateServerCandidateSpec {
            update_job_id: &job,
            image: &image,
            volume: &volume,
        })
        .unwrap();
        assert!(
            command
                .windows(2)
                .any(|window| window == ["--network", "none"])
        );
        assert!(
            command
                .windows(2)
                .any(|window| window == ["--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864"])
        );
        assert!(!command.iter().any(|value| value == "--entrypoint"));
        assert!(
            parse_observed_update_server_candidate_json(&inspect(
                serde_json::json!(NORMAL_ENTRYPOINT),
                serde_json::Value::Null
            ))
            .is_ok()
        );
        for unexpected in [serde_json::json!(["n8n"]), serde_json::json!([])] {
            assert!(
                parse_observed_update_server_candidate_json(&inspect(
                    serde_json::json!(NORMAL_ENTRYPOINT),
                    unexpected,
                ))
                .is_err()
            );
        }
    }
    #[test]
    fn production_inspect_projection_emits_parseable_json() {
        let bytes = inspect(
            serde_json::json!(NORMAL_ENTRYPOINT),
            serde_json::Value::Null,
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let row = &value[0];
        let mut rendered = UPDATE_CANDIDATE_INSPECT_FORMAT.to_owned();
        for (field, pointer) in [
            ("Id", "/Id"),
            ("Name", "/Name"),
            ("State.Running", "/State/Running"),
            ("Config.Image", "/Config/Image"),
            ("Config.Labels", "/Config/Labels"),
            ("Config.Entrypoint", "/Config/Entrypoint"),
            ("Config.Cmd", "/Config/Cmd"),
            ("HostConfig.NetworkMode", "/HostConfig/NetworkMode"),
            (
                "HostConfig.RestartPolicy.Name",
                "/HostConfig/RestartPolicy/Name",
            ),
            ("HostConfig.PortBindings", "/HostConfig/PortBindings"),
            ("HostConfig.Tmpfs", "/HostConfig/Tmpfs"),
            ("NetworkSettings.Ports", "/NetworkSettings/Ports"),
            ("Mounts", "/Mounts"),
        ] {
            rendered = rendered.replace(
                &format!("{{{{json .{field}}}}}"),
                &serde_json::to_string(row.pointer(pointer).unwrap()).unwrap(),
            );
        }
        assert!(!rendered.contains("{{json"));
        let observed = parse_observed_update_server_candidate_json(rendered.as_bytes()).unwrap();
        assert_eq!(observed.id, "b".repeat(64));
        assert_eq!(observed.update_job_id, job().as_str());
    }
    #[test]
    fn parsers_reject_the_other_process_and_any_exposure() {
        let normal = inspect(
            serde_json::json!(NORMAL_ENTRYPOINT),
            serde_json::Value::Null,
        );
        let inert = inspect(
            serde_json::json!([INERT_ENTRYPOINT]),
            serde_json::json!(["-e", INERT_KEEPALIVE_ARGUMENT]),
        );
        assert!(parse_observed_update_seed_json(&normal).is_err());
        assert!(parse_observed_update_server_candidate_json(&inert).is_err());
        let exposed = String::from_utf8(normal)
            .unwrap()
            .replace("\"NetworkMode\":\"none\"", "\"NetworkMode\":\"bridge\"");
        assert!(parse_observed_update_server_candidate_json(exposed.as_bytes()).is_err());
        let mut conflicting: serde_json::Value = serde_json::from_slice(&inspect(
            serde_json::json!(NORMAL_ENTRYPOINT),
            serde_json::Value::Null,
        ))
        .unwrap();
        conflicting[0]["Config"]["Labels"]["io.neoth.n8n-job"] = serde_json::json!(job().as_str());
        assert!(parse_observed_update_server_candidate_json(
            &serde_json::to_vec(&conflicting).unwrap(),
        ).is_err());
    }
    #[test]
    fn parsers_bind_the_exact_reserved_name() {
        let normal = inspect(
            serde_json::json!(NORMAL_ENTRYPOINT),
            serde_json::Value::Null,
        );
        let renamed = String::from_utf8(normal)
            .unwrap()
            .replace("neoth-n8n-update-candidate-", "other-");
        assert!(parse_observed_update_server_candidate_json(renamed.as_bytes()).is_err());
        let seed = inspect(
            serde_json::json!([INERT_ENTRYPOINT]),
            serde_json::json!(["-e", INERT_KEEPALIVE_ARGUMENT]),
        );
        assert!(parse_observed_update_seed_json(&seed).is_err());
    }
}
