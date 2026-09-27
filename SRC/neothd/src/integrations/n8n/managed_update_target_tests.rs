use super::*;
use std::collections::BTreeMap;

struct FakeReader { responses: BTreeMap<String, Vec<u8>> }
#[async_trait]
impl RegistryTargetReader for FakeReader {
    async fn read(&self, object: RegistryObject) -> Result<Vec<u8>> { self.responses.get(&format!("{object:?}")).cloned().ok_or_else(|| anyhow!("fixture_missing")) }
}
#[derive(Default)]
struct FakeDocker { calls: Vec<Vec<String>>, observed: Option<DockerImageObservation>, pull_fails: bool, inspect_fails: bool }
#[async_trait]
impl UpdateTargetDockerRunner for FakeDocker {
    async fn pull_exact_target(&mut self, platform: &str, image: &str) -> Result<()> { self.calls.push(vec!["pull".into(), "--platform".into(), platform.into(), image.into()]); if self.pull_fails { Err(anyhow!("fake_pull")) } else { Ok(()) } }
    async fn inspect_pulled_target(&mut self, image: &str) -> Result<DockerImageObservation> { self.calls.push(vec!["image".into(), "inspect".into(), image.into()]); if self.inspect_fails { return Err(anyhow!("fake_inspect")); } self.observed.clone().ok_or_else(|| anyhow!("fixture_observation_missing")) }
}
struct Fixture { target: UpdateTargetCatalogEntry, index: Vec<u8>, amd_child: Vec<u8>, config_digest: String }
fn leak(value: String) -> &'static str { Box::leak(value.into_boxed_str()) }
fn sha(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
fn manifest(config: &str) -> Vec<u8> { format!("{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{config}\",\"size\":1}}}}").into_bytes() }
fn fixture() -> Fixture {
    let config_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();
    let amd_child = manifest(&config_digest); let arm_child = manifest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let amd_digest = leak(sha(&amd_child)); let arm_digest = leak(sha(&arm_child));
    let index = format!("{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{amd_digest}\",\"size\":{},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}},{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{arm_digest}\",\"size\":{},\"platform\":{{\"os\":\"linux\",\"architecture\":\"arm64\"}}}}]}}", amd_child.len(), arm_child.len()).into_bytes();
    let index_digest = leak(sha(&index)); let platforms = Box::leak(Box::new([PlatformEntry { os: "linux", architecture: "amd64", child_manifest_digest: amd_digest }, PlatformEntry { os: "linux", architecture: "arm64", child_manifest_digest: arm_digest }]));
    Fixture { target: UpdateTargetCatalogEntry { selector: "fixture-n8n", version: "fixture", runtime_image: "docker.io/n8nio/n8n@fixture-index", repo_digest: "n8nio/n8n@fixture-index", index_digest, catalog_evidence_sha256: "evidence", platforms }, index, amd_child, config_digest }
}
fn reader(fixture: &Fixture) -> FakeReader { FakeReader { responses: BTreeMap::from([(format!("{:?}", RegistryObject::Manifest(fixture.target.index_digest)), fixture.index.clone()), (format!("{:?}", RegistryObject::Manifest(fixture.target.platforms[0].child_manifest_digest)), fixture.amd_child.clone())]) } }
fn observed(fixture: &Fixture) -> DockerImageObservation { DockerImageObservation { id: fixture.config_digest.clone(), repo_digests: vec![fixture.target.repo_digest.into()], os: "linux".into(), architecture: "amd64".into() } }

#[tokio::test]
async fn full_fake_proof_pulls_then_inspects_only_after_registry_and_child_proof() {
    let fixture = fixture(); let reader = reader(&fixture); let mut docker = FakeDocker { observed: Some(observed(&fixture)), ..Default::default() };
    let receipt = verify_target_with(&fixture.target, "linux/amd64", &reader, &mut docker).await.unwrap();
    assert_eq!(receipt.index_digest, fixture.target.index_digest); assert_eq!(receipt.child_manifest_digest, fixture.target.platforms[0].child_manifest_digest); assert_eq!(receipt.config_digest, fixture.config_digest);
    let expected: Vec<Vec<String>> = vec![vec!["pull".into(), "--platform".into(), "linux/amd64".into(), fixture.target.runtime_image.into()], vec!["image".into(), "inspect".into(), fixture.target.runtime_image.into()]];
    assert_eq!(docker.calls, expected);
}
#[tokio::test]
async fn selector_platform_and_registry_failures_have_no_docker_effects() {
    let fixture = fixture(); let reader = reader(&fixture); let mut docker = FakeDocker::default();
    assert!(resolve_target("tag:latest").is_err()); assert!(verify_target_with(&fixture.target, "windows/amd64", &reader, &mut docker).await.is_err());
    let oversize = FakeReader { responses: BTreeMap::from([(format!("{:?}", RegistryObject::Manifest(fixture.target.index_digest)), vec![0; MAX_REGISTRY_BYTES + 1])]) };
    assert!(verify_target_with(&fixture.target, "linux/amd64", &oversize, &mut docker).await.is_err()); assert!(docker.calls.is_empty());
}
#[tokio::test]
async fn wrong_index_child_size_and_config_shape_reject_before_pull() {
    for mutation in ["index", "size", "config"] {
        let mut broken = fixture(); match mutation { "index" => broken.index[0] ^= 1, "size" => { broken.index.splice(0..6, b"999999".iter().copied()); }, "config" => broken.amd_child = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"wrong","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1}}"#.to_vec(), _ => unreachable!() }
        let reader = reader(&broken); let mut docker = FakeDocker::default(); assert!(verify_target_with(&broken.target, "linux/amd64", &reader, &mut docker).await.is_err()); assert!(docker.calls.is_empty());
    }
}
#[test]
fn child_descriptor_size_and_config_media_shape_are_checked_after_digest() {
    let config = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let child = manifest(config); let entry = PlatformEntry { os: "linux", architecture: "amd64", child_manifest_digest: leak(sha(&child)) };
    assert!(verify_child_manifest(&child, &entry, child.len() as i64 + 1).is_err());
    let malformed = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"wrong","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1}}"#.to_vec();
    let malformed_entry = PlatformEntry { os: "linux", architecture: "amd64", child_manifest_digest: leak(sha(&malformed)) };
    assert!(verify_child_manifest(&malformed, &malformed_entry, malformed.len() as i64).is_err());
}
#[tokio::test]
async fn pull_failure_never_inspects_and_inspect_failure_never_retries() {
    let fixture = fixture(); let reader = reader(&fixture); let mut pull = FakeDocker { pull_fails: true, ..Default::default() };
    assert!(verify_target_with(&fixture.target, "linux/amd64", &reader, &mut pull).await.is_err()); assert_eq!(pull.calls.len(), 1);
    let mut inspect = FakeDocker { inspect_fails: true, ..Default::default() }; assert!(verify_target_with(&fixture.target, "linux/amd64", &reader, &mut inspect).await.is_err()); assert_eq!(inspect.calls.len(), 2);
}
#[tokio::test]
async fn wrong_repo_platform_config_and_extra_aliases_are_handled_after_exact_command_contract() {
    let fixture = fixture();
    for mutation in ["repo", "platform", "config"] { let reader = reader(&fixture); let mut value = observed(&fixture); match mutation { "repo" => value.repo_digests = vec!["n8nio/n8n@wrong".into()], "platform" => value.architecture = "arm64".into(), "config" => value.id = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(), _ => unreachable!() } let mut docker = FakeDocker { observed: Some(value), ..Default::default() }; assert!(verify_target_with(&fixture.target, "linux/amd64", &reader, &mut docker).await.is_err()); assert_eq!(docker.calls.len(), 2); }
    let reader = reader(&fixture); let mut value = observed(&fixture); value.repo_digests = vec!["docker.io/n8nio/n8n@fixture-index".into(), "foreign/repo@sha256:bad".into()]; let mut docker = FakeDocker { observed: Some(value), ..Default::default() }; assert!(verify_target_with(&fixture.target, "linux/amd64", &reader, &mut docker).await.is_ok());
}
#[test]
fn docker_hub_token_envelope_accepts_standard_optional_fields_without_exposing_them() { assert_eq!(parse_docker_hub_token(br#"{"token":"safe-token","access_token":"alternate","expires_in":300,"issued_at":"2026-09-27T00:00:00Z"}"#).unwrap(), "safe-token"); }
