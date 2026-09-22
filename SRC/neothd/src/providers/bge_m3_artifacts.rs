//! Immutable BGE-M3 dense-embedding artifact manifest and local-cache boundary.
//!
//! This module deliberately does not make readiness network-capable. A caller
//! can mint VerifiedBgeM3Artifacts only after every reviewed byte has passed
//! SHA-256 verification. Acquisition is a separate transition and requires the
//! existing durable model-download attempt.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::media::model_manager::{
    ArtifactFingerprint, ArtifactKind, CacheHealth, ExpectedArtifactFingerprint,
    ModelDownloadAttempt, RequiredArtifact,
};

pub(crate) const BGE_M3_REPOSITORY: &str = "BAAI/bge-m3";
pub(crate) const BGE_M3_REVISION: &str = "5617a9f61b028005a4858fdac845db406aefb181";
/// Compatibility names for lifecycle consumers; both are immutable pins.
pub(crate) const DEFAULT_REPO: &str = BGE_M3_REPOSITORY;
pub(crate) const DEFAULT_REVISION: &str = BGE_M3_REVISION;
pub(crate) const BGE_M3_MODEL_ID: &str = "bge-m3";
pub(crate) const BGE_M3_EMBEDDING_DIMENSION: usize = 1024;
pub(crate) const BGE_M3_MAX_TOKENS: usize = 8192;
/// The official PTH is ~2.27 GiB. Acquisition may temporarily retain both the
/// HF blob and NEOTH's atomically-installed copy, so require 5 GiB free.
pub(crate) const BGE_M3_DOWNLOAD_MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

pub(crate) const CONFIG_FILE: &str = "config.json";
pub(crate) const TOKENIZER_CONFIG_FILE: &str = "tokenizer_config.json";
pub(crate) const SPECIAL_TOKENS_FILE: &str = "special_tokens_map.json";
pub(crate) const TOKENIZER_FILE: &str = "tokenizer.json";
pub(crate) const SENTENCEPIECE_FILE: &str = "sentencepiece.bpe.model";
pub(crate) const WEIGHTS_FILE: &str = "pytorch_model.bin";

pub(crate) const REQUIRED_ARTIFACTS: &[RequiredArtifact] = &{
    [
        RequiredArtifact {
            filename: WEIGHTS_FILE,
            kind: ArtifactKind::NonEmpty {
                minimum_bytes: 2_271_145_830,
            },
            expected: Some(ExpectedArtifactFingerprint {
                len: 2_271_145_830,
                sha256: "b5e0ce3470abf5ef3831aa1bd5553b486803e83251590ab7ff35a117cf6aad38",
            }),
        },
        RequiredArtifact {
            filename: SENTENCEPIECE_FILE,
            kind: ArtifactKind::NonEmpty {
                minimum_bytes: 5_069_051,
            },
            expected: Some(ExpectedArtifactFingerprint {
                len: 5_069_051,
                sha256: "cfc8146abe2a0488e9e2a0c56de7952f7c11ab059eca145a0a727afce0db2865",
            }),
        },
        RequiredArtifact {
            filename: TOKENIZER_FILE,
            kind: ArtifactKind::NonEmpty {
                minimum_bytes: 17_098_108,
            },
            expected: Some(ExpectedArtifactFingerprint {
                len: 17_098_108,
                sha256: "21106b6d7dab2952c1d496fb21d5dc9db75c28ed361a05f5020bbba27810dd08",
            }),
        },
        json_artifact(
            CONFIG_FILE,
            687,
            "26159e7ad065073448460117eb24b7a4572f6f4e78eadff65dc0a11c052449fa",
        ),
        json_artifact(
            TOKENIZER_CONFIG_FILE,
            444,
            "a62b2b6784f990259fddef5f16388693a8043be4f69179e6a5257eeb3f9abac4",
        ),
        json_artifact(
            SPECIAL_TOKENS_FILE,
            964,
            "8c785abebea9ae3257b61681b4e6fd8365ceafde980c21970d001e834cf10835",
        ),
        opaque_artifact(
            "modules.json",
            349,
            "84e40c8e006c9b1d6c122e02cba9b02458120b5fb0c87b746c41e0207cf642cf",
        ),
        json_artifact(
            "1_Pooling/config.json",
            191,
            "e54c164a07274f2eb45bb724f54a79d1efcc90c41573887cd9a29aeee0597352",
        ),
        json_artifact(
            "sentence_bert_config.json",
            54,
            "eb9b44b13c0f52a3b3685c3b1cbdea1ba8b04bea123b98f61610048940776eb1",
        ),
        json_artifact(
            "config_sentence_transformers.json",
            123,
            "1eef72430e7194a1e59680e635aed81ffa083f05668dbc5bb1c56c04c0999c38",
        ),
    ]
};

/// The upstream Sentence Transformers module graph is a JSON array, while the
/// cache manager's JsonObject validator intentionally rejects arrays. Its
/// immutable length/SHA-256 remain the structural and identity proof.
const fn opaque_artifact(
    filename: &'static str,
    len: u64,
    sha256: &'static str,
) -> RequiredArtifact {
    RequiredArtifact {
        filename,
        kind: ArtifactKind::NonEmpty { minimum_bytes: len },
        expected: Some(ExpectedArtifactFingerprint { len, sha256 }),
    }
}

const fn json_artifact(filename: &'static str, len: u64, sha256: &'static str) -> RequiredArtifact {
    RequiredArtifact {
        filename,
        kind: ArtifactKind::JsonObject,
        expected: Some(ExpectedArtifactFingerprint { len, sha256 }),
    }
}

/// An exact location and immutable BGE-M3 manifest. Its fields stay private so
/// adapter construction cannot substitute a repo, revision, or artifact path.
#[derive(Debug, Clone)]
pub(crate) struct BgeM3Artifacts {
    cache_dir: PathBuf,
    hf_cache_dir: PathBuf,
}

impl BgeM3Artifacts {
    pub(crate) fn at_neoth_home(neoth_home: &Path) -> Self {
        let models_root = neoth_home.join("models");
        Self {
            cache_dir: models_root.join(BGE_M3_MODEL_ID),
            hf_cache_dir: models_root.join(".hf-hub"),
        }
    }

    pub(crate) fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Cheap, side-effect-free status for UI/CLI. This does not download or
    /// hash the large checkpoint; callers that need authority use verify.
    pub(crate) fn cache_health(&self) -> CacheHealth {
        crate::media::model_manager::cache_health(&self.cache_dir, &REQUIRED_ARTIFACTS)
    }

    /// Verify every exact manifest byte and mint the only capability accepted
    /// by the local BGE-M3 adapter. This has no downloader side effect.
    pub(crate) fn verify(self) -> Result<VerifiedBgeM3Artifacts> {
        let health = crate::media::model_manager::verified_cache_health(
            &self.cache_dir,
            &REQUIRED_ARTIFACTS,
        );
        if !health.is_ready() {
            bail!("BGE-M3 cache is not verified: {health}");
        }
        Ok(VerifiedBgeM3Artifacts { artifacts: self })
    }

    /// Materialise the reviewed immutable HF revision. The caller must already
    /// own a durable D7-authorized model download attempt. Readiness never calls
    /// this method.
    pub(crate) async fn acquire_from_hf(
        &self,
        attempt: &ModelDownloadAttempt,
    ) -> Result<VerifiedBgeM3Artifacts> {
        let cache_dir = self.cache_dir.clone();
        let health = tokio::task::spawn_blocking(move || {
            crate::media::model_manager::verified_cache_health_during_install(
                &cache_dir,
                REQUIRED_ARTIFACTS,
            )
        })
        .await
        .context("join BGE-M3 pre-acquisition SHA-256 verification")?;
        if health.is_ready() {
            return Ok(VerifiedBgeM3Artifacts {
                artifacts: self.clone(),
            });
        }
        if !attempt.network_authorized(&self.cache_dir, BGE_M3_REPOSITORY) {
            bail!("BGE-M3 network access is not authorized by a confirmed model-download attempt");
        }
        crate::providers::local_qwen::preflight_disk_space(
            &self.cache_dir,
            BGE_M3_DOWNLOAD_MIN_FREE_BYTES,
        )
        .context("disk-space pre-flight before BGE-M3 download")?;

        use hf_hub::api::tokio::ApiBuilder;
        use hf_hub::{Repo, RepoType};

        let api = ApiBuilder::new()
            .with_cache_dir(self.hf_cache_dir.clone())
            .build()
            .context("initialize Hugging Face API for BGE-M3")?;
        let repo = api.repo(Repo::with_revision(
            BGE_M3_REPOSITORY.to_string(),
            RepoType::Model,
            BGE_M3_REVISION.to_string(),
        ));

        for artifact in REQUIRED_ARTIFACTS {
            let expected = artifact
                .expected
                .context("BGE-M3 manifest artifact is missing its fingerprint")?;
            let source = repo.download(artifact.filename).await.with_context(|| {
                format!("download pinned BGE-M3 artifact {}", artifact.filename)
            })?;
            crate::media::model_manager::install_from_hf_source(
                &source,
                &self.cache_dir.join(artifact.filename),
                &ArtifactFingerprint {
                    len: expected.len,
                    sha256: expected.sha256.to_string(),
                },
            )
            .await
            .with_context(|| format!("install verified BGE-M3 artifact {}", artifact.filename))?;
        }

        self.clone().verify_during_install().await
    }

    async fn verify_during_install(self) -> Result<VerifiedBgeM3Artifacts> {
        let cache_dir = self.cache_dir.clone();
        let health = tokio::task::spawn_blocking(move || {
            crate::media::model_manager::verified_cache_health_during_install(
                &cache_dir,
                REQUIRED_ARTIFACTS,
            )
        })
        .await
        .context("join BGE-M3 post-install SHA-256 verification")?;
        if !health.is_ready() {
            bail!("BGE-M3 cache failed post-install verification: {health}");
        }
        Ok(VerifiedBgeM3Artifacts { artifacts: self })
    }
}

/// Side-effect-free full integrity status for a caller-owned exact cache path.
/// This is the adapter gate; it neither discovers another cache nor downloads.
pub(crate) fn verified_cache_health_at(cache_dir: &Path) -> CacheHealth {
    crate::media::model_manager::verified_cache_health(cache_dir, REQUIRED_ARTIFACTS)
}

/// Capability minted only after exact manifest verification. Consumers may use
/// its reviewed paths, but cannot construct it from an arbitrary cache.
#[derive(Debug)]
pub(crate) struct VerifiedBgeM3Artifacts {
    artifacts: BgeM3Artifacts,
}

impl VerifiedBgeM3Artifacts {
    pub(crate) fn cache_dir(&self) -> &Path {
        self.artifacts.cache_dir()
    }

    pub(crate) fn config_path(&self) -> PathBuf {
        self.cache_dir().join(CONFIG_FILE)
    }

    pub(crate) fn tokenizer_path(&self) -> PathBuf {
        self.cache_dir().join(TOKENIZER_FILE)
    }

    pub(crate) fn weights_path(&self) -> PathBuf {
        self.cache_dir().join(WEIGHTS_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modules_artifact() -> RequiredArtifact {
        *REQUIRED_ARTIFACTS
            .iter()
            .find(|artifact| artifact.filename == "modules.json")
            .expect("BGE-M3 manifest must retain the Sentence Transformers module graph")
    }

    #[test]
    fn official_modules_array_is_accepted_at_the_manifest_boundary() {
        let cache = tempfile::tempdir().unwrap();
        // Exact pinned upstream content: Transformer -> CLS Pooling -> Normalize.
        let modules = concat!(
            "[\n",
            "  {\n    \"idx\": 0,\n    \"name\": \"0\",\n    \"path\": \"\",\n",
            "    \"type\": \"sentence_transformers.models.Transformer\"\n  },\n",
            "  {\n    \"idx\": 1,\n    \"name\": \"1\",\n    \"path\": \"1_Pooling\",\n",
            "    \"type\": \"sentence_transformers.models.Pooling\"\n  },\n",
            "  {\n    \"idx\": 2,\n    \"name\": \"2\",\n    \"path\": \"2_Normalize\",\n",
            "    \"type\": \"sentence_transformers.models.Normalize\"\n  }\n]"
        );
        assert_eq!(modules.len(), 349);
        std::fs::write(cache.path().join("modules.json"), modules).unwrap();
        assert!(
            crate::media::model_manager::verified_cache_health(cache.path(), &[modules_artifact()])
                .is_ready()
        );
    }

    #[test]
    fn modules_artifact_missing_or_truncated_is_not_ready() {
        let cache = tempfile::tempdir().unwrap();
        let artifact = modules_artifact();
        assert!(matches!(
            crate::media::model_manager::cache_health(cache.path(), &[artifact]),
            CacheHealth::Missing { .. }
        ));
        std::fs::write(cache.path().join("modules.json"), b"[]").unwrap();
        assert!(matches!(
            crate::media::model_manager::cache_health(cache.path(), &[artifact]),
            CacheHealth::Corrupt { .. }
        ));
    }

    #[tokio::test]
    async fn acquisition_refuses_missing_cache_before_hf_initialization_without_d7() {
        let home = tempfile::tempdir().unwrap();
        let artifacts = BgeM3Artifacts::at_neoth_home(home.path());
        let attempt =
            ModelDownloadAttempt::acquire(artifacts.cache_dir(), BGE_M3_REPOSITORY, "test")
                .await
                .unwrap();

        let error = artifacts.acquire_from_hf(&attempt).await.unwrap_err();
        assert!(error.to_string().contains("not authorized"));
        assert!(!artifacts.cache_dir().join(WEIGHTS_FILE).exists());
    }

    #[tokio::test]
    async fn terminal_ready_retry_is_not_network_authorized() {
        struct FailTerminalAudit;

        #[async_trait::async_trait]
        impl crate::media::model_manager::ModelDownloadAuditSink for FailTerminalAudit {
            async fn append_model_download(&self, event_type: u8, _payload: Vec<u8>) -> Result<()> {
                if event_type == crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE {
                    anyhow::bail!("inject D8 replay failure")
                }
                Ok(())
            }
        }

        let home = tempfile::tempdir().unwrap();
        let artifacts = BgeM3Artifacts::at_neoth_home(home.path());
        let mut first =
            ModelDownloadAttempt::acquire(artifacts.cache_dir(), BGE_M3_REPOSITORY, "test")
                .await
                .unwrap();
        let sink = FailTerminalAudit;
        first.ensure_started(&sink).await.unwrap();
        assert!(first.network_authorized(artifacts.cache_dir(), BGE_M3_REPOSITORY));
        assert!(
            first
                .finish_ready(&sink, artifacts.cache_dir())
                .await
                .is_err()
        );
        drop(first);

        let retry = ModelDownloadAttempt::acquire(artifacts.cache_dir(), BGE_M3_REPOSITORY, "test")
            .await
            .unwrap();
        assert_eq!(
            retry.pending_outcome(),
            Some(crate::media::model_manager::PendingModelDownloadOutcome::Ready)
        );
        assert!(!retry.network_authorized(artifacts.cache_dir(), BGE_M3_REPOSITORY));
        // `acquire_from_hf` must return a fully verified cache before this
        // network-authorisation disposition is consulted.
    }
}
