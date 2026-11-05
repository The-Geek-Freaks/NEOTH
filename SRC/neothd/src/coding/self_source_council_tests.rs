use super::super::{GateError, apply_to_live_tree, run_gate_stack_with_context};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const PASS: &str = r#"{"kind":"pass","evidence":["bounded patch inspection"]}"#;
const FAIL: &str =
    r#"{"kind":"fail","failures":[{"kind":"invariant","message":"effect boundary uncertain"}]}"#;
const DIFF: &str = "--- a/src/cli/dummy.rs\n+++ b/src/cli/dummy.rs\n@@ -1 +1,2 @@\n fn dummy() {}\n+// reviewed change\n";

struct FixtureLeaf {
    calls: AtomicUsize,
    responses: Vec<&'static str>,
    hang: bool,
    drift_root: Option<std::path::PathBuf>,
}

impl FixtureLeaf {
    fn new(responses: Vec<&'static str>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            responses,
            hang: false,
            drift_root: None,
        }
    }
}

#[async_trait::async_trait]
impl ReviewLeaf for FixtureLeaf {
    async fn ask(
        &self,
        role: HemisphereRole,
        context: &LeafContext<'_>,
    ) -> Result<LeafOutput, String> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(format!("{role:?}"), format!("{:?}", ROLES[index]));
        assert!(context.prompt.contains("<<<UNTRUSTED_SOURCE_DATA>>>"));
        if self.hang {
            std::future::pending::<()>().await;
        }
        if index == 2
            && let Some(root) = &self.drift_root
        {
            std::fs::write(root.join("drift.txt"), "new index entry").unwrap();
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(root)
                    .args(["add", "drift.txt"])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        self.responses
            .get(index)
            .map(|s| LeafOutput {
                text: (*s).to_owned(),
                completion_identity_sha256: "fixture-only".into(),
            })
            .ok_or_else(|| "missing role".into())
    }
}

fn enabled_config() -> FreedomConfig {
    let mut cfg = FreedomConfig::default();
    cfg.coding.self_edit.council_review.enabled = true;
    cfg.coding.self_edit.council_review.changed_line_threshold = 1;
    cfg
}

fn writer(home: &Path) -> (WalWriterHandle, tokio::task::JoinHandle<()>) {
    let path = home.join("wal/000001.wal");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::wal::writer::spawn_for_home(path, home.to_owned()).unwrap()
}

#[test]
fn risk_policy_uses_component_boundaries_and_rejects_invalid_configuration() {
    let broad = crate::config::ops::SelfEditConfig {
        allowed_modules: vec!["src".into()],
        ..Default::default()
    };
    for path in [
        "src/coding/self_source_council.rs",
        "src/council/qa_verdict.rs",
        "src/council/budget.rs",
    ] {
        assert!(super::super::layer2_allowlist(&broad, &[path.into()], 1).is_err());
    }
    let mut policy = SelfEditCouncilConfig {
        enabled: true,
        ..Default::default()
    };
    assert!(required(&policy, &["src/coding/worker.rs".into()], 1).unwrap());
    assert!(required(&policy, &["SRC/Coding/worker.rs".into()], 1).unwrap());
    assert!(!required(&policy, &["src/coding_extra/worker.rs".into()], 1).unwrap());
    assert!(required(&policy, &[], 50).unwrap());
    for prefix in ["", "/src", "src/../cli", "src//cli", "src\\cli", "src/*"] {
        policy.risky_paths = vec![prefix.into()];
        assert!(required(&policy, &[], 1).is_err(), "{prefix}");
    }
    policy = SelfEditCouncilConfig {
        enabled: true,
        ..Default::default()
    };
    policy.timeout_secs = 0;
    assert!(required(&policy, &[], 1).is_err());
    policy.enabled = false;
    assert!(
        !required(&policy, &[], 100).unwrap(),
        "disabled migration makes no provider demand"
    );
}

#[tokio::test]
async fn three_strict_role_verdicts_bind_action_policy_and_separate_override() {
    let home = tempfile::tempdir().unwrap();
    let (wal, join) = writer(home.path());
    let cfg = enabled_config();
    let leaf = FixtureLeaf::new(vec![PASS, FAIL, PASS]);
    let mut reviewed = review(&cfg, home.path(), DIFF, "action", &wal, &leaf)
        .await
        .unwrap();
    assert_eq!(leaf.calls.load(Ordering::SeqCst), 3);
    assert!(
        reviewed
            .validate("action", &cfg.coding.self_edit.council_review)
            .is_err()
    );
    let confirmed = reviewed.confirmation_binding().unwrap();
    reviewed.acknowledge_override().unwrap();
    assert_eq!(
        reviewed.confirmation_binding().unwrap(),
        confirmed,
        "the operator confirmed immutable review bytes"
    );
    assert_eq!(
        reviewed.override_confirmation.as_deref(),
        Some(confirmed.as_str())
    );
    reviewed
        .validate("action", &cfg.coding.self_edit.council_review)
        .unwrap();
    assert!(
        reviewed
            .validate("different action", &cfg.coding.self_edit.council_review)
            .is_err()
    );
    let mut changed = cfg.coding.self_edit.council_review.clone();
    changed.max_total_tokens += 1;
    assert!(reviewed.validate("action", &changed).is_err());
    reviewed.persist(&wal).await.unwrap();
    reviewed.deadline = tokio::time::Instant::now();
    assert!(
        reviewed
            .validate("action", &cfg.coding.self_edit.council_review)
            .is_err()
    );
    drop(wal);
    join.await.unwrap();
    let bytes = std::fs::read(home.path().join("wal/000001.wal")).unwrap();
    let mut found = 0;
    crate::wal::scan::for_each_frame(&bytes, |_, frame| {
        if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
            && frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::SelfEditCouncilReview as u8
        {
            found += 1;
            let text = String::from_utf8_lossy(frame.payload);
            assert!(!text.contains("effect boundary uncertain"));
            assert!(!text.contains("reviewed change"));
            assert!(text.contains(&confirmed));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(found, 1);
}

#[tokio::test]
async fn malformed_missing_and_timed_out_reviews_never_mint_a_capability() {
    let home = tempfile::tempdir().unwrap();
    let (wal, join) = writer(home.path());
    let mut cfg = enabled_config();
    for responses in [
        vec![PASS, PASS],
        vec![PASS, r#"{"kind":"fail","failures":[]}"#],
        vec![PASS, r#"{"kind":"pass","unexpected":true}"#],
        vec!["not json"],
    ] {
        assert!(
            review(
                &cfg,
                home.path(),
                DIFF,
                "action",
                &wal,
                &FixtureLeaf::new(responses)
            )
            .await
            .is_err()
        );
    }
    cfg.coding.self_edit.council_review.timeout_secs = 1;
    let mut hung = FixtureLeaf::new(vec![]);
    hung.hang = true;
    let Err(error) = review(&cfg, home.path(), DIFF, "action", &wal, &hung).await else {
        panic!("timed-out review must not mint a capability");
    };
    assert!(error.contains("timed out"));
    assert_eq!(hung.calls.load(Ordering::SeqCst), 1);
    let unused = FixtureLeaf::new(vec![PASS; 3]);
    assert!(
        review(
            &cfg,
            home.path(),
            &"x".repeat(MAX_DIFF_BYTES + 1),
            "action",
            &wal,
            &unused
        )
        .await
        .is_err()
    );
    assert_eq!(unused.calls.load(Ordering::SeqCst), 0);
    drop(wal);
    join.await.unwrap();
}

#[tokio::test]
async fn required_review_receipt_refuses_a_closed_writer() {
    let home = tempfile::tempdir().unwrap();
    let (wal, join) = writer(home.path());
    let cfg = enabled_config();
    let reviewed = review(
        &cfg,
        home.path(),
        DIFF,
        "action",
        &wal,
        &FixtureLeaf::new(vec![PASS; 3]),
    )
    .await
    .unwrap();
    join.abort();
    let _ = join.await;
    assert!(reviewed.persist(&wal).await.is_err());
}

#[tokio::test]
async fn central_self_edit_review_reaches_real_effect_only_after_all_gates_and_receipt() {
    assert!(
        super::super::tests::git_available(),
        "hosted acceptance requires Git"
    );
    for mode in ["pass", "dissent", "malformed", "drift", "disabled", "audit"] {
        let root = tempfile::tempdir().unwrap();
        super::super::tests::init_fixture_repo(root.path());
        let home = root.path().join("home");
        let (wal, join) = writer(&home);
        let mut cfg = enabled_config();
        cfg.autonomy = crate::permissions::AutonomyLevel::Elevated;
        cfg.coding.self_edit.source_root = Some(root.path().to_path_buf());
        cfg.coding.self_edit.apply_cooldown_secs = 0;
        cfg.coding.self_edit.allowed_modules = vec!["src/cli".into()];
        let mut leaf = FixtureLeaf::new(match mode {
            "dissent" => vec![PASS, FAIL, PASS],
            "malformed" => vec![PASS, "invalid"],
            _ => vec![PASS; 3],
        });
        if mode == "drift" {
            leaf.drift_root = Some(root.path().to_path_buf());
        }
        if mode == "disabled" {
            cfg.coding.self_edit.enabled = false;
        }
        if mode == "audit" {
            join.abort();
        }
        let effects = Arc::new(AtomicUsize::new(0));
        let observed = effects.clone();
        let segment = home.join("wal/000001.wal");
        let result = run_gate_stack_with_context(
            DIFF,
            &cfg,
            false,
            true,
            Some(&wal),
            None,
            None,
            move |root, diff| {
                let bytes = std::fs::read(&segment)?;
                let mut reviews = 0;
                crate::wal::scan::for_each_frame(&bytes, |_, frame| {
                    if frame.header.event_subtype
                        == crate::wal::events::ExtendedSubtype::SelfEditCouncilReview as u8
                        && frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                    {
                        reviews += 1;
                    }
                    Ok(())
                })?;
                assert_eq!(reviews, 1, "required review must be durable before effect");
                observed.fetch_add(1, Ordering::SeqCst);
                apply_to_live_tree(root, diff)
            },
            &home,
            &leaf,
        )
        .await;
        if mode == "pass" {
            result.unwrap();
            assert_eq!(effects.load(Ordering::SeqCst), 1);
            assert!(
                std::fs::read_to_string(root.path().join("src/cli/dummy.rs"))
                    .unwrap()
                    .contains("reviewed change")
            );
        } else {
            assert!(result.is_err(), "{mode}");
            if mode == "drift" {
                assert!(matches!(result, Err(GateError::StateDrift(_))));
            }
            assert_eq!(effects.load(Ordering::SeqCst), 0, "{mode}");
        }
        if mode == "disabled" {
            assert_eq!(leaf.calls.load(Ordering::SeqCst), 0);
        }
        drop(wal);
        if mode == "audit" {
            let _ = join.await;
        } else {
            join.await.unwrap();
        }
    }
}
