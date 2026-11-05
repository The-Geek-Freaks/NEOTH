use super::tests::{CannedWorker, authenticated_apply_writer, green_outcome, notes_task};
use super::*;
use crate::coding::self_source_gate::council_review::{LeafContext, LeafOutput, ReviewLeaf};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const PATCH: &str = "diff --git a/src/cli/dummy.rs b/src/cli/dummy.rs\n--- a/src/cli/dummy.rs\n+++ b/src/cli/dummy.rs\n@@ -1 +1,2 @@\n fn dummy() {}\n+// reviewed change\n";
const PASS: &str = r#"{"kind":"pass","evidence":["bounded source review"]}"#;
const FAIL: &str =
    r#"{"kind":"fail","failures":[{"kind":"invariant","message":"reject this effect"}]}"#;

struct Leaf {
    calls: AtomicUsize,
    dissent: bool,
    drift: Option<PathBuf>,
}

#[async_trait::async_trait]
impl ReviewLeaf for Leaf {
    async fn ask(
        &self,
        _role: crate::config::inference::HemisphereRole,
        _context: &LeafContext<'_>,
    ) -> std::result::Result<LeafOutput, String> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 2
            && let Some(root) = &self.drift
        {
            std::fs::write(root.join("drift.txt"), "changed index").unwrap();
            git(root, &["add", "drift.txt"]);
        }
        Ok(LeafOutput {
            text: if self.dissent { FAIL } else { PASS }.into(),
            completion_identity_sha256: "injected-transport-only".into(),
        })
    }
}

fn git(repo: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn source_repo(repo: &Path) {
    std::fs::create_dir_all(repo.join("src/cli")).unwrap();
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname=\"fixture\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(repo.join("src/cli/dummy.rs"), "fn dummy() {}\n").unwrap();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "neoth-test@example.com"]);
    git(repo, &["config", "user.name", "neoth-test"]);
    git(repo, &["add", "."]);
    git(repo, &["commit", "-q", "-m", "fixture"]);
}

#[tokio::test]
async fn dispatcher_reviews_before_real_worktree_and_never_inherits_dissent_override() {
    for mode in [
        "pass", "dissent", "drift", "missing", "low", "foreign", "audit",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        source_repo(&repo);
        let home = dir.path().join("home");
        let (writer, join) = authenticated_apply_writer(&home);
        let leaf = Arc::new(Leaf {
            calls: AtomicUsize::new(0),
            dissent: mode == "dissent",
            drift: (mode == "drift").then(|| repo.clone()),
        });
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Elevated;
        config.coding.self_edit.source_root = Some(repo.clone());
        config.coding.self_edit.council_review.enabled = true;
        config
            .coding
            .self_edit
            .council_review
            .changed_line_threshold = if mode == "low" { 50 } else { 1 };
        if mode == "missing" {
            config.coding.self_edit.source_root = Some(dir.path().join("missing"));
        }
        if mode == "foreign" {
            let foreign = dir.path().join("other-neoth");
            source_repo(&foreign);
            config.coding.self_edit.source_root = Some(foreign);
        }
        let mut apply = DispatchApplyConfig::new(&repo, ApplyOrigin::CliConfirmed, &config, &home)
            .with_policy(config.autonomy_policy())
            .with_local_cli_confirmation()
            .with_wal_writer(writer.clone());
        apply.council_context = apply.council_context.with_leaf(leaf.clone());
        let task = notes_task(None);
        let mut outcome = green_outcome();
        outcome.patch_text = PATCH.into();
        let worker = CannedWorker {
            outcome,
            name: "council-dispatch",
        };
        let accepted = WorkerContract::for_dispatch(&task, &worker, &home)
            .validate_and_materialize(&task, &worker, worker.outcome.clone())
            .unwrap();
        if mode == "audit" {
            join.abort();
            while !join.is_finished() {
                tokio::task::yield_now().await;
            }
        }
        let result = authorize_patch_apply_before_worktree(&task, &accepted, &apply).await;
        let worktree = crate::coding::worktree::worktree_path_for(&repo, task.task_id);
        assert!(
            !worktree.exists(),
            "authorization itself created a worktree"
        );
        let expected_calls = if matches!(mode, "missing" | "low" | "foreign") {
            0
        } else {
            3
        };
        assert_eq!(leaf.calls.load(Ordering::SeqCst), expected_calls, "{mode}");
        if matches!(mode, "pass" | "low" | "foreign") {
            let admission = result.unwrap().unwrap();
            if mode == "pass" {
                let reviewed = admission.council.as_ref().unwrap();
                let scratch = crate::coding::worktree::create_task_worktree_at(
                    &repo, task.task_id, reviewed.commit(),
                ).unwrap();
                std::fs::write(scratch.join("src/cli/dummy.rs"), "unreviewed state\n").unwrap();
                assert!(reviewed.verify_worktree(&scratch).is_err());
                crate::coding::worktree::cleanup_worktree(&repo, &scratch, true).unwrap();
            }
            let apply_clone = apply.clone();
            tokio::task::spawn_blocking(move || {
                apply_admitted_patch_in_worktree(admission, &task, &accepted, &apply_clone, None)
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                std::fs::read_to_string(worktree.join("src/cli/dummy.rs")).unwrap(),
                "fn dummy() {}\n// reviewed change\n"
            );
            assert_eq!(
                std::fs::read_to_string(repo.join("src/cli/dummy.rs")).unwrap(),
                "fn dummy() {}\n"
            );
            crate::coding::worktree::cleanup_worktree(&repo, &worktree, true).unwrap();
        } else {
            assert!(
                result.is_err(),
                "{mode} must refuse before worktree creation"
            );
        }
        drop(apply);
        drop(writer);
        if mode == "audit" {
            let _ = join.await;
        } else {
            join.await.unwrap();
        }
    }
}

#[tokio::test]
async fn dispatcher_review_rejects_changed_base_and_expiry_at_blocking_effect() {
    for expire in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        source_repo(&repo);
        let home = dir.path().join("home");
        let (writer, join) = authenticated_apply_writer(&home);
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Elevated;
        config.coding.self_edit.source_root = Some(repo.clone());
        config.coding.self_edit.council_review.enabled = true;
        config
            .coding
            .self_edit
            .council_review
            .changed_line_threshold = 1;
        let leaf = Arc::new(Leaf {
            calls: AtomicUsize::new(0),
            dissent: false,
            drift: None,
        });
        let mut apply = DispatchApplyConfig::new(&repo, ApplyOrigin::CliConfirmed, &config, &home)
            .with_policy(config.autonomy_policy())
            .with_local_cli_confirmation()
            .with_wal_writer(writer.clone());
        apply.council_context = apply.council_context.with_leaf(leaf);
        let task = notes_task(None);
        let mut outcome = green_outcome();
        outcome.patch_text = PATCH.into();
        let worker = CannedWorker {
            outcome,
            name: "council-drift",
        };
        let accepted = WorkerContract::for_dispatch(&task, &worker, &home)
            .validate_and_materialize(&task, &worker, worker.outcome.clone())
            .unwrap();
        let admission = authorize_patch_apply_before_worktree(&task, &accepted, &apply)
            .await
            .unwrap()
            .unwrap();
        if expire {
            tokio::time::pause();
            tokio::time::advance(std::time::Duration::from_secs(901)).await;
        } else {
            std::fs::write(repo.join("new.txt"), "new commit").unwrap();
            git(&repo, &["add", "new.txt"]);
            git(&repo, &["commit", "-q", "-m", "after review"]);
        }
        let apply_clone = apply.clone();
        let result = tokio::task::spawn_blocking(move || {
            apply_admitted_patch_in_worktree(admission, &task, &accepted, &apply_clone, None)
        })
        .await
        .unwrap();
        if expire {
            tokio::time::resume();
        }
        assert!(
            result.is_err(),
            "stale admission crossed the effect boundary"
        );
        assert!(!crate::coding::worktree::worktree_path_for(&repo, KanbanTaskId(1)).exists());
        drop(apply);
        drop(writer);
        join.await.unwrap();
    }
}

#[test]
fn dispatcher_source_scope_covers_moves_deletions_and_rejects_ambiguous_paths() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let crate_dir = repo.join("SRC/neothd");
    std::fs::create_dir_all(crate_dir.join("src/cli")).unwrap();
    let rename = "diff --git a/other.rs b/SRC/neothd/src/cli/new.rs\nsimilarity index 100%\nrename from other.rs\nrename to SRC/neothd/src/cli/new.rs\n";
    assert_eq!(
        council_review::source_paths(repo, &crate_dir, rename).unwrap(),
        vec!["src/cli/new.rs"]
    );
    let deletion = "diff --git a/SRC/neothd/src/cli/old.rs b/SRC/neothd/src/cli/old.rs\ndeleted file mode 100644\n--- a/SRC/neothd/src/cli/old.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n";
    assert_eq!(
        council_review::source_paths(repo, &crate_dir, deletion).unwrap(),
        vec!["src/cli/old.rs"]
    );
    let sibling = rename.replace("SRC/neothd/", "SRC/neothd-other/");
    assert!(
        council_review::source_paths(repo, &crate_dir, &sibling)
            .unwrap()
            .is_empty()
    );
    for bad in [
        rename.replace("src/cli/new.rs", "../escape.rs"),
        "diff --git \"a/SRC/neothd/x\" \"b/SRC/neothd/x\"\n".into(),
        "diff --git a/SRC/neothd/x b/SRC/neothd/x\nGIT binary patch\nliteral 1\nx\n".into(),
    ] {
        assert!(council_review::source_paths(repo, &crate_dir, &bad).is_err());
    }
    let broad = crate::config::ops::SelfEditConfig {
        allowed_modules: vec!["src".into()],
        ..Default::default()
    };
    for path in [
        "src/coding/dispatcher_council.rs",
        "src/coding/dispatcher.rs",
        "src/coding/service.rs",
        "src/cli/code.rs",
        "src/code_map/diff.rs",
    ] {
        assert!(
            crate::coding::self_source_gate::layer2_allowlist(&broad, &[path.into()], 1).is_err()
        );
    }
}
