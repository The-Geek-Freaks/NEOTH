//! Run the production W52 impact controller against a real Git repository and
//! an indexed SQLite code-map database. The fixture does not seed controller
//! state or substitute a mock core call.

#[path = "../../neothd-gui/src/code_map_impact_controller.rs"]
mod code_map_impact_controller;

#[expect(
    dead_code,
    reason = "headless impact harness omits desktop callers checked by the GUI gate"
)]
#[path = "../../neothd-gui/src/gui_action.rs"]
pub mod gui_action;

#[expect(
    clippy::len_without_is_empty,
    reason = "headless import exposes a private desktop module for parser tests"
)]
#[path = "../../neothd-gui/src/panel_logic.rs"]
pub mod panel_logic;

use std::path::{Path, PathBuf};
use std::process::Command;

use code_map_impact_controller::{
    CodeMapImpactCompletion, CodeMapImpactController, CodeMapImpactSource,
    CodeMapImpactViewInvalidation,
};
use neothd::code_map::{
    CanonicalRepoRoot, DiffImpactSourceDescriptor, ImpactOptions, RebuildOptions, rebuild_snapshot,
};

struct GitImpactFixture {
    _repo_parent: tempfile::TempDir,
    _db_parent: tempfile::TempDir,
    repo: PathBuf,
    database: PathBuf,
}

impl GitImpactFixture {
    fn new() -> Self {
        let repo_parent = tempfile::tempdir().expect("repository parent");
        let repo = repo_parent.path().join("repo");
        std::fs::create_dir_all(repo.join("src")).expect("source directory");
        std::fs::create_dir_all(repo.join("tests")).expect("test directory");
        std::fs::write(
            repo.join("src/work.rs"),
            "pub fn work() { wrapper(); }\npub fn wrapper() { work(); }\n",
        )
        .expect("initial source");
        let mut observed_tests = "#[test]\nfn observes_work() { work(); }\n".to_owned();
        for index in 0..40 {
            observed_tests.push_str(&format!(
                "#[test]\nfn observes_work_{index}() {{ work(); }}\n"
            ));
        }
        std::fs::write(repo.join("tests/work_tests.rs"), observed_tests)
            .expect("initial test source");

        git(&repo, &["init"]);
        git(&repo, &["config", "user.email", "w52@example.invalid"]);
        git(&repo, &["config", "user.name", "W52 Fixture"]);
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-m", "initial"]);

        // Keep a Git diff from HEAD while publishing an index over the current
        // files. W43 then sees a fresh index and a real working-tree diff.
        std::fs::write(
            repo.join("src/work.rs"),
            "pub fn work() { wrapper(); wrapper(); }\npub fn wrapper() { work(); }\n",
        )
        .expect("changed source");

        let db_parent = tempfile::tempdir().expect("database parent");
        let database = db_parent.path().join("code_map.db");
        let root = CanonicalRepoRoot::discover(&repo).expect("canonical repository root");
        rebuild_snapshot(&root, &database, RebuildOptions::default())
            .expect("publish complete code-map snapshot");
        Self {
            _repo_parent: repo_parent,
            _db_parent: db_parent,
            repo,
            database,
        }
    }

    fn controller(&self) -> CodeMapImpactController {
        CodeMapImpactController::new(self.database.clone())
    }

    fn stage_change(&self) {
        git(&self.repo, &["add", "."]);
    }

    fn commit_change(&self) {
        git(&self.repo, &["commit", "-m", "changed"]);
    }
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("start git {:?}: {error}", args));
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_observed_test(analysis: &code_map_impact_controller::CodeMapImpactAnalysis) {
    assert!(
        analysis.test_gap.no_observed_test_is_not_absence,
        "the receipt must retain the no-absence invariant"
    );
    assert!(
        analysis.test_gap.per_node.iter().any(|node| {
            node.coverage.as_ref().is_some_and(|coverage| {
                coverage.observed_tests.iter().any(|observed| {
                    observed.test.file == "tests/work_tests.rs"
                        && observed.test.symbol == "observes_work"
                        && observed.target.file == "src/work.rs"
                        && observed.target.symbol == "work"
                })
            })
        }),
        "the actual indexed test relation must reach the W52 controller receipt"
    );
}

#[test]
fn working_staged_and_committed_sources_use_real_git_and_read_only_core_receipts() {
    let fixture = GitImpactFixture::new();
    let controller = fixture.controller();

    let working = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::WorkingTree,
            ImpactOptions::default(),
        )
        .expect("claim working-tree analysis");
    let working_analysis = controller.analyze(&working).expect("analyze working tree");
    assert!(matches!(
        &working_analysis.impact.source,
        DiffImpactSourceDescriptor::WorkingTree
    ));
    assert_observed_test(&working_analysis);
    assert_eq!(controller.finish(&working), CodeMapImpactCompletion::Render);

    fixture.stage_change();
    let staged = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::Staged,
            ImpactOptions::default(),
        )
        .expect("claim staged analysis");
    let staged_analysis = controller.analyze(&staged).expect("analyze staged diff");
    assert!(matches!(
        &staged_analysis.impact.source,
        DiffImpactSourceDescriptor::Staged
    ));
    assert_observed_test(&staged_analysis);
    assert_eq!(controller.finish(&staged), CodeMapImpactCompletion::Render);

    fixture.commit_change();
    let committed = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::Committed {
                base: "HEAD~1".into(),
                target: "HEAD".into(),
            },
            ImpactOptions::default(),
        )
        .expect("claim committed analysis");
    let committed_analysis = controller
        .analyze(&committed)
        .expect("analyze committed range");
    assert!(matches!(
        &committed_analysis.impact.source,
        DiffImpactSourceDescriptor::Committed { .. }
    ));
    assert_observed_test(&committed_analysis);
    assert_eq!(
        controller.finish(&committed),
        CodeMapImpactCompletion::Render
    );
}

#[test]
fn late_completion_with_a_changed_git_source_cannot_repaint_the_current_view() {
    let fixture = GitImpactFixture::new();
    let controller = fixture.controller();
    let operation = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::WorkingTree,
            ImpactOptions::default(),
        )
        .expect("claim real working-tree analysis");
    let analysis = controller.analyze(&operation).expect("real core analysis");
    assert_observed_test(&analysis);
    assert_eq!(
        controller.finish(&operation),
        CodeMapImpactCompletion::Render
    );

    assert!(
        !controller.is_current_view(&operation, &fixture.repo, &CodeMapImpactSource::Staged),
        "a late working-tree completion must not replace a staged selection"
    );
    assert!(
        controller.is_current_view(&operation, &fixture.repo, &CodeMapImpactSource::WorkingTree,),
        "the receipt remains eligible only for its exact original source"
    );
}

#[test]
fn stale_index_is_rejected_without_a_gui_stale_opt_in() {
    let fixture = GitImpactFixture::new();
    std::fs::write(
        fixture.repo.join("src/work.rs"),
        "pub fn work() { wrapper(); wrapper(); wrapper(); }\npub fn wrapper() { work(); }\n",
    )
    .expect("make indexed source stale");
    let controller = fixture.controller();
    let operation = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::WorkingTree,
            ImpactOptions::default(),
        )
        .expect("claim stale analysis");
    let error = controller
        .analyze(&operation)
        .expect_err("stale analysis must not produce a display receipt");
    assert!(
        error.to_string().contains("stale"),
        "W43 freshness rejection stays visible to the GUI: {error:#}"
    );
    assert_eq!(
        controller.finish(&operation),
        CodeMapImpactCompletion::Render
    );
}

#[test]
fn two_delayed_folder_picker_completions_preserve_interlocks_until_discarded_terminal() {
    let fixture = GitImpactFixture::new();
    let replacement_parent = tempfile::tempdir().expect("replacement parent");
    let replacement_root = replacement_parent.path().join("replacement");
    std::fs::create_dir_all(&replacement_root).expect("replacement root");
    let controller = fixture.controller();
    let operation = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::WorkingTree,
            ImpactOptions::default(),
        )
        .expect("claim old-root analysis");
    let analysis = controller
        .analyze(&operation)
        .expect("real old-root analysis");
    assert_observed_test(&analysis);

    // These are the exact values consumed by the production picker callback.
    // The real W43/W48 read has reached its worker terminal handoff but has not
    // called finish yet. The first picker removes the visible view. The second
    // arrives before that terminal handoff, so only view_invalidated changes;
    // active execution must keep lifecycle/native-Coding interlocks asserted.
    assert_eq!(
        controller.invalidate_view(),
        CodeMapImpactViewInvalidation {
            view_invalidated: true,
            analysis_active: true,
        }
    );
    assert_eq!(
        controller.invalidate_view(),
        CodeMapImpactViewInvalidation {
            view_invalidated: false,
            analysis_active: true,
        },
        "a second late picker completion must not report the old read as idle"
    );
    assert_eq!(
        controller.finish(&operation),
        CodeMapImpactCompletion::Discarded
    );
    assert!(!controller.has_active_analysis());
    assert_eq!(
        controller.invalidate_view(),
        CodeMapImpactViewInvalidation {
            view_invalidated: false,
            analysis_active: false,
        },
        "only terminal settlement releases the production callback interlocks"
    );
    assert!(!controller.is_current_view(
        &operation,
        &replacement_root,
        &CodeMapImpactSource::WorkingTree,
    ));
}

#[test]
fn real_impact_receipt_caps_display_rows_and_reports_omissions() {
    let fixture = GitImpactFixture::new();
    let controller = fixture.controller();
    let operation = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::WorkingTree,
            ImpactOptions::default(),
        )
        .expect("claim analysis");
    let analysis = controller.analyze(&operation).expect("real core analysis");
    assert_observed_test(&analysis);

    let presentation = panel_logic::present_code_map_impact(&analysis);
    assert_eq!(
        presentation.observed_tests.len(),
        panel_logic::MAX_CODE_MAP_IMPACT_VISIBLE_ROWS,
        "the production presentation must cap before the Slint model is built"
    );
    assert!(
        presentation
            .observed_tests_omitted
            .contains("omitted from this display"),
        "the real W43/W48 receipt must disclose structural display omission"
    );
    assert!(presentation.is_limited, "row omission is a visible limit");
    assert_eq!(
        controller.finish(&operation),
        CodeMapImpactCompletion::Render
    );
}

#[test]
fn completed_impact_requires_matching_lifecycle_root_and_physical_identity() {
    let fixture = GitImpactFixture::new();
    let controller = fixture.controller();
    let operation = controller
        .begin(
            &fixture.repo,
            CodeMapImpactSource::WorkingTree,
            ImpactOptions::default(),
        )
        .expect("claim analysis");
    let analysis = controller.analyze(&operation).expect("real core analysis");
    let root = analysis.impact.root.display().to_owned();
    let identity = analysis.impact.root.identity().as_str().to_owned();

    assert!(panel_logic::code_map_impact_matches_lifecycle(
        &analysis, &root, &identity,
    ));
    assert!(
        !panel_logic::code_map_impact_matches_lifecycle(
            &analysis,
            &root,
            "replacement-physical-identity",
        ),
        "same display spelling with a different physical identity is unsafe"
    );
    assert!(
        !panel_logic::code_map_impact_matches_lifecycle(
            &analysis,
            "C:/different-repository",
            &identity,
        ),
        "a lifecycle receipt for another root cannot accompany this impact"
    );
    assert_eq!(
        controller.finish(&operation),
        CodeMapImpactCompletion::Render
    );
}

#[test]
fn admitted_limits_remain_bound_to_real_analysis_until_the_next_operation() {
    let fixture = GitImpactFixture::new();
    let controller = fixture.controller();
    let mut accepted = ImpactOptions {
        max_nodes: 1,
        ..ImpactOptions::default()
    };
    let frozen = controller
        .begin(&fixture.repo, CodeMapImpactSource::WorkingTree, accepted)
        .expect("admit narrow snapshot");
    accepted.max_nodes = 8;
    let narrow = controller
        .analyze(&frozen)
        .expect("analyze admitted narrow policy after caller changed limits");
    assert_eq!(narrow.impact.impact.impacted_nodes.len(), 1);
    assert!(narrow.impact.impact.truncated);
    assert_eq!(controller.finish(&frozen), CodeMapImpactCompletion::Render);
    let next = controller
        .begin(&fixture.repo, CodeMapImpactSource::WorkingTree, accepted)
        .expect("admit wider subsequent operation");
    let wide = controller
        .analyze(&next)
        .expect("analyze subsequent wide policy");
    assert!(wide.impact.impact.impacted_nodes.len() > narrow.impact.impact.impacted_nodes.len());
    assert_eq!(wide.impact.root, narrow.impact.root);
    assert_eq!(wide.impact.diff_sha256, narrow.impact.diff_sha256);
    assert_eq!(wide.impact.index_generation, narrow.impact.index_generation);
    assert_eq!(wide.impact.graph_generation, narrow.impact.graph_generation);
    assert_eq!(controller.finish(&next), CodeMapImpactCompletion::Render);
}
