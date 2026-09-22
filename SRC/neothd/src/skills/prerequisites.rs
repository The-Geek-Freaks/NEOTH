//! Closed, bundled-skill runtime prerequisite admission.
//!
//! This deliberately does not read manifests for commands.  The only inputs
//! are compiled-in exact Skill ids and the policy-effective enabled bit.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const REAP_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum BundledSkillPrerequisite {
    DrawioPython,
    PptMasterPythonPptx,
    GraphifyRuntime,
    OfficeCli,
}

impl BundledSkillPrerequisite {
    const ORDER: [Self; 4] = [
        Self::DrawioPython,
        Self::PptMasterPythonPptx,
        Self::GraphifyRuntime,
        Self::OfficeCli,
    ];
}

/// The map intentionally uses exact normalized ids.  Adding an OfficeCli
/// capability is a source and test change, never an implicit prefix match.
pub(crate) fn for_effective_skill_id(id: &str) -> Option<BundledSkillPrerequisite> {
    match id.trim().to_ascii_lowercase().as_str() {
        "drawio_diagram" => Some(BundledSkillPrerequisite::DrawioPython),
        "ppt_master" => Some(BundledSkillPrerequisite::PptMasterPythonPptx),
        "graphify" => Some(BundledSkillPrerequisite::GraphifyRuntime),
        "officecli_docx_convert"
        | "officecli_docx_create"
        | "officecli_docx_edit"
        | "officecli_docx_format"
        | "officecli_office_pipeline"
        | "officecli_pdf_convert"
        | "officecli_pptx_create"
        | "officecli_pptx_edit"
        | "officecli_xlsx_create"
        | "officecli_xlsx_edit"
        | "officecli_xlsx_formula" => Some(BundledSkillPrerequisite::OfficeCli),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrerequisiteStatus {
    Ready,
    NotReady,
}

/// Private async seam so fixtures exercise the admission logic without using
/// host Python or OfficeCli installations.
pub(crate) trait SkillPrerequisiteProbe: Send + Sync {
    fn inspect(
        &self,
        prerequisite: BundledSkillPrerequisite,
    ) -> Pin<Box<dyn Future<Output = PrerequisiteStatus> + Send + '_>>;
}

struct ProductionSkillPrerequisiteProbe;

impl SkillPrerequisiteProbe for ProductionSkillPrerequisiteProbe {
    fn inspect(
        &self,
        prerequisite: BundledSkillPrerequisite,
    ) -> Pin<Box<dyn Future<Output = PrerequisiteStatus> + Send + '_>> {
        Box::pin(async move {
            match prerequisite {
                BundledSkillPrerequisite::DrawioPython => {
                    fixed_command_ready("python", &["-I", "-c", "import sys"]).await
                }
                BundledSkillPrerequisite::PptMasterPythonPptx => {
                    fixed_command_ready("python", &["-I", "-c", "import pptx"]).await
                }
                BundledSkillPrerequisite::GraphifyRuntime => {
                    if crate::graphify_runner::GraphifyRuntime::discover("python")
                        .await
                        .is_ok()
                    {
                        PrerequisiteStatus::Ready
                    } else {
                        PrerequisiteStatus::NotReady
                    }
                }
                BundledSkillPrerequisite::OfficeCli => {
                    fixed_command_ready("officecli", &["--version"]).await
                }
            }
        })
    }
}

/// Fixed argv, null streams, finite wait, and kill-on-drop make this a bounded
/// readiness check without retaining child output.  No caller can supply an
/// executable or arguments through this helper.
async fn fixed_command_ready(binary: &str, args: &[&str]) -> PrerequisiteStatus {
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let Ok(mut child) = command.spawn() else {
        return PrerequisiteStatus::NotReady;
    };
    match tokio::time::timeout(PROBE_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => PrerequisiteStatus::Ready,
        Ok(_) => PrerequisiteStatus::NotReady,
        Err(_) => {
            let _ = child.start_kill();
            // Reaping must not turn the five-second readiness deadline into
            // an unbounded wait when a platform leaves the child unreapable.
            let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await;
            PrerequisiteStatus::NotReady
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SkillPrerequisiteSnapshot {
    by_id: BTreeMap<String, PrerequisiteStatus>,
}

impl SkillPrerequisiteSnapshot {
    pub(crate) async fn inspect_enabled_candidates<'a>(
        candidates: impl Iterator<Item = (&'a str, bool)>,
        probe: &dyn SkillPrerequisiteProbe,
    ) -> Self {
        let candidates = candidates
            .filter_map(|(id, enabled)| enabled.then(|| (id, for_effective_skill_id(id))))
            .filter_map(|(id, prerequisite)| prerequisite.map(|prerequisite| (id, prerequisite)))
            .collect::<Vec<_>>();
        let required = candidates
            .iter()
            .map(|(_, prerequisite)| *prerequisite)
            .collect::<BTreeSet<_>>();
        let mut statuses = BTreeMap::new();
        for prerequisite in BundledSkillPrerequisite::ORDER {
            if required.contains(&prerequisite) {
                statuses.insert(prerequisite, probe.inspect(prerequisite).await);
            }
        }
        Self {
            by_id: candidates
                .into_iter()
                .map(|(id, prerequisite)| {
                    (id.to_owned(), statuses[&prerequisite])
                })
                .collect(),
        }
    }

    pub(crate) async fn inspect_production<'a>(
        candidates: impl Iterator<Item = (&'a str, bool)>,
    ) -> Self {
        Self::inspect_enabled_candidates(candidates, &ProductionSkillPrerequisiteProbe).await
    }

    pub(crate) fn permits(&self, id: &str) -> bool {
        !matches!(self.by_id.get(id), Some(PrerequisiteStatus::NotReady))
    }

    pub(crate) fn prerequisite_for(&self, id: &str) -> Option<BundledSkillPrerequisite> {
        self.by_id.get(id).and_then(|_| for_effective_skill_id(id))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FixtureProbe {
        statuses: BTreeMap<BundledSkillPrerequisite, PrerequisiteStatus>,
        calls: Mutex<Vec<BundledSkillPrerequisite>>,
    }

    impl SkillPrerequisiteProbe for FixtureProbe {
        fn inspect(
            &self,
            prerequisite: BundledSkillPrerequisite,
        ) -> Pin<Box<dyn Future<Output = PrerequisiteStatus> + Send + '_>> {
            self.calls.lock().unwrap().push(prerequisite);
            Box::pin(async move {
                self.statuses
                    .get(&prerequisite)
                    .copied()
                    .unwrap_or(PrerequisiteStatus::Ready)
            })
        }
    }

    #[test]
    fn w197_closed_exact_id_map_rejects_near_matches() {
        assert_eq!(for_effective_skill_id("drawio_diagram"), Some(BundledSkillPrerequisite::DrawioPython));
        assert_eq!(for_effective_skill_id("ppt_master"), Some(BundledSkillPrerequisite::PptMasterPythonPptx));
        assert_eq!(for_effective_skill_id("graphify"), Some(BundledSkillPrerequisite::GraphifyRuntime));
        assert_eq!(for_effective_skill_id("officecli_xlsx_edit"), Some(BundledSkillPrerequisite::OfficeCli));
        for id in ["officecli_extra", "officecli_", "graphify-extra", "drawio_diagram_extra", "ordinary"] {
            assert_eq!(for_effective_skill_id(id), None, "{id}");
        }
    }

    #[tokio::test]
    async fn w197_disabled_and_office_family_candidates_have_one_ordered_probe() {
        let probe = FixtureProbe::default();
        let snapshot = SkillPrerequisiteSnapshot::inspect_enabled_candidates(
            [
                ("drawio_diagram", false),
                ("officecli_xlsx_edit", true),
                ("officecli_docx_create", true),
                ("graphify", true),
            ]
            .into_iter(),
            &probe,
        )
        .await;
        assert!(snapshot.permits("officecli_xlsx_edit"));
        assert_eq!(
            *probe.calls.lock().unwrap(),
            vec![BundledSkillPrerequisite::GraphifyRuntime, BundledSkillPrerequisite::OfficeCli]
        );
    }

    #[tokio::test]
    async fn w197_not_ready_disables_only_its_closed_family() {
        let probe = FixtureProbe {
            statuses: [(BundledSkillPrerequisite::OfficeCli, PrerequisiteStatus::NotReady)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let snapshot = SkillPrerequisiteSnapshot::inspect_enabled_candidates(
            [("officecli_xlsx_edit", true), ("ordinary", true)].into_iter(),
            &probe,
        )
        .await;
        assert!(!snapshot.permits("officecli_xlsx_edit"));
        assert!(snapshot.permits("ordinary"));
    }

    #[tokio::test]
    async fn w197_all_disabled_candidates_request_zero_probes() {
        let probe = FixtureProbe::default();
        let _ = SkillPrerequisiteSnapshot::inspect_enabled_candidates(
            [("drawio_diagram", false), ("ppt_master", false), ("graphify", false), ("officecli_xlsx_edit", false)].into_iter(),
            &probe,
        )
        .await;
        assert!(probe.calls.lock().unwrap().is_empty());
    }
}
