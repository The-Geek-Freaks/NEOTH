# Public Launch Checklist

Repo-surface readiness for the public push. Code readiness lives in
[PROGRESS_v1_0.md](PROGRESS_v1_0.md) — this list is only what a first-time
visitor hits.

## Done (verified this pass, 2026-07-03)

- [x] README: hero, demo loops, Why-NEOTH, DAU/Pro split, privacy proof,
      Babel-Index section, comparison with honest Partial/Goal marks,
      one-glance uniqueness table with proof commands
- [x] docs/: quickstart, install, privacy, babel-index, evaluation (skeptic
      path), faq, architecture, compare/ with per-competitor pages
- [x] All README/docs links + anchors verified by script (no dead links)
- [x] SVG assets audited against current feature state; stale claims fixed
      (memory tiers, WAL codes, kanban states)
- [x] GitHub About: description names the Babel-Index USP; topics set (20)
- [x] GitHub Discussions enabled
- [x] Issue templates: PLACEHOLDER URLs fixed, config.yml points at real
      Discussions + SECURITY.md
- [x] License layout: combined LICENSE pointer removed so GitHub licensee
      detects LICENSE-MIT + LICENSE-APACHE (dual); README links both
- [x] CITATION.cff added (cites delta-kosmologie as reference)
- [x] neothd Cargo.toml: repository placeholder fixed, crates.io
      description/keywords/categories set

## Open — needs a human or a release event

- [ ] **Social preview upload**: render `.github/assets/neoth-social-preview.svg`
      to 1280×640 PNG and upload via Settings → General → Social preview
      (no API for this; SVG is the source of truth)
- [ ] **Verify license badge** on github.com shows both licenses after push
      (licensee runs server-side; if still NOASSERTION, check LICENSE-MIT
      wording against the exact MIT template)
- [ ] **Discussions categories**: seed Welcome + Q&A + Show-and-tell, pin a
      "start here" post
- [ ] **Demo GIF freshness**: re-record the four README demo loops against
      the current GUI before announcing (install/memory/coding/privacy)
- [ ] **crates.io publish** (`cargo install neoth` path) — lands with 1.0
- [ ] **Release binaries**: tag → release.yml artifacts verified on all
      targets, checksums in release notes
- [ ] **Announce**: HN (Show HN), r/rust, r/LocalLLaMA, lobste.rs — lead with
      the evaluation page (docs/evaluation.md), not adjectives; delta-kosmologie
      cross-post links back
- [ ] **Orphan assets decision**: 12 unreferenced files in .github/assets
      (act-*.svg, hero-dark/light, brain-regions, divider, neoth-hero-white,
      life-automation, system, trust-stack, v02-stats) — delete or re-use
- [ ] **DeepWiki refresh** after the docs wave lands on main
