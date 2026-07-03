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

## Done — live and public

- [x] **GitHub Release v1.0.0-beta.1 published** (2026-07-03) — public,
      pre-release: https://github.com/The-Geek-Freaks/NEOTH/releases/tag/v1.0.0-beta.1
- [x] **Discussions seeded** — Announcements ("NEOTH is public — start here"),
      Q&A ("Q&A and claim checks"), Show-and-tell posts live.
- [x] Repo topics + About description + docs/assets overhaul on public `main`.

## Open — needs a human (browser login required, cannot be automated)

- [ ] **THE traction trigger — Show HN + Reddit**: paste from
      `PLAN/LAUNCH_KIT.md` (Tue-Thu ~15:00 UTC). Everything else is prep; this
      is what actually pulls stars. Reply to comments the first 4 hours.
- [ ] **Social preview upload**: PNG is rendered and committed at
      `.github/assets/neoth-social-preview.png` (1280×640). Just upload it via
      Settings → General → Social preview (no API for this — one manual click).
- [ ] **CI is stuck (credibility blocker for the build badge)**: all recent
      `ci.yml` runs sit in `queued` and never complete (20/20 no conclusion),
      so the README build badge renders grey "no status". `runs-on` uses
      standard GitHub-hosted runners, so this is an account/org setting —
      check Settings → Actions (enabled? runner access?) and billing/spending
      limits. Until a run goes green, the build badge undersells the repo.
- [ ] **Verify license badge** on github.com shows both licenses after push
      (licensee runs server-side; if still NOASSERTION, check LICENSE-MIT
      wording against the exact MIT template)
- [x] **Discussions categories**: Announcements + Q&A + Show-and-tell seeded.
      (Optionally pin the "start here" announcement via the web UI.)
- [x] **Demo loops**: replaced the four raster GIFs with animated SVGs
      (install/memory/coding/privacy) — text-editable, accurate to current
      product (fixed the old GIFs' `cargo install neoth` and "six memory
      layers" errors), render inline on GitHub. Optionally re-record real
      screencasts later, but the SVGs are correct and shippable now.
- [ ] **crates.io publish** (`cargo install neoth` path) — lands with 1.0
- [ ] **Release binaries**: tag → release.yml artifacts verified on all
      targets, checksums in release notes
- [ ] **Announce**: HN (Show HN), r/rust, r/LocalLLaMA, lobste.rs — lead with
      the evaluation page (docs/evaluation.md), not adjectives; delta-kosmologie
      cross-post links back
- [x] **Orphan assets resolved**: 3 accurate ones re-used (system.svg →
      architecture.md, trust-stack.svg → privacy.md, life-automation.svg →
      README), 9 stale ones deleted (act-*, old heros, brain-regions,
      divider, v02-stats — recoverable from git history)
- [ ] **DeepWiki refresh** after the docs wave lands on main
