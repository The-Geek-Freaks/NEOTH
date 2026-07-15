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
- [x] neoth Cargo.toml: public package/binary contract, repository, crates.io
      description/keywords/categories set

## Done — live and public

- [x] **GitHub Release v1.0.0-beta.1 published** (2026-07-03) — public,
      pre-release source anchor:
      https://github.com/The-Geek-Freaks/NEOTH/releases/tag/v1.0.0-beta.1
- [x] **GitHub Release v1.0.0-beta.4 binaries** — non-destructive rebuild with
      current GitHub macOS Intel runner labels and portable macOS checksum
      generation plus Windows-safe tag output; verified 29 release assets
      including both Windows zips, per-asset `.sha256`, `.cosign.bundle`,
      `.minisig`, and `SHA256SUMS`:
      https://github.com/The-Geek-Freaks/NEOTH/releases/tag/v1.0.0-beta.4
- [x] **Discussions seeded** — Announcements ("NEOTH is public — start here"),
      Q&A ("Q&A and claim checks"), Show-and-tell posts live.
- [x] Repo topics + About description + docs/assets overhaul on public `main`.

## Open — needs a human (browser login required, cannot be automated)

- [ ] **THE traction trigger — Show HN + Reddit**: paste from
      `PLAN/LAUNCH_KIT.md` (Tue-Thu ~15:00 UTC). Everything else is prep; this
      is what actually pulls stars. Reply to comments the first 4 hours.
- [x] **Social preview upload**: GitHub reports `usesCustomOpenGraphImage=true`
      and the committed PNG is 1280×640.
- [x] **CI queue unstuck**: stale queued main runs cancelled; current Security
      run is green and current CI is executing on GitHub-hosted runners.
- [x] **License visibility verified**: GitHub's repo API/sidebar metadata
      currently detects `Apache-2.0` only, while the README badge + License
      section expose `MIT OR Apache-2.0` and link both license files. Do not
      block launch on GitHub licensee showing a dual expression.
- [x] **Discussions categories**: Announcements + Q&A + Show-and-tell seeded.
      (GitHub GraphQL exposes no Discussion pin mutation; pinning the "start
      here" announcement remains web-UI-only.)
- [x] **Demo loops**: replaced the four raster GIFs with animated SVGs
      (install/memory/coding/privacy) — text-editable, accurate to current
      product (fixed the old GIFs' `cargo install neoth` and "six memory
      layers" errors), render inline on GitHub. Optionally re-record real
      screencasts later, but the SVGs are correct and shippable now.
- [ ] **crates.io publish** (`cargo install neoth` path) — run the manual
      `publish-crates.yml` workflow on the approved `v1.0.0` tag. It fails
      closed unless tag/version/package/bin contracts match, publishes
      `neoth-plugin-sdk` first, waits until Cargo can resolve that exact SDK
      version, packages `neoth`, and only then publishes the public crate.
      Configure the `crates-io` environment with required reviewer protection
      and `CARGO_REGISTRY_TOKEN`; no publication has been performed yet.
- [ ] **Stable v1.0.0 release binaries**: the fail-closed `release.yml`
      contract is ready, but the `v1.0.0` tag and its artifacts do not exist
      yet. Push the approved tag only after exact-head CI is green, then verify
      every target archive plus `SHA256SUMS`, per-asset checksums, cosign
      bundles, minisigs, and the pinned public-key asset. The beta.4 artifact
      run remains recorded above as historical evidence, not as stable-v1
      publication.
- [ ] **Announce**: HN (Show HN), r/rust, r/LocalLLaMA, lobste.rs — lead with
      the evaluation page (docs/evaluation.md), not adjectives; delta-kosmologie
      cross-post links back
- [x] **Orphan assets resolved**: 3 accurate ones re-used (system.svg →
      architecture.md, trust-stack.svg → privacy.md, life-automation.svg →
      README), 9 stale ones deleted (act-*, old heros, brain-regions,
      divider, v02-stats — recoverable from git history)
- [x] **DeepWiki reachable after docs wave**: `https://deepwiki.com/The-Geek-Freaks/NEOTH`
      returns 200 and renders the NEOTH page. No public refresh API was found;
      re-index cadence is DeepWiki-owned.
