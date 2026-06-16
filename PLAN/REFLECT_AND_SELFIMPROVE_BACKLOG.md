# Reflect + Self-Improve — post-ship backlog

Concrete follow-ups flagged by the operator (2026-06-16) after the daily/weekly/
yearly self-reflection + SkillOpt self-improve arc landed. All "später" (not
blocking 1.0) but real — captured with integration points so they're buildable
cold, not vague deferrals. Ranked within each section by leverage.

## A. Reflection hygiene — stop Obsidian filling with mid-relevant noise

The daily/weekly/yearly cadences archive JSONL under `~/.neoth/reflections/<kind>/`
and (opt-in) write Obsidian notes under `<vault>/<subdir>/{Daily,Weekly,Yearly}/`.
Left unbounded, daily alone is ~365 notes/year of decreasing value.

1. **Retention** — prune/age out old daily reflections (e.g. keep daily ≤ 90d,
   weekly ≤ 1y, yearly forever). Integration: a sweep in
   `daemon/reflection_cron.rs` (own marker, like the cadence ticks) over
   `reflection::periodic::periodic_dir(home, kind)` + the vault `<subdir>/Daily`.
   Config: `reflect_topics.yaml` (e.g. `daily_retention_days`), never freedom.yaml.
2. **Dedup** — a near-identical day ("rust, slint" two days running) shouldn't
   spawn a near-duplicate note. Reuse the topic-set: skip/merge when the new
   reflection's topics ⊇/≈ the previous period's (Jaccard over `topics`).
   Integration: in `run_period_reflection_tick_once` before `periodic::append`.
3. **Vault hygiene** — a cleanup pass that removes orphaned `.md.tmp` (now
   impossible after the atomic_write fix, but old ones may linger) + empty
   period dirs. Small, runs with retention.
4. **Yearly synthesis from daily/weekly** — today yearly = top topics over a
   365d episode window. Better: SYNTHESISE the year from the archived
   daily/weekly `PeriodReflection`s (`periodic::load_for_tag` across the year)
   so the yearly note is a roll-up of what was already reflected, not a fresh
   raw-episode scan. Optional LLM summary (gated like dreaming `summarize_themes`).
5. **Topic merge** — a synonym/stem map so "kubernetes"/"k8s"/"k8s-networking"
   collapse to one topic across reflections. Shared with the HN tech-currency
   gap pass (`sources/hackernews.rs` FUTURE note already tracks clustering/
   synonym/ontology) — build once, use in both.

## B. Self-improve quality — make the score more than theatre

`Proposal` carries `score_before/after`, `heldout_eval_summary`,
`why_this_improves`, `risk_notes` (parsed from the engine's JSON envelope via
`self_improve::parse_proposal_output`). The number is only as trustworthy as the
held-out eval behind it. Add provenance + trust signals:

1. **Quality schema version** — `quality_schema_version: u32` on `Proposal` so
   the envelope contract can evolve without misreading old proposals.
2. **Eval source** — `eval_source: String` (which gate/corpus produced the
   score: SkillOpt-Sleep run id, a named test suite, operator-manual).
3. **Test corpus hash** — `corpus_hash: String` (xxh3 of the held-out set) so a
   reviewer knows two proposals were scored on the SAME corpus (else the deltas
   aren't comparable).
4. **Confidence** — `confidence: f64`/enum (n-samples / variance the engine
   reports). A +0.3 delta at low confidence ≠ a +0.05 at high confidence.
5. **Regression warnings** — `regressions: Vec<String>` (held-out cases that got
   WORSE even though the aggregate improved). Surface prominently in
   `cli/self_improve.rs::quality_lines` + the upstream PR body so an operator
   never adopts a net-positive-but-locally-regressing edit blind.

All five extend `parse_proposal_output`'s envelope contract + the
`quality_lines` / PR-body renderers. Keep serde-default so old proposals load.

## C. Recon (done — reference)

`0xF6 RECON_RUN` WAL audit shipped (daemon-forward-else-one-shot, args hashed).
Remaining recon ideas if pursued: wizard auto-install of uncover/tlsx, an ivre
external-source connector (query an operator's existing instance — never embed).
