# SPEC -- Recall-Parity Methodology — NEOTH v1.1

**Version:** 1.1
**Last-Updated:** 2026-08-20
**Implementation-Status:** PARTIAL — the deterministic scorer and P1-07
versioned roster/coverage gate are implemented. Live goldset extraction,
shadow-run execution, external provider provenance, and P1-08 cryptographic
batch binding remain open. Underlying multi-tier recall (hot+warm+cold+groundtruth)
it evaluates is SHIPPED at `SRC/neothd/src/memory/{store, tiers, consolidate,
groundtruth}.rs` + `cli/recall.rs`.

> Status: DESIGN (eval methodology). Fixes: H6 (test_all_three_agree_and_wrong unfalsifiable), H7 (grader-family bias via 4-grader cross-family protocol).
> Binds to Day 77-79 of RUNBOOK_phase3_cutover.md.

---

## 1. Goldset Construction

100 queries extracted from live Jarvis transcripts. Sources:
  ~/.claude/projects/*/sessions/*.jsonl (Claude CLI session turns)
  ~/.openclaw/workspace/memory/*.md (OpenClaw session MDs)

Category split -- 4 x 25 queries:
  recall    25: e.g. what did the operator say last Thursday about WiFi?
  summarize 25: e.g. summarize last week project work
  action    25: e.g. send the operator a reminder at 18:00
  factual   25: e.g. what is the Cube IP?

Selection criteria:
- Prefer queries that exercise all 5 brain regions (Hippocampus/Amygdala/Insula/Cerebellum/Basal_Ganglia)
- At least 5 recall queries must require >2 WAL events to answer correctly
- At least 5 factual queries must be from HIPPOCAMPUS_CORE.md (importance >= 0.75)
- Action queries must involve Needle low_risk_intent allowlist verification

Output: eval/goldset.jsonl (100 lines). Schema:

```json
{
  "query_id":        "q001",
  "query_text":      "what did the operator say last Thursday about WiFi?",
  "category":        "recall",
  "category_weight": 1.5,
  "expected_sources": ["wal_evt_abc123", "wal_evt_def456", "wal_evt_ghi789"],
  "expected_response": "Du hast Donnerstag um 14:32 gesagt WiFi-Bridge auf Cube faellt taglich aus, brauchst Static DHCP fuer 192.168.178.45."
}
```

category_weight: recall=1.5, summarize=1.0, action=1.5, factual=1.0 (higher = harder to pass)

---

## 2. Expected Outputs

Per query, document:
- expected_sources: 3 WAL event_ids from Jarvis that should appear in recall results
- expected_response: reference answer text (1-3 sentences, in Jarvis voice)

Sourcing method for expected_sources:
1. Run query against live Jarvis: neothctl jarvis-recall --query TEXT
2. Capture top-3 returned event_ids
3. Manually verify each returned event contains the claimed information
4. Record event_ids as expected_sources

Sourcing method for expected_response:
1. Send query to live Jarvis via Telegram
2. Record Jarvis actual response as expected_response
3. Manual review: flag if Jarvis response is factually wrong (rare, but happens)

---

## 3. Grading Rubric

5 dimensions, 0-5 Likert each. Graders score each (query, response) pair independently.

Dimension 1 -- Factual Correctness (weight 1.5)
  5: Response contains all facts from expected_sources, no factual errors.
  4: All key facts present, minor omission or slight imprecision.
  3: Most facts correct, one notable error or significant omission.
  2: Some facts correct, multiple errors or omissions.
  1: Mostly incorrect or hallucinated facts.
  0: Completely wrong, contradicts expected_sources.

Dimension 2 -- Completeness (weight 1.5)
  5: All expected aspects covered (all 3 expected_sources addressed).
  4: 2 of 3 expected_sources addressed well.
  3: 1 of 3 expected_sources addressed.
  2: Partial coverage, significant gaps.
  1: Minimal coverage.
  0: Empty or off-topic.

Dimension 3 -- On-Tone (weight 1.0)
  5: Matches Jarvis voice: blunt, direct, German-if-operator-speaks-German, technical, no padding.
  3: Mostly correct tone, occasional filler or wrong language register.
  1: Wrong tone (overly verbose, apologetic, or artificial pleasantries).
  0: Completely wrong voice.

Dimension 4 -- Usefulness (weight 1.5)
  5: Operator would immediately act on this response as-is.
  4: Operator would act with minor follow-up.
  3: Response helps but requires significant follow-up.
  2: Marginally helpful.
  1: Not useful.
  0: Actively misleading or harmful.

Dimension 5 -- Brevity (weight 1.0)
  5: No padding, no hedging, matches expected_response length +/- 30%.
  4: Slightly verbose but on-topic.
  3: Notable padding (safety disclaimers, excessive hedging).
  1: Way too long or way too short.
  0: Empty or infinite loop pattern.

---

## 4. 4-Grader Protocol (H7 fix: external + anchor grader added)

**Problem v0.8:** Three graders (Claude Opus, Codex GPT-5.5, Gemini 3.1 Pro) share stylistic priors. Claude-grading-Claude-output has systematic upward bias. High kappa + shared bias = confidently wrong evaluation. Kappa measures agreement, not accuracy.

**Fix v1.1:** 4-grader protocol.

| Grader | Role | Provider |
|--------|------|----------|
| A | Architecturally-similar grader 1 | Claude Opus 4.7 |
| B | Architecturally-similar grader 2 | Codex GPT-5.5 |
| C | Architecturally-similar grader 3 | Gemini 3.1 Pro |
| **D** | **External-architecture grader (NEW)** | **Mistral Large 2 OR DeepSeek-V3.5 OR Qwen2.5-72B-Instruct** — NOT trained from Anthropic/OpenAI/Google data ancestry. |
| **E** | **Operator calibration anchor (NEW)** | **Operator hand-labels 20 of the 100 queries (20%) BEFORE Phase 3 Day 77 grading.** Operator's scores serve as ground truth for the 20-query subset. |

**Anchor protocol (E):**
1. At Phase-3 Day 73 (before automated grading), the operator receives 20 randomly-selected (query, response) pairs from each of NEOTH and Jarvis (40 total pairs).
2. Operator scores each pair against the 5-dimension rubric. Saved as `eval/operator-anchor.jsonl`.
3. The remaining 80 queries graded by A+B+C+D only.

**Family-bias detection:**
For the 20 anchored queries, compute per-grader systematic bias:
```
bias(grader_X, dim_d) = mean(grader_X_score - operator_score) for the 20 anchored queries
```
If `|bias(grader_X, dim_d)| > 0.5 Likert points` AND `sign(bias)` is the same for A, B, C: this is **family bias** — Claude/Codex/Gemini all score higher (or lower) than the operator on dimension d.

**Family-bias correction:**
For the 80 unanchored queries on the biased dimension, subtract the mean(A,B,C) bias from each automated score before computing parity. Grader D and operator anchor unaffected.

**Inter-rater kappa now computed across A+B+C+D (4-way), not 3-way:**
- Pairwise: AB, AC, AD, BC, BD, CD (6 pairs)
- Pass if mean kappa ≥ 0.6 AND no individual pair < 0.4
- D being architecturally distinct from A/B/C catches family-prior collapse

Protocol per (query, response) pair:
1. Each grader receives: `system_prompt = eval/grading-prompt.md`
2. Each grader receives: `user_prompt = query + response_under_test` (one pair per API call)
3. Grader outputs JSON with 5 integer scores: `{factual:N, completeness:N, on_tone:N, useful:N, brevity:N}`
4. No reference to other graders' scores. No chain-of-thought exposed to other graders.

Output per grader: `eval/grades-grader-{A,B,C,D}.jsonl` (100 lines each × 2 systems NEOTH+Jarvis = 800 records total). Plus `eval/operator-anchor.jsonl` (40 records).

`grading-prompt.md` structure:
  - Role: you are a quality evaluator for a personal AI assistant
  - Context: the assistant is Neoth, personal AI for the operator (solo dev, security researcher)
  - Voice standard: blunt, direct, German if German, no pleasantries, technical substance exact
  - Rubric: paste of 5 dimensions above
  - Output format: JSON object with 5 integer keys, nothing else

### 4.1 P1-07 roster and complete-coverage gate (implemented)

`neoth recall-score` requires both `--grader-config <PATH>` and
`--goldset <PATH>` for every scoring run. The file is a strict JSON object with
`schema_version: 1` and a `graders` array; unknown fields and unknown enum tags
are rejected. One roster member has exactly these fields:

```json
{
  "grader_id": "external",
  "provider": "mistral",
  "model_id": "mistral-large-2",
  "family": "independent_external"
}
```

Accepted provider tags are `anthropic`, `openai`, `google`, `mistral`,
`deepseek`, and `qwen`. Their required family tags are deterministic:

| Provider tags | Required `family` tag |
|---|---|
| `anthropic`, `openai`, `google` | `anthropic_openai_google` |
| `mistral`, `deepseek`, `qwen` | `independent_external` |

The roster must contain at least one member from each family, use unique
`grader_id` values, and use unique `(provider, model_id)` pairs. It is limited
to 64 graders and a 64 KiB JSON file. A `grader_id` is 1–64 ASCII characters:
its first character is alphanumeric and subsequent characters are limited to
alphanumerics, `.`, `_`, and `-`. A `model_id` is a trimmed 1–128-character
ASCII identifier containing at least one alphanumeric character and using only
`A–Z`, `a–z`, `0–9`, `.`, `_`, `-`, `/`, `:`, `@`, and `+`. The provider is the
source of the family rule; a persisted `family` label cannot claim independence
for an Anthropic/OpenAI/Google grader.

Before calculating kappa or parity, the scorer treats the validated roster and
the mandatory goldset as the closed identity sets. The goldset loader accepts at
most 4 MiB and requires exactly 100 records with unique canonical `query_id`
values. Query IDs and grader IDs are 1–64 ASCII characters: an alphanumeric
first character followed only by alphanumerics, `.`, `_`, or `-`. For every one
of those 100 goldset queries, every roster member must provide exactly one
record for `system: neoth` and exactly one for `system: reference`. It rejects
duplicates of the full `(query_id, grader_id, system)` tuple, unknown grader
IDs, unused configured graders, missing observations, and any grade query ID
missing from or extra to the goldset. Thus, an incomplete external-family sheet
cannot be silently omitted from a mean, and no caller can obtain a PASS from a
cherry-picked grade corpus.

Inputs are bounded before scoring: the goldset JSONL is capped at 4 MiB; each
grades JSONL is capped at 16 MiB and 12,800 records; and the aggregate grade
submission cannot exceed the exact `100 × configured graders × 2 systems`
matrix. Grade records are independently revalidated by the scorer for canonical
identifiers and all five `0..=5` Likert values before any parity math, so a
direct caller cannot bypass the file-loader boundary.

The score report exposes stable participant metadata only: `grader_id`,
`provider`, `family`, and `model_id`, plus the independent-external-family gate
result. This validates declared configuration and coverage; it is not a signed
provider receipt or other proof that the named provider/model generated the
grades. P1-08 retains ownership of provenance, grading-batch binding, and
cryptographic hashes/attestations.

---

## 5. Inter-Rater Agreement (4-way, H7 fix)

Cohens Kappa per dimension, computed pairwise across 4 graders (AB, AC, AD, BC, BD, CD = 6 pairs), then averaged.

Formula for pairwise Cohen kappa:
  p_o = proportion of observations where two graders agree (within 1 Likert point = agreement)
  p_e = expected agreement by chance
  kappa = (p_o - p_e) / (1 - p_e)

Agreement definition: scores within 1 Likert point = agree; >1 apart = disagree.

Thresholds:
  kappa < 0.40: poor agreement -- rubric is broken, full rewrite needed
  0.40 <= kappa < 0.60: fair -- rubric under-specified, expand examples, redo grading
  0.60 <= kappa < 0.80: acceptable -- proceed
  kappa >= 0.80: strong -- proceed with high confidence

On kappa < 0.60 for ANY dimension:
  1. Identify dimension with lowest kappa
  2. Add 3 concrete examples (good/medium/bad) to that dimension in grading-prompt.md
  3. Discard all 800 grade records (4 graders × 100 queries × 2 systems)
  4. Re-run grading (Day 77-78 repeat). Max 2 redo cycles before escalating to rubric redesign.

Output: eval/kappa-report.json:
  {factual_kappa, completeness_kappa, on_tone_kappa, useful_kappa, brevity_kappa,
   overall_kappa (mean of 5), grading_date, grader_versions}

---

## 6. Parity Score Computation

Per query q, per dimension d:
  parity_raw(q, d) = neoth_score(q, d) / jarvis_score(q, d)
  Clamped to [0.0, 1.0]. If jarvis_score = 0 and neoth_score = 0: parity = 1.0.
  If jarvis_score = 0 and neoth_score > 0: parity = 1.0 (NEOTH exceeds Jarvis baseline).

Kappa-adjusted parity per dimension:
  parity_kappa(d) = (sum over q of parity_raw(q, d)) / n_queries * kappa(d)
  i.e. mean parity across queries, then multiplied by inter-rater reliability weight.

Aggregate parity score:
  parity_aggregate = harmonic_mean over d in DIMENSIONS of parity_kappa(d) * weight(d)

Where weight(d):
  factual:      1.5  (highest -- wrong facts are unacceptable)
  completeness: 1.5  (high -- incomplete recall misses operator intent)
  on_tone:      1.0  (medium -- tone matters but is stylistic)
  usefulness:   1.5  (highest -- if operator wouldnt act on it, it failed)
  brevity:      1.0  (medium -- verbosity is annoying but not dangerous)

Harmonic mean formula (weighted):
  parity_aggregate = (sum of weights) / (sum over d of weight(d) / parity_kappa(d))

Example computation:
  Assume kappas: factual=0.72, completeness=0.68, on_tone=0.61, useful=0.75, brevity=0.66
  Assume mean per-query parities: factual=0.91, completeness=0.88, on_tone=0.84, useful=0.89, brevity=0.92
  parity_kappa: factual=0.91*0.72=0.655, completeness=0.88*0.68=0.598, on_tone=0.84*0.61=0.512,
               useful=0.89*0.75=0.668, brevity=0.92*0.66=0.607
  weighted harmonic mean with weights 1.5,1.5,1.0,1.5,1.0 = 6.5 / (1.5/0.655+1.5/0.598+1.0/0.512+1.5/0.668+1.0/0.607)
                                                           = 6.5 / 2.290+2.508+1.953+2.246+1.647
                                                           = 6.5 / 10.644 = 0.611
  This example would FAIL (< 0.85). Weak on_tone kappa drags the harmonic mean.

Pass threshold: parity_aggregate >= 0.85.

---

## 7. CRITICAL Divergence Detection

A response is CRITICAL-class if ANY of:
- kappa-adjusted `parity_kappa(factual) < 0.50` for that query
- kappa-adjusted `parity_kappa(usefulness) < 0.50` for that query
- NEOTH response is empty string or contains error text
- NEOTH returns data from wrong session or wrong human_uuid (identity cross-contamination)

CRITICAL events trigger immediate Phase-3 abort (WAL event 0x32 SHADOW_RUN_ABORTED).
A single CRITICAL event in 14d shadow is sufficient to abort. No exceptions.

CRITICAL events logged as WAL 0x3E EVAL_CRITICAL_DIVERGENCE with:
  query_id: str
  neoth_scores: dict
  jarvis_scores: dict
  dimension_triggered: str (factual | usefulness | empty | identity_contamination)
  shadow_day: u32

## 7.1 Absolute-Quality Floor (H7 second fix — "parity against unvalidated Jarvis" gap)

**Problem v0.8:** Target `parity ≥ 0.85` measures NEOTH-relative-to-Jarvis. But Jarvis's absolute quality is unmeasured. NEOTH at 85% parity of a 2/5 Jarvis = absolute 1.7/5. Useless.

**Fix v1.1:** Absolute floors per dimension (NEOTH must score ≥ X regardless of parity):

| Dimension | Absolute floor (NEOTH score across all 100 queries, mean per dim) | Rationale |
|-----------|------------------------------------------------------------------|-----------|
| Factual | ≥ 3.5/5 | Wrong facts are unacceptable regardless of baseline |
| Completeness | ≥ 3.0/5 | Incomplete recall misses operator's intent |
| On-Tone | ≥ 3.0/5 | Tone matters but is stylistic |
| Usefulness | ≥ 3.5/5 | If operator wouldn't act on it, it failed |
| Brevity | ≥ 3.0/5 | Verbose is annoying but not dangerous |

Decision gate: `parity_aggregate ≥ 0.85` AND all 5 absolute floors met AND zero CRITICAL.

---

## 8. Evaluation Schedule

Day 61: Extract and annotate goldset.jsonl (operator: <your-id>)
Day 73-76: Daily goldset runs against both NEOTH and Jarvis (automated)
Day 77: 4-grader evaluation (automated, parallel API calls — Graders A/B/C + external Grader D)
Day 78: Kappa computation + threshold check (automated)
Day 79: Decision gate -- parity_aggregate >= 0.85 AND 0 CRITICAL events -> proceed to Day 80

---

## 9. Eval Session Isolation

Goldset runs MUST use eval sessions (prefix eval-): LOWKEY base stack NOT injected.
WAL event 0x29 SKILL_INJECT_SKIPPED emitted per eval session per request.

This ensures parity measurement is not confounded by LOWKEY prompt injection.
Both NEOTH and Jarvis eval runs use the same isolation condition: no LOWKEY.

freedom.yaml configuration for eval sessions:
  [lowkey]
  disabled_for_eval_sessions = [eval-001 through eval-200]

---

## 10. Grading Reproducibility

Each grading run records in eval/grading-run-N.json:
  run_id: UUID v7
  goldset_sha256: first 16 bytes of SHA-256(goldset.jsonl bytes)
  grading_prompt_hash: SHA-256(grading-prompt.md bytes)
  grader_A_model: claude-opus-4-7
  grader_B_model: gpt-5.5
  grader_C_model: gemini-3.1-pro
  grader_D_model: mistral-large-2 | deepseek-v3.5 | qwen2.5-72b-instruct  # external, H7 fix
  operator_anchor_sha256: first 16 bytes of SHA-256(operator-anchor.jsonl bytes)
  family_bias_per_dim: dict   # mean(A+B+C) - operator on 20 anchored queries
  family_bias_correction_applied: bool
  kappa_report_sha256: first 16 bytes of SHA-256(kappa-report.json bytes)
  parity_aggregate: float
  absolute_floors_per_dim: dict   # mean NEOTH score per dimension
  absolute_floors_met: bool
  pass: bool   # parity AND floors AND zero-CRITICAL

This record is immutable once written. Re-runs create new run_id.
Binding record for Phase 3 go/no-go: most recent passing run_id.

## 11. Council `test_all_three_agree_and_wrong` Fix (H6)

**Problem v0.8:** Council adversarial test `test_all_three_agree_and_wrong` (in v0.8 §6 council adversarial suite) declares: "All 3 hemispheres trained or prompted to converge on wrong answer. Expected: dissent-detector catches via factual_contradiction_check tool (deterministic). Fails if Council ships wrong answer."

But `factual_contradiction_check` fires on **hemisphere disagreement**. Unanimous-wrong = no disagreement = tool silent. Test cannot work as specified.

**Fix v1.1:** Add `GROUND_TRUTH_TAG` to test fixtures. The test fixture explicitly tags the correct answer in the test setup context, separate from what the hemispheres produce.

```rust
// tests/council_adversarial.rs

#[test]
fn test_all_three_agree_and_wrong() {
    // Setup: synthetic fixture with GROUND_TRUTH_TAG
    let fixture = CouncilTestFixture {
        prompt: "What is 2+2 in base 3?",
        ground_truth_tag: GroundTruth {
            answer: "11",  // 2+2 = 4, which is "11" in base 3
            rationale: "Decimal 4 = base-3 'one ten plus one one' = 11.",
            source: "mathematical fact, deterministic",
        },
        // Force all 3 hemispheres to converge on wrong answer (e.g., "4" — base-10 answer)
        force_left_response: Some("The answer is 4."),
        force_right_response: Some("Confirming: 4."),
        force_callosum_response: Some("Both agree: 4."),
    };

    let verdict = run_council_with_fixture(&fixture);

    // factual_contradiction_check NOW has the GROUND_TRUTH_TAG as a reference
    // and DOES fire even on unanimous-wrong because it checks against the tag
    // not just inter-hemisphere disagreement.
    assert!(
        verdict.factual_contradiction_detected,
        "factual_contradiction_check must catch unanimous wrong answer when GROUND_TRUTH_TAG present"
    );
    assert!(
        !verdict.shipped_to_user,
        "Council must NOT ship a response that contradicts GROUND_TRUTH_TAG"
    );
    assert_eq!(verdict.mirror_refusal_triggered, true);
}
```

**Test infrastructure additions:**
- `CouncilTestFixture::ground_truth_tag` — optional GroundTruth reference for test contexts
- `factual_contradiction_check` accepts ground_truth_tag and checks response against it
- Production runs have no ground_truth_tag — tool operates only on hemisphere-vs-hemisphere
- Test mode: tool also checks response-vs-tag for unanimous-wrong detection

This makes `test_all_three_agree_and_wrong` falsifiable. Without GROUND_TRUTH_TAG, the test is theater.
