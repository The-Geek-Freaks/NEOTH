# Runbook — Jarvis → NEOTH recall-parity migration gate (ARCH-05 / SPEC-08)

The go/no-go gate before NEOTH becomes the **primary** memory store. NEOTH must
prove its recall is at parity with the live Jarvis system before cutover. This
runbook is the operator procedure; the deterministic scoring is shipped in
`neoth recall-score` (see `SRC/neothd/src/recall/{parity,goldset,parity_run}.rs`).

> **Why a gate at all:** memory is the one thing a wrong cutover loses
> irreversibly. A high inter-rater agreement (kappa) with a shared grader bias is
> *confidently wrong* — so the protocol adds an independent-external grader + an
> operator anchor, and a single CRITICAL divergence aborts. See
> `PLAN/SPEC_recall_parity_methodology.md` for the full methodology.

## What ships in NEOTH (verifiable today)

- **`neoth recall-score --grader-config <roster.json> --goldset <goldset.jsonl>
  --grades <file>… [--no-audit]`** — requires a validated, versioned grader
  roster and the canonical 100-query goldset before it accepts any grader sheet.
  It then computes per-dimension
  Cohen's kappa (within-1-Likert agreement), the kappa-adjusted weighted-harmonic
  **parity aggregate**, and the per-query **CRITICAL** divergences. It prints a
  report, emits a WAL
  `0x3E EVAL_CRITICAL_DIVERGENCE` per flagged query, and **exits non-zero if the
  gate fails** (so a cutover script can hard-gate on it).
- The pure scoring math (`recall::parity`) + the JSONL file formats
  (`recall::goldset`) — fully unit-tested, no live Jarvis needed. P1-07 also
  fail-closes the exact goldset-bound grade matrix; it never silently scores a
  subset or a widened corpus.

## What is the operator's live work (not in the binary)

- Extracting the 100-query goldset from the live Jarvis `recall.sh`.
- The 14-day shadow-run with Telegram dual-write.
- The 4-grader grading itself (Claude / Codex / Gemini / external family-D +
  the operator's 20-query anchor).
- The YubiKey/TOTP-gated primary-store switch + the 30-minute rollback window.

## Procedure

1. **Goldset** — extract **exactly 100** representative queries →
   `eval/goldset.jsonl`
   (`{query_id, query_text, category, expected_sources, expected_response}` per
   line). Categories: `recall`/`summarize`/`action`/`factual`.
2. **Anchor** — the operator hand-grades 20 of the 100 against the 5-dimension rubric
   → `eval/operator-anchor.jsonl`.
3. **Shadow-run (14 days)** — dual-write every Telegram turn to NEOTH + Jarvis;
   collect both systems' answers to the goldset queries.
4. **Grade** — each of the 4 graders scores every (query, system) pair on the
   5 dimensions (0–5 Likert) → `eval/grades-grader-{A,B,C,D}.jsonl`
   (`{query_id, grader_id, system: neoth|reference, factual, completeness,
   on_tone, usefulness, brevity}` per line).
5. **Write the P1-07 grader roster** — create `eval/grader-config.v1.json`
   once for this grading run. `--grader-config` is mandatory; do not use the
   historical A/B/C/D filenames as identity evidence. The accepted JSON v1
   contract is:

   ```json
   {
     "schema_version": 1,
     "graders": [
       {
         "grader_id": "claude",
         "provider": "anthropic",
         "model_id": "claude-opus-4-7",
         "family": "anthropic_openai_google"
       },
       {
         "grader_id": "external",
         "provider": "mistral",
         "model_id": "mistral-large-2",
         "family": "independent_external"
       }
     ]
   }
   ```

   The field names and enum tags are exact and lowercase. Allowed `provider`
   tags are `anthropic`, `openai`, `google`, `mistral`, `deepseek`, and `qwen`.
   `anthropic`/`openai`/`google` must use `anthropic_openai_google`;
   `mistral`/`deepseek`/`qwen` must use `independent_external`. The roster must
   contain both families, distinct `grader_id` values, and distinct
   `(provider, model_id)` pairs. Unknown fields/tags and unsupported schema
   versions fail before scoring. The maximum file size is 64 KiB and the maximum
   roster size is 64 graders. `grader_id` must be 1–64 ASCII characters: an
   alphanumeric first character followed only by alphanumerics, `.`, `_`, or
   `-`. `model_id` must be a trimmed 1–128-character ASCII identifier containing
   at least one alphanumeric and using only `A–Z`, `a–z`, `0–9`, `.`, `_`, `-`,
   `/`, `:`, `@`, or `+`. Invalid IDs/models fail before scoring.
6. **Score the gate:**

   ```
   neoth recall-score \
     --grader-config eval/grader-config.v1.json \
     --goldset eval/goldset.jsonl \
     --grades eval/grades-grader-A.jsonl \
     --grades eval/grades-grader-B.jsonl \
     --grades eval/grades-grader-C.jsonl \
     --grades eval/grades-grader-D.jsonl
   ```
   - **PASS** = aggregate ≥ **0.85** AND **zero** CRITICAL divergences AND mean
     kappa ≥ 0.60 (reliability). Exit code 0.
   - **FAIL** = below threshold OR any CRITICAL (factual/usefulness kappa-parity
     < 0.50, or an empty/error response) — exit code non-zero, `0x3E` frames in
     the WAL. **Do not cut over.**
7. **Cutover** (PASS only) — operator switches the primary memory store to NEOTH
   behind a YubiKey/TOTP confirm, keeps Jarvis warm for a 30-minute rollback
   window, and verifies a smoke set before standing Jarvis down.

## P1-07 submission checks (fail closed)

The roster and mandatory goldset are the only accepted identity sets for a
scoring run. The goldset is bounded to 4 MiB and must contain exactly 100
records with unique canonical `query_id` values. Query IDs and grader IDs are
1–64 ASCII characters: an alphanumeric first character followed only by
alphanumerics, `.`, `_`, or `-`. For **every goldset query**, every configured
grader must supply exactly one observation for each system: `neoth` and
`reference`. Consequently, the scorer rejects rather than averages around any
of the following:

- A duplicate `(query_id, grader_id, system)` observation.
- A grade whose `grader_id` is absent from the roster (unknown identity).
- A roster grader with no grade at all (a dangling/unparticipating identity).
- A missing `(query_id, grader_id, system)` observation, including an incomplete
  independent-external grader.
- A duplicate, invalid, missing, or extra grade query ID relative to the
  mandatory 100-query goldset.

Input size is bounded before scoring: a grades JSONL file may be at most 16 MiB
and at most 12,800 records; the aggregate submission may not exceed the exact
`100 × configured graders × 2 systems` matrix. Grade records are checked again
by the scorer before its math runs, including canonical IDs and all five Likert
values (`0..=5`). This prevents a direct caller from bypassing the file-loader
validation.

The terminal and JSON reports expose only stable, safe participant metadata —
`grader_id`, `provider`, `family`, and `model_id` — plus whether the independent
external-family gate was met. They do not treat a roster claim as an API receipt,
credential, prompt transcript, or cryptographic proof.

### P1-07 boundary

P1-07 proves an exact 100-query, complete cross-family matrix against a strict
declared roster. It **does not** prove that a named provider/model actually
produced a submitted grade sheet, bind the roster to a grading batch, or attest
a prompt/goldset hash. Those cryptographic provenance and batch-binding
guarantees remain explicitly open in **P1-08**; do not present a P1-07 PASS as
provider provenance.

## Reading the result

`neoth wal show --type eval_critical_divergence` lists every query that ever
tripped the CRITICAL floor across runs — the durable abort evidence. A clean
gate run leaves none.
