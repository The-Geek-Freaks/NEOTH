# Runbook — Jarvis → NEOTH recall-parity migration gate (ARCH-05 / SPEC-08)

The go/no-go gate before NEOTH becomes the **primary** memory store. NEOTH must
prove its recall is at parity with the live Jarvis system before cutover. This
runbook is the operator procedure; the deterministic scoring is shipped in
`neoth recall-score` (see `SRC/neothd/src/recall/{parity,goldset,parity_run}.rs`).

> **Why a gate at all:** memory is the one thing a wrong cutover loses
> irreversibly. A high inter-rater agreement (kappa) with a shared grader bias is
> *confidently wrong* — so the protocol adds an external grader (family-D) + an
> operator anchor, and a single CRITICAL divergence aborts. See
> `PLAN/SPEC_recall_parity_methodology.md` for the full methodology.

## What ships in NEOTH (verifiable today)

- **`neoth recall-score --grades <file>… [--goldset <file>] [--no-audit]`** —
  loads the grader sheets, computes per-dimension Cohen's kappa (within-1-Likert
  agreement), the kappa-adjusted weighted-harmonic **parity aggregate**, and the
  per-query **CRITICAL** divergences. Prints a report, emits a WAL
  `0x3E EVAL_CRITICAL_DIVERGENCE` per flagged query, and **exits non-zero if the
  gate fails** (so a cutover script can hard-gate on it).
- The pure scoring math (`recall::parity`) + the JSONL file formats
  (`recall::goldset`) — fully unit-tested, no live Jarvis needed.

## What is the operator's live work (not in the binary)

- Extracting the 100-query goldset from the live Jarvis `recall.sh`.
- The 14-day shadow-run with Telegram dual-write.
- The 4-grader grading itself (Claude / Codex / Gemini / external family-D +
  the operator's 20-query anchor).
- The YubiKey/TOTP-gated primary-store switch + the 30-minute rollback window.

## Procedure

1. **Goldset** — extract 100 representative queries → `eval/goldset.jsonl`
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
5. **Score the gate:**
   ```
   neoth recall-score \
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
6. **Cutover** (PASS only) — operator switches the primary memory store to NEOTH
   behind a YubiKey/TOTP confirm, keeps Jarvis warm for a 30-minute rollback
   window, and verifies a smoke set before standing Jarvis down.

## Reading the result

`neoth wal show --type eval_critical_divergence` lists every query that ever
tripped the CRITICAL floor across runs — the durable abort evidence. A clean
gate run leaves none.
