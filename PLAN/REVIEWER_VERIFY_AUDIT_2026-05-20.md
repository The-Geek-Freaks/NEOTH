# Code-Review Audit: verify.rs + webhook_verify.rs
Date: 2026-05-20
Scope: SRC/neothd/src/cli/verify.rs - SRC/neothd/src/wal/redact.rs - SRC/neothd/src/cli/memory.rs - SRC/neothd/src/channels/webhook_verify.rs

---

## Finding 1 -- Path::display().to_string() fragile match

**Verdict: PARTIAL-CONFIRMED**

### Evidence

Writer at `redact.rs:246` serialises the segment path into the 0xF3 WAL frame payload:

    "segment": segment_path.display().to_string(),

`segment_path` is the `&path` from `memory.rs:498-520`, where `path = entry.path()` -- raw `DirEntry::path()`, not canonicalised.

Reader at `verify.rs:235,237` reconstructs the comparison string from the same kind of raw path:

    let seg_display = seg.display().to_string();  // verify.rs:235
    if r.segment != seg_display { continue; }     // verify.rs:237

`seg` also originates from `entry.path()` via `list_segments`. The design is intentional and documented at `verify.rs:172-173`: "The segment string matches the WAL frame payload verbatim."

### When they diverge

In the default-path flow (both sides call `FreedomConfig::default_wal_dir()`) the strings are identical. The match breaks in three cases:

1. `--wal-dir` passed as a relative path on the verify side but redaction ran against the absolute form.
   Stored marker: `/home/user/.neoth/wal/000001.wal`
   Verifier: `./wal/000001.wal`
   Result: all authorised reclassifications become false negatives -- HMAC mismatches that should be pardoned FAIL instead, `run_verify` exits non-zero.

2. WAL directory accessed via a symlink that resolves differently between the two invocations.

3. Windows vs Unix path-separator mismatch in a portable-WAL scenario.

### Fix

Store only the filename component (all segments are co-located in one directory):

    // redact.rs:246
    "segment": segment_path.file_name()
        .and_then(|n| n.to_str()).unwrap_or(""),

    // verify.rs:235-237
    let seg_name = seg.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if r.segment != seg_name { continue; }

Immune to absolute/relative differences, symlinks, and path-separator conventions.

---

## Finding 2 -- run_verify high complexity

**Verdict: CONFIRMED**

### Evidence

`run_verify` body: `verify.rs:34-147` = **113 lines**. Six distinct responsibilities:

| Lines   | Responsibility                                               |
|---------|--------------------------------------------------------------|
| 35-44   | Resolve and load HMAC key                                    |
| 46-50   | Collect segment list                                         |
| 52-63   | Collect authorised redaction ranges across all segments      |
| 64-96   | HMAC verification loop + reclassification logic (~33 lines)  |
| 98-141  | Output rendering -- JSON and Table branches (~44 lines)      |
| 144-146 | Exit-code decision                                           |

### Proposed split

`list_segments` and `compaction::load_or_init_key` already exist as separate functions. Two blocks to extract:

- `verify_segments(segs, key, authorised) -> Result<VerifyReport>` -- lines 64-96, ~33 lines
- `render_verify_output(format, report, segs)` -- lines 98-141, ~44 lines

After extraction `run_verify` is under 30 lines and each helper stays under 50.

---

## Finding 3 -- Webhook query-string parser fragile

**Verdict: PARTIAL -- correctness gap confirmed, security impact overstated**

### Evidence

Parser at `webhook_verify.rs:99-110`: `query.split('&')` + `split_once('=')` + `url_decode(v)`. Keys matched raw.

`url_decode` at lines 265-296: handles `%XX` and `+`. Malformed `%` at end-of-input falls through to literal passthrough (intentional, documented lines 267-269).

### Edge cases

| Case | Behaviour | Security impact |
|------|-----------|-----------------|
| Duplicate key (hub.verify_token=a&...=b) | Last value wins silently | None -- worst outcome is TokenMismatch |
| Key with no equals sign | Skipped via continue | None -- required key missing -> BadRequest |
| Percent-encoded key name (hub%2Emode) | No arm match -> BadRequest | None -- Meta does not encode key dots |
| Trailing lone % or %X at end of value | Emitted as literal (intentional) | None -- causes TokenMismatch |
| Plus in key name | Not decoded; no arm match | None -- -> BadRequest |

No edge case routes to `Echo(challenge)` with an unverified token. The claimed security-logic escape does not materialise.

### Actual gap

Duplicate keys are undocumented. RFC 3986 allows the same key multiple times. If Meta sends a duplicated parameter, last value silently wins. This is a correctness gap only, not a security issue.

### Fix sketch

Minimum: add a comment documenting last-write-wins for duplicates. The current behaviour is safe given the downstream constant-time comparison.

Optional: swap to `form_urlencoded::parse` from the `url` crate ecosystem; only warranted if that crate is already a dependency or the parser needs to grow.

---

## Finding 4 -- Segment sort lexicographic not numeric

**Verdict: PARTIAL -- convention is enforced, risk is theoretical**

### Evidence

Sort at `verify.rs:165`:

    out.sort();  // PathBuf lexicographic sort

The sole code path creating sequence-named segments is `writer.rs:430`:

    parent.join(format!("{:06}.wal", next_seq))

Test at `verify.rs:299-310` creates `000001.wal`, `000002.wal`, `000003.wal`.

### Analysis

For a fixed-width `{:06}` format, lexicographic order equals numeric order across the full 0-999999 range. There is one call site and no divergence path in normal daemon operation.

Risk materialises only if an operator manually drops a non-padded file (e.g., a backup named `1.wal`) into the WAL directory. That is an operator error, not a code defect.

### Fix sketch (low priority)

    out.sort_by_key(|p| {
        p.file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });

Non-numeric filenames sort to end. No naming convention change required.

---

## Review Summary

| Finding | Severity | Verdict | Required action |
|---------|----------|---------|-----------------|
| F1: display().to_string() path match | P0 HIGH | PARTIAL-CONFIRMED | Use filename-only key in marker payload. Default flow safe; `--wal-dir` relative paths and symlinks trigger false FAILs on reclassification. |
| F2: run_verify complexity | P1 HIGH | CONFIRMED | Extract `verify_segments` (lines 64-96) and `render_verify_output` (lines 98-141). `run_verify` drops to ~25 lines. |
| F3: webhook query parser | P1 HIGH | PARTIAL | No security bypass possible. Document last-write-wins for duplicate keys. `form_urlencoded` swap optional. |
| F4: lexicographic sort | P2 MEDIUM | PARTIAL | No action required. `{:06}` convention enforced at `writer.rs:430`. Add numeric sort-by-key if defensive posture wanted. |

**Verdict: WARNING** -- F1 and F2 should be resolved before any scenario involving backup restore or non-default `--wal-dir` invocations. F3 and F4 are low urgency.
