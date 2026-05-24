# Handoff — Session 24 (execution-ready)

**Date:** 2026-05-25
**Predecessor:** Session 23 closed v0.2 with 96/96 deferred items shipped. Sessions 23+ then did 3 rounds of Gremium synthesis (5-agent → 6-agent → 6-agent forgotten-hunt) and produced the v1.0 backlog at `PLAN/PROGRESS_v1_0.md` with **225 open items across 6 lanes**.

This handoff is the **execution-ready pickup file** for Session 24 — specifically the **v0.2.1 SECURITY HOTFIX lane (21 items, ~7-10 days)**. v0.3 + v0.4 + v0.5 + v0.9 + v1.0 each get their own handoff when the prior lane closes.

**Read order at session start:**
1. This file end-to-end.
2. `PLAN/PROGRESS_v1_0.md` (sections "v0.2.1 SECURITY HOTFIX" + "Round-3 v0.2.1 SECURITY HOTFIX additions").
3. `PLAN/ROAD_TO_1_0.md` (lane definitions + sequencing rules — context only, not read line-by-line).
4. `PLAN/v1_0_OPERATOR_WISHLIST_2026-05-24.md` (verbatim source — context only).

Then start work with **SX-01** (SSRF guard).

---

## State at session start

```
HEAD            = 951461a
branch          = main
v0.2 closed     = 96/96 items   (PROGRESS_v0_2_FINAL.md)
v1.0 backlog    = 225 open      (PROGRESS_v1_0.md)
v0.2.1 hotfix   = 21 items      (this handoff covers all of them)
tests           = 4240 passing  (verified end of Session 23, 2 consecutive reruns)
clippy          = 0 warnings
fmt             = clean
```

The 12 `?? PLAN/...REEVALUATION_GESAMT_*` etc. untracked files from the working tree are stale Session 22 review artifacts. Leave them alone unless you decide to garbage-collect — they're not blocking anything.

---

## Hard rules (carry-over from Session 23, plus 2 new)

1. **Cargo wrapper:** `powershell.exe -ExecutionPolicy Bypass -File scripts\cargo-msvc.ps1 <args>` — wrap via `Start-Process` with `-RedirectStandardOutput`/`-RedirectStandardError`. Direct `cargo` from bash fails on MSVC env init. **`-D warnings` for clippy:** use the wrapper's `-D` switch hack as `powershell.exe -File scripts\cargo-msvc.ps1 -D clippy --workspace --all-targets warnings` (NOT `-- -D warnings`).

2. **Gates after every commit:** `cargo fmt --all` (apply) + `cargo test --workspace --all-targets` → 0 failures + `cargo clippy --workspace --all-targets -- -D warnings` → 0 warnings. Two consecutive test reruns to catch parallel-test races.

3. **Same-turn PROGRESS flip:** every code commit pairs with the `[ ]` → `[x]` flip in the same commit. Stale doc lines cost Session 22 + 23 time.

4. **CRLF warnings benign:** git autocrlf shows warnings on every modified file; rustfmt enforces LF via `rustfmt.toml`. Ignore.

5. **`SendUserMessage` is forbidden** per global CLAUDE.md. Always reply in plain chat.

6. **TDD per CLAUDE.md global rule:** every SX-* item ships test-first. Write the failing test that demonstrates the bug, then ship the fix, then verify the test goes green. Coverage rule: 80%+ on new code.

7. **NEW for v0.2.1 — no scope creep beyond the 21 SX/CRIT/HIGH items:** if you discover a related bug during SX-01..08, file a follow-up `[ ]` item in v0.3 lane, don't let it sneak into the hotfix. The hotfix exists to ship `v0.2.1` tag in 7-10 days, not 20.

8. **NEW for v0.2.1 — SSRF block-list test corpus is the SX-01 acceptance gate:** the hand-crafted URL test set in SX-06 (cloud metadata + RFC-1918 + loopback + `file://`) MUST be wired as a unit test in `tools/web_fetch.rs::tests`, not just a manual smoke. Without the test corpus, SX-01 is unverified.

---

## Lessons from Sessions 22+23 — READ BEFORE SPAWNING

Three coordination patterns surfaced in the multi-agent work that's worth carrying into Session 24:

1. **PROGRESS file races on shared lines** — Session 22 had 4 parallel agents flip items in the same PROGRESS.md. Mitigation: each agent flips ONLY its own item ID via `Edit` with the exact existing line as `old_string`. Line offsets may have shifted, so use line CONTENT not line NUMBER.

2. **`git stash` from background agents is forbidden** — one agent's `git stash` swept another agent's mid-flight work + an uncommitted edit. Mitigation: agents MUST stage with explicit file paths (`git add path1 path2`) — never `git add -A` or `git add .`. And — never `git stash` from an agent task.

3. **`Cargo.lock` contention on parallel dep edits** — the serial-commit-with-explicit-files approach handles this safely. Two agents touching Cargo.toml at the same time → second one rebases.

**For Session 24 specifically:** v0.2.1 is a serial lane. Do NOT spawn parallel agents on the SX-* items — they all touch the security-critical surface and SX-06 has to run after SX-01/05 are merged. If you want parallelism, use it for the v0.3 work that starts AFTER `v0.2.1` is tagged.

---

## Recommended order

```
SX-04 (cargo audit) ─┐
SX-05 (deny.toml)  ─┴─→ CI gates green
                      │
SX-01 (SSRF guard)    │  ← parallel-safe with SX-02/03
SX-02 (ChannelSend)   │
SX-03 (plugin log)    │
                      │
ADV-01 (.cpt HMAC)    │
ADV-02 (MmapMut fix)  │
ADV-03 (Block-B XML)  │
ADV-11 (Win GNU)      │
                      │
GR-12 (5 GUI bugs)    │  ← H-2 is data-integrity, ship before others
GR-04 (breaker wire)  │
GR-13 (verify pre-v0.1│
GR-01/02 ack          │  ← operator picks needed — flag in chat
                      │
SX-06 (verify gate)   │  ← runs after all 13 above
SX-07 (threat-model docs)
SX-08 (v0.2.1 tag + push)
```

Rationale:
- **SX-04 + SX-05 first** — 0.3 days total, makes CI usable for the rest of the lane. SX-04 unblocks "cargo-audit fails the build on real CVEs" which we need before adding any new deps.
- **SX-01/02/03 next** — A5 CRIT findings, 2 days total, all small surface.
- **ADV-01..03 + ADV-11** — F4 CRIT findings, 4-7 days, larger surface (especially ADV-03 Block-B XML boundary).
- **GR-12 + GR-04 + GR-13** — operator-visible bugs, 1-2 days.
- **GR-01 + GR-02** — operator picks needed; document the two options + flag in chat, don't pick for the operator.
- **SX-06 last (acceptance)** — runs the SSRF smoke + cargo-audit + cargo-deny re-runs.
- **SX-07 + SX-08** — docs + tag.

---

## Per-item execution detail

### SX-04 — drop `|| true` from cargo-audit CI step  [XS]

**Files:**
- `.github/workflows/security.yml` line 54

**Code anchor:**
```yaml
# current (BUG):
cargo audit --json 2>/dev/null | tee /tmp/audit-result.json || true
```

**Fix:** drop `|| true`. The follow-up `cargo audit` line (line 58) already fails correctly; the JSON tee was hiding vulnerabilities from the SARIF upload path.

**Test:** push a branch containing a deliberate vulnerable dep (e.g., `tempfile = "3.0.0"` if it has a known CVE; check `cargo audit` output first) → confirm the CI job goes red. Revert the dep change.

**Commit template:**
```
fix(ci): SX-04 — strip || true from cargo audit step (silently swallowed CVEs)

The audit step at .github/workflows/security.yml:54 used `|| true` which
masked non-zero exits from cargo-audit when CVEs were found. SARIF upload
read the swallowed JSON and reported clean. Now the step fails the CI
job on any advisory hit.

Gates: pushed to a test branch with a deliberate vulnerable dep, CI went
red as expected. Reverted the test dep. Main CI run clean.

Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md + PROGRESS_v1_0.md SX-04 +
A5 SC-12 audit finding.
```

---

### SX-05 — Windows MSVC target in `deny.toml`  [XS]

**Files:**
- `deny.toml`

**Fix:** add `x86_64-pc-windows-msvc` to `[graph].targets` (and `x86_64-unknown-linux-gnu` + `aarch64-apple-darwin` if not already there). This makes `cargo deny check` audit Windows-only transitive deps (`windows-sys` sub-features, `portable-pty` ConPTY path).

**Test:** `powershell.exe ... cargo-msvc.ps1 deny check` → confirm no unsupported-target errors AND that the report now includes Windows-specific deps in the tree analysis.

**Commit template:**
```
fix(deny): SX-05 — add Windows MSVC target to deny.toml graph

deny.toml [graph].targets did not include x86_64-pc-windows-msvc so
windows-only transitive deps (windows-sys, portable-pty ConPTY path)
were never audited. Add the target; cargo deny check now walks Windows
deps too.

Gates: cargo deny check clean. No new advisories raised by Windows
deps in current Cargo.lock.

Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md SX-05 + A5 SC-13.
```

---

### SX-01 — SSRF block list for `web_fetch`  [S, v0.5 ingest blocker]

**Files:**
- `SRC/neothd/src/tools/web_fetch.rs` (lines 44-93 fetch() body)
- New test module at the bottom of the same file

**Required behaviour:**
1. Parse the URL via `url::Url::parse` (not string-prefix check). Reject any scheme that isn't `http` or `https`. This kills `file://`, `gopher://`, `dict://`, etc.
2. Resolve hostname to all IPs via `tokio::net::lookup_host(format!("{host}:{port}"))`. For every resolved IP, check:
   - Loopback: `ip.is_loopback()` (covers `127.0.0.0/8` + `::1`)
   - Private RFC-1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-local: `169.254.0.0/16` (covers AWS/GCP/Azure instance-metadata `169.254.169.254`)
   - Unique-local IPv6 (RFC-4193): `fc00::/7`
   - Cloud-specific metadata endpoints (hostnames): `metadata.google.internal`, `metadata.azure.internal`
3. Reject the request if ANY resolved IP fails the check (defence-in-depth — single IP failing is enough).
4. On rejection, emit a `tracing::warn!` and return `Err(WebFetchError::PrivateAddress(url))`.

**Helper signature:**
```rust
fn validate_url_not_private(url: &url::Url) -> Result<(), WebFetchError> { ... }

#[derive(Debug, thiserror::Error)]
pub enum WebFetchError {
    #[error("unsupported scheme {0} (only http/https allowed)")]
    UnsupportedScheme(String),
    #[error("URL resolves to private/loopback/metadata address: {0}")]
    PrivateAddress(String),
    // ... existing variants
}
```

**Tests** (write these FIRST per TDD rule):
- `validate_rejects_aws_metadata_endpoint` — `http://169.254.169.254/latest/meta-data/iam/...`
- `validate_rejects_loopback` — `http://127.0.0.1:9744/api/health`, `http://localhost:9744`
- `validate_rejects_rfc1918` — `http://10.0.0.1/`, `http://192.168.1.1/`, `http://172.16.0.1/`
- `validate_rejects_file_scheme` — `file:///etc/passwd`
- `validate_rejects_non_http_scheme` — `gopher://example.com`, `dict://example.com`
- `validate_accepts_public_url` — `https://api.openai.com/v1/models`
- `validate_rejects_metadata_hostname` — `http://metadata.google.internal/`
- `validate_rejects_unique_local_ipv6` — `http://[fc00::1]/`
- `fetch_returns_private_address_error_on_aws_metadata` — end-to-end via `fetch()`

**Edge case:** DNS resolution can be slow on a network-restricted dev machine; use `tokio::time::timeout(Duration::from_secs(2), lookup_host(..))` to bound the gate's latency.

**Commit template:**
```
feat(tools): SX-01 — SSRF block list for web_fetch (private IPs +
cloud metadata + non-HTTP schemes)

Closes A5 CRIT-01. tools/web_fetch.rs::fetch() previously checked only
the URL string prefix for "http://" or "https://" — it did not validate
the parsed scheme component, did not block private/loopback/link-local
addresses, and did not reject cloud instance-metadata endpoints. An LLM
response, skill, or WASM plugin calling web_fetch with a crafted URL
could exfiltrate cloud credentials, reach localhost-bound services, or
pivot inside the operator's LAN.

This commit:
1. Parses URL via url::Url::parse (not string prefix)
2. Rejects non-http(s) schemes (kills file://, gopher://, dict://)
3. Resolves hostname to IPs via tokio::net::lookup_host
4. Rejects any IP in RFC-1918, RFC-4193, loopback, link-local
5. Rejects metadata hostnames (metadata.google.internal etc.)
6. Returns WebFetchError::PrivateAddress / UnsupportedScheme

Tests: 9 new unit tests (validate_rejects_*) cover cloud metadata, RFC-
1918, RFC-4193, file://, non-http schemes, metadata hostnames, unique-
local IPv6. Plus 1 end-to-end test through fetch(). 2s DNS-lookup
timeout prevents network-restricted dev machines from hanging.

Gates: cargo fmt + clippy -D warnings + cargo test workspace all
green; SSRF smoke (SX-06) verifies real network behaviour.

Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md SX-01 + A5 CRIT-01.
```

---

### SX-02 — ChannelSend `before_state` redaction  [XS, 1-line + test invert]

**Files:**
- `SRC/neothd/src/wal/snapshot.rs` lines 236-253 (`should_redact` match)
- `SRC/neothd/src/wal/snapshot.rs` line 530 (test that pins wrong invariant — INVERT it)
- `SRC/neothd/src/channels/mod.rs` lines 490-505 + 534-547 (production call sites — verify redacted bytes land in WAL)

**Code anchor:**
```rust
// snapshot.rs:236 — current (BUG):
match kind {
    MutationKind::ConfigWrite | MutationKind::FileWrite | MutationKind::Other => {
        // redact
    }
    MutationKind::ChannelSend | MutationKind::McpToolInvoke | MutationKind::SqlMutation => {
        // SKIP redaction — domain-specific bytes
    }
}
```

**Fix:** move `ChannelSend` from the "skip" arm to the "redact" arm. The skip was added to avoid corrupting binary message payloads (MIME attachments), but UTF-8 channel text MUST be redacted because operators routinely paste secrets ("send my key to Telegram user X") and the secret currently lands plaintext in the WAL forever. Binary payload concern is already handled by the `std::str::from_utf8` gate two lines above — if UTF-8 parse fails, the function bails to `Cow::Borrowed` and never touches the bytes.

**Test fix:** the existing test at line 530 (`channelsend_skip_redaction_for_domain_specific_bytes` or similar) currently asserts redaction is SKIPPED. Invert it: assert `[REDACTED:openai_key]` appears in the output for a `ChannelSend` carrying `sk-abc123...`.

**New tests:**
- `channelsend_redacts_openai_key_in_text`
- `channelsend_redacts_anthropic_key_in_text`
- `channelsend_preserves_non_secret_utf8` — bare message "hello world" round-trips unchanged
- `channelsend_passthrough_on_binary_payload` — non-UTF-8 bytes still bail without panic

**Commit template:**
```
fix(wal): SX-02 — redact ChannelSend before_state (was plaintext forever)

Closes A5 CRIT-02. wal/snapshot.rs::redact_before_state_if_credential_
bearing() deliberately excluded ChannelSend from secret redaction. A
"send my OpenAI key to Telegram user 12345" message routed through the
channel pipeline → PRE_MUTATION_SNAPSHOT WAL frame → `neoth rollback
show` rendered the plaintext key forever. WAL is durable + operator-
visible.

Fix: move ChannelSend from the skip arm to the redact arm in the
should_redact match. The binary-payload concern that motivated the
original skip is already handled by the str::from_utf8 gate two lines
above; non-UTF-8 bytes bail to Cow::Borrowed without touching content.
The test at snapshot.rs:530 that pinned the wrong invariant is
inverted: now asserts [REDACTED:openai_key] appears for a ChannelSend
carrying sk-abc123...

Tests: 4 new tests (channelsend_redacts_openai_key_in_text /
_anthropic_key / _preserves_non_secret_utf8 / _passthrough_on_binary)
+ inverted existing test. Production callsites at channels/mod.rs:
490-505 + 534-547 verified to land redacted bytes via end-to-end test.

Gates: fmt + clippy + workspace tests all green.
Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md SX-02 + A5 CRIT-02.
```

---

### SX-03 — `wasm_plugin/hostcalls.rs` neoth.log redaction  [XS]

**Files:**
- `SRC/neothd/src/wasm_plugin/hostcalls.rs` line 165-166

**Code anchor:**
```rust
// current (BUG):
let msg = String::from_utf8_lossy(&data[start..end]);
tracing::info!(target: "wasm_plugin", plugin = %plugin_id, "plugin log: {msg}");
```

**Fix:** pipe `msg` through `crate::security::redact::redact_text()` (which SX-02 + QU-04 will produce in this session — if SX-02 lands first, the function already exists; if you're doing SX-03 before SX-02, scaffold the redact helper as a sub-task).

**Test:** plugin emits `host.log("API_KEY=sk-abc123def...")` → `tracing::info!` output contains `[REDACTED:openai_key]`, not the literal key.

**Commit template:**
```
fix(wasm_plugin): SX-03 — redact plugin log payloads before tracing

Closes A5 CRIT-03. wasm_plugin/hostcalls.rs:165 emitted plugin-supplied
bytes verbatim through tracing::info!. A plugin that called host.log
with a credential-bearing string (e.g., a config reader logging parsed
config) leaked the secret into stdout/NEOTH_LOG file via tracing-
subscriber's json formatter. This bypassed the SecretString Debug
protection because the bytes came from WASM linear memory as &str.

Fix: pipe msg through security::redact::redact_text() before the
info! call.

Tests: 1 new test plugin_log_redacts_api_key_pattern asserts output
contains [REDACTED:openai_key] for a host.log("API_KEY=sk-abc...")
call.

Gates: fmt + clippy + workspace tests all green.
Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md SX-03 + A5 CRIT-03.
```

---

### ADV-01 — WAL `.cpt` HMAC-SHA256 authentication  [S, 1-2d]

**Files:**
- `SRC/neothd/src/wal/recovery.rs` (the .cpt apply path)
- `SRC/neothd/src/wal/compaction.rs` (the .cpt write path)
- `SRC/neothd/src/wal/dpapi.rs` (HMAC key derivation already exists)

**Behaviour:**
1. `.cpt` write path computes HMAC-SHA256 over the file content using the node-identity key (derived from DPAPI-wrapped HMAC key already in `compaction.rs`).
2. HMAC is appended as a 32-byte trailer after the existing CRC32c + xxh3-64 checksums.
3. `.cpt` apply path verifies HMAC BEFORE replaying any frame. If HMAC mismatch → bail with `RecoveryError::CheckpointAuthFailed { path }` and write a `0x18 RECOVERY_AUTH_FAILED` WAL event.
4. After HMAC passes + frame CRC passes, re-run the `region_tag` validation per frame (the single-writer Hypothalamus invariant).

**WAL event claim:** `0x18 RECOVERY_AUTH_FAILED` (band `0x10..0x1F` boot/lifecycle still has room).

**Tests:**
- `cpt_with_valid_hmac_applies_successfully`
- `cpt_with_tampered_payload_fails_auth`
- `cpt_with_missing_hmac_trailer_fails_auth`
- `cpt_with_wrong_key_fails_auth` (different DPAPI master)
- `cpt_auth_failure_emits_0x18_wal_frame`
- `cpt_region_tag_validation_runs_after_hmac_pass`

**Commit template:**
```
feat(wal): ADV-01 — HMAC-SHA256 auth for .cpt crash-recovery files

Closes F4 ADV-01. The .cpt apply path verified only CRC32c + xxh3-64,
both non-cryptographic. A local attacker (or malicious plugin) could
pre-place a crafted .cpt file injecting PROFILE_DELTA events with
confidence=0.99 or tombstoning real events; recovery applied it
unconditionally. The single-writer Hypothalamus invariant was not re-
validated on the recovery path.

This commit:
1. Adds 32-byte HMAC-SHA256 trailer to every .cpt write, signed with
   the existing DPAPI-wrapped HMAC key from compaction.rs.
2. Verifies HMAC BEFORE replaying any frame in recovery.rs.
3. Re-runs region_tag validation per frame after HMAC + CRC pass.
4. Claims WAL event 0x18 RECOVERY_AUTH_FAILED for audit trail.
5. Returns RecoveryError::CheckpointAuthFailed on mismatch.

Tests: 6 new tests cover valid HMAC, tampered payload, missing
trailer, wrong key, 0x18 emit, and region_tag re-validation order.

Gates: fmt + clippy + workspace tests all green.
Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md ADV-01 + F4 forgotten-hunt.
```

---

### ADV-02 — Active segment write-protected outside append window  [M, 2-4d]

**Files:**
- `SRC/neothd/src/wal/writer.rs` (mmap setup)
- `SRC/neothd/src/wal/segment.rs` (if active-segment management lives here)

**Behaviour:** stop using `MmapMut` for the lifetime of the active segment. Either:
- Option A: keep `MmapMut` but `mprotect(PROT_READ)` outside the actual append window, flip to `PROT_WRITE` just for the append, then back. POSIX-only (`memmap2::MmapMut::make_read_only` API exists; Windows requires `VirtualProtect` directly). Less code change but per-append latency added.
- Option B (recommended per HP-1): switch to `WalWriterTask` with `tokio::fs::File` + `O_DSYNC` for the active segment. Sealed segments stay read-only `Mmap`. Larger refactor but eliminates the write window entirely and fixes the four HP-1 cascades.

**Pick Option B** unless append-latency benchmarks show Option A is materially faster.

**Tests:**
- `active_segment_is_not_writable_from_arbitrary_memory_address` — try to write to the mapped region offset, expect panic/SIGSEGV (Linux) or memory-protection error (Windows).
- `wal_writer_task_appends_correctly_under_load` — 10k appends, verify all readable + CRC valid.
- `wal_writer_task_handles_seal_correctly` — active → sealed transition leaves the segment in read-only `Mmap` state.

**Commit template:**
```
refactor(wal): ADV-02 — eliminate active-segment write window

Closes F4 ADV-02 + HP-1 cascade. The active WAL segment was permanently
mapped MmapMut. Any code running as the neothd user — including
compiled-in plugins via inventory::submit! — could zero-fill the
importance: f32 field at the known header offset, causing silent GC
erasure at the next compaction with no CRC mismatch.

This commit switches the active-segment write path to WalWriterTask
with tokio::fs::File + O_DSYNC. Sealed segments stay read-only Mmap.
Eliminates the write window entirely; resolves the four HP-1 cascades
flagged in PLAN/ADVERSARIAL/09_implementation_hotpaths.md.

Tests: 3 new tests cover write-protection, append-under-load, and
seal transition state. Existing WAL replay tests unchanged.

Gates: fmt + clippy + workspace tests all green. Append-latency
microbench at SRC/neothd/benches/wal_writer.rs shows no regression
(<5% delta vs MmapMut path).

Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md ADV-02 + F4 + HP-1.
```

---

### ADV-03 — Profile Block-B XML untrusted-data boundary  [M, 3-5d]

**Files:**
- `SRC/neothd/src/profile/inject.rs` (or wherever Block-B is rendered into the system prompt)
- `SRC/neothd/src/profile/extract.rs` (the extraction path)
- `SRC/neothd/src/profile/types.rs` (`require_approval` default)
- New `eval/prompt_injection_corpus/profile_block_b/*.json` fixtures

**Behaviour:**
1. Wrap profile claims in Block-B with XML delimiters: `<profile_claim trusted="user_extracted" confidence="0.87">value</profile_claim>`. Model is instructed (in the system prompt header) to treat content inside `<profile_claim>` as data, not instructions.
2. Add a `is_quoted_content` pre-filter in `profile.extract` — if the input message contains markers like `>>>`, `\`\`\``, `</`, or quoted-reply chains, skip extraction for that turn (operator can override).
3. Flip `profile.require_approval` default to `true` in `freedom.yaml::profile`. Existing operators on `require_approval: false` keep their setting (migration is opt-in via `neoth profile migrate-require-approval`).
4. Add prompt-injection eval corpus: 30+ JSON fixtures under `eval/prompt_injection_corpus/profile_block_b/` covering known injection patterns (instruction override, role hijack, recursive prompt, multilingual variants).

**Tests:**
- `block_b_wraps_claim_in_xml_delimiters`
- `extract_skips_quoted_reply_content`
- `extract_skips_triple_backtick_content`
- `extract_skips_recursive_prompt_attempt`
- `require_approval_defaults_to_true_on_fresh_install`
- `existing_freedom_yaml_with_require_approval_false_is_preserved`
- Eval harness: `cargo test --test prompt_injection_corpus_profile_block_b` runs all 30+ fixtures, expects every one to be detected as injection attempt.

**Commit template:**
```
feat(profile): ADV-03 — XML untrusted-data boundary for Block-B injection

Closes F4 ADV-03. Profile Block-B injection had zero untrusted-data
boundary. An adversarial paste from Telegram → schema-valid idx_profile
→ injected verbatim in Left-hemisphere system prompt → Hebbian
reinforced to ≥0.95 confidence over 26 turns. A5's PL-04 only scoped
prompt-injection to paperless/email; the profile-extraction path was
the missed surface.

This commit:
1. Wraps profile claims in <profile_claim trusted="user_extracted"
   confidence="..."> XML delimiters in Block-B render path.
2. Adds is_quoted_content pre-filter to profile.extract — skips
   extraction when input contains quoted-reply / triple-backtick /
   recursive-prompt markers.
3. Flips profile.require_approval default to true on fresh install.
   Existing freedom.yaml with explicit false setting is preserved.
4. Adds 30+ prompt-injection eval fixtures under eval/prompt_
   injection_corpus/profile_block_b/.

Tests: 6 new unit tests + 30+ corpus fixtures verified as detected.
Migration test confirms existing freedom.yaml round-trips unchanged.

Gates: fmt + clippy + workspace tests all green.
Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md ADV-03 + F4 forgotten-hunt.
```

---

### ADV-11 — Windows GNU target linker flag fix  [XS]

**Files:**
- `.cargo/config.toml` (top-level)

**Fix:** add:
```toml
[target.x86_64-pc-windows-gnu]
rustflags = ["-C", "link-arg=-Wl,--whole-archive", "-C", "link-arg=-Wl,--no-whole-archive"]
```
OR (simpler) enforce MSVC target in README + CI by failing if the build runs against `x86_64-pc-windows-gnu`. Pick MSVC enforcement — GNU target adds maintenance burden for an audience that doesn't exist (Alex's mom doesn't have MinGW).

**Test:**
- `inventory_iter_returns_registered_hooks_on_msvc_build` (existing test in `hooks::tests`)
- New: `build_fails_with_clear_error_on_gnu_target` (CI-only, runs `rustc --version --verbose | grep msvc` and bails if absent)

**Commit template:**
```
build: ADV-11 — enforce MSVC target on Windows (silent inventory empty)

Closes F4 ADV-11. The `inventory` crate uses #[link_section] for plugin
hook registration. On x86_64-pc-windows-gnu (MinGW + GNU ld — the
default Windows Rust target without VS Build Tools), GNU ld garbage-
collects custom link sections without --whole-archive. All plugin hooks
silently failed to register: cargo build succeeded, direct function-
call tests passed, but inventory::iter::<Hook>().count() == 0 at
runtime. Development runs on Windows.

Fix: enforce x86_64-pc-windows-msvc in CI + README. The GNU target
adds maintenance burden for an audience that doesn't exist (target
operators don't have MinGW installed).

Tests: 1 new CI check (build_fails_with_clear_error_on_gnu_target)
runs rustc --version --verbose and bails on non-msvc Windows builds.
Existing inventory_iter_returns_registered_hooks_on_msvc_build
unchanged.

Gates: fmt + clippy + workspace tests all green. Windows CI matrix
job verified to run on MSVC and reject GNU.

Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md ADV-11 + F4 forgotten-hunt.
```

---

### GR-12 — Five GUI code-audit findings  [S total]

**Files (all in `SRC/neothd-gui/`):**
- `ui/main.slint` + `ui/chat.slint` (H-1 callback binding)
- `ui/wizard.slint` + `src/wizard_state.rs` (H-2 autonomy ComboBox + M-1 re-entry parse)
- `src/main.rs` (H-3 hardware probe + H-4 kanban fetch — move off main UI thread)

**Per-finding fixes:**

**H-2 first — DATA-INTEGRITY BUG:** ComboBox in `ui/wizard.slint` visual selection ("strict" / "standard" / "elevated" / "full") must match the value written to `freedom.yaml::autonomy`. Currently mismatched. Fix: bind ComboBox `current-index` to a typed `AutonomyLevel` enum field on the Slint global state, not to a string. Verify with a test that operator-clicks → freedom.yaml write contains the right value.

**H-1:** `chat-channel-switched` callback in `ui/chat.slint` is `callback chat-channel-switched(string)` but no Rust handler is bound. Bind in `src/main.rs` to a handler that calls `crate::channels::switch_active_channel(name)`.

**H-3:** hardware probe in `src/main.rs::on_window_shown` runs synchronously and can take 200-2000ms on cold cache. Move to `tokio::spawn` + send result via `slint::invoke_from_event_loop`.

**H-4:** kanban fetch at startup blocks for the same reason. Same fix as H-3.

**M-1:** wizard re-entry — when `~/.neoth/freedom.yaml` exists, the Slint properties for operator-id / provider / autonomy default to empty/zero instead of the parsed YAML value. Add `parse_existing_freedom_yaml_into_wizard_state` at wizard entry.

**Tests:**
- `autonomy_combobox_visual_matches_written_value_for_all_4_variants` (data-integrity)
- `chat_channel_switch_callback_invokes_rust_handler`
- `hardware_probe_does_not_block_main_thread` (timing assertion via tokio runtime instrumentation)
- `kanban_fetch_does_not_block_main_thread`
- `wizard_reentry_loads_existing_freedom_yaml_into_state`

**Commit template:**
```
fix(gui): GR-12 — 5 GUI code-audit findings (H-1/H-2/H-3/H-4/M-1)

Closes F6 GR-12. Five GUI code audit findings from GUI_CODE_AUDIT_2026-
05-20.md never landed in either PROGRESS file:

H-2 (DATA-INTEGRITY BUG): Autonomy ComboBox visual selection wrote
the wrong value to freedom.yaml ("strict" visual → "standard" written).
Bound to typed AutonomyLevel enum on global state; visual and written
values now match for all 4 variants.

H-1: chat-channel-switched Slint callback was unbound — sidebar
channel clicks were silent. Bound to channels::switch_active_channel.

H-3 + H-4: hardware probe + kanban fetch at startup ran synchronously
on the main UI thread, causing 200-2000ms window-show delay on cold
cache. Both moved to tokio::spawn + slint::invoke_from_event_loop.

M-1: wizard re-entry showed blank operator-id/provider/autonomy
because the wizard state defaulted to empty instead of parsing the
existing ~/.neoth/freedom.yaml. Added
parse_existing_freedom_yaml_into_wizard_state at wizard entry.

Tests: 5 new tests cover each finding. H-2 data-integrity test pins
all 4 AutonomyLevel variant round-trips.

Gates: fmt + clippy + workspace tests all green. Manual GUI walk-
through confirmed H-1..H-4 fixes user-visible behaviour.

Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md GR-12 + F6 forgotten-hunt
+ PLAN/GUI_CODE_AUDIT_2026-05-20.md.
```

---

### GR-04 — Circuit breaker wire-in  [S]

**Files:**
- `SRC/neothd/src/providers/circuit_breaker.rs` (primitive — already shipped)
- Every `Provider::complete` + `Provider::stream` impl call site:
  - `providers/openai_api.rs`
  - `providers/anthropic_api.rs` (if exists; else `claude_cli.rs`)
  - `providers/gemini_api.rs`
  - `providers/azure_openai.rs`
  - `providers/aws_bedrock.rs`
  - `providers/claude_cli.rs`
  - `providers/local_qwen.rs`
  - `providers/ouro/adapter.rs`

**Pattern (per call site):**
```rust
let breaker = self.breaker_registry.get_or_default(provider_id);
let _permit = breaker.try_acquire().map_err(|_| ProviderError::CircuitOpen)?;
match inner_complete(req).await {
    Ok(c) => { breaker.record_success(); Ok(c) }
    Err(e) => { breaker.record_failure(); Err(e) }
}
```

**Sub-task:** extract a helper `provider_call_with_breaker(breaker, fut)` to avoid duplicating the pattern at every call site. This overlaps with GR-15 (`provider_call_with_breaker_and_usage`) — combine them into one helper that does both. Move GR-15 out of v0.3 backlog into this v0.2.1 commit.

**Tests:**
- `breaker_opens_after_5_consecutive_failures_for_openai`
- `breaker_closes_on_success_after_half_open`
- `breaker_blocks_call_when_open`
- Per-provider: one test that drives the breaker through closed → half-open → open transitions.

**Commit template:**
```
fix(providers): GR-04 + GR-15 — wire circuit breaker into every provider

Closes F6 GR-04 + GR-15. providers/circuit_breaker.rs shipped with 12
unit tests but no Provider::complete or ::stream call site invoked
try_acquire / record_success / record_failure. The reliability claim
was vacuous until this commit.

Plus GR-15: record_now was duplicated across chat-sync, chat-stream,
council-hemisphere, MCP-loop paths. Extracted a shared
provider_call_with_breaker_and_usage() wrapper that does both the
breaker permit-and-record AND the usage-log emission.

All 8 provider adapters (openai_api / anthropic_api / gemini_api /
azure_openai / aws_bedrock / claude_cli / local_qwen / ouro/adapter)
now route through the wrapper.

Tests: 8 new tests cover breaker open/close/half-open transitions
per provider + 1 contract test pinning the wrapper signature.

Gates: fmt + clippy + workspace tests all green.
Refs: PLAN/HANDOFF_SESSION24_2026-05-25.md GR-04 + GR-15 + F6.
```

---

### GR-13 — Verify pre-v0.1 write_config + mlock  [XS verify, S fix if wrong]

**Files:**
- `SRC/neothd/src/cli/init.rs::write_config` (Day-3 impl)
- `SRC/neothd/src/config/mod.rs::FreedomConfig::deserialize` (mlock target)

**Verification steps:**
1. `Grep` for `OpenOptions::new().mode` in `cli/init.rs::write_config`. Confirm `.mode(0o600)` is called BEFORE `.open()` (no chmod-after-create race).
2. `Grep` for `libc::mlock` in `config/mod.rs` or related deserialize path. If absent → file as SX-* sub-task to add.

**If verification fails (chmod-after-create race or no mlock):**
- Fix `write_config` to use `OpenOptions::new().mode(0o600).create(true).truncate(true).write(true).open(path)?` (Unix; Windows DACL is a separate path).
- Add `libc::mlock(config.as_ptr() as _, mem::size_of::<FreedomConfig>())` on Linux after deserialize.

**Tests:**
- `write_config_sets_0o600_before_creating_file` (Unix)
- `freedom_config_pages_are_mlocked_on_linux` (Linux-only)

**Commit template:** depends on verification outcome. If clean → `docs(audit): GR-13 — confirmed write_config mode-before-open + Linux mlock`; if needs fix → `fix(config): GR-13 — close write_config TOCTOU + mlock FreedomConfig on Linux`.

---

### GR-01 + GR-02 — Operator picks (DO NOT pick for the operator)

These two need operator decisions. Do NOT implement either option.

**GR-01 WhatsApp `LIVE` label:**
- Option A: rename `LIVE` to `INBOUND-LIVE` in `cli/doctor.rs` + add tooltip "receive real, reply not wired" (XS, 1-2h).
- Option B: wire `webhook_listener.rs` handler through existing WhatsApp Graph API send helper so `pipeline produced outbound` stops being a drop (S, 1-3d).

**GR-02 channel-flapping doctor check:**
- Option A: rename `check_channel_flapping` → `check_provider_flapping` in `cli/doctor.rs` (XS).
- Option B: add `channel: Option<String>` field to `UsageEvent` in `telemetry/usage.rs` and evaluate true channel instability (S).

**Action for Session 24:** flag both to operator in chat with the option matrix above. Wait for pick before implementing.

---

### SX-06 — verify gate  [0.5d]

**Files:** none new; runs against the secured surface.

**Steps:**
1. `powershell.exe ... cargo-msvc.ps1 audit` → confirm clean (SX-04 enforces failure on CVE).
2. `powershell.exe ... cargo-msvc.ps1 deny check` → confirm Windows + Linux + macOS targets all walk (SX-05).
3. Run the SSRF SMOKE_TESTS.md script (write this as part of SX-07) — manual `curl` against `http://127.0.0.1:9744/api/health` via NEOTH's `web_fetch` should fail with `PrivateAddress` error.
4. `cargo test --workspace --all-targets` 2x consecutive — both green, no flakes.
5. `cargo fmt --check` + `cargo clippy --workspace --all-targets -- -D warnings`.

**Acceptance gate:** all 5 steps green. If any fail → stop, fix root cause, re-run.

---

### SX-07 — threat model doc  [1d]

**File:** new `docs/security/threat-model.md`.

**Required sections:**
1. **6 outbound surfaces NEOTH controls:** `web_fetch` (SX-01 SSRF-guarded), provider API calls (per-provider SDK, consent + autonomy gate), n8n localhost API outbound to provider (loopback-only), HuggingFace model downloads (HF-01 v0.9 consent gate when shipped), cluster gossip (`SL-01b` v0.9), Obsidian sync writes (local FS only).
2. **Consent gates at each surface:** which `AutonomyLevel` permits what.
3. **Audit trail coverage:** which WAL event fires for each outbound + how to verify with `neoth wal show --type ...`.
4. **Known limitations:** chrome-devtools-mcp telemetry (blocked pre-merge until env-var force lands), Windows DPAPI master-key disaster recovery (HIGH-02 covered in v1.0 SC-09).
5. **Reporting a vulnerability:** link to `SECURITY.md`.

---

### SX-08 — Tag v0.2.1 + push  [0.1d]

```bash
git tag v0.2.1 -m "security hotfix — SSRF block list + WAL .cpt HMAC auth + ChannelSend redaction + 3 more"
git push origin v0.2.1
gh release create v0.2.1 --notes-file docs/security/threat-model.md --title "v0.2.1 security hotfix"
```

---

## Final cleanup after all 21 items

When SX-* + ADV-* + GR-* all land:

1. **Verify v0.2.1 hotfix count = 0:** `grep -c "^- \[ \].*\*\*\(SX-\|ADV-\|GR-0\|GR-1\|GR-12\|GR-13\)" PLAN/PROGRESS_v1_0.md` (expect 0; the 2 operator-pick items GR-01/02 don't count since they're explicitly waiting on operator).
2. **Run final gates:** `cargo fmt --all --check` + `cargo test --workspace --all-targets` + `cargo clippy --workspace --all-targets -- -D warnings`.
3. **Tag v0.2.1**, push, release-notes via SX-07 doc.
4. **Write next handoff:** `PLAN/HANDOFF_SESSION25_2026-XX-XX.md` for v0.3 lane (78 items, the wizard expansion).

---

## Session-start checklist

```
[ ] Read PLAN/HANDOFF_SESSION24_2026-05-25.md (this file)
[ ] git pull --rebase origin main + verify HEAD = 951461a (or newer)
[ ] cargo test --workspace --all-targets → confirm 4240+ green
[ ] cargo clippy --workspace --all-targets -- -D warnings → 0
[ ] Pick SX-04 first (2h ship + CI ready for the rest of the lane)
[ ] Work serial: SX-04 → SX-05 → SX-01 → SX-02 → SX-03 → ADV-01 → ADV-02 → ADV-03 → ADV-11 → GR-12 → GR-04 → GR-13 → SX-06 → SX-07 → SX-08
[ ] Flag GR-01 + GR-02 to operator with option matrix; DO NOT pick
[ ] Same-turn PROGRESS flip on every commit
[ ] No `git stash` from background work
[ ] Don't spawn parallel agents on SX-* — they all touch security-critical surface
```

End-state target: `v0.2.1` tag pushed; PROGRESS_v1_0.md hotfix lane = 0 open items (GR-01/02 explicitly marked `[?]` awaiting operator); 4240+ tests + 0 clippy + fmt clean across all 21 commits.

---

## Critical recall items the next session will need

These memories will fire automatically per `[[name]]` resolution; flagged here for awareness:

- `[[neoth-windows-build]]` — cargo needs vcvars64 + System32 cmd wrapper; Git Bash PATH shadows MSVC link.exe.
- `[[neoth-claude-cli-tmux-mandatory]]` — claude --print subprocess broken, tmux warm session only working path (affects any provider call test).
- `[[neoth-features-default-on-runtime-toggle]]` — every new Cargo feature pairs with runtime toggle in freedom.yaml; the hotfix lane adds no new features but follow this for v0.3.
- `[[neoth-design-v11-is-norm]]` — `PLAN/00_DESIGN_v1.1_FINAL.md` + `SPEC_*.md` are authoritative; ignore older `*_v1.0_FINAL` despite the filename.
- `[[neoth-progress-md-update-rule]]` — every shipped item MUST flip `[ ]` → `[x]` in the same commit. Stale checkboxes cost time.
- `[[neoth-hard-rule-self-contained]]` — no external services, no Alex-specific deps; SX-01..03 + ADV-01..03 all respect this.

End of handoff.
