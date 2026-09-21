# W155 - explicit claim and DOI citation lookup

This admission contains Core, private consent protocol, HTTP, CLI and the real
Chat citation panel for GOLD-LF-P1-12. Independent source review approved its
claim/consent boundaries and repaired child-process lifecycle. Hosted compilation,
native callback execution, rendering and provider acceptance remain required;
no Road item is closed. All executable validation runs on GitHub.

## User-visible behavior

The CLI and Chat citation panel accept an explicit claim and DOI. The GUI
selects one provider and defaults to offline lookup. The CLI can select that
same provider or use the bounded sequential order Crossref, OpenAlex, Semantic
Scholar when `--provider` is omitted. A validated result produces a claim-bound citation chip and an in-app
detail card. Model Markdown and arbitrary URLs cannot initiate lookup or
navigation. Switching conversation/history or replacing a request invalidates
the old result, its open detail and any pending consent projection.

The private cache is consulted before authorization or HTTP. A cache hit is
rebound to the current claim. Offline misses perform no egress or HTTP audit.
Cache read/write problems remain visible without treating an unvalidated
provider response as a result.

## Live lookup and operator consent

Live calls use fixed provider GET endpoints, bounded responses, provider-specific
serialization and bounded cooldowns. Redirects are not followed. Provider
records must match the selected provider and canonical DOI before they can enter
the cache or a display binding. Timeout, rate limiting, missing records, denial
and unavailable providers have distinct typed outcomes.

A GUI live miss first runs a cache-first preflight. A current Allow can continue
without a proof, but the final HTTP seam re-reads policy and fails closed if it
now requires confirmation or denies the action. This Ready path explicitly
replaces inherited TTY confirmation with `FailClosed`.

A confirmation challenge requires an explicit Approve or Deny. Challenges and
one-use proofs bind provider/query, normalized claim, GUI request/revision,
configuration generation and expiry. Private no-follow records and locks retain
the selected home and filesystem identity. Tokens travel through bounded private
stdin and zeroizing memory, never argv or Slint properties. The final check binds
the actual method, URL, provider surface and empty body before the normal
permission and HTTP intent/result audit. A later Deny remains decisive.

The GUI callback fixture drives the real registrations and selected fake child:
offline miss, found/detail, stale completion, history invalidation, Approve,
duplicate decision, Deny without final lookup, mismatched preflight, and Ready
without proof stdin. The repaired direct-child runner enforces a 10-second
deadline, parallel 512-KiB stdout / 32-KiB stderr limits, cancellation leases and
kill/reap. Replacement and both history transitions cancel prior work. Capture
buffers and private stdin are zeroized on success/error/discard. The fixture also
covers hung-child replacement/history cancellation, output flood and recovery.
This establishes source coverage only; descendant-tree containment, app shutdown,
rendering and actual runtime success are not claimed.

## Evidence and remaining gates

Independent review records and the exact test inventory are retained under
`work/gold-20260906/wave155-citation-map`. The canonical source manifest and
test matrix bind the admitted files and their required JUnit identities. The
core/consent/HTTP/CLI inventory contains 49 cases, including two Unix-only
filesystem cases; GUI requirements are recorded separately.

Required next evidence: integrated hosted format/static gates,
full native and GUI tests including macOS callback discovery, and applicable
portable acceptance. Generated CLI documentation must come from the admitted
binary. Earlier CI/preview runs do not validate this Citation implementation.

## First hosted compilation and repairs

W155 source da2a5582 passed Code Quality35624480765. Preflight35624481124
reported 119 exact Rustfmt hunks in eight Citation files; those hosted layouts
are now imported. Reference build35624482185 found six Rust compiler errors:
missing Context imports, TryLockError variants, a policy-reference argument,
an Option mapping signature and the required geteuid unsafe block. The narrow
repairs passed hosted core/reference35626050057 on 2f3ceab5. The initial 334-input
manifest and all required test hashes bind the repaired source. No executable
validation ran locally and no Road checkbox closes.

## Integrated GUI admission

10 pure GUI cases and one Linux/macOS callback join the canonical test matrix.
The exact native macOS harness catalog/discovery contract now lists 17 names.
Final GUI review: GUI-REREVIEW.md (451649CF417DAC401D95361558C643F592EE66B7E826F285124D2EFF049F5BB2).
Core repair 2f3ceab5 passed reference run35626050057; its Preflight35626050807
requested two final hosted layout/newline corrections, imported without local execution.

The generated CLI reference was imported from that successful run after source-head
and SHA-256 checks: 3E3ADE1EC9283383A49582AAA91B31E6138ED0482E83367758FF3632226874D7.
GUI source c34603c0 passed Code Quality35626612606. Its Preflight35626613666
supplied 59 exact Rustfmt hunks in citation_gui.rs/main.rs; all are imported.
These format and core-build results do not establish native GUI test success.

## Hosted strict-lint and shared-test follow-up

Full CI35627170807 on7c6f1684 passed nine component jobs but exposed nine strict
Citation Clippy errors and three shared-library test compilation errors; that
failed-source run is confirmed cancelled. The narrow repair boxes large enum
payloads, groups existing request/liveness arguments without changing their
checks, removes unused/redundant code and repairs cache-free test values plus a
shadowed test helper. The serialized record/consent contract is preserved.
New hosted compilation, strict lint and native/GUI execution remain required.
The exact failure logs, repair mapping and independent review are retained as
7c6-linux-quality.log, 7c6-adapters.log, CLIPPY-HOSTED-REPAIR.md and
CLIPPY-HOSTED-REVIEW.md. The successful2f3 core/reference build remains historical
proof for that version; it does not validate these newer representation changes.
