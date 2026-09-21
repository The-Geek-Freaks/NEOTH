# W155 - explicit claim and DOI citation lookup

This admission contains the Core, private consent protocol, HTTP transport and
CLI for `GOLD-LF-P1-12`. It awaits hosted compilation and native tests. The GUI
source is prepared separately and remains unpublished while child-process
deadline, output-cap and cancellation handling are completed. The Road item
stays open until all required checks cover the integrated source. All executable
validation runs on GitHub.

## User-visible behavior

The CLI and prepared Chat citation panel accept an explicit claim and DOI. The GUI
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

The unpublished GUI callback fixture drives the real registrations and selected fake child:
offline miss, found/detail, stale completion, history invalidation, Approve,
duplicate decision, Deny without final lookup, mismatched preflight, and Ready
without proof stdin. Its independent review identified unbounded process output
and wait time; the owner is repairing that concrete lifecycle gap before GUI
admission. These source assertions do not constitute hosted execution evidence.

## Evidence and remaining gates

Independent review records and the exact test inventory are retained under
`work/gold-20260906/wave155-citation-map`. The canonical source manifest and
test matrix bind the admitted files and their required JUnit identities. The
core/consent/HTTP/CLI inventory contains 49 cases, including two Unix-only
filesystem cases; GUI requirements are recorded separately.

Required next evidence: hosted format/static gates, core/CLI-reference build,
full native and GUI tests including macOS callback discovery, and applicable
portable acceptance. Generated CLI documentation must come from the admitted
binary. Earlier CI/preview runs do not validate this Citation implementation.

## First hosted compilation and repairs

W155 source da2a5582 passed Code Quality35624480765. Preflight35624481124
reported 119 exact Rustfmt hunks in eight Citation files; those hosted layouts
are now imported. Reference build35624482185 found six Rust compiler errors:
missing Context imports, TryLockError variants, a policy-reference argument,
an Option mapping signature and the required geteuid unsafe block. The narrow
repairs are reviewed separately and await a fresh hosted build. The 334-input
manifest and all required test hashes bind the repaired source. No executable
validation ran locally and no Road checkbox closes.
