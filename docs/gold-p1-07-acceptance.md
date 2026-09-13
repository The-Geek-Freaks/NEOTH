# P1-07 — external-family grader gate

Accepted 2026-09-13 against the existing implementation at `1f2860cdf1becbd2b827720ed7ae1bc53476d875`.
No production code change was needed; the open roadmap status lagged the source.

`recall/goldset.rs` persists a closed provider/family roster, validates the family
against its provider, rejects duplicate grader IDs or provider/model entries and
requires both the shared and independent families. Unvalidated family text cannot
assert independence: that property derives from the validated provider enum.

`recall/parity_run.rs` rejects missing, duplicate, unknown or spoofed observations,
requires the complete matrix for every configured grader, derives participating
metadata from that validated roster and includes external-family participation in
the final `verdict.passed` condition. The gate cannot pass with only the shared
family or by omitting the configured external grader's observations.

The fresh Wave 7 library binary passed **21 goldset and 15 parity-run tests**,
zero failures. These include every provider/family mismatch, mixed rosters,
missing/unknown tags, duplicate identities, incomplete matrices and spoofed IDs.
Exact source and executable hashes plus filter results are in
`verification/gold-p1-07-acceptance.json`.

This closes P1-07's configuration and deterministic scoring gate. It does not
prove live network provider identity, transcript producer provenance, four-grader
execution or the complete P1-08 attested release workflow. Those remain separate
acceptance requirements in the recall-parity specification and provenance ADR.
