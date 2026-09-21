# W158 - native hosted failure recovery

This batch remains under repair. No Road item closes from these source changes.
All executable verification uses GitHub-hosted runners; the workstation performs
only bounded source, metadata, artifact and Git work.

## Observed execution

Both jobs below ran source `ff146652e6ef230bd500206978f183e5040644d6` in CI
`35604563909`. Their results do not validate later W153 or W155 code.

| Runner | Job | Executed | Passed | Failed | Skipped |
| --- | --- | ---: | ---: | ---: | ---: |
| Windows | 106348405161 | 16938 | 16926 (one leaky) | 12 | 22 |
| macOS | 106348405393 | 17003 | 16990 | 13 | 23 |

Windows full log SHA-256:
`64FFA3CCBD22ADC4F958C935B94A26424F0EDD8CBDD4791DE964F872C1D94D7A`.
Windows JUnit SHA-256:
`846CCC176111A7CEB991141AF49F2FA4ADF47B065D11C5F6F9101276E19A9CEA`.
macOS full log SHA-256:
`41E5D5FA5E94E1475BFE1BC9B98600CB4FC52392175FFF632AAFDA008EB49662`.
macOS JUnit SHA-256:
`6FC1AC59959F01E488905944F27442C7008ACC37C6280BB8F7F26613B7067101`.

## Required repairs

Five self-improve failures exercise approval receipt precedence, current quality
evidence, approval payload CAS, home-root freshness, and repeat-accept idempotency.
The source repair preserves current quality, audited approval and final CAS.

The retained MCP-scope fixture needs one provider turn for each comparison run;
its real uncapped transport baseline and capped no-second-transport assertion
remain required. The delegated channel fixture must retain automatic Skill
selection, actual TOML agent loading and the original scope assertions. A global
registry ownership mismatch is a separate candidate source defect; it has not
established the cause of the isolated Nextest failure.

The proactive source contracts must distinguish the connection-bound registry
proxy from the sole direct transport seam. All thirteen route arms still require
the durable dispatcher choke point. The GUI contract must require the real
SelfImproveAcceptAck, selected evidence argument, verified receipt and fresh
readback.

macOS also timed out in the W142 Self-Improve refresh callback fixture. The
callback counter and stale-revision guard already existed at ff146652. They
are not a later fix. The log does not identify which terminal condition failed;
a failure-only snapshot is now added, and a fresh hosted run is needed before declaring a cause
or repair. Deadlines and behavioral assertions must remain intact.

Detailed local evidence is retained in work/gold-20260906/wave158-windows-native
and wave158-macos-native. The canonical manifest and test matrix bind four reviewed repair families and
the W142 diagnostic. W137 remains unresolved; Citation work is a separate batch.
