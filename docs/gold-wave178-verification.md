# W178 — Windows integration failures and precise repairs

The completed Windows job106526765041 in CI35658155763 on cc0af938 compiled
successfully and then executed 13,607 tests: 13,587 passed and 20 failed. The
remaining 3,542 of 17,149 were not run after fail-fast. This was an assertion
failure run, not a timeout. JUnit artifact SHA-256 matches GitHub's digest:
6146F639EC672402A2EFD765BA4DF6EC7345B67173A87C36C075C6D2DAEF58B9.

The current repair covers all 20 reported identities, retaining their behavioral
requirements. Three reasoning fixtures now verify and remove only the exact
additional terminal throughput typed/wire pair before asserting their original
reasoning sequence, state, counters, control token and WAL result. The throughput
producer fixture requires four ordered typed/wire pairs. The zero-sequence
fixture expects the existing shared sequence_zero error; zero is still refused.

The installed-agent fixture now persists its accepted configuration in the same
home read by the actual loader. The loop fixture derives its WAL segment using
the canonical child naming helper. The parallel-child fixture seeds the required
home-bound HMAC key before constructing its session. None weakens the production
installed-skill, parent/child scope or WAL ownership gates.

Two provider inventories now include the reviewed typed event-stream path.
Babel still samples only visible successful responses after terminal settlement
and excludes incognito and reasoning content. Transport construction remains
inside three authorized paths plus three inline test compatibility paths.
The raw-callsite inventory had already been updated after the failed older run;
its existing newer digest is retained and still requires Hosted confirmation.

Windows citation directories now use a sibling of the existing NT capability-
relative file primitive. New directories receive a protected inheritable current-
user DACL atomically. Existing directories are opened without DACL mutation and
must already pass the same handle/owner/no-reparse/private checks. The verified
handle becomes the retained directory capability without a reopen gap.

The native private-create helper preserves typed AlreadyExists only for the
actual CreateDirectoryW collision. Cache code can therefore reopen an existing
cache through its original collision branch and mandatory private-directory
verification. Cache hit and offline return remain before authorizer construction,
GUI preflight or proof consumption. No citation HTTP behavior is relaxed.
Two new Windows regression tests cover typed collision and rejection of an
existing unsafe consent directory without changing its DACL.

The first citation repair is retained as rejected evidence: its raw-code check
could not recover an error wrapped as text, and its unconditional DACL setter
would have repaired existing unsafe directories. Receipt02 records the correction.

Independent source approval:
- W178-INDEPENDENT-REVIEW-01.md: B6A89DCBAAE9BA10A8176A06BA7E8FD25672F065083C6A87EAE77DBF3152FC0B.
- PROVIDER-REVIEW.md: 169DA1149CB0B1661AB0B2611AD0D719E1E8F6287C724489CF566332DAE87364.
- CITATION-REPAIR-02.md: B6BC9F5E7A340C09DC47A4C0602CC0E38B23045E403D16471CF2178EEF159D9A.

Reports and exact failed-test metadata are in work/gold-20260906 under
wave178-hosted-repair and wave177-windows-ci-diagnosis. The canonical matrix
retains all 20 affected identities, adds the two missing provider inventories
and the two Windows-specific regressions. All current source behavior and
platform compilation/format/Clippy gates still require GitHub-hosted execution.
No local compiler, parser, formatter, tests, fixtures or product ran. No Road
checkbox closes on this source review or on the older partial test result.

W178 Code Quality 35667204404 passed on 4da66bdf. The exact four Hosted
formatting hunks from Preflight 35667205647 are imported in two Windows citation
source files. W175 CLI/reference 35666823374 passed on 405c9de6; the generated
232,129-byte reference includes --hippocampus and is imported byte-for-byte.
Its Preflight 35666822254 and Code Quality 35666822323 also passed. W175/W178
behavior remains pending and W177 implementation remains unadmitted.
Format receipt SHA-256: 8F61ABF79A6D226587127FCCD6181994FE3D3C27AF53DFB7504F96C1055E80F7.
