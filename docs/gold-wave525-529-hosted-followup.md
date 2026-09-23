# W525-W529 hosted Chat and Paperless follow-up

Group8906b (35924883048, source 6b8f86a87763bd43f9bb3e529a82c83ee5561f31)
is admitted as 888 PASS, 2 FAIL, zero missing terminals, with 176 source/input
bindings. The failures are not accepted behavior.

W526 corrects the CLI stream regression's expected behavior after an accepted
PostProviderCall replacement. Production clears native termination metadata;
the fixture now requires refused=false and absent finish/refusal fields, and
requires no native refusal observation. The separate positive native refusal
path and all stream-content, hash, receipt and recovery checks remain strict.

W525 retains W458's real preflight/consent/decide/start/attach/producer path and
its exactly-one-provider and three-chunk assertions. Because the preceding
run terminated before the provider opened, test support now records only an
allowlisted failure-stage category and terminal labels/frame counts. It never
prints an error chain, prompt, secret or arbitrary provider/model value. This
is diagnostic instrumentation, not a causal runtime repair or a passing test.

Core35926460874 and GUI35926464147 at8945aad13d582618bb3b16add651a2a9591758d6
both failed on the unresolved crate::config::Credentials import. W527/W528 use
the actual config::credentials::Credentials module in production and three
test references. GUI148 had zero executed fixtures; its source bindings alone
are not acceptance. Prior GUI35924886082 was cancelled, also with zero execution.
Quality35926398704 completed successfully for its two CodeQL language jobs.

Preflight35926398281 failed formatting. Artifact10778877634's SHA-256 receipt,
source HEAD, and complete before/after Git blobs were verified for all four
paths before the exact hosted patch was imported. The credential correction
was then applied on top. No local formatter ran. Static independent review
approved W525, W526 and W527/W528; fresh hosted behavior remains pending.

W515's published source manifest actually contained754 paths; the preceding
PLAN note's751 count is corrected. This follow-up has755 paths,1198 universal
native tests, platform extras25Windows/33Linux/32macOS, Group903 and GUI148Linux/
144macOS. Road1044checked/278open/2partial and WS-LF37done/81open are unchanged.
P1-18, P2-26a and P2-20 remain open. CLI export remains pending after the failed
Core run. No local executable checks, Slint edits or release claims.
