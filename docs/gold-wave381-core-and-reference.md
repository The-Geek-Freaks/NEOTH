# W381 — admitted core and exact browser CLI reference

GitHub run 35855695782 completed successfully on
21612331dbc4e1fc8929e6990775f165c86fb3f1. All four explicit steps passed:
production slim Clippy, core test-target typecheck, public CLI build, and
reference export. The source-head and artifact SHA were checked before import.

The generated reference adds only browser, browser install, and browser status.
SHA-256: B6D3EB5644BC388C96E1E1F1BEAB281DD88F648BE1B9BFA9173CCFCE3559412F.
The ordinary CLI-reference equality fixture remains selected in Group780.
Receipt: work/gold-20260906/wave377-publication/core216/ADMISSION.json.

Preflight216 run35855667194 passed. GUI135 run35856964423 and official BGE2
run35856967745 started on the same21612331 source after test-target success,
while the CLI binary was built. This import changes documentation only.
PLAN/BUILD_AND_RELEASE_CADENCE.md Evidence ladder permits unchanged relevant
binary/source evidence across unrelated documentation changes. Both behavior
lanes still require their own actual terminals and artifact admission.

macOS in FullCI954 run35850855062 executed17811tests:17797passed/14failed.
Ten failures match the repaired Group721 causes. Two additional browser
fixtures use an old uncanonicalized temporary root; current216 already fixes
both. W378 records that comparison. Two macOS GUI failures remain in W379
triage. Windows tests are still active; Linux failed on runner shutdown143.
This is not full-CI acceptance and closes no parent Road checkbox.

The workstation BSOD hold remains absolute. No local executable validation ran.
