# W503-W508 hosted regression repairs

Group890 run35920469488 at42d455ea7dfcebd9c6cbf3de160b495a66842c45
executed all890 selected cases:888PASS,2FAIL,0missing terminals. Root verified
all176 source/input bindings, selection/order, actual Rust test terminals and
the failure inventory. Both W500 real request-bound consent-proof cases pass.
Admission: work/gold-20260906/wave506-group890/ADMISSION.json.

W507 repairs the remaining CLI stream fixture failure. The real StreamFrames
carrier is authenticated and starts with CHAT_STREAM_CONTROL_PREFIX; decoding
the entire line as JSON failed at column1. The fixture now requires and removes
that prefix before decoding. Delta sequencing, redaction, content-free done
hash/count, receipt, Complete, no secret leakage and no recovery remain asserted.

W508 repairs the actual daemon schedule lifecycle. start removes the consumed
Preflight. schedule_turn then looked up that removed entry and returned before
opening the provider. The admitted message/model/skill inputs now live on Turn,
so scheduling consumes its accepted descriptor without depending on a consumed
preflight. The real producer/attach regression protects this behavior.

GUIc7 run35917420707 failed compilation before executing any GUI case. The
source, receipt and source-manifest bind c7b946f1; the main.rs source blob and
SHA256 match. Its log has exactly E0594x9 and E0631x2; started/executed/completed
lists are empty. W504 fixes two lines: the mutable WizardSnapshot fixture and
the by-value SharedString iterator closure. W477 independently reviewed W504,
W507 and the runtime repair. These source repairs require fresh hosted checks.

W503 imports the hosted formatter patch from Preflight35920437900 artifact
10777031344. Its2SHA256 entries and all3 complete before/after Gitblob pairs
were checked before import; W504's later main.rs change preserves that import.
Core42 and GUI42 were deliberately cancelled because their unchanged GUI code
would repeat the same known compiler errors; neither supplies acceptance.
CodeQuality42 passed. No local compiler or formatter ran.

The Windows storage lane now selects24 exact cases: the existing17 plus one
withheld-delete-share read and six real retention-v2 quarantine/receipt/restart
cases. This is required because the intervening Windows storage changes affect
absolute/verbatim roots, descendant DELETE sharing, private DACLs and native
relative publication. The old generic17PASS cannot establish those downstream
behaviors. P2-04 stays open until the seven fresh cases pass. The missing
Windows-only test is added to the inventory (Windows extras25).

No Slint, layout, theme, copy, focus controls or motion changed. Those design-lint
and visual-audit dimensions are N/A for these Rust fixture/type/lifecycle repairs;
source integrity was reviewed and actual GUI behavior remains pending. There
is no screenshot, accessibility, package or complete-release acceptance claim.
P1-18 and P2-26a remain open. The absolute local BSOD hold is unchanged.

W513 follow-up: Preflight8003 run35922289920 produced one formatting-only
main.rs hunk (artifact10777886345). Root confirmed postblob
0deec71a4c625535b08c5e262eb1e11ed3598b98; the receipt and complete before/after
pair were verified before import. Core/Group/GUI/Windows behavioral runs at
8003 remain relevant because this hunk only wraps the already-corrected closure.
The same Preflight's later static steps were skipped; a fresh Preflight is required.
