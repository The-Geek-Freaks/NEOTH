# Gold Wave 42 — typed channel-health evidence

**Receipt status:** LOCAL VALIDATION COMPLETE.

This receipt records the three-file Wave 42 channel-health slice on
published Waves 39–40 `e4b4a117f258df401467b5c10c17e6ef1d266b2c`. It does not
claim a roadmap closure, a full-CI pass, or any change to outbound behavior.

## Admitted behavior

The reader accepts proactive health observations only from the authenticated,
typed v4/v5 evidence families already defined by the WAL. A v5 observation
requires its sealed `ChannelAccountBinding`, an incarnation, and the same exact
typed Telegram `ChannelRef` through Prepared, Armed, and Result. v1–v3 remain
reader-compatible but produce no account observation. A missing, stripped,
mismatched, duplicate, malformed, incomplete, or tampered relation contributes
no partial rate.

Live typed evidence stays separate by exact channel reference. In particular,
the authenticated home-WAL projection keeps `telegram/default` and
`slack/default` separate even when their textual `account_id` values are equal.
The provider error-rate diagnostic remains provider-only; transport diagnosis is
the existing typed channel/account check. The slice performs no routing,
recipient, credential, retry, probe, or outbound-delivery change.

## Source admission

The admission receipt is `work/gold-20260906/wave42-admission.json`; the final
source triplet below is frozen against the Wave 42 checkpoint:

- `daemon/channel_transport_evidence.rs` —
  `D03E60632A2E92479010708EA05E7A13AA05C90F55CA487CEDF532DB5EFAB26E`
- `daemon/proactive_egress.rs` — final source
  `C49EF55D9961F980A9D2C59F912BD752C05CFF9EA157160AC97B83BA35F2DFD2`
  after the local test-fixture `E0618` rename correction
- `cli/doctor/checks/providers.rs` —
  `DD5611C3C341A1F645229AC3C130567A093D391ADC01774072E5CDCB39826F70`

`work/gold-20260906/wave42-channel-health-proposed/CHECKPOINT.md` defines the
closed eligible-evidence grammars and `REVIEW.md` approves the proposal. Those
records are proposal/admission evidence; they are not gate receipts.

## Validation placeholders

Clippy02 **PASS** in 2m41s (221.51 GiB minimum free, 7.01 GiB peak). TestBuild01
**PASS** in 3m34s (217.27 GiB minimum free, 10.99 GiB peak). The four focused
filters for `daemon::channel_transport`, `proactive_egress`, `cli::doctor`, and
docgen passed **266 / 0 / 0** in 17.79s. The fresh unit executable SHA-256 is
`5EFA85E946A6B7026D4F1229992E92FB5B64BD315C6FAE5C32BFEB874768DF91`
(284,851,712 bytes) from the 14,531-test catalog.

The two contract targets **PASS** with **373 / 0 / 0**: `gui_channel_status`
contributed 353 outcomes and `proactive_egress_contract_source_gate` 20. Their
compile time was 2m17s with 220.74 GiB minimum free and 7.52 GiB peak use.
Python19+11+8 **PASS** in 1.130s/0.111s/0.002s.

No GUI source changed. A W42 GUI check is therefore not required; the retained
W39 GUI check is historical-only evidence. Clippy01 failed before the E0618
fixture correction and is not pass evidence.

`docs/verification/gold-wave42-source-manifest.json` and
`docs/verification/gold-wave42-test-matrix.json` are the public complete
receipts. They record 204 inputs, three binaries, the 14,531-test catalog, 266
unit outcomes, and 373 contract outcomes. The W39–40 full CI
[34857514849](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34857514849)
is still running; its [Preflight 34857493885](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34857493885)
and [CodeQL/quality 34857493659](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34857493659)
succeeded. This does not establish a W42 commit, push, or exact-head CI claim.

## Limits

P1-17 remains partial because supported provenance is limited to typed live
Telegram/Slack plus account-bound proactive Telegram. P1-14 and P1-16 remain
open. Roadmap counts remain **1324 total / 1012 done / 310 open / 2 partial**.
Wave 41 remains a proposal.
