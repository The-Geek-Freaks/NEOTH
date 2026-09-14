# Gold Waves 30, 32 and 34 — SelfStage, account retirement, and legacy provenance

**Receipt status:** **LOCALLY VERIFIED.** The
repaired shared W30 production/fixture post-verification helper is independently
reviewed and admitted. It records intent before the private operation, retains
the prepared receipt and generation lease through the contained helper, and
publishes the visible pending stage only from that helper. The 41-source/49-path
scope is locally verified. Final Clippy13 **PASS** in 3.05s; TestBuild05 **PASS**
in 3m31s; fullSelected06 **1327 pass / 0 fail / 0 ignored** in 59.20s from
14,488 catalogued tests and 29 filters. The unit binary is 284684288 bytes, SHA-256
`F021798D7D7A4D38A0DDF72A7BB99718005CA849139FAC6357748F5A551422B3`.

All 13 account-config integration targets pass **157/0/0**. The GUI check
passes in 6m11s without a GUI link; its 13 existing `trusted_probe_supervisor`
warnings are unchanged, and this is not native GUI execution evidence. The three
Python suites pass 19, 11, and 8 tests. [Source manifest](verification/gold-wave30-34-source-manifest.json)
and [test matrix](verification/gold-wave30-34-test-matrix.json) record 188
source inputs and 14 executables.

The final standalone contract-only delta is
`SRC/neothd/tests/proactive_egress_contract_source_gate.rs`, SHA-256
`8A263D92A6A73B6447BB30D3E2576A22E5636B36CB7E850FABA8A3EAE38EEA8C`.
It proves exact v5/v4/unbound guards and whitespace-independent recovery
source matching. Strict Clippy and all 13 contract targets reran after it;
unit, library, and GUI production inputs were unchanged, so this receipt does
not claim a rebuilt unit binary for that test-only delta.

Focused regressions cover the repaired supplied-config preservation, mapped
historical `incarnation: None` compatibility, retirement/re-add isolation,
owned helper invalidation, no-append recovery checkpoints, and proactive
suppression boundaries. The final proactive source SHA-256 is
`508FBB4F483435C0AE87EB0E969226BAA5297E660381D24D8BDC8CAB56C7A437`.

Publication identity will be the Git commit containing this receipt. No
current-head full-CI, native-GUI, live-provider, or all-Gold claim is made.

W29 Preflight `34803231833` and Code Quality `34803231157` passed. W29–31 full
CI `34803269509` completed failed: Linux, Windows, and other independent jobs
pass, while macOS failed
`updater_cron::generation_cancelled_loopback_leaf_joins_before_lane_replacement`.
TCP EOF had already confirmed HTTP cancellation; the subsequent test-only
one-second durable-drain wait expired. The macOS compile/test step also reached
its 90-minute limit before suite completion. Neither result validates this source.

## W30 — owned SelfStage staging boundary

The admitted foundation models the owned outer/helper lifecycle and ordered
receipts. SelfStage remains opt-in verified staging only. The production path
and fixture now use the same post-verification helper. Local runtime tests prove
the contained helper's ordered receipts, cancellation, and recovery boundaries.
Native packaged updater journeys remain outside this receipt.

`neoth update --self --apply` remains the manual binary-swap path. Recurring
self checks and verified staging require their existing operator opt-ins.
Recurring external CLI, npm, Git, OSV, installer, and Skill effects remain
denied. R3-18B remains open for its other required runtime and containment work.

## W32 — mapped-account retirement and re-add

The admitted command is:

```powershell
neoth channel account remove telegram --account <account-id>
```

It retires exactly the selected mapped account. A later same-name re-add gets a
fresh internal UUID, preventing prior leases, pairing state, and v5 work from
authorizing the replacement. Historical records without a UUID stay compatible
only against exact current historical state and are never silently relabelled.
P1-16 remains open.

## W34 — legacy live transport provenance

W34 covers only legacy Telegram and Slack factories. Mapped Telegram remains a
separate path. This does not establish general channel provenance or close
P1-17.

## Limits

No checkbox or count changes are made. Counts remain 1,324 total / 1,011
complete / 311 open / 2 partial (313 raw; 312 pre-tag blockers). This receipt
does not claim native packaged GUI execution, live external provider delivery,
cross-platform acceptance, or current-head full CI.
