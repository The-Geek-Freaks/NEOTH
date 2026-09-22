# W240 — Hosted GUI runtime fixture follow-up

This note records the active hosted evidence only. It is not a GUI acceptance
claim and does not turn source inspection into runtime proof.

## Evidence boundary

The authoritative fixture batch is hosted run `35795046176`, retained as
`work/gold-20260906/wave234-native-gui/gui116-480`, against source commit
`480ff458`. It executed all 116 selected GUI fixtures: 113 passed and W153,
W164, and W168 failed. The preserved source commit is `50fe1b18`; an already
GUI123 run (`35798455505`) is separately source-bound below; it stopped at
compilation and supplies no fixture-execution evidence.

## Admitted observations

- W142 and W184 retain their exact receipt and fresh-readback assertions. Their
  visible toast counts are bounded by the production three-slot FIFO: the
  asserted visible counts are two `Accepted` toasts for W142 and one `Vault
  mirror verified` toast for W184.
- W153 and W164 both time out with `child did not write a stage marker`. The
  previous staged fake wrote its first marker only after it had consumed the
  launch envelope, so that run cannot distinguish a failed child spawn from a
  child waiting for envelope delivery. The fixture now writes `shell-entry`
  before its stdin read and prints a bounded visible status plus up to three
  bounded rendered failure rows on timeout. That is diagnostic coverage only;
  it does not change the containment or launch path.
- The Linux supervisor requires a trusted `systemd-run --user` transient
  notify service, a verified unit and the private cgroup/PID/mount/user
  namespace guardian before the fake provider can execute. The GUI116 workflow
  installs Xvfb dependencies but contains no user-manager/session-bus
  provisioning or required-containment flag. This is a contract-supported
  launch-boundary hypothesis, not proof of the exact hosted failure. A future
  Linux fixture lane must provide the supervisor's actual manager capability
  and make `NEOTH_GUI_REQUIRE_SYSTEMD_CONTAINMENT_TESTS=1` fatal; it must not
  bypass containment for the fixture.
- W168 times out waiting for `W153 W168 Main live throughput`. The fixture's
  own `Measuring { VisibleEvent, 12.5 }` state is rendered as `Stream events:
  12.5/s`, while its predicate required `Stream events: live rate`. The source
  now asserts that typed rendered value and uses a separate release ticket for
  Main and Buddy, so each visible live state is observed before its terminal
  event. This is a source repair awaiting hosted proof; GUI116 remains the
  evidence boundary for the original failure.

## Validation boundary

The local BSOD hold remains in force. This wave used static text, Git, and
hosted-artifact inspection only; it did not run Cargo, Rustfmt, Rust tests, a
GUI, a shell fixture, or a Rust parser locally. Any source change requires
fresh hosted runtime evidence before these remaining fixtures can be called
repaired.

## W233 compile follow-up on source50fe

GUI123 run35798455505 stopped before fixture discovery: Slint reported
`Unknown element NeothLineEdit` in buddyconfig.slint. The TaskDelegate field
used the existing component without importing it. The import now names the
existing NeothLineEdit export; its documented text/placeholder/enabled and
accepted/edited API is unchanged. No GUI execution is claimed for that run.

Applicable design evidence: PRODUCT.md, DESIGN.md and COMPONENT_API.md were
read. The change is import-only, with no new visual values, motion or copy;
source token/theme integrity is preserved. Render, keyboard/accessibility and
native runtime checks remain pending under AUDIT_CHECKLIST.md; no screenshot
or gate-now result is inferred from this source correction.
