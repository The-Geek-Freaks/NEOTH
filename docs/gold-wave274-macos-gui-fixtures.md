# Wave 274 macOS GUI fixture contract

The macOS-native GUI harness continues to dispatch the W153 and W164 fixture identities. On macOS, those fixtures exercise the unchanged legacy-child request and require the explicit `NEOTH_GUI_CONTAINMENT_UNAVAILABLE` result: no staged child start, no staged-child invocation, no provider launch, and no successful repaint. This is a fail-closed platform refusal test, not macOS GUI or provider acceptance. Linux retains the existing real legacy-child success coverage.

W155 waits for the approved final lookup's private-proof witness: one proof-bearing `citation lookup` call and the fixed fixture's `lookup-stdin` content. The ready path remains a negative assertion that no private-proof stdin file exists. A bounded timeout diagnostic records the fixture's command-call evidence only; the fixed `proof-test` value is test data and no production credential is logged.
