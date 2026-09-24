# W559 / W565 / W566 — Obsidian lifecycle and hosted follow-up

## W559 native Obsidian plugin lifecycle

`neoth obsidian bridge status|install|repair|uninstall --vault PATH` manages only
`.obsidian/plugins/neoth-archive-bridge`. The compiled payload embeds the real
manifest and JS bundle admitted from the W558 hosted build, not a placeholder.
The plugin remains a read-only inspector; pairing and sync are not implemented.

Installation publishes a complete private stage through an exclusive, source-
identity-bound rename. A fresh check of the requested namespace prevents a
successful result after its parent is replaced. Existing foreign slots are
preserved. Repair restores only the expected payloads in an authenticated slot;
settings and extensions remain intact. Uninstall binds each read leaf before
removing it, preserves additions with the ownership marker, and resumes after
already-removed payloads. It removes an empty slot using only an empty-directory
operation. Status propagates I/O and unsafe-path errors instead of hiding them.

Independent review approved the lifecycle and final CLI/race-test corrections.
The hosted selection adds 15 cases: 9 portable module cases, 4 Unix namespace/
leaf cases, and 2 actual CLI parse/dispatch cases. Universal native selection is
1226, with Windows25/Linux40/macOS39 extras; Group949 includes all 15 on Linux.
No local executable validation ran. Compilation, formatting and these behaviors
remain pending on GitHub. P2-21 remains open for pairing/sync, updates and full
clean-machine qualification.

## W565 admitted Group934 evidence

Run 35935802912 at `5a5b13ea957bb442bbfb5b7e1f840a66f1ada87e` executed all 934
selected cases: 930 passed, 4 failed, none missing. Root verified all three ZIP
digests, 184 source/input bindings and every actual terminal. All 29 Paperless
and 13 wizard IPC cases passed. Permanent selected terminals and bindings:
`docs/verification/gold-wave565-paperless-wizard-terminals.json`.

The four failures are tracked separately: the two default-account delivery
cases predate the published W561 fix; the parity inventory still named the
former direct Finish registration; W458 replay exhausted its frame budget.
No broader installer or wizard GUI criterion is closed by the 42 support cases.

## W566 replay cursor and parity correction

W458 now requests frames after each authenticated attach exchange's
`initial_sequence`. Its historical Accepted/lifecycle prefix is already present
in the BridgeSink metadata adopted by each controller. Capturing it again used
the bounded frame allowance before the real post-provider result arrived.
Both attachment grants still precede provider release. Provider/chunk counts,
Block/Replace hook evidence, secret exclusion, terminal checks and the capture
limit remain unchanged. Independent native-to-GUI consumer review approved.

The parity inventory now anchors the production
`register_wizard_finish_callback(&window, move |w|` body and still requires its
`finish(&state)` dispatch. Neither fix changes Slint files. Fresh W458 native
and W480 GUI terminals are required for P2-26a; P118 is independently assessed.
