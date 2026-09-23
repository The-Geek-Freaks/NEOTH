# W389 managed-browser CLI/GUI parity triage

## Trigger

Hosted Group780 reported that
`cli::parity_drift::every_cli_capability_is_triaged_for_gui_parity` had no
inventory row for the new `browser` CLI capability.

## Classification

`neoth browser status` and `neoth browser install` are explicitly `CliOnly`.
They inspect or install the reviewed managed-browser artifact. They do not
provide a GUI action, start a browser, open CDP, navigate, or establish browser
runtime readiness.

The CLI implementation states this boundary in
`SRC/neothd/src/cli/browser.rs`: its module contract prohibits launch/CDP/
navigation/runtime actions, `Status` reports artifact integrity only, and
`Install` never launches the installed browser. Its command is registered in
the live Clap tree in `SRC/neothd/src/cli/mod.rs`.

## Open gap

P2-13 remains open. A GUI/CDP/runtime workflow has not been implemented or
mapped here. This triage only records the current CLI-only managed-artifact
surface; it does not claim GUI parity.
