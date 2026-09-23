# W421 — W404 citation terminal matcher repair

## Trigger and finding

Hosted W404 run `35871580933` reached native identity 41,
`citation_cli_contract::gui_decide_rejects_oversized_private_stdin_before_consent_mutation`.
Rust recorded one passing test and an exit code of zero, but the acceptance runner
recorded it as failed. Its old matcher accepted only the single-line form:
`test NAME ... ok`.

The real harness wrote expected child-process stderr and a backtrace after
`test NAME ... Error: ...`, then printed a standalone final `ok`, followed by
`test result: ok. 1 passed; 0 failed; ...`. This was a runner parsing defect,
not a product failure. The historical result remains 41 Rust passes, with the
lane aggregate failed and the remaining nine selected identities unstarted.

## Repair

`packaging/tests/citation_acceptance.py` now accepts exactly one selected test
header followed by diagnostic lines and one final standalone `ok`. It still
requires the runner exit code to be zero, no runner timeout, and exactly one
`1 passed; 0 failed` summary. The ordinary one-line terminal remains accepted.

It rejects a failed terminal, a wrong selected identity, zero tests, and
multiple selected headers. The native discovery gate is unchanged and still
requires exactly one discovered identity before execution.

The workflow runs the script's seven-case `self-test` mode immediately after
checkout and before Rust setup or Cargo work. That hosted step covers the
ordinary pass, stderr-interleaved pass, failed terminal including a spurious later `ok`, wrong identity,
duplicate-selected-header, and zero-test rejection cases without compiling the product.

## Required next evidence

A new main-only W404 dispatch must produce a source-bound native receipt. It
may accept identity 41 only if the new matcher observes its actual final `ok`
and its sole passing summary. It must retain the existing discovery, selected
identity, source-binding, timeout, failure, and unstarted accounting rules.
No production citation source, selection, or provider probe behavior changed.

## Boundary

This repair was prepared by text inspection only. No local Python execution,
Cargo operation, compiler, formatter, test, GUI, runtime, browser, or network
operation was run.
