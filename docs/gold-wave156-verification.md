# W156 - hosted GUI compile recovery

Full CI35602100258 compiled source c34bce29d4d514e7306a8f602c9fac3224347cd6.
The Linux quality job106340395933 stopped at E0282/E0283 in the shared
Buddy/Self-improve parser and unused Ouro re-exports in a headless test
inclusion. The beta job106340396175 independently found the same parser error,
three production GUI callback registrations passing MainWindow by value where
references were required, and the W130 fixture still using a Cell-style get()
after its observation state became Arc<Mutex<Option<bool>>>.

The focused repair changes exactly three source files:

- panel_logic.rs constrains three existing validated projections to
  Result<String, String>. It retains every digest validation and nullable-field
  rule.
- gui_action.rs keeps the Ouro product re-exports and gives only that re-export
  a reasoned unused-import allowance for headless inclusions omitting ouro_gui.
- main.rs borrows the existing MainWindow for three registrations, reads the
  W130 observation through its mutex while preserving the Some(false)
  assertion, and removes one unused test-module import. The production
  readback validator remains present and called.

The main.rs repair was staged from the exact c34bce29 blob plus these five
changes. Concurrent W153 reasoning work in the working source is excluded.
No source implementation or acceptance from W153 is claimed by this batch.

Both known-uncompilable runs were confirmed completed/cancelled: CI35602100258
and preview35602103625. Earlier successful component jobs prove only their
own scopes. There is no complete native suite or portable lifecycle result
for this source. Fresh hosted format, strict lint, compilation, native tests
and preview acceptance remain required; no Road checkbox closes.

Evidence hashes:

- complete Linux job log: DA1C05543AEB982B7DCBBBFFEA051003F6991EA029E2FDA50CE4D9DCC3D603A2
- complete beta job log: 51A3F0AC36283BA5DA2F3F3350C476A7218CA33BDE32AB08960B658F97153EA1

All executable validation remains GitHub-hosted under the workstation
stability restriction. Local activity was limited to source/log text,
metadata, hashing and scoped Git/GitHub operations.
