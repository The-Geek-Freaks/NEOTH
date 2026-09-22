# W185 final assembled source review

**Reviewed frozen set:** `FROZEN-SOURCES.json`, captured `2026-09-22T02:22:29Z`, base `a130526e8a4c2d1a13b4435805a55951ede070d9`.

All 15 listed inputs were re-hashed before review and exactly match their
recorded SHA-256 values. This finding set applies only to those bytes. It is
not an executable, rendered-GUI, audio/device, or GitHub-gate approval.

The final admission-only correction removed a trailing whitespace character at
the IPC EOF and normalized staged text/JSON to LF. The freeze was regenerated
after that mechanical normalization; the 14 other source entries retain their
prior hashes and the reviewed IPC source now hashes
`496318E3A6006C4668B7DD5D06DEDE3873B0C0EDAE09B8910612EF67782B984D`.

## Verdict: source review passed; Hosted gates pending

The two prior blockers are repaired in this frozen set.

- **W185-FINAL-01 repaired.** `models ollama` now accepts a scoped `--config
  PATH`, and `ollama_ipc_home` derives exactly the same parent instance home as
  `serve --config`. The no-override route retains `NEOTH_HOME`-aware default
  selection. The parser/regression covers a whitespace-containing configured
  parent and the bare relative `freedom.yaml` case. Documentation makes the
  GUI's inherited `NEOTH_HOME` selection explicit.
- **W185-FINAL-02 repaired.** The Linux/Android peer-credential code documents
  the live Unix FD, writable `ucred`/length storage, and the successful
  exact-length check before `assume_init`; BSD-family code documents its valid
  out-pointers and pointer-free `geteuid` use. Failed credential calls remain
  fail-closed.

## Source findings that were checked

- Core serializes refresh/mutation admission with an owned semaphore, parks a
  worker before critical intent persistence, holds the state lock through that
  persistence, and retains the join handle through terminal reconciliation.
  The frozen tests include real blocked-pull cancel/shutdown and blocked
  terminal-reconciliation scenarios.
- The post-inference probe re-reads tags and `ps`, returns a matching fresh
  `LoadedModelUse`, and the core replaces the row's loaded data only on digest
  match. Restart clears earlier Ready/loaded observations.
- IPC has bounded request/response framing, no TCP fallback, token plus
  OS-private endpoint discovery, a bounded `JoinSet`, and a native
  bind/discover/status/start/cancel/drain fixture. Same-user peer credential
  admission is explicitly documented and fail-closed.
- GUI status DTOs are deny-unknown-field typed; each action checks a typed ACK,
  exact operation binding, and a separate status readback no older than the
  ACK snapshot. Retry is restricted to a retained `Failed` receipt and cancel
  is bound to the selected active operation id. The Slint source uses the
  existing Theme token surface and exposes disabled/working/error states.

## Required unexecuted evidence ceiling

No local executable validation was run under the BSOD hold. Require exact-head
GitHub compilation/format/Clippy plus the registered core, CLI, IPC, GUI, and
macOS fixture-discovery tests. Rendered keyboard, responsive, contrast, and
native GUI behavior evidence remains separate from this source review.
