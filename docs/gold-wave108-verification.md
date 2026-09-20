# W108/W109 — Matrix state-store parity and compile recovery

This bounded R4-07 slice exposes the existing `matrix_store_path` credential
setting through the typed `channel add matrix --matrix-store-path` command and
the Matrix setup form. It uses the existing channel configuration transaction
and private stdin envelope. It does not change Matrix transport authorization,
E2EE handling, probe semantics or the runtime store implementation.

## Behavior

- An explicit nonblank path selects the crypto/session store. Outer whitespace
  is trimmed consistently with the existing plain channel fields.
- An omitted or blank path preserves an already configured custom store during
  credential reconfiguration. An initially unset path retains the runtime default
  beneath the selected NEOTH home.
- The GUI passes the optional public path alongside its existing credential
  fields through the same private stdin operation. The six secret-field mask
  slots and the Matrix plaintext policy retain their separate meanings.
- Explicit channel removal clears the path. A configuration containing only a
  Matrix store path counts as an actual removal; it cannot be mutated while
  reporting that nothing was removed.
- Choosing a path is configuration only. It does not copy, migrate or delete an
  encrypted store directory or create a new Matrix session by itself.

## Observed compile repairs

W107 full CI `35532960640` on `3922ee4b` passed nine component jobs, then
reported two undefined Slint theme properties and two MCP fixture ownership
errors. Both that CI run and preview `35532961776` are confirmed cancelled.
W109 uses the existing canonical `Theme.surface-2` and `Theme.space-1` tokens
for the readiness panel, clones the database path before its later child
spawner use, and moves the authority-rejection label into its async future.
No production authority policy or test assertion is relaxed.

The Matrix regressions cover typed flags, strict channel-scoped stdin fields,
new/existing/blank store staging, store-only removal, unchanged secret slots,
and the real private request plus subprocess argv. Source review follows the
Slint callback forwarding; the request test is not a native callback test.

## Evidence boundary

Source review and remote validation are separate. The W107 full CI
`35532960640` and preview `35532961776` run the preceding `3922ee4b` source;
they cannot establish W108's new CLI/GUI behavior. W108 needs its own exact-source
format, contract, compile and regression results on GitHub.

All local dynamic validation remains suspended on the affected workstation.
No local parser, formatter, compiler, test, product or GUI execution is part of
this batch. Visual layout, keyboard/accessibility behavior and actual Matrix
login/E2EE continuity remain separate acceptance obligations. No R4-07 or other
roadmap checkbox closes on this source slice.
