# W310 — P2-08 live-egress WAL session propagation

## Scope

W310 closes the remaining source-level P2-08 gap for a reply streamed after a
channel message has been admitted. It uses the `channel_wal_session` capability
already minted at the authenticated channel admission boundary in
`cli/serve_pipeline.rs`; it never derives a WAL identity from the recipient,
chat ID, request/response body, provider identity, or channel provenance.

## Propagation

The accepted live-stream path constructs `LiveDelivery` and immediately
attaches its existing optional `WalSessionContext`. `LiveDelivery` carries that
turn-local value through its pre-egress intent, terminal result, successful and
failed `CHANNEL_SEND`, stream `CHANNEL_ERROR`, and outbound `CHANNEL_EDIT`
headers. Contextual `send_gate` variants use `HeaderBuilder::session_context`;
the established non-contextual APIs remain wrappers passing `None`.

`None` remains meaningful: standalone/proactive delivery, legacy factories,
transport rejection, webhook/outbox maintenance, and any caller that has not
been given an admitted turn capability retain `SessionId::ZERO`.

## Regressions

`channels/live_delivery.rs` adds source fixtures that decode actual frames:

- two independent admitted live deliveries receive separate opaque contexts;
  each decoded intent is bound to its recipient/body hashes, each result to
  that intent ID, and each `CHANNEL_SEND` to the same metadata identity before
  exact `SessionPartition` matching. A swapped A/B header therefore fails,
  while an unbound delivery stays in `UNATTRIBUTED`;
- the existing mapped transport-failure fixture now carries an admitted
  session and verifies attribution of its intent, failed `CHANNEL_SEND`, and
  authenticated terminal result while retaining its durable-account checks;
- an interrupted stream verifies the same supplied context on its paired
  intent/result, `CHANNEL_SEND`, `CHANNEL_ERROR`, and final `CHANNEL_EDIT`
  frames. This covers the failure path without weakening metadata-only payload
  assertions.

## Acceptance boundary

This is source and fixture coverage only. The active BSOD hold prohibited local
Cargo, compiler, formatter, parser, test, and runtime execution.
P2-08 remains open pending hosted compilation/formatting and execution of the
focused live-delivery plus exact-session query regressions on the published
head.
