# W127 — identifiable Telegram pairing challenge

The first pairing challenge now gives its sender both the exact request ID and
the private code, with an instruction to share them privately with the operator.
This lets the operator select the corresponding opaque row in the pending-request
panel instead of guessing which request belongs to that sender. The GUI guidance
uses the same two-piece flow.

The adapter passes the request ID already produced by the durable admission
store to `PairingReplySender`. The reply validates the same request-ID and code
formats used by private approval, then uses the existing mapped-account
LiveDelivery/WAL/egress path. Duplicate requests still receive no new plaintext
code. No raw challenge body or code is added to application audit payloads.

Fresh hosted compilation and behavioral verification remain required. No local
compiler, parser, formatter, fixture, test, product or GUI execution ran. This
completes the source flow accompanying W126; it is not live Telegram/provider,
portable-release or roadmap-parent acceptance.
