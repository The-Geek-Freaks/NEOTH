# Gold Wave 298 - chat preparation lint accommodation

Hosted Core run `35826459440` reported `clippy::too_many_arguments` for
`prepare_chat_turn_input` at `neothd/src/cli/chat.rs`. The function is the
single adapter boundary for the CLI and daemon callers. Its arguments keep the
per-turn consent, stream-control token, GUI mode, reload controller,
cancellation authority, and event sink explicit rather than placing them in a
reusable context that could cross a chat-turn boundary.

The focused `#[allow(clippy::too_many_arguments)]` documents that intentional
boundary. No local compiler, formatter, parser, test, runtime, or fixture was
run under the BSOD hold. Hosted Core validation remains required.
