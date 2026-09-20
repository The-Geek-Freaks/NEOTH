# W117 — BlueBubbles watched-chat GUID filter in Settings

The existing BlueBubbles form now exposes its optional watched-chat GUID CSV
through the already mapped fourth private input slot. Nonblank input restricts
accepted chats using the existing adapter allowlist. Blank input removes a
previous filter on save; the required allowed sender remains authoritative.
The adjacent hint states that effect before the operator saves.

No callback signature, command-line interface, credential schema, persistence
rule or adapter behavior changes. The field retains descriptor-derived masking
and the existing private stdin transport. There is no chat discovery operation
or saved-credential readback.

The regression exercises the real builder for trimmed multiple GUIDs, a
whitespace-only null value, and refusal of a blank required sender even when
a GUID filter is supplied:

`panel_logic::tests::bluebubbles_chat_guid_form_slot_trims_or_clears_without_weakening_sender`.

Independent source review approved this slice. Remote execution remains a separate gate. The existing
NeothLineEdit, caption and Theme tokens are reused; no motion is added.
Native rendering, keyboard/accessibility acceptance and a real BlueBubbles
setup-to-runtime check remain pending. No local compiler, formatter, parser,
tests or product execution ran. No R4-07 or release checkbox closes.
