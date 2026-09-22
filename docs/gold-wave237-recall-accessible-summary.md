# W237 — reduced recall summary accessibility labels

## Scope

This narrow source change gives each current-response recall summary line a
literal accessible label on both supported GUI surfaces:

- `SRC/neothd-gui/ui/chat.slint`
- `SRC/neothd-gui/ui/overlay.slint`

Each passive `Text` row remains `AccessibleRole.text`. No `TouchArea`, callback,
focus scope, `accessible-action-default`, navigation, persistence, or recall
lookup target was added.

## Source evidence

`SRC/neothd-gui/src/chat_recall_chips.rs` defines the admitted projection as
content-free. Its protocol comment excludes recall text, source identity, hash,
session value, prompt, provider value, WAL value, history, and click targets.
The reduced row carries only `tier`, optional `score`, and `source_state`.

`SRC/neothd-gui/src/main.rs` formats only those reduced fields into the
projection lines:

- ready row: `Recall · <tier> · <score> · source <state>`
- unavailable row: `Recall unavailable · <status>`

The two Slint repeaters now expose the same already-rendered `line` as
`Current response recall summary: <line>`. This removes the previous repeated,
constant accessible label without adding any source identity or recall content.

## Static acceptance boundary

Source review can establish the following only:

1. Main Chat and Buddy each retain a passive `AccessibleRole.text` row for every
   projected recall line.
2. The row's accessible label includes the same reduced, rendered line.
3. The change does not add an interactive control, keyboard action, callback,
   target, or external navigation.
4. No visual token, layout, motion, or color value changed. The relevant
   design-lint evidence is source/text review; no `gate-now` rule was run.

P2-27 remains open. This report does not claim a rendered accessibility tree,
screen-reader announcement, tab order, keyboard behavior, hosted GUI result,
or literal bound source/provenance acceptance. Those require the separately
specified target-platform acceptance evidence.
