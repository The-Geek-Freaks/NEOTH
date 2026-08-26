# NEOTH GUI Product Contract

Read this document and [`DESIGN.md`](DESIGN.md) before reviewing or changing
any Slint surface. They state the product intent and visual constraints; the
compiled token authority remains
[`SRC/neothd-gui/ui/theme.slint`](../SRC/neothd-gui/ui/theme.slint).

## Product and operator

NEOTH is a local-first, private AI companion. Its desktop GUI gives one
operator a legible, governable view of their assistant: current work, memory,
audit evidence, autonomy boundaries, model usage, connected channels, and
background activity. The UI must make the assistant's real state clearer; it
must not manufacture progress, readiness, consent, or a successful outcome.

The primary operator is technically capable but should not have to infer
system state from logs. They need quick orientation, direct access to the
common next action, and explicit evidence whenever NEOTH acts, waits, is
blocked, or sends data outside the device.

## Surface map

| Surface | Operator job | Truth that must remain visible |
|---|---|---|
| Chat | Start, steer, and inspect a conversation. | Provider/connection state, streaming/error state, consent boundary, and the difference between a sent request and a completed reply. |
| Activity and audit | Understand recent operations and recoverable evidence. | Timestamp, state, scope, and whether an entry is a fact, warning, pending work, or terminal receipt. |
| Memory and recall | Inspect and use operator-owned context. | Local ownership, source/provenance, freshness, and any unavailable or incomplete retrieval result. |
| Usage and budget | See cost and capacity without invented zeroes. | Known versus unknown usage, time window, workflow/provider scope, and stale/unavailable meter state. |
| Autonomy, consent, and security | Set authority boundaries and review their effect. | What a setting permits, what still requires confirmation, and which operation is irreversible or external. |
| Channels, tools, and integrations | Configure and observe outside connections. | Credential/connection state, target identity, failure state, and data-egress implication. |
| Jobs, cron, code, and self-development | Review background or proposed work. | Pending versus applied state, cancellation/retry behavior, and operator approval requirements. |
| Wizard and settings | Establish a safe, usable first-run and ongoing configuration. | Defaults, validation errors, unavailable prerequisites, and the exact setting being changed. |

## Modes and state vocabulary

Every interactive surface should distinguish these states where applicable:

| State | Product requirement |
|---|---|
| Ready | The next available action is clear and enabled only when it can run. |
| Working | Show that work is underway without pretending it has completed; offer cancellation only when it is real. |
| Waiting / unavailable | Name the missing daemon, provider, credential, consent, or prerequisite and provide a truthful recovery action. |
| Needs confirmation | Make the affected action, target, and consequence explicit before the operator grants authority. |
| Failed | Preserve the operation's context, expose a safe next step, and never render a failure as success. |
| Complete / receipt | Show completion only after the supporting operation has reached its terminal state. |

## Interaction principles

1. **Truth before decoration.** Status color, motion, progress, and copy must
   map to live state or a documented local state transition.
2. **Sovereignty is visible.** When data leaves the device or an action changes
   durable state, identify the boundary and the relevant operator choice.
3. **Recoverability is a feature.** Pending, retry, cancel, undo, and failure
   controls must describe what they actually do; do not expose a dead control.
4. **Density serves orientation.** Prefer a compact, scannable hierarchy over
   generic dashboard ornament. Detail is available on demand, never hidden by
   ambiguous icons alone.
5. **Accessibility is part of the state model.** Focus, labels, errors,
   disabled state, and signal meaning cannot depend on color, hover, or motion
   alone.

## Review boundary

This is a product contract for GUI work, not an implementation or release
approval. Use [`lint_rules.md`](lint_rules.md) and
[`AUDIT_CHECKLIST.md`](AUDIT_CHECKLIST.md) for the applicable review evidence.
Run the checked-in GUI lint gate when the local PC-safety policy permits it;
its four token checks do not replace a rendered UI review or exact-head remote
CI/security evidence.
