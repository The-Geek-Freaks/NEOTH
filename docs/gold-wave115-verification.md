# W115 — required sender inputs in eight existing channel forms

The existing private setup builder already rejects missing inbound sender
policies. Eight Settings forms omitted those required slots, so completing all
visible fields still failed locally before spawning the CLI. This source slice
adds the missing inputs without changing the backend requirement or transport.

| Form | Existing input slot | Private field |
| --- | --- | --- |
| Slack | f3 | allowed_sender |
| WhatsApp Business | f5 | allowed_sender |
| Discord | f2 | allowed_sender |
| Signal | f3 | allowed_sender |
| BlueBubbles iMessage | f3 | allowed_sender |
| Mattermost | f3 | allowed_sender |
| Google Chat | f3 | allowed_sender |
| Nostr | f3 | allowed_sender |

The forms retain descriptor-projected secret masks and existing six-slot
private stdin forwarding. There is no callback signature, CLI, daemon, adapter,
routing, or persistence change. Existing validation and empty-field rejection
remain authoritative; no default allowlist is inferred.

The focused builder regression supplies each form's complete inputs, checks
its exact channel and allowed_sender in the real serialized envelope, and then
clears precisely the newly visible required slot to prove rejection. This is
behavioral coverage of the shared mapper, not a source-string layout test.

Implementation and independent source review are complete. All execution is remote:
formatting/contracts, GUI compilation, focused unit coverage, actual native
interaction and real-provider configuration remain distinct gates. No local
validation ran. This slice does not close R4-07 or account/adoption parity.

Required focused GUI test identity:

`panel_logic::tests::required_sender_form_slots_map_to_private_allowed_sender_and_reject_blank`.

W115 source `eb316b5e` passed Code Quality `35539591989`. Preflight `35539592066` requested only two array layouts in `panel_logic.rs`; this follow-up applies those exact remote Rustfmt hunks without local formatter execution. Fresh static and native gates remain required.
