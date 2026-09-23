# W469 live assignments and integrated regression coverage

This batch combines the reviewed W465/W466 live assignment implementation,
the W458 daemon streaming regression and the W468 wizard persistence regression.
It does not close P2-18, P2-26a or P1-22 before hosted behavioral evidence.

## Live scoped and outbound assignments

The authenticated membership RPC now exposes explicit scoped and outbound
assignment mutations. Strict requests bind the authenticated peer identity,
exact skill/channel/account scope and expected revision; outbound requests
also carry the priority. The controller returns the store's committed result
directly, avoiding a second read that could observe another mutation.

The CLI chooses the live RPC path while the daemon owns its PID lock. Any
discovery, authentication, refusal or CAS error propagates without an offline
fallback or implicit retry. Offline changes retain the existing exclusive
PID-file guard through the mutation, so a concurrent daemon cannot acquire
ownership halfway through the update. Peer-advertised capabilities never
authorize a route: the existing exact operator assignments remain authority.

Outbound dispatch and assignment mutation now share the authority gate across
candidate selection, durable prepare, synchronous queueing and acceptance.
No remote-response wait holds that gate. The bounded race regression covers
both a deny that wins first and a dispatch that wins first, and checks that
neither ordering creates a replayable duplicate operation. The dispatch-first
fixture observes actual lock contention before releasing the dispatch.

The existing typed membership endpoint regression additionally checks the new
endpoints for authentication, exact-scope isolation, successful CAS, stale CAS,
deny/reset and unknown-field rejection. A new CLI regression proves that a live
daemon with an unavailable endpoint cannot create an offline membership store.

## Real producer to Main and Buddy daemon streams

The runtime regression schedules the real GUI worker, executes a three-chunk
provider, loads a post-provider hook from the fixture home and routes the
result through RuntimeSink and two real daemon attach streams. It constructs
no GUI output frames by hand. Each case requires one actual stream invocation
and three yielded chunks. Block also requires the drained WAL to contain the
specific post_provider_call HOOK_BLOCKED event, so an unrelated earlier error
cannot satisfy the test. Neither stream may contain the source secret.

Replace must produce one redacted delta, one provider-done record and a complete
terminal whose response digest matches the replacement. Both attachments must
receive the same payload sequence. This fixture begins from admitted runtime
state; it does not exercise public admission or the separate desktop GUI
bridge/controller/reducers. P2-26a remains open for that consumer boundary.

## Wizard persistence and re-entry

The GUI finish wrapper supplies its canonical home to the extracted preparation
function. The regression uses that same preparation path, the real private
WizardSessionController and daemon IPC server, and the prepared configuration
hash commit. It checks a typed Completed/Finished acknowledgement, reopens the
GUI projection, reruns preparation and reloads the daemon's effective config.
Three distinct canonical left/right/cerebellum provider/model slots must survive.
No Slint source or visual layout changes are included.

## Selection and current evidence

New native identities:

- `cli::cluster::tests::live_scoped_and_outbound_assignment_rpc_failures_never_fall_back_offline`
- `cluster::outbound_tests::deny_that_wins_outbound_authority_gate_sends_nothing_and_leaves_no_replayable_prepare`
- `daemon::gui_chat_runtime::lifecycle_tests::w458_real_producer_post_hook_is_visible_to_main_and_buddy_only_after_acceptance`

The existing selected RPC identity is
`daemon::audit_rpc::tests::membership_invite_confirm_revoke_and_status_are_typed_and_authenticated`.

New universal GUI identity:
`interface_preference_tests::p122_custom_topology_survives_shared_commit_and_gui_rerun`.

Independent static reviews passed after the race and Block-causation repairs.
Root checked the selector namespaces and removed newly redundant path borrows.
The grouped lane selects 885 native identities; the GUI lane selects 115
universal plus 30 Linux identities (145 total; 141 on macOS). The inventory has
731 paths and 1180 universal native identities. Executable verification is
pending on GitHub; no local compiler, parser, formatter, test or runtime ran.
