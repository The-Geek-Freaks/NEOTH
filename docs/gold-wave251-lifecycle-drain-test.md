# W251: lifecycle drain fixture synchronization

The Hosted `connectors::control_plane::tests::lifecycle_drain_commits_after_the_held_lease_releases` fixture failed while waiting for lifecycle admission to close. The worker sets the plane-wide `transition_in_progress` marker before it closes an account gate. A new operation-lease acquisition therefore returns `TransitionInProgress` at its plane check and never reaches the gate, so it cannot be used to observe the gate's closed admission state.

The fixture now waits for its already-issued `AccountAuthority` to return `AuthorityRetired` from `ensure_live`. That method directly observes the same account gate and returns only after `accepting_leases` is false. It proves the worker has suspended the gate while the separately held operation lease still prevents the bounded drain from completing. The fixture then drops that held lease, receives the transition, publishes the prepared update, and asserts `Paused` status.

The one-second transition and receive bounds are unchanged. This is a synchronization correction, not a timeout increase. Hosted Group42409ac supplied the failure evidence; local verification is intentionally limited to static text and Git checks during the BSOD hold.
