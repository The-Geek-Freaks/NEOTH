# W128 — connection-owned proactive delivery

IRC, Twitch and Nostr proactive routes now resolve the adapter already owned by
the daemon. A configured destination alone is insufficient. The dispatcher needs
the exact default-account `ChannelRef`, the current coherent config/credential
fingerprint, a current lifecycle generation and an adapter that has acknowledged
readiness. There is no second IRC connection or Nostr relay client for delivery.
This slice advances GOLD-LF-P1-14; it does not invent multi-account identities for
these adapters or close the broader GOLD-LF-P1-16 contract.

IRC readiness follows the server's `001 RPL_WELCOME`, and Nostr readiness follows
a relay EOSE for the exact subscribed request. Adapter-local drop guards revoke
readiness on normal exit, error and task cancellation. A separate tracked
publisher set keeps readiness monitoring distinct from inbound task supervision.

The live registry returns a lease wrapper, never a bare reusable adapter. It
checks generation/fingerprint again at the actual send boundary. The short entry
lock then releases so readiness loss can close admission while the existing lease
drains. The global effect gate stays held through the underlying send, preserving
the shutdown fence without blocking the readiness test on the entry lock.
Replacement and shutdown reject new
acquisition and retain already acquired delivery work until it drains. A permanent
shutdown fence also rejects a late publication for a previously absent reference.
Lifecycle wiring covers startup, changed/invalid config, unexpected adapter exit,
readiness loss and ordered shutdown.

Delivery continues through the existing `execute_claimed_once` protocol and its
Prepared, durable Intent, Armed, transport and terminal-result boundaries.
Absent, unready, mismatched or revoked handles stay `SidecarOnly`. Target syntax
is checked before live-adapter admission and Armed transport. A refused route
can still
write the established durable SidecarOnly no-effect record; transport failure
cannot become Delivered.
The existing accepted configuration, egress permission, deadline and one-use
claim remain authoritative.

Regression source covers exact reference isolation despite equal destinations,
readiness, replacement/publication races, active lease draining, shutdown fencing,
invalid destinations and successful/failed delivery history. All compilation,
Clippy, tests and protocol execution remain GitHub-only under the workstation
constraint. Independent source review and hosted execution are separate gates;
fake-adapter tests do not establish live IRC/Twitch/Nostr provider acceptance.

The existing hosted feature matrix adds one IRC/Nostr lane. Every requested
hermetic test must have exactly one discovered match before it runs; it includes
the IRC welcome, matching Nostr EOSE, lease drain, readiness publisher and real
durable dispatcher success/failure paths. The default-feature matrix separately
covers the registry, lifecycle, dispatcher and GUI bridge tests. Only actual
hosted outcomes can satisfy these execution gates.
