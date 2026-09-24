# W535: durable connection-bound proactive delivery

The live IRC/Twitch/Nostr route transfers one opaque, non-cloneable permit to
the durable executor. The executor acknowledges Prepared, Intent and Armed
before consuming the permit. At the adapter boundary the permit rechecks
closure, acceptance, the exact ChannelRef, generation, fingerprint and adapter
identity; it cannot be converted into a reusable channel handle.

The v6 claim and WAL binding authenticate that connection identity. History v2
retains it, while historical v1-v5 grammars and hash preimages remain unchanged
and reject injected connection metadata. An expired Armed claim without a
terminal result recovers as CrashUnknown without reacquiring a live adapter or
retrying its send.

Two new native regressions cover authenticated identity/tampering and real
Prepared-to-Armed crash recovery. Ten existing registry/dispatcher regressions
join the focused hosted selection; the delivery case now checks the actual
authenticated Intent/Result/history identity and a second zero-send tick.

Independent static review is complete. Hosted formatting, compilation and
behavioral execution remain pending at publication. No local executable ran
under the BSOD hold. This slice does not close P1-14 or establish live provider
acceptance.

## W561: canonical default account before the v6 claim

Hosted GChat35934263615 atce7394ba executed four exact feature cases. The
positive same-instance case failed: the planned ConnectionBound route and live
permit named the default account, but the original queue item had no account.
The strict v6 validator rejected that mismatch before Claim and emitted only
SidecarOnly, making the expected delivery count zero.

The dispatcher now copies the selected ConnectionBound account into the in-flight
item before Egress. Explicit mapped-account items keep their earlier authoritative
path and continue before this normalization; g_01_mini stays sidecar-only. Claims,
WAL, History and permit validation remain strict and share the same chosen account.
The same shared path applies to default IRC, Twitch and Nostr routes. No live
instance reconstruction or alternative send path was introduced.

Independent review approved; the four GChat-feature cases require a fresh hosted
run. Retained prior source/log/receipt ZIP hashes live under
work/gold-20260906/wave561-gchatce7394. No new Road acceptance or local execution.

## W567 hosted confirmation

Run 35936050813 at `3bd923a0318737b3a1188ceec5c815c9dfd72cce` is admitted:
4 executed, 4 passed, none missing. Root checked three ZIP digests, eight exact
Git source/input bindings, discovery hashes and each actual terminal. Both
aliases use the published live instance; missing/revoked permits remain no-send.
The source-gate integration target uses Cargo's documented leaf-name terminal.
This proves the focused feature-on regression, not a real Google Chat account
or external-service qualification. Evidence:
`docs/verification/gold-wave567-gchat-terminals.json`.
