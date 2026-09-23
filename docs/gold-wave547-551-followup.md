# W547-W551: Paperless publication and live chat follow-up

## Admitted execution before these changes

Hosted run [35930437377](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35930437377)
at `a53a95f426607b476b6d9ac1937e26c871b8244e` executed all 903 selected
fixtures: 902 passed, one failed, and none lacked a terminal. Root verified
the three artifact archive digests, 179 source/input bindings and each ordered
discovery/execution/terminal record. The 13 Paperless authenticated-readiness
cases and 13 Wizard IPC support cases passed. Selected permanent evidence is
in `docs/verification/gold-wave549-selected-terminals.json`; these passes do
not establish the newer preparation implementation or GUI acceptance.

The remaining W458 producer failed before opening its streaming provider.
Its fixed diagnostic labels reported the provider/post-provider boundary;
inspection showed that the dedicated streaming fixture had not declared the
W41 effect-start capability required to reach `stream_raw`. W550 adds that
explicit declaration only to the private fixture. The ordinary provider
default, exactly-one invocation checks and three-chunk assertions remain.

## Paperless publication

W547 resolves operator-selected parents from a fixed filesystem root and
retains directory capabilities for creation, bounded reads and enumeration.
The prepared directory has a retained source-identity binding; exclusive
publication uses the existing cross-platform bound rename helper and then
checks that the requested namespace still names that identity. A competing
empty destination, replaced stage or swapped parent is refused. Cleanup
removes only the bound stage identity. Already-prepared inspection also
revalidates its namespace and preserves operator environment/state.

Four regressions exercise the empty destination and stage replacement on all
supported platforms, plus parent replacement during publication and inspection
on Unix. Owned temporary test roots are canonicalized so platform aliases such
as macOS `/var` are not confused with the explicit symlink-rejection case.

## Google Chat live-instance ownership

W548 publishes the running Google Chat adapter under its exact default
ChannelRef and the existing service-account-content fingerprint. Both `gchat`
and `google_chat` use the same opaque v6 permit and durable executor; the
dispatcher no longer constructs a replacement adapter or rereads the key for
each send. Completion of the receive task revokes and drains publication;
the existing fleet supervisor retains reload/crash ownership.

The optional `gchat-channel` feature has a separate four-case hosted workflow.
It exercises the published instance for both aliases, repeated-tick zero-send,
missing/revoked-instance refusal, feature-on configuration, and the source
contract. Those feature-only fixtures are not presented as default-feature
native passes. No external Google account or effect is exercised.

## Core test adaptation

Run [35931376195](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35931376195)
passed slim production Clippy at `6d0fa73c` and then exposed six private-method
test calls plus one use of a consumed permit. W551 supplies an opaque,
non-cloneable test-only wrapper for the existing readiness/drain test and
removes the obsolete second drop. Production visibility remains restricted;
there is no raw channel accessor. The affected readiness test joins the
focused grouped lane.

All source changes require their fresh hosted compile and behavior results.
No local compiler, formatter, test, code parser or product runtime was run
under the workstation BSOD hold. These changes alone close no Road item.
