# Account-aware routing and Windows Paperless staging

Explicit routing saves now write schema 2 to `channel_routing.json`. Each route
is either `legacy_unbound` with a canonical channel, or `bound` with one exact
`ChannelRef`. Loading an old file is read-only. Bare legacy Telegram never gains
an implicit default account; legacy account companions must match their channel
and source. The retired legacy `destinations.keet_topic` input is discarded and
is never used or emitted. Unknown fields, unsupported versions, duplicate map
entries and invalid account identifiers reject the document.

Source, failure and default selection keep the complete selected route together.
The CLI still permits account selection only for an exactly authenticated named
Telegram account. Cron seals that authenticated Telegram binding before queue
admission and rejects unsupported account-bound channels. Already-bound queue
items keep their durable account regardless of later routing edits. An unbound
item facing a later bound route records an adapter configuration error before
planning or transport. A malformed routing document leaves the queue intact;
after correction the preserved local item settles exactly once.

Windows run `35956846675` at `afbb5ebbb0743164462611237d5bd5e59619afcb`
compiled and ran all 47 selected tests: 43 passed and 4 failed. Root verified
55 internal hashes, 10 source blobs, 2 build inputs and every individual terminal.
The retained DELETE-parent diagnostic failed with `ERROR_SHARING_VIOLATION` (32),
while its otherwise identical released-handle twin passed. This disproves the
old diagnostic's expected compatibility; it is not a successful product test.

Paperless now holds a delete-sharing read directory capability and its physical
identity throughout file creation, late mutation rebind, identity comparison and
final rename. Only the initial DELETE-requesting handle is released before
nested writes. A new swap regression covers replacement before late rebind.
The old diagnostic identity
`private_stage_create_new_composes_with_retained_delete_bound_parent` is replaced
explicitly by
`private_stage_create_new_reports_sharing_violation_with_retained_delete_parent`:
it asserts the precise sharing error, no published target and temporary-file
cleanup. The released-handle success twin remains separate and unchanged.
The production installation tests must still pass after the repair.

The earlier routing tests `empty_account_map_is_omitted_from_legacy_routing_json`
and `oversized_persisted_route_is_settled_without_starving_valid_successor`
are superseded by explicit schema-2 output and malformed-document preservation,
recovery and bound-route settlement tests. They were not present in the required
native matrix. The new grouped selection adds 35 exact portable identities,
including retained route compatibility and caller tests. Grouped total: 1025;
portable native total: 1295. Windows selection: 48, including the stage swap.

Core run `35956844607` passed slim Clippy, core test-target typechecking and CLI
build/export at `afbb5ebb`. The digest-verified generated CLI reference is imported
byte-for-byte (SHA256 `8d97c9a7ddd81e8284bdcf724e324084e12a9c3d7aa127056c71f715833ce09f`).
These results precede the current routing/staging changes; their behavior remains
pending hosted checks. Independent static review is complete. No local compiler,
formatter, test, GUI, Docker or other product runtime was executed.
