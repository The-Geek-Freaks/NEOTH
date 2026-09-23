# W271 Doctor transport caller acceptance

## Implementation; hosted validation pending

W271 connects the production authenticated live-evidence emitters to the
actual Doctor transport-flapping caller in one hermetic fixture. It writes five
failed default Signal replies and five accepted default Discord replies through
the sealed writer functions into one home WAL, then invokes
`check_channel_transport_flapping`.

The asserted Doctor outcome warns only for `signal/default` at five failures of
five attempts. It omits the healthy `discord/default` row, proving that the
production reader, exact stored `ChannelRef`, and Doctor classifier preserve
channel isolation even when both account IDs are `default`.

The fixture makes no network, provider, current-configuration, retry, or
recipient-delivery claim. Hosted runtime validation remains pending.
