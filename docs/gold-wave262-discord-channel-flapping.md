# W262 Discord default live-egress evidence

## Implementation; hosted validation pending

W262 implements authenticated transport evidence for replies sent by the default
Discord Gateway adapter. Hosted runtime validation remains pending. The startup
branch creates that adapter only after it
has a bot token, a normalized immutable allowlisted sender snowflake, and a
shared provider. In that same branch it mints the sealed
`ChannelRef::default_account(Discord)` provenance and passes it to the actual
Gateway reply sender.

Before a reply leaves the adapter, that sender must append an authenticated
`CHANNEL_EGRESS_INTENT`. If the append fails, it refuses the Discord request.
After the adapter accepts the request or returns an error, it appends the
matching authenticated terminal result. `delivered` means only that Discord's
adapter request was accepted; it is not a recipient, read, or physical delivery
claim.

The historical reader consumes only complete authenticated WAL frames. It takes
the stored `ChannelRef` from the intent itself and never consults current
Discord configuration, provider selection, credentials, routes, inbound payload
fields, or runtime health. Under `legacy_singleton_v2`, only exact default
Telegram, Slack, and Discord references with their matching channel strings are
admitted. A non-default Discord reference, unmarked Discord row, mismatched
channel/reference, missing reference, mapped binding, or unknown marker is
rejected before counters are produced.

Doctor groups its recent counters by the full `ChannelRef`; therefore
`discord/default` and `telegram/default` remain independent even though their
account-id text is the same. The focused regression warns for five Discord
attempts with two adapter failures while omitting a healthy default Telegram
channel from the detail.

## Boundary

This does not add Discord account maps, proactive Discord egress, retries,
runtime-health authority, routing authority, generic outbound evidence, or a
remote-delivery claim. Provider fields, free payload fields, current config, and
historical unbound records cannot manufacture Discord Doctor observations.
