# W268 Signal default live-egress evidence

## Implementation; hosted validation pending

W268 implements authenticated transport evidence only for replies emitted by the
default Signal receive-poll adapter. Startup requires the Signal service URL,
the registered local E.164 number, a normalized exact allowed E.164 sender, and
a provider. That same startup arm mints sealed `signal/default` provenance for
the actual receive-to-reply sender.

The sender persists an authenticated intent before calling signal-cli. A missing
intent refuses the adapter call. It persists a matching terminal result after
adapter acceptance or an adapter error; `delivered` means adapter acceptance,
not recipient or physical delivery. The historical collector reads only complete
authenticated WAL frames and their stored `ChannelRef`; it does not consult
current Signal configuration, provider selection, credentials, routes, free
message fields, or runtime health.

Only the exact `legacy_singleton_v2` marker with matching `signal` string and
`signal/default` reference is admitted. Signal account maps, proactive sends,
retries, generic outbound records, and remote-delivery claims remain out of
scope.
