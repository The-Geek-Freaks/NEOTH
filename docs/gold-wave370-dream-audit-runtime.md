# Gold Wave 370 - Dream audit Hosted repair

Group721 exposed a shared W332 failure: `DreamAuditDescriptor::header()` mints a
fresh HLC/event-id header. The writer then minted a second header while checking
its already queued request and compared them for equality. The descriptors were
identical but their writer-owned headers differed, so every fresh Dream append
returned `Indeterminate` before its durable-before-ACK gate.

The repair retains the closed authority: it compares the canonical descriptor
payload and the reserved extended subtype, while the actual HLC/event-id header
remains the one minted for the queued append. Home binding, authority lock,
authenticated scan, exact replay, conflicts and post-append readback remain
unchanged.
