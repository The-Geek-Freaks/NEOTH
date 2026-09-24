# Authenticated channel provenance at the MCP effect boundary

Named Telegram and Slack accounts can opt into `channel_accounts.ifc_source_labels.telegram` or `.slack`, mapping an existing account id to `public`, `internal`, `confidential`, or `secret`. An orphan label entry rejects account resolution. Missing labels remain explicitly unclassified compatibility provenance.

The resolved authenticated account binding mints an opaque provenance value for each inbound turn. Its request commitment includes account identity, incarnation, label and a fresh turn nonce. Clones within the same turn preserve the commitment. Preflight and authorization own that value; the final MCP leaf rejects caller provenance drift and uses the stored original for its information-flow decision. A compatibility entry point cannot downgrade trusted authorization.

Non-public channel sources stop before SmartApprove discovery, child spawn and actual tools/call. Trusted Public turns can complete the normal policy and pre-tool-use path. Five exact regressions cover these boundaries, including a real hermetic successful tools/call and fresh-turn request-binding refusal.

This W911/W924 slice was independently source-reviewed in W920. Root inspected the added positive test. Hosted formatting, strict core Clippy, test-target typecheck, and Linux/Windows behavior remain pending. It does not close the wider ADOPT31-C7 criterion. The HTTP transport slice is reviewed and published separately.
