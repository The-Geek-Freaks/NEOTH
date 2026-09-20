# W121 — pending Telegram pairing requests in Settings

Mapped Telegram accounts with DM pairing enabled now expose a pending-request
panel. The panel lists only the existing CLI's request ID and creation time,
with separate loading, empty, unavailable and retained-stale states. It never
projects sender identity, a pairing code, credential or binding-generation data.
Refresh uses the existing account-bound CLI operation, which can initialize its
private pairing store; this is not advertised as a no-write filesystem probe.

Dismissal requires an explicit confirmation for a displayed request and invokes
the existing CLI transaction with the selected canonical account and exact
request ID. Only a successful process exit and strict matching `dismissed:true`
receipt permit a new list read. Unconfirmed outcomes retain the prior projection,
disable further dismissal until refresh, and never retry automatically. A failed
read after confirmed dismissal is reported separately from an unconfirmed write.
Approval still requires the sender's private code through the CLI.

The pure command builders share real Clap integration coverage. Strict response
parsers reject unknown fields, wrong identities, duplicate or malformed IDs,
invalid timestamps, oversized payloads and lists beyond the core's current
three-request bound. Callback admission serializes list, dismiss, account
retirement and pairing-policy changes. Selection remains fixed until completion;
an account no longer projected as pairing-enabled cannot accept a returned list.

This is a source implementation slice of GOLD-R4-07 and GOLD-LF-P1-16. Independent
review, remote compilation and native behavioral results are recorded separately.
Visible layout, keyboard/accessibility, actual daemon/provider acceptance and the
remaining pairing approval flow are not established by source or parser evidence.
No local compiler, formatter, parser, tests or GUI ran. No roadmap checkbox closes.
