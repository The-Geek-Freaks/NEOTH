# W130 — guided legacy Telegram migration

The channel settings panel now guides the existing transactional migration from
a configured, valid Telegram singleton to an explicit named account. It shows
the target, retains the existing inbound credentials/sender policy, and explains
that channel-only proactive routing cannot automatically select the new account.
The step does not claim connection testing or provider acceptance. Existing CLI
config/credential publication, rollback and interrupted-commit recovery remain
the migration authority; the GUI does not implement a second writer.

The callback invokes exactly `channel migrate-legacy telegram --account <id>
--output json` through the normal resolved, hidden-console CLI launcher. A bounded,
deny-unknown receipt must bind channel, canonical account, configured-account
inbound mode, available probe capability and `migrated_legacy_singleton:true`.
Only then does it fetch canonical inventory and require the selected account to
be present. An uncertain result preserves the projection and requires an explicit
successful status refresh before retry, with no automatic command repetition.

Migration admission serializes against pairing, policy and retirement operations,
and blocks new channel credential mutations while pending. Every asynchronous
channel inventory producer captures the window's inventory generation. Migration
advances that generation; old replies and replies delivered while migration is
pending cannot restore a legacy row or clear the reconciliation requirement.

Source tests cover real Clap parsing, strict receipt rejection and the actual
native callback/child/event-loop path, including duplicate admission, unconfirmed
results, explicit reconciliation, one successful canonical readback and queued
stale replies during/after migration. The native executable fixture is Unix/macOS
scoped. Existing Theme components and explicit text states are used; rendered
focus, scaling and accessibility are still unverified.

This advances GOLD-LF-001-04 and GOLD-LF-001-14. Independent review, fresh hosted
execution and actual migration/restart qualification remain required. No local
compiler, formatter, parser, test, product or GUI execution ran, and no Road
checkbox is closed by source work alone.

The hosted macOS fixture-discovery gate is updated from the old five callbacks
to all ten now declared by the actual native harness, including W116, W121,
W122, W126 and W130. Exact ownership, nonignored discovery and runnable filters
remain required. The cadence contract now binds the verifier inventory to the
actual source declaration so another added callback cannot silently invalidate
the hosted discovery gate. This is a source-found mismatch; no failing macOS
result is invented and no native callback pass is claimed.
