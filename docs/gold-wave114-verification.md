# W114 — explicit mapped Telegram account retirement in the GUI

This R4-07/P1-16 source slice exposes the existing named-account CLI retirement
transaction in Settings → Channels. Each valid mapped Telegram row offers
Retire followed by an explicit confirmation showing its visible account ID.
The flat parent-channel remove remains unavailable while a map is active;
malformed maps remain repair-only through the CLI. Retirement controls are
disabled while a removal request is pending, and the Rust callback rejects
a second admission before constructing or spawning another operation.

## Request and completion behavior

The pure builder validates canonical Telegram and a canonical explicit
ChannelAccountId, then constructs only:

`neoth channel account remove telegram --account <selected-id> --output json`

An explicitly selected account called `default` is an ordinary named account,
never an inferred fallback. The normal GUI launcher removes GUI-control
environment state and suppresses a console window. No token is transported.

Success requires a successful process exit plus a strict JSON acknowledgement
with exactly channel, account and removed. It must identify Telegram and the
selected canonical account with removed=true. Unknown fields, missing/mismatched
identity, false, nonboolean, or malformed output cannot confirm retirement.
Only confirmed success fetches and applies the canonical channel inventory;
no optimistic removal of another row occurs. Failure or ambiguous completion
preserves the current projection and does not automatically retry the mutation.

The user confirms a public account ID. This slice does not introduce a persisted
internal-UUID precondition into the existing CLI transaction. Re-add identity,
retired leases and queued-work isolation remain the existing core authority.

## Validation boundary

Independent source review approved the implementation and focused regressions
after the Rust callback admission guard was added. Actual Slint compilation, native GUI event-loop and visible confirmation,
account retirement/reload/re-add behavior, and exact-source CI remain required.
No local validation workload is permitted or was run. No P1-16, R4-07 or Gold
release checkbox closes on this source slice.

Focused required regression:

`panel_logic::tests::named_telegram_account_retirement_command_and_ack_bind_the_exact_account`.

The regression inspects actual Command arguments and calls the strict receipt
parser with positive and negative payloads; it does not replace the required
native event-loop, confirmation-layout or process/reload acceptance.

## Remote formatting follow-up

W114 source `098dd7e1` passed Code Quality `35538615032`. Preflight `35538615267` requested four Rustfmt layouts in `panel_logic.rs`; the follow-up applies those exact remote hunks once to the canonical source. No behavior changed and no local formatter ran. Fresh static and native gates remain required.
