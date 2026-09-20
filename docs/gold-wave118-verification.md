# W118 — exact-account Telegram DM-pairing controls

Mapped Telegram account rows expose their effective configured DM-pairing
policy and an explicit enable/disable confirmation for the displayed account.
Enabling permits eligible private senders to submit pending pairing requests;
it does not automatically authorize them. Disabling prevents new pairing
requests. Listing, approving and dismissing pending requests remain separate
CLI operations.

The core inventory derives the new required dm_pairing boolean from each
authenticated account's effective admission. Invalid or partial maps still
produce no usable child rows. The projection contains no token, sender ID,
incarnation, request code or pairing-store data and makes no liveness claim.
The GUI rejects missing or nonboolean policy values rather than guessing false.

The existing CLI uses a presence flag: enable appends --enabled, and explicit
GUI disable omits it. Both commands identify Telegram and the selected
canonical account. The GUI shares the normal scrubbed, hidden-console launcher.
Retirement and pairing changes exclude each other while either is pending.
Only a successful exit and a strict receipt binding the selected account,
requested boolean and saved:true allow an inventory refresh. Unconfirmed
completion preserves the current projection and does not retry automatically.

Behavioral coverage includes two distinct configured account policies,
secret-free serialization, invalid-map refusal, strict GUI field types,
exact enable/disable argv and receipt rejection. The headless integration test
passes the actual GUI builder's argv to the real Clap parser for both states,
protecting the existing flag contract without changing the public CLI.

Required new identities:

- channels::probe::tests::telegram_account_projection_distinguishes_exact_pairing_policy
- cli::channel::tests::channel_status_projects_pairing_enabled_and_disabled_accounts_without_secrets
- mapped_pairing_gui_command_parses_with_the_real_cli_for_both_states (gui_channel_status)
- panel_logic::tests::parse_channel_status_requires_boolean_dm_pairing_for_mapped_accounts
- panel_logic::tests::named_telegram_account_dm_pairing_command_and_ack_bind_the_exact_policy

Independent source review approved the core, GUI and callback integration. Remote execution remains a separate gate. Native
interaction, rendering/accessibility, actual account mutation/reload and provider
acceptance remain required. No local build, formatter, parser or tests ran.
This slice does not close R4-07, P1-16 or the complete pairing workflow.

Combined source `27291a9d` passed Code Quality `35541417873`. Preflight `35541418088` requested twelve Rustfmt layouts/import-order hunks in five Rust files; this follow-up applies exactly those remote findings. No behavior changed and no local formatter ran. Fresh static, native and preview gates remain required.
