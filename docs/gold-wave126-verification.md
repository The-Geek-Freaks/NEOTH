# W126 — private selected-request pairing approval

The pending Telegram DM request panel now supports explicit approval using the
sender's eight-character pairing code. The operator selects an existing request,
enters the code in a password field, and confirms that exact request. Submit and
cancel clear the field. Approval, dismissal, listing, policy changes and account
retirement share the existing in-flight admission fence.

The GUI invokes the hidden `channel pairing approve-request` command with only
the selected channel/account in argv. A strict, versioned stdin envelope carries
the request ID and code, is limited to 1 KiB, and is serialized directly into
zeroizing storage. The CLI keeps the parsed code in `SecretString`, rejects
unknown or mismatched fields with a generic error, and requires JSON output.
The existing public `approve --code` interface is retained.

The store matches the selected request ID and code commitment in the same
immediate transaction before consuming the pending row or approving its sender.
A valid code from another request cannot authorize the selected row. The GUI
requires a successful exit and an exact account/request-bound `approved:true`
receipt before re-listing that account. Unconfirmed results preserve the displayed
rows, require an explicit refresh, and never cause an automatic retry.

Regression source covers the atomic selected-request contract, strict private
envelope and public CLI compatibility, real Clap parsing of the GUI command,
private-body/receipt validation, and the actual native callback/private-child
path. The native child fixture is Unix/macOS scoped and checks exact non-secret
argv, the private stdin body, duplicate admission, failed receipts, retained rows
and one successful same-account refresh. Windows callback execution is not
claimed by that Unix fixture.

Source/text GUI evidence uses existing Theme tokens, buttons and password entry;
copy names the selected request and actual pending/error states. No new animation
is introduced. Rendered focus, accessibility, contrast and small-window acceptance
remain unverified. All local compilation, formatting, parser and test execution
stays suspended. Independent source review is approved; fresh GitHub gates are required; this
source slice does not close GOLD-R4-07, GOLD-LF-P1-16 or any Road checkbox.
