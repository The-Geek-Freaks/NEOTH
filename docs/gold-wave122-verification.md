# W122 — native Telegram pairing callback coverage

The existing generated MainWindow, production callback registration, executable
resolver, controlled subprocess and Slint event loop are used to exercise the
W118 account-pairing policy path. The fixture covers exact enable/disable command
semantics, duplicate and cross-action admission, unconfirmed receipts preserving
the account projection, and confirmed receipt-driven refresh.

This test is scoped to Linux/macOS and registered in the custom macOS native
harness. It does not supply a Windows executable fixture or provider acceptance.
The W121 request-list/dismiss callback is covered separately within the same
native fixture module. Required identities and hashes are recorded in the
remote test matrix after final source review.

All fixture execution remains GitHub-hosted. Source review is not a native pass;
no local test, compiler, formatter, parser or GUI was run. No Road item closes.
