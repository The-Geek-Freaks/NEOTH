# W116 — native mapped-account retirement callback coverage

The application and native test now register the same private retirement
callback helper. The test constructs the generated MainWindow and invokes its
real callback. It checks the normal executable resolver against a staged CLI
before starting any child, then drives real subprocess completion through the
Slint event loop and canonical channel projection.

The first controlled child blocks with a bounded wait. A second callback is
refused while retirement is pending. Malformed, mismatched, removed:false and
nonzero results preserve the selected account projection and perform no list
read. Only a zero exit with the exact selected account's removed:true receipt
reads the complete canonical registry inventory and removes the retired row
from the displayed projection. The fixture releases its blocked child on unwind.

Required native GUI identity:

`w58_gui_callback_runtime_tests::w116_channel_account_retirement_callback_preserves_projection_until_exact_receipt`.

The fixture is scoped to Linux and macOS. macOS includes it in the existing
main-thread harness allowlist and dispatch. Windows requires an executable
fixture compatible with its actual resolver; no production bypass was added.
Independent source review approved the callback extraction and test seam.
Remote compilation and execution remain pending; this does not prove visible
confirmation, accessibility, actual daemon retirement/re-add, or Windows runtime
acceptance. No local validation ran and no Road checkbox closes.
