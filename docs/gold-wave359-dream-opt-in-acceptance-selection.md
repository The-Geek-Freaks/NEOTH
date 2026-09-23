# W359 Dream opt-in acceptance selection

P2-23 remains open for actual functional acceptance. This slice changes only
the hosted selection and source inventory; it does not change Dream or GUI
production code.

Twelve existing native fixtures now explicitly cover default-off status,
lossless enable and idempotent disable, malformed/uninitialized config,
runtime-status autonomy refusal, reload retirement and commit draining,
fresh re-enable gates, and the scheduler's Strict/Custom admission rules.
The canonical exact identities are in
gold-wave95-96-test-matrix.json::wave359DreamOptInAcceptance.

Six existing GUI Settings fixtures additionally cover mutation receipt then
matching readback, mismatched readback refusal, command-only control,
verified-only publication, concurrent/error authority, and late-refresh
fencing. They are selected by the focused Linux GUI workflow.

The four prior Dream wizard witnesses passed in GUI129 run35837802269.
Their relevant GUI source blobs are unchanged through954f838a. They remain
valid evidence for their own scope; they cannot substitute for the newly
selected native and Settings checks.

All newly selected terminals require GitHub-hosted execution and source
admission before P2-23 closure. Broader platform, packaging and release
qualification remains separate. No local executable validation ran.
