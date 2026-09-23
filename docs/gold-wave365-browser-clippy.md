# Wave 365 managed-browser Clippy repair

The hosted slim-core Clippy run `35851965740` at commit `ed749` reported two
diagnostics in `managed_browser.rs`.

- The async download closure already captures the `u64` parameter by value, so
  its `let expected_bytes = expected_bytes` rebind was removed.
- The unpublished-stage error path now matches the install result directly.
  A successful cleanup returns the original install error; a failed cleanup
  returns that same install error with the cleanup failure as context. This
  keeps both failure signals without `err().expect()` or a `Debug` bound.

No local executable command was run under the BSOD hold. GitHub must rerun the
exact hosted gate before acceptance.
