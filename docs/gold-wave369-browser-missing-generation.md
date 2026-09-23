# W369 — missing managed-browser generation resolver repair

## Hosted failure

Hosted Group721 run 954 failed only `tools::managed_browser::tests::missing_generation_fails_closed_without_ambient_fallback`. The previous assertion expected the incidental lower-level text `managed-browser root`; the no-follow directory helper's platform/context wording did not guarantee that exact fragment.

## Repair

`resolve_from_manifest` now adds the stable caller-owned context:

```text
resolve managed-browser root beneath explicit home
```

when the required direct `managed-browser` child cannot be opened as a real no-follow directory. The fixture asserts this explicit resolver contract and also proves that the absent child remains absent after failure.

The resolver still uses `open_absolute_bound_directory(..., false, ...)` followed by `open_bound_real_child_dir`. It creates no directory, follows no link/reparse point, reads no ambient browser location, and supplies no PATH/HOME/registry/default-browser fallback. No check was weakened; only the failure boundary is made meaningful and stable for the actual resolver responsibility.

## Verification boundary

`git diff --check -- SRC/neothd/src/tools/managed_browser.rs docs/gold-wave369-browser-missing-generation.md` is the only local check under the BSOD hold. Hosted focused execution remains required.
