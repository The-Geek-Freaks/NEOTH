# Wave 362 managed-browser permission type repair

The hosted slim-core Clippy run `35851362763` at commit `356` failed only in
the managed-browser staged executable permission block.

`open_bound_regular_file` returns a capability-scoped `cap_std::fs::File`, so
its `set_permissions` method requires `cap_std::fs::Permissions`, and its
metadata returns that same capability permission type. The block now uses the
matching `cap_std::fs::PermissionsExt` trait and
`cap_std::fs::Permissions::from_mode(0o700)`.

The retained file handle, owner-only `0700` mode, metadata postcheck, and
permission sync remain unchanged. No local executable command was run under
the BSOD hold; GitHub must rerun the exact hosted gate.
