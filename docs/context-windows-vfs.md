# Windows Context SQLite VFS contract

`ContextStore` on Windows uses the native VFS in
`neothd::context_graph::windows_vfs`. This document records the boundary
because registering a VFS by name alone is not proof that SQLite has stopped
resolving paths through its stock Win32 VFS.

The integration receives a `PinnedContextDirectory`, not a database path.  The
directory must have been opened from an independently trusted anchor one
component at a time with `FILE_OPEN_REPARSE_POINT`; its live handle must prove:

* it is a directory and not a reparse point;
* it has a stable volume/file identity; and
* it is owned by TokenUser with the protected, inheritable private DACL already
  checked by `wal::win_native::verify_private_directory_handle_dacl`.

`ContextStoreVfs::register` retains that handle and registers a unique raw
SQLite VFS. `ContextStore` retains the `ContextStoreVfs` for at least as long
as its `rusqlite::Connection` opened with that VFS name. The VFS is
process-lifetime registered on purpose: unregistering a VFS while SQLite still
owns an `sqlite3_file` would leave a dangling callback table.

The sole `ContextStore` rusqlite opener should include
`OpenFlags::SQLITE_OPEN_FULL_MUTEX`. SQLite strips this connection flag before
calling VFS `xOpen`, so the VFS cannot and does not try to enforce it there.
Its raw `sqlite3_file` state has a per-file mutex and remains callback-safe
without relying on a process-wide SQLite setting.

Registration is deduplicated by the pinned root's kernel identity. Reopening
the same store returns the prior VFS only when the requested quota is identical;
a different quota is rejected instead of silently changing live accounting. The
process retains at most four distinct Context roots, which bounds the deliberate
process-lifetime allocations and makes repeated service reconnects non-leaking.

Every `xOpen`, `xAccess`, and `xDelete` accepts exactly `context.db`,
`context.db-wal`, `context.db-shm`, or `context.db-journal`.  `xOpen` invokes
the capability-relative native child creator; it does not delegate opening to
SQLite's `win32` VFS and it has no absolute-path fallback.  A new child gets a
protected single-TokenUser DACL before it is observable, and every opened
handle is checked again for object type, reparse state, stable identity, and
DACL.  Parent and child handles deny delete sharing while their VFS objects are
live, so a replacement cannot be substituted after verification.

The raw I/O table implements byte-range database locks and shared-memory locks
with `LockFileEx`, performs positional reads/writes, flushes each durable
commit, and maps SHM in allocation-granularity-aligned regions.  A per-VFS SHM
registry makes concurrently opened SQLite connections share the same mapping
objects and accounting.  The VFS reports SQLite I/O errors instead of silently
falling back to an ambient handle; temporary databases use SQLite's memory
store only.

The native Windows acceptance suite covers these fixtures:

1. Bind a directory capability created below the trusted instance anchor, open
   one VFS, create the context schema, insert a transaction, close, reopen, and
   verify the committed row.
2. Enable WAL, keep two `rusqlite` connections open through the same VFS, run
   writer/reader transactions, checkpoint, terminate the writer after a
   committed WAL frame, and verify recovery after reopening.
3. Configure a small VFS quota and prove an extending main/WAL write returns
   `SQLITE_FULL` without changing accounting; then checkpoint and prove space
   is released.
4. Attempt a junction/symlink/ADS/trailing-dot alias for every allowed name;
   swap each sidecar after opening; and relax the parent or child DACL.  Every
   operation must fail before SQLite reads or writes the substituted object.
5. Create a private ContextStore parent, drive `RuntimeLocalImport` through
   plan, outcome reservation, confirmed apply, VFS-backed reopen, and receipt
   replay. The test also checks that the post-commit maintenance marker was
   cleared. An ordinary inherited-DACL temporary parent is rejected before
   SQLite creates `context.db`.

The raw VFS fixtures belong in `context_graph/windows_vfs.rs` behind
`cfg(all(test, windows))`; the ContextStore lifecycle fixture belongs in
`context_graph/mod.rs` under the same gate. They use ordinary Windows SQLite,
never `SQLITE_TEST` or `SQLITE_FCNTL_WIN32_SET_HANDLE`.
