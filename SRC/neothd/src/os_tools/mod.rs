//! PC-01 — OS-tool surface. Slice 1: consent-gated, allowlisted file READ.
//!
//! Security model — fail-closed, three layers, every outcome WAL-audited:
//!   1. **Allowlist** ([`allowlist`]): the target must canonicalize to a path
//!      under one of `freedom.yaml::tools.os.allowed_paths` (default empty =
//!      deny-all). `..` segments are rejected before touching the FS, and
//!      symlinks are resolved by canonicalizing BOTH sides so a link can't
//!      escape the allowlist.
//!   2. **Autonomy gate** ([`crate::permissions::evaluate`]): `OsFileRead`
//!      confirms at Strict (and there's no TTY here ⇒ fail-closed), allows at
//!      Standard/Elevated/Full (the allowlist is the operator's opt-in).
//!   3. **Audit** ([`gate`]): `0xA8 OS_FILE_READ` on success (with byte count),
//!      `0xA9 OS_FILE_DENIED` on any allowlist / autonomy / read failure.
//!
//! Shipped slices: file READ (`0xA8`/`0xA9`), file WRITE (`0xAA`/`0xAB`), and
//! app LAUNCH (`0xAC`/`0xAD` — exec-allowlisted, no-args, no-shell, detached
//! stdio). Clipboard / window-mgmt / audio land in later PC-01 slices, each
//! with its own gate + WAL code. NO registry / system-paths / process-kill is
//! representable in this surface.

pub mod allowlist;
pub mod gate;
pub mod launch;
pub mod read;
pub mod write;

pub use gate::{OsGateError, launch_os_app, read_os_file, write_os_file};
