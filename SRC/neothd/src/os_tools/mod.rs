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
//! Scope is deliberately READ-only here. Write / app-launch / clipboard /
//! audio land in later PC-01 slices, each with its own gate + WAL code. NO
//! registry / system-paths / process-kill is representable in this surface.

pub mod allowlist;
pub mod gate;
pub mod read;

pub use gate::{OsGateError, read_os_file};
