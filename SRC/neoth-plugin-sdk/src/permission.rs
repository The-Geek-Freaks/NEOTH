//! PermissionToken typestate (S3 fix from ADVERSARIAL/03).
//!
//! Compile-time API guidance: native Rust integration APIs can take a
//! `&PermissionToken<L>` at the appropriate level, and the sealed
//! `PermissionLevel` trait prevents consumers from adding new lattice points.
//! `PermissionToken::mint()`, grant construction, and upgrades are hidden from
//! the default feature set behind `_host` to keep normal plugin code on the
//! intended API path.
//!
//! `_host` is not access control. Cargo features are selected by consumers, so
//! a zero-sized token or grant must never be treated as an unforgeable runtime
//! capability. For WASM plugins, the real security boundary is the NEOTH
//! runtime's Wasmtime sandbox, operator-approved capability state, and
//! per-hostcall allowlist enforcement.

use std::marker::PhantomData;

mod sealed {
    /// Private sub-trait; external crates cannot implement `PermissionLevel`.
    pub trait Sealed {}
}

/// Marker trait for permission-level types. Sealed.
pub trait PermissionLevel: sealed::Sealed + 'static {}

/// Models the no-permission level in Rust APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct None;

/// Models read-only access in Rust APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnly;

/// Models permission to mutate vault state (WAL appends, SQLite writes,
/// `~/.neoth/` file writes) — but NOT to make external network calls
/// or spawn processes. F-17: separates DB writes from RPC so a hook
/// that needs to update memory does not need to authorise outbound
/// HTTP. Ladder is `ReadOnly → Write → Execute → Dangerous`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write;

/// Models permission to call integration tools that perform external network calls
/// (LLM provider HTTP, channel sends, MCP server spawn). Implies
/// `Write` (you can mutate state on the way out / in).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Execute;

/// Models shell-like operations: process spawn, raw filesystem, arbitrary
/// network. Operator policy commonly requires hardware 2FA for this level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dangerous;

impl sealed::Sealed for None {}
impl sealed::Sealed for ReadOnly {}
impl sealed::Sealed for Write {}
impl sealed::Sealed for Execute {}
impl sealed::Sealed for Dangerous {}

impl PermissionLevel for None {}
impl PermissionLevel for ReadOnly {}
impl PermissionLevel for Write {}
impl PermissionLevel for Execute {}
impl PermissionLevel for Dangerous {}

/// Compile-time subtyping over the permission lattice (F-18).
///
/// `L: AtLeast<M>` reads as "level `L` is at least as powerful as level
/// `M`". Rust integration APIs use this as a generic bound so any higher-or-equal
/// level satisfies a "needs at least `M`" requirement:
///
/// ```ignore
/// fn read_file<L: PermissionLevel + AtLeast<ReadOnly>>(
///     _token: &PermissionToken<L>, path: &str,
/// ) { /* ... */ }
/// ```
///
/// Both `PermissionToken<ReadOnly>` and `PermissionToken<Execute>`
/// satisfy that bound; `PermissionToken<None>` does not. Sealed
/// transitively via `PermissionLevel` so external crates cannot
/// introduce new lattice points.
///
/// Lattice (top to bottom — higher dominates lower):
///   `Dangerous → Execute → Write → ReadOnly → None`
pub trait AtLeast<L: PermissionLevel>: PermissionLevel {}

// Reflexive — every level is at least itself.
impl AtLeast<None> for None {}
impl AtLeast<None> for ReadOnly {}
impl AtLeast<None> for Write {}
impl AtLeast<None> for Execute {}
impl AtLeast<None> for Dangerous {}

impl AtLeast<ReadOnly> for ReadOnly {}
impl AtLeast<ReadOnly> for Write {}
impl AtLeast<ReadOnly> for Execute {}
impl AtLeast<ReadOnly> for Dangerous {}

impl AtLeast<Write> for Write {}
impl AtLeast<Write> for Execute {}
impl AtLeast<Write> for Dangerous {}

impl AtLeast<Execute> for Execute {}
impl AtLeast<Execute> for Dangerous {}

impl AtLeast<Dangerous> for Dangerous {}

/// Compile-time marker for Rust APIs that operate at permission level `L`.
///
/// This is a zero-sized API-ergonomics type, not a runtime authority proof.
/// `mint()` is absent from the default feature set, but Cargo consumers can
/// explicitly enable `_host`; runtime code must enforce capabilities
/// independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionToken<L: PermissionLevel> {
    _level: PhantomData<L>,
}

impl<L: PermissionLevel> PermissionToken<L> {
    /// Constructor for native Rust integration paths.
    ///
    /// `_host` keeps this out of the default plugin API, but Cargo features are
    /// consumer-selectable. Callers must not treat this constructor or its
    /// zero-sized result as a security boundary.
    #[cfg(feature = "_host")]
    pub fn mint() -> Self {
        PermissionToken {
            _level: PhantomData,
        }
    }
}

/// Typed marker available to Rust integration code when transitioning to level
/// `L`.
///
/// An integration may pair this marker with independently validated operator
/// policy. The production Wasmtime path does not consume this zero-sized value:
/// it stores the approved `HostcallPermission` in `PluginStoreState` and checks
/// that grant on every hostcall.
#[derive(Debug)]
pub struct FreedomGrant<L: PermissionLevel> {
    _level: PhantomData<L>,
}

impl<L: PermissionLevel> FreedomGrant<L> {
    /// Constructor for native Rust integration paths.
    ///
    /// Feature-gating reduces accidental use; it does not make grants
    /// unforgeable or replace runtime authorization.
    #[cfg(feature = "_host")]
    pub fn issue() -> Self {
        FreedomGrant {
            _level: PhantomData,
        }
    }
}

/// Upgrade `ReadOnly -> Write` with a `FreedomGrant<Write>`. F-17:
/// new intermediate step in the ladder so a hook that needs DB writes
/// without network access can model the minimal level.
///
/// F-20 (rust-reviewer H-4): every upgrade fn is `_host`-feature gated so the
/// default dependency surface does not expose host integration transitions.
/// This is compile-time API hygiene only: Cargo consumers can select `_host`,
/// and the runtime must independently authorize every privileged operation.
impl PermissionToken<ReadOnly> {
    /// Consume self and a `Write` grant to produce a `Write` token.
    #[cfg(feature = "_host")]
    pub fn upgrade_to_write(self, _grant: FreedomGrant<Write>) -> PermissionToken<Write> {
        PermissionToken {
            _level: PhantomData,
        }
    }

    /// Shortcut upgrade `ReadOnly -> Execute` with a `FreedomGrant<Execute>`.
    /// Retained for adapters that model outbound network without going through
    /// the intermediate `Write` marker.
    #[cfg(feature = "_host")]
    pub fn upgrade_to_execute(self, _grant: FreedomGrant<Execute>) -> PermissionToken<Execute> {
        PermissionToken {
            _level: PhantomData,
        }
    }
}

/// Upgrade `Write -> Execute` with a `FreedomGrant<Execute>`.
impl PermissionToken<Write> {
    /// Consume self and an `Execute` grant to produce an `Execute` token.
    #[cfg(feature = "_host")]
    pub fn upgrade_to_execute(self, _grant: FreedomGrant<Execute>) -> PermissionToken<Execute> {
        PermissionToken {
            _level: PhantomData,
        }
    }
}

/// Upgrade `Execute -> Dangerous` with a `FreedomGrant<Dangerous>`.
impl PermissionToken<Execute> {
    /// Consume self and a `Dangerous` grant to produce a `Dangerous` token.
    #[cfg(feature = "_host")]
    pub fn upgrade_to_dangerous(
        self,
        _grant: FreedomGrant<Dangerous>,
    ) -> PermissionToken<Dangerous> {
        PermissionToken {
            _level: PhantomData,
        }
    }
}

/// Error available to Rust integration adapters when a level check fails.
///
/// The production Wasmtime hostcall path has its own fail-closed status and WAL
/// audit event; it does not use this SDK error as its authorization boundary.
#[derive(thiserror::Error, Debug)]
#[error("plugin lacks required permission level: needs {required:?}, has {actual:?}")]
pub struct UnauthorizedLevel {
    /// Permission level the Rust adapter requires for this operation.
    pub required: &'static str,
    /// Permission marker the caller provides at the call site.
    pub actual: &'static str,
}

/// Runtime-tagged permission token (F-19 step 1).
///
/// `PermissionToken<L>` is zero-cost + compile-time safe but its
/// type parameter makes a heterogeneous registry (a `HashMap` of
/// hooks at different levels) impossible without per-level boxing.
/// `PermissionTokenAny` erases the level into a tag for Rust adapters or tests
/// that need a heterogeneous collection. Production Wasmtime dispatch uses its
/// separate `HostcallPermission` value in `PluginStoreState` and does not
/// consume this enum as authority.
///
/// The level tag is the same `&'static str` the trait-level shape
/// already uses (`"read_only"` / `"write"` / `"execute"` /
/// `"dangerous"` / `"none"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionTokenAny {
    /// Wraps a `PermissionToken<None>` marker.
    None(PermissionToken<None>),
    /// Wraps a `PermissionToken<ReadOnly>` marker.
    ReadOnly(PermissionToken<ReadOnly>),
    /// Wraps a `PermissionToken<Write>` marker.
    Write(PermissionToken<Write>),
    /// Wraps a `PermissionToken<Execute>` marker.
    Execute(PermissionToken<Execute>),
    /// Wraps a `PermissionToken<Dangerous>` marker.
    Dangerous(PermissionToken<Dangerous>),
}

impl PermissionTokenAny {
    /// Stable snake_case string id for the wrapped level.
    pub fn level(&self) -> &'static str {
        match self {
            PermissionTokenAny::None(_) => "none",
            PermissionTokenAny::ReadOnly(_) => "read_only",
            PermissionTokenAny::Write(_) => "write",
            PermissionTokenAny::Execute(_) => "execute",
            PermissionTokenAny::Dangerous(_) => "dangerous",
        }
    }

    /// True when the held marker level is >= `required` per the [`AtLeast`]
    /// lattice. Useful for Rust adapters and tests only; production Wasmtime
    /// authorization uses `HostcallPermission::allows` on host state.
    pub fn satisfies(&self, required: &'static str) -> bool {
        // Rank levels by ladder position; higher dominates.
        let rank = |s: &str| match s {
            "none" => 0,
            "read_only" => 1,
            "write" => 2,
            "execute" => 3,
            "dangerous" => 4,
            _ => -1, // unknown level — never satisfies
        };
        let r_required = rank(required);
        if r_required < 0 {
            return false;
        }
        rank(self.level()) >= r_required
    }
}

/// Conversions from typed token to type-erased token. Rust integration code
/// rarely needs the reverse direction: downcasting back to a specific level
/// requires the caller to commit at compile time, which `PermissionToken<L>`
/// already provides.
impl From<PermissionToken<None>> for PermissionTokenAny {
    fn from(t: PermissionToken<None>) -> Self {
        PermissionTokenAny::None(t)
    }
}
impl From<PermissionToken<ReadOnly>> for PermissionTokenAny {
    fn from(t: PermissionToken<ReadOnly>) -> Self {
        PermissionTokenAny::ReadOnly(t)
    }
}
impl From<PermissionToken<Write>> for PermissionTokenAny {
    fn from(t: PermissionToken<Write>) -> Self {
        PermissionTokenAny::Write(t)
    }
}
impl From<PermissionToken<Execute>> for PermissionTokenAny {
    fn from(t: PermissionToken<Execute>) -> Self {
        PermissionTokenAny::Execute(t)
    }
}
impl From<PermissionToken<Dangerous>> for PermissionTokenAny {
    fn from(t: PermissionToken<Dangerous>) -> Self {
        PermissionTokenAny::Dangerous(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests exercise the host-integration API under `_host`. With default
    // features `mint()` is intentionally absent, keeping ordinary plugin code
    // on the typed surface; runtime security is tested in the Wasmtime host.
    #[cfg(feature = "_host")]
    #[test]
    fn mint_and_upgrade_chain() {
        let ro: PermissionToken<ReadOnly> = PermissionToken::mint();
        let exec = ro.upgrade_to_execute(FreedomGrant::issue());
        let _dangerous = exec.upgrade_to_dangerous(FreedomGrant::issue());
    }

    /// F-17: full ladder ReadOnly → Write → Execute → Dangerous via
    /// the new intermediate step. Compiles only when the upgrade
    /// signatures stay aligned; if the chain drifts (e.g. Write::
    /// upgrade_to_execute renamed), this test fails to build and the
    /// SDK ABI break is visible.
    #[cfg(feature = "_host")]
    #[test]
    fn full_ladder_via_write_step() {
        let ro: PermissionToken<ReadOnly> = PermissionToken::mint();
        let write = ro.upgrade_to_write(FreedomGrant::issue());
        let exec = write.upgrade_to_execute(FreedomGrant::issue());
        let _dangerous = exec.upgrade_to_dangerous(FreedomGrant::issue());
    }

    #[test]
    fn write_is_a_distinct_permission_level() {
        // Sanity: Write is a real type that implements PermissionLevel.
        // Compile-time check via the sealed trait bound.
        fn assert_impl<L: PermissionLevel>() {}
        assert_impl::<Write>();
    }

    /// F-18: reflexive case — every level satisfies `AtLeast<Self>`.
    #[test]
    fn atleast_is_reflexive() {
        fn assert_at_least<L: AtLeast<L>>() {}
        assert_at_least::<None>();
        assert_at_least::<ReadOnly>();
        assert_at_least::<Write>();
        assert_at_least::<Execute>();
        assert_at_least::<Dangerous>();
    }

    /// F-18: upward closure — higher levels satisfy lower bounds.
    /// Compile-only proof; if a lattice impl is removed, the bound
    /// fails to resolve and this test breaks the build.
    #[test]
    fn atleast_upward_closure() {
        fn requires_readonly<L: AtLeast<ReadOnly>>() {}
        requires_readonly::<ReadOnly>();
        requires_readonly::<Write>();
        requires_readonly::<Execute>();
        requires_readonly::<Dangerous>();

        fn requires_write<L: AtLeast<Write>>() {}
        requires_write::<Write>();
        requires_write::<Execute>();
        requires_write::<Dangerous>();

        fn requires_execute<L: AtLeast<Execute>>() {}
        requires_execute::<Execute>();
        requires_execute::<Dangerous>();

        fn requires_dangerous<L: AtLeast<Dangerous>>() {}
        requires_dangerous::<Dangerous>();
    }

    /// F-18: the practical use-case — a generic Rust adapter gated by an
    /// `AtLeast<ReadOnly>` bound accepts every higher level. Spot-checks
    /// that the ergonomics work as advertised.
    #[cfg(feature = "_host")]
    #[test]
    fn host_tool_with_atleast_bound_accepts_higher_tokens() {
        fn read_state<L: PermissionLevel + AtLeast<ReadOnly>>(_t: &PermissionToken<L>) -> u32 {
            42
        }
        let ro: PermissionToken<ReadOnly> = PermissionToken::mint();
        let w: PermissionToken<Write> = PermissionToken::mint();
        let e: PermissionToken<Execute> = PermissionToken::mint();
        let d: PermissionToken<Dangerous> = PermissionToken::mint();
        assert_eq!(read_state(&ro), 42);
        assert_eq!(read_state(&w), 42);
        assert_eq!(read_state(&e), 42);
        assert_eq!(read_state(&d), 42);
    }

    /// F-19: typed → erased conversion reports the expected level tag.
    #[cfg(feature = "_host")]
    #[test]
    fn permission_token_any_tags_each_level_correctly() {
        let ro: PermissionToken<ReadOnly> = PermissionToken::mint();
        let w: PermissionToken<Write> = PermissionToken::mint();
        let e: PermissionToken<Execute> = PermissionToken::mint();
        let d: PermissionToken<Dangerous> = PermissionToken::mint();
        assert_eq!(PermissionTokenAny::from(ro).level(), "read_only");
        assert_eq!(PermissionTokenAny::from(w).level(), "write");
        assert_eq!(PermissionTokenAny::from(e).level(), "execute");
        assert_eq!(PermissionTokenAny::from(d).level(), "dangerous");
    }

    /// F-19: `satisfies` mirrors the [`AtLeast`] lattice at runtime.
    /// Every level satisfies its own requirement + every lower one;
    /// strictly higher requirements fail; unknown level strings always
    /// fail (defensive — an unknown input must not satisfy a requirement).
    #[cfg(feature = "_host")]
    #[test]
    fn permission_token_any_satisfies_matches_atleast_lattice() {
        let ro: PermissionTokenAny = PermissionToken::<ReadOnly>::mint().into();
        let w: PermissionTokenAny = PermissionToken::<Write>::mint().into();
        let e: PermissionTokenAny = PermissionToken::<Execute>::mint().into();
        let d: PermissionTokenAny = PermissionToken::<Dangerous>::mint().into();

        // Reflexive
        assert!(ro.satisfies("read_only"));
        assert!(w.satisfies("write"));
        assert!(e.satisfies("execute"));
        assert!(d.satisfies("dangerous"));

        // Upward closure
        assert!(d.satisfies("read_only"));
        assert!(d.satisfies("write"));
        assert!(d.satisfies("execute"));
        assert!(e.satisfies("read_only"));
        assert!(e.satisfies("write"));
        assert!(w.satisfies("read_only"));

        // Strictly higher requirements fail.
        assert!(!ro.satisfies("write"));
        assert!(!ro.satisfies("execute"));
        assert!(!ro.satisfies("dangerous"));
        assert!(!w.satisfies("execute"));
        assert!(!w.satisfies("dangerous"));
        assert!(!e.satisfies("dangerous"));

        // Unknown level string never satisfies — defensive guard
        // against unknown external input.
        assert!(!d.satisfies("admin"));
        assert!(!d.satisfies(""));
    }
}
