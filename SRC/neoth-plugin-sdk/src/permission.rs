//! PermissionToken typestate (S3 fix from ADVERSARIAL/03).
//!
//! Compile-time enforcement: every host hostcall takes a
//! `&PermissionToken<L>` of the appropriate level. Plugin authors cannot
//! forge tokens because:
//!   1. `PermissionLevel` is sealed (private trait + `sealed::Sealed`).
//!   2. `PermissionToken::mint()` is gated behind the `_host` Cargo feature.
//!      Plugin crates do NOT enable that feature.
//!   3. `PermissionToken<L>` is zero-sized but cannot be constructed by safe
//!      code without `mint()` — no `Default`, no public fields.
//!
//! Upgrade transitions require a `FreedomGrant<L>` from the host — also
//! sealed via `_host`.

use std::marker::PhantomData;

mod sealed {
    /// Private sub-trait; external crates cannot implement `PermissionLevel`.
    pub trait Sealed {}
}

/// Marker trait for permission-level types. Sealed.
pub trait PermissionLevel: sealed::Sealed + 'static {}

/// No authority. Default for plugin-issued contexts before any grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct None;

/// Permission to call host tools that read state without mutating it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnly;

/// Permission to mutate vault state (WAL appends, SQLite writes,
/// `~/.neoth/` file writes) — but NOT to make external network calls
/// or spawn processes. F-17: separates DB writes from RPC so a hook
/// that needs to update memory does not need to authorise outbound
/// HTTP. Ladder is `ReadOnly → Write → Execute → Dangerous`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write;

/// Permission to call host tools that perform external network calls
/// (LLM provider HTTP, channel sends, MCP server spawn). Implies
/// `Write` (you can mutate state on the way out / in).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Execute;

/// Permission to invoke shell-like operations: process spawn, raw filesystem,
/// arbitrary network. Requires hardware-2FA grant on most operator profiles.
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
/// `M`". Host tools use this as a generic bound so any higher-or-equal
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

/// Compile-time proof of authorization to invoke host tools at level `L`.
///
/// Zero-sized — costs nothing at runtime. Cannot be constructed by plugin
/// crates because `mint()` is gated behind the `_host` Cargo feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionToken<L: PermissionLevel> {
    _level: PhantomData<L>,
}

impl<L: PermissionLevel> PermissionToken<L> {
    /// Host-internal token minting. Plugin authors do NOT have access to this
    /// function — the `_host` Cargo feature is private to `neothd`.
    #[cfg(feature = "_host")]
    pub fn mint() -> Self {
        PermissionToken {
            _level: PhantomData,
        }
    }
}

/// Operator-issued grant that authorizes a host runtime to mint a token of
/// level `L`. Sealed via `_host` feature like `PermissionToken::mint()`.
///
/// In the host, a `FreedomGrant<L>` is produced by validating
/// `~/.neoth/freedom.yaml` capabilities + (for Dangerous) hardware 2FA.
#[derive(Debug)]
pub struct FreedomGrant<L: PermissionLevel> {
    _level: PhantomData<L>,
}

impl<L: PermissionLevel> FreedomGrant<L> {
    /// Host-internal grant minting.
    #[cfg(feature = "_host")]
    pub fn issue() -> Self {
        FreedomGrant {
            _level: PhantomData,
        }
    }
}

/// Upgrade `ReadOnly -> Write` with a `FreedomGrant<Write>`. F-17:
/// new intermediate step in the ladder so a hook that needs DB writes
/// without network access can hold the minimal authority.
///
/// F-20 (rust-reviewer H-4): every upgrade fn is `_host`-feature
/// gated. Plugin crates cannot enable that feature, so a plugin
/// holding a `ReadOnly` token cannot call upgrade even if it
/// somehow obtained a `FreedomGrant<Write>`. The grant constructor
/// (`FreedomGrant::issue()`) is also `_host`-gated, but a layered
/// defence keeps the path closed under future refactors that might
/// accidentally expose a grant.
impl PermissionToken<ReadOnly> {
    /// Consume self and a `Write` grant to produce a `Write` token.
    #[cfg(feature = "_host")]
    pub fn upgrade_to_write(self, _grant: FreedomGrant<Write>) -> PermissionToken<Write> {
        PermissionToken {
            _level: PhantomData,
        }
    }

    /// Shortcut upgrade `ReadOnly -> Execute` with a `FreedomGrant<Execute>`.
    /// Retained for callers that need outbound network without going
    /// through the intermediate `Write` step; the operator's grant
    /// authorises the larger surface directly.
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

/// Error returned when a runtime check determines a plugin lacks the required
/// permission level (e.g. via hostcall_allowlist in the WASM Phase 2 host).
#[derive(thiserror::Error, Debug)]
#[error("plugin lacks required permission level: needs {required:?}, has {actual:?}")]
pub struct UnauthorizedLevel {
    /// Permission level the host requires for this operation.
    pub required: &'static str,
    /// Permission level the plugin holds at the call site.
    pub actual: &'static str,
}

/// Runtime-tagged permission token (F-19 step 1).
///
/// `PermissionToken<L>` is zero-cost + compile-time safe but its
/// type parameter makes a heterogeneous registry (a `HashMap` of
/// hooks at different levels) impossible without per-level boxing.
/// `PermissionTokenAny` erases the level into a tag so the host can
/// dispatch hooks of mixed levels through one collection. Plugin
/// authors stay on `PermissionToken<L>`; the host converts via
/// `to_any()` only at the dispatch boundary.
///
/// The level tag is the same `&'static str` the trait-level shape
/// already uses (`"read_only"` / `"write"` / `"execute"` /
/// `"dangerous"` / `"none"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionTokenAny {
    /// Wraps a `PermissionToken<None>` — no authority granted yet.
    None(PermissionToken<None>),
    /// Wraps a `PermissionToken<ReadOnly>` — host-state reads only.
    ReadOnly(PermissionToken<ReadOnly>),
    /// Wraps a `PermissionToken<Write>` — vault mutations, no network.
    Write(PermissionToken<Write>),
    /// Wraps a `PermissionToken<Execute>` — outbound network + RPC.
    Execute(PermissionToken<Execute>),
    /// Wraps a `PermissionToken<Dangerous>` — process spawn + raw FS.
    Dangerous(PermissionToken<Dangerous>),
}

impl PermissionTokenAny {
    /// Stable string id for the wrapped level. Matches the snake_case
    /// names used by the wire schema in `freedom.yaml::capabilities`.
    pub fn level(&self) -> &'static str {
        match self {
            PermissionTokenAny::None(_) => "none",
            PermissionTokenAny::ReadOnly(_) => "read_only",
            PermissionTokenAny::Write(_) => "write",
            PermissionTokenAny::Execute(_) => "execute",
            PermissionTokenAny::Dangerous(_) => "dangerous",
        }
    }

    /// True when the held level is >= `required` per the [`AtLeast`]
    /// lattice. Useful for the runtime check the host performs at
    /// the hostcall_allowlist boundary.
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

/// Conversions from typed token to type-erased token. Plugin code
/// rarely needs the reverse direction — the host minted the typed
/// variant, and downcasting back to a specific level requires the
/// caller to commit at compile time which is what `PermissionToken<L>`
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

    // These tests run under the `_host` feature only. With default features
    // (plugin author setup), `mint()` is unavailable and these would not
    // compile — that's the point.
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

    /// F-18: the practical use-case — a generic host tool gated by an
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
    /// fail (defensive — operator typo should not silently grant).
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
        // against operator typos in freedom.yaml.
        assert!(!d.satisfies("admin"));
        assert!(!d.satisfies(""));
    }
}
