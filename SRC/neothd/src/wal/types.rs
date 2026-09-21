// WAL newtypes + enums -- SPEC_wire_header_v2_slim.md §3.1, §5, §8
// All newtypes are compile-time distinct (no accidental EventId/SessionId mixups).

use std::fmt;
use std::path::Path;

use bitflags::bitflags;
use hmac::{Hmac, Mac};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use sha2::Sha256;
use zeroize::Zeroize;

use super::error::HeaderParseError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(pub u64);

impl EventId {
    pub const NONE: EventId = EventId(0);
    pub fn raw(&self) -> u64 {
        self.0
    }
}

/// GOLD-ARCH-20: coarse fan-out routing tag in `EventHeaderV2`, evaluated
/// before payload decode (SPEC_wire_header_v2_slim.md §7). Newtype over the
/// wire `u32` so a raw integer (or a `WalCategory`) can't be passed where a
/// scope is expected. `#[repr(transparent)]` + LE passthrough keep the
/// 96-byte wire format byte-identical — `PROG-19`'s pinned-offset oracle
/// still holds.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct WalScope(pub u32);

impl WalScope {
    /// No routing scope — the production default (no code sets a non-zero
    /// scope yet; reserved for future fan-out routing).
    pub const UNSET: Self = Self(0);
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
    pub const fn from_le_bytes(b: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(b))
    }
}

/// GOLD-ARCH-20: routing tag paired with [`WalScope`] in `EventHeaderV2`
/// (SPEC_wire_header_v2_slim.md §7). Distinct newtype so scope and category
/// can't be swapped at a construction site. Wire-format byte-identical.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct WalCategory(pub u32);

impl WalCategory {
    /// No routing category — the production default.
    pub const UNSET: Self = Self(0);
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
    pub const fn from_le_bytes(b: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(b))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    pub const ZERO: SessionId = SessionId([0u8; 16]);

    pub fn from_bytes(b: [u8; 16]) -> Self {
        SessionId(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// `ZERO` is the durable legacy/unattributed sentinel. It is not a named
    /// session and callers requesting it must use [`SessionPartition::UNATTRIBUTED`].
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// Canonical, opaque operator representation. The raw admitted logical
    /// identifier never belongs in WAL output or a query filter.
    pub fn opaque_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse only the exact lower-hex representation emitted by
    /// [`SessionId::opaque_hex`]. Accepting arbitrary casing, a UUID shape, or
    /// a raw logical label would turn this display representation into an
    /// attribution authority.
    pub fn from_opaque_hex(value: &str) -> Result<Self, SessionIdTextError> {
        if value.len() != 32 {
            return Err(SessionIdTextError::WrongLength);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit()))
        {
            return Err(SessionIdTextError::InvalidLowerHex);
        }
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| SessionIdTextError::InvalidLowerHex)?;
        Ok(Self(bytes))
    }
}

/// Strict parse failure for the opaque session representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionIdTextError {
    WrongLength,
    InvalidLowerHex,
}

impl fmt::Display for SessionIdTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => f.write_str("WAL session ID must be exactly 32 lower-hex characters"),
            Self::InvalidLowerHex => f.write_str("WAL session ID must use canonical lower-hex"),
        }
    }
}

impl std::error::Error for SessionIdTextError {}

/// Selection semantics for readers. Its representation is private so an
/// external caller cannot construct the invalid state `Exact(SessionId::ZERO)`
/// and silently merge legacy/unattributed rows into a named session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionPartition(SessionPartitionKind);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SessionPartitionKind {
    Any,
    Exact(SessionId),
    Unattributed,
}

impl SessionPartition {
    /// Existing broad query behaviour. Consumers that promise one session must
    /// use [`SessionPartition::exact`] instead.
    pub const ANY: Self = Self(SessionPartitionKind::Any);
    /// Only legacy/no-session records (`SessionId::ZERO`).
    pub const UNATTRIBUTED: Self = Self(SessionPartitionKind::Unattributed);

    pub fn exact(session_id: SessionId) -> Result<Self, SessionPartitionError> {
        if session_id.is_zero() {
            return Err(SessionPartitionError::ZeroMustBeUnattributed);
        }
        Ok(Self(SessionPartitionKind::Exact(session_id)))
    }

    /// Strict CLI/API parsing. `unattributed` is the sole spelling for the
    /// zero bucket; a non-zero value must be the canonical opaque lower-hex.
    pub fn from_filter(value: &str) -> Result<Self, SessionPartitionError> {
        if value == "unattributed" {
            return Ok(Self::UNATTRIBUTED);
        }
        Self::exact(SessionId::from_opaque_hex(value).map_err(SessionPartitionError::InvalidId)?)
    }

    /// The validated non-zero identity for a SQL equality predicate, if this
    /// partition represents one named session.
    pub fn exact_id(self) -> Option<SessionId> {
        match self.0 {
            SessionPartitionKind::Exact(session_id) => Some(session_id),
            SessionPartitionKind::Any | SessionPartitionKind::Unattributed => None,
        }
    }

    pub fn is_any(self) -> bool {
        matches!(self.0, SessionPartitionKind::Any)
    }

    pub fn is_unattributed(self) -> bool {
        matches!(self.0, SessionPartitionKind::Unattributed)
    }

    pub fn matches(self, session_id: SessionId) -> bool {
        match self.0 {
            SessionPartitionKind::Any => true,
            SessionPartitionKind::Exact(expected) => expected == session_id,
            SessionPartitionKind::Unattributed => session_id.is_zero(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPartitionError {
    InvalidId(SessionIdTextError),
    ZeroMustBeUnattributed,
}

impl fmt::Display for SessionPartitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(error) => error.fmt(f),
            Self::ZeroMustBeUnattributed => {
                f.write_str("the zero WAL session ID must be selected as `unattributed`")
            }
        }
    }
}

impl std::error::Error for SessionPartitionError {}

/// Explicit, copyable authority to stamp one already-admitted turn's WAL
/// events. Its public type name satisfies public audit-sink signatures, while
/// its field and every minting or header-access method remain crate-private.
/// Request payloads, provider audit metadata, and serialised sub-agent tasks
/// therefore cannot select or inspect a session.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalSessionContext(SessionId);

impl fmt::Debug for WalSessionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WalSessionContext(<opaque>)")
    }
}

/// Upper bound for a canonical identity tuple passed by an admission adapter.
/// This bounds HMAC work before a value becomes durable header metadata.
pub(crate) const MAX_ADMITTED_IDENTITY_BYTES: usize = 4096;
const WAL_SESSION_ID_DOMAIN: &[u8] = b"neoth/wal/session-id/v1\0";

impl WalSessionContext {
    /// Derive an opaque, non-zero header ID from a **canonicalised,
    /// already-admitted** identity tuple. The caller must supply an
    /// unambiguous, length-delimited tuple and retain this context across
    /// retries/fallbacks rather than re-deriving it at a later leaf.
    ///
    /// The existing home-bound WAL HMAC key is used read-only. This function
    /// never creates key material: caller integration must run after the WAL
    /// writer has initialized the instance namespace. Key rotation therefore
    /// cannot change a live turn because the derived context, not its source,
    /// is propagated to every child.
    pub(crate) fn from_admitted_identity(
        home: &Path,
        canonical_identity: &[u8],
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !canonical_identity.is_empty(),
            "refuse empty admitted WAL session identity"
        );
        anyhow::ensure!(
            canonical_identity.len() <= MAX_ADMITTED_IDENTITY_BYTES,
            "admitted WAL session identity exceeds {} bytes",
            MAX_ADMITTED_IDENTITY_BYTES
        );

        let key_path = home.join("wal").join("hmac.key");
        let mut key = super::compaction::load_existing_home_key(home, &key_path)
            .map_err(|error| anyhow::anyhow!("load existing WAL session authority: {error:#}"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|_| anyhow::anyhow!("initialize WAL session HMAC"))?;
        key.zeroize();
        mac.update(WAL_SESSION_ID_DOMAIN);
        mac.update(&(canonical_identity.len() as u64).to_be_bytes());
        mac.update(canonical_identity);
        let digest = mac.finalize().into_bytes();
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&digest[..16]);
        let session_id = SessionId(raw);
        anyhow::ensure!(
            !session_id.is_zero(),
            "refuse all-zero derived WAL session identity"
        );
        Ok(Self(session_id))
    }

    pub(crate) const fn header_id(self) -> SessionId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    pub const ZERO: NodeId = NodeId([0u8; 16]);

    pub fn from_bytes(b: [u8; 16]) -> Self {
        NodeId(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Importance score bounded [0.0, 1.0]. NaN unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Importance(f32);

impl Importance {
    pub const ZERO: Importance = Importance(0.0);
    pub const MAX: Importance = Importance(1.0);
    pub const PROMOTION_THRESHOLD: Importance = Importance(0.75);

    pub fn new(v: f32) -> Result<Self, HeaderParseError> {
        if v.is_nan() || !(0.0..=1.0).contains(&v) {
            return Err(HeaderParseError::InvalidImportance(v));
        }
        Ok(Self(v))
    }

    pub fn raw(&self) -> f32 {
        self.0
    }
}

impl Eq for Importance {}

impl Ord for Importance {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .expect("Importance: NaN excluded at construction")
    }
}

/// Region routing tag. 0=None means event does not target a brain-region view.
#[repr(u8)]
#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionTag {
    None = 0,
    Hippocampus = 1,
    Amygdala = 2,
    Insula = 3,
    Cerebellum = 4,
    BasalGanglia = 5,
    Hypothalamus = 6,
}

/// Originator: who produced this event. v1.1 fix S4 (was `hemisphere` with `4=BOTH`).
#[repr(u8)]
#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Originator {
    NA = 0,
    Left = 1,
    Right = 2,
    Callosum = 3,
    Council = 4,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EventFlags: u8 {
        const TOMBSTONE      = 0x01;
        const SUPERSEDED     = 0x02;
        const SYNTHETIC      = 0x04;
        const REDACTED       = 0x08;
        const STREAM_PARTIAL = 0x10;
        // bits 5..7 reserved; parser rejects if any are set.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn importance_rejects_nan() {
        assert!(Importance::new(f32::NAN).is_err());
    }

    #[test]
    fn importance_rejects_out_of_range() {
        assert!(Importance::new(-0.1).is_err());
        assert!(Importance::new(1.01).is_err());
    }

    #[test]
    fn importance_accepts_bounds() {
        assert_eq!(Importance::new(0.0).unwrap().raw(), 0.0);
        assert_eq!(Importance::new(1.0).unwrap().raw(), 1.0);
    }

    #[test]
    fn region_tag_roundtrip() {
        for v in 0u8..=6 {
            let tag = RegionTag::try_from(v).unwrap();
            let back: u8 = tag.into();
            assert_eq!(back, v);
        }
        assert!(RegionTag::try_from(7u8).is_err());
    }

    #[test]
    fn originator_roundtrip() {
        for v in 0u8..=4 {
            let o = Originator::try_from(v).unwrap();
            let back: u8 = o.into();
            assert_eq!(back, v);
        }
        assert!(Originator::try_from(5u8).is_err());
    }

    #[test]
    fn event_flags_rejects_reserved_bits() {
        assert!(EventFlags::from_bits(0xE0).is_none());
        assert!(EventFlags::from_bits(0x1F).is_some());
    }

    #[test]
    fn session_id_opaque_hex_is_canonical_and_strict() {
        let id = SessionId([0xabu8; 16]);
        let rendered = id.opaque_hex();
        assert_eq!(rendered, "ab".repeat(16));
        assert_eq!(SessionId::from_opaque_hex(&rendered).unwrap(), id);
        assert!(matches!(
            SessionId::from_opaque_hex(&rendered.to_uppercase()),
            Err(SessionIdTextError::InvalidLowerHex)
        ));
        assert!(matches!(
            SessionId::from_opaque_hex("abc"),
            Err(SessionIdTextError::WrongLength)
        ));
    }

    #[test]
    fn session_partition_never_treats_zero_as_named_session() {
        let zero_filter = SessionId::ZERO.opaque_hex();
        assert!(matches!(
            SessionPartition::exact(SessionId::ZERO),
            Err(SessionPartitionError::ZeroMustBeUnattributed)
        ));
        assert!(matches!(
            SessionPartition::from_filter(&zero_filter),
            Err(SessionPartitionError::ZeroMustBeUnattributed)
        ));
        assert_eq!(
            SessionPartition::from_filter("unattributed").unwrap(),
            SessionPartition::UNATTRIBUTED
        );
        assert!(SessionPartition::UNATTRIBUTED.matches(SessionId::ZERO));
        assert!(!SessionPartition::UNATTRIBUTED.matches(SessionId([1u8; 16])));
        assert!(SessionPartition::UNATTRIBUTED.exact_id().is_none());
        assert!(SessionPartition::exact(SessionId([1u8; 16]))
            .unwrap()
            .exact_id()
            .is_some());
    }

    #[test]
    fn admitted_context_is_stable_nonzero_and_home_bound() {
        let first_home = tempfile::tempdir().unwrap();
        let second_home = tempfile::tempdir().unwrap();
        let first_key = first_home.path().join("wal").join("hmac.key");
        let second_key = second_home.path().join("wal").join("hmac.key");
        crate::wal::compaction::load_or_init_key(&first_key).unwrap();
        crate::wal::compaction::load_or_init_key(&second_key).unwrap();

        let first = WalSessionContext::from_admitted_identity(first_home.path(), b"cli\0operator\0turn-7")
            .unwrap();
        let same = WalSessionContext::from_admitted_identity(first_home.path(), b"cli\0operator\0turn-7")
            .unwrap();
        let other_identity =
            WalSessionContext::from_admitted_identity(first_home.path(), b"cli\0operator\0turn-8")
                .unwrap();
        let other_home =
            WalSessionContext::from_admitted_identity(second_home.path(), b"cli\0operator\0turn-7")
                .unwrap();

        assert_eq!(first.header_id(), same.header_id());
        assert_ne!(first.header_id(), other_identity.header_id());
        assert_ne!(first.header_id(), other_home.header_id());
        assert!(!first.header_id().is_zero());
        assert_eq!(first.header_id().opaque_hex().len(), 32);
    }

    #[test]
    fn admitted_context_rejects_empty_or_unbounded_identity_before_attribution() {
        let home = tempfile::tempdir().unwrap();
        assert!(WalSessionContext::from_admitted_identity(home.path(), b"").is_err());
        let oversized = vec![b'x'; MAX_ADMITTED_IDENTITY_BYTES + 1];
        assert!(WalSessionContext::from_admitted_identity(home.path(), &oversized).is_err());
        assert!(
            !home.path().join("wal").exists(),
            "invalid identity must not create a WAL authority"
        );
    }
}
