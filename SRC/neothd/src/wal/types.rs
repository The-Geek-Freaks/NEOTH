// WAL newtypes + enums -- SPEC_wire_header_v2_slim.md §3.1, §5, §8
// All newtypes are compile-time distinct (no accidental EventId/SessionId mixups).

use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};

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
}
