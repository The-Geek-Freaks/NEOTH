//! Small cross-cutting utilities shared across NEOTH subsystems.
//!
//! Helpers here are deliberately dependency-light and domain-agnostic — they
//! encode one mechanical concern (crash-safe writes, encoding, …) that several
//! modules would otherwise hand-roll inconsistently. Extracted under WS-E
//! (architecture debt) to kill copy-pasted variants.

pub mod atomic_write;
pub mod url_encode;

/// Returns the largest byte index ≤ `cap` that is a valid UTF-8 char boundary.
///
/// Use this instead of a raw `&s[..cap]` or `s.truncate(cap)` when `cap` may
/// fall inside a multibyte codepoint — both of those panic on stable Rust.
/// (`str::floor_char_boundary` is nightly-only; this is the stable equivalent.)
///
/// # Examples
/// ```
/// use neothd::util::byte_floor;
/// let s = "hello€world"; // € = 3 bytes
/// let i = byte_floor(s, 7); // byte 7 is inside €
/// assert_eq!(i, 5);         // floor to before €
/// let _ = &s[..i];          // no panic
/// ```
pub fn byte_floor(s: &str, cap: usize) -> usize {
    let c = cap.min(s.len());
    if s.is_char_boundary(c) {
        c
    } else {
        (0..=c).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::byte_floor;

    #[test]
    fn byte_floor_ascii_exact() {
        assert_eq!(byte_floor("hello", 3), 3);
        let s = "hello";
        let _ = &s[..byte_floor(s, 3)]; // no panic
    }

    #[test]
    fn byte_floor_cap_beyond_len() {
        // cap > len → clamp to len (always a boundary)
        assert_eq!(byte_floor("hi", 100), 2);
    }

    #[test]
    fn byte_floor_zero_cap() {
        assert_eq!(byte_floor("hello", 0), 0);
    }

    #[test]
    fn byte_floor_mid_multibyte_euro() {
        // "€" is 3 bytes (0xE2 0x82 0xAC).
        // Construct: 4 ASCII bytes + "€" + "tail"
        // Byte layout: 0='a' 1='a' 2='a' 3='a' 4=0xE2 5=0x82 6=0xAC 7='t' …
        let s = "aaaa€tail";
        // cap=5 lands at byte 5, inside the 3-byte €; floor → 4
        assert_eq!(byte_floor(s, 5), 4);
        // cap=6 lands at byte 6, still inside €; floor → 4
        assert_eq!(byte_floor(s, 6), 4);
        // cap=7 is the first byte after €; is a boundary
        assert_eq!(byte_floor(s, 7), 7);
        // No panic at any of the above indices
        let _ = &s[..byte_floor(s, 5)];
        let _ = &s[..byte_floor(s, 6)];
        let _ = &s[..byte_floor(s, 7)];
    }

    #[test]
    fn byte_floor_cap_at_exact_char_start() {
        // "€" starts at byte 4; cap exactly on the boundary → return it as-is
        let s = "aaaa€tail";
        assert_eq!(byte_floor(s, 4), 4);
    }
}
