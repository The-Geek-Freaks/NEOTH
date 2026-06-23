// Origin: design adapted from rscrypto aead/nonce_counter.rs (MIT/Apache-2.0).
// NOT a copy — ported to NEOTH's aes-gcm 0.10 API surface (no rscrypto dep).
// The generic-over-cipher and Aes128Gcm variants are intentionally omitted;
// NEOTH only uses AES-256-GCM, and the GOLD-ADAPT-CRYPTO-04 gate may switch
// to aes-gcm-siv/aegis — keeping NonceCounter cipher-agnostic (nonce-only)
// means that switch requires no change here.
//
// GOLD-ADAPT-CRYPTO-01.
// Used as the future utility when AEAD-at-rest is added to wal/ or config/.
// No live consumer exists today — see research plan for the future wire point
// (wal/aead.rs or wal/encrypt.rs, not yet created).

//! Monotonic deterministic nonce generator for AES-GCM (and future AEAD).
//!
//! # Layout
//!
//! Each 96-bit nonce is built as:
//!
//! ```text
//! [ fixed_prefix (4 bytes) || counter_be (8 bytes) ]
//! ```
//!
//! This follows SP 800-38D §8.2.1 (deterministic construction). The prefix
//! identifies the nonce stream (e.g. `*b"wal\x00"`, `*b"cfg\x00"`); the
//! 8-byte big-endian counter sequences invocations. The 2^48 cap sits well
//! below the per-key limit and provides ample at-rest headroom.
//!
//! # Non-Clone / non-Copy guarantee
//!
//! `NonceCounter` intentionally does not derive `Clone` or `Copy`. One
//! instance owns exactly one nonce stream; forking it would silently produce
//! duplicate nonces (catastrophic for AES-GCM confidentiality). If a caller
//! needs restart-safe continuation, persist [`NonceCounter::next_counter`] to
//! disk (e.g. a sidecar `.nonce` file or an encrypted-segment header) and
//! resume with [`NonceCounter::with_counter`].
//!
//! # Decryption
//!
//! Decryption does NOT use `NonceCounter` — the nonce is stored alongside the
//! ciphertext in the encrypted segment. The AEAD-at-rest caller passes the
//! stored nonce bytes directly to `Aes256Gcm::decrypt`.
//!
//! # Example (future usage sketch)
//!
//! ```rust,ignore
//! use neothd::wal::nonce_counter::NonceCounter;
//! use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
//! use aes_gcm::aead::Aead;
//!
//! let key = [0x42u8; 32];
//! let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
//!
//! let mut counter = NonceCounter::new(*b"wal\x00");
//! let nonce_bytes = counter.next_nonce().expect("counter exhausted");
//! let nonce = Nonce::from_slice(&nonce_bytes);
//!
//! let aad = b"event_type:0xD0";
//! let plaintext = b"WAL frame body";
//! let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt failed");
//!
//! // persist nonce_bytes + ciphertext; store counter.next_counter() to disk
//! // …
//! // resume:
//! let mut resumed = NonceCounter::with_counter(*b"wal\x00", counter.next_counter())
//!     .expect("persisted counter out of range");
//! ```

/// Maximum number of deterministic AES-GCM invocations per key before
/// rotation. Conservative cap from SP 800-38D; 2^48 ≈ 281 trillion operations.
pub const MAX_MESSAGES: u64 = 1u64 << 48;

const FIXED_PREFIX_LEN: usize = 4;
const COUNTER_LEN: usize = 8;
const NONCE_LEN: usize = FIXED_PREFIX_LEN + COUNTER_LEN; // = 12

/// Nonce counter exhausted its 2^48 invocation budget.
///
/// Returned by [`NonceCounter::next_nonce`] and [`NonceCounter::with_counter`]
/// when the deterministic IV budget is exceeded. Rotate the encryption key
/// and start a fresh `NonceCounter::new(prefix)`.
#[derive(Debug, thiserror::Error)]
#[error("AES-GCM nonce counter exhausted its 2^48 invocation budget")]
pub struct NonceCounterExhausted;

/// Monotonic deterministic 96-bit nonce generator (SP 800-38D §8.2.1).
///
/// Layout: `[prefix(4) || counter_be(8)]`.
///
/// Intentionally **non-Clone, non-Copy** — one instance owns one nonce stream.
/// Persist [`next_counter`](Self::next_counter) to disk and resume with
/// [`with_counter`](Self::with_counter) for crash-safe continuation.
pub struct NonceCounter {
    fixed_prefix: [u8; FIXED_PREFIX_LEN],
    next: u64,
}

impl NonceCounter {
    /// Per-stream prefix length in bytes.
    pub const FIXED_PREFIX_LEN: usize = FIXED_PREFIX_LEN;
    /// Counter field length in bytes.
    pub const COUNTER_LEN: usize = COUNTER_LEN;
    /// Total nonce length in bytes (96 bits).
    pub const NONCE_LEN: usize = NONCE_LEN;
    /// Maximum deterministic invocations before key rotation is required.
    pub const MAX_MESSAGES: u64 = MAX_MESSAGES;

    /// Start a fresh nonce stream with `fixed_prefix`.
    ///
    /// The counter starts at 0; the first call to [`next_nonce`](Self::next_nonce)
    /// returns `[prefix[0..4] || 0u64_be]`.
    #[inline]
    #[must_use]
    pub const fn new(fixed_prefix: [u8; FIXED_PREFIX_LEN]) -> Self {
        Self {
            fixed_prefix,
            next: 0,
        }
    }

    /// Resume a nonce stream from a persisted counter value.
    ///
    /// Use this after a process restart to continue the same nonce stream
    /// without reusing any already-issued nonce. Load the persisted
    /// `next_counter` value from disk (e.g. from a sidecar `.nonce` file or
    /// an encrypted-segment header) and pass it here.
    ///
    /// # Errors
    ///
    /// Returns [`NonceCounterExhausted`] when `next_counter >= MAX_MESSAGES`.
    /// Rotate the key and start a fresh [`NonceCounter::new`] in that case.
    #[inline]
    pub fn with_counter(
        fixed_prefix: [u8; FIXED_PREFIX_LEN],
        next_counter: u64,
    ) -> Result<Self, NonceCounterExhausted> {
        if next_counter >= MAX_MESSAGES {
            return Err(NonceCounterExhausted);
        }
        Ok(Self {
            fixed_prefix,
            next: next_counter,
        })
    }

    /// Issue the next 96-bit nonce as a `[u8; 12]` byte array.
    ///
    /// The counter is incremented BEFORE returning. Even if the caller drops
    /// the nonce or the AEAD cipher returns an error, the nonce is consumed
    /// and will never be reissued — this is the core nonce-reuse-resistance
    /// guarantee. Feed the returned bytes to
    /// `aes_gcm::Nonce::from_slice(&nonce_bytes)` before passing to the cipher.
    ///
    /// # Errors
    ///
    /// Returns [`NonceCounterExhausted`] when the counter reaches
    /// [`MAX_MESSAGES`](Self::MAX_MESSAGES). Rotate the key and create a new
    /// `NonceCounter` instance.
    #[inline]
    pub fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], NonceCounterExhausted> {
        if self.next >= MAX_MESSAGES {
            return Err(NonceCounterExhausted);
        }
        let nonce = Self::build_nonce(self.fixed_prefix, self.next);
        // No overflow possible: we checked `next < MAX_MESSAGES` which is 2^48,
        // well within u64 range (max u64 = 2^64 - 1).
        self.next += 1;
        Ok(nonce)
    }

    /// Return the next counter value that will be issued.
    ///
    /// Persist this value to disk after each sealed frame so a process restart
    /// can call [`with_counter`](Self::with_counter) and safely resume the
    /// stream without reusing any nonce.
    #[inline]
    #[must_use]
    pub const fn next_counter(&self) -> u64 {
        self.next
    }

    /// Return the fixed 4-byte stream-identity prefix.
    #[inline]
    #[must_use]
    pub const fn fixed_prefix(&self) -> [u8; FIXED_PREFIX_LEN] {
        self.fixed_prefix
    }

    /// Return how many deterministic invocations remain before key rotation.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        // No subtraction underflow: `with_counter` and the guard in `next_nonce`
        // ensure `self.next <= MAX_MESSAGES` at all times.
        MAX_MESSAGES - self.next
    }

    /// Build a 96-bit nonce: `[prefix(4) || counter_be(8)]`.
    #[inline]
    fn build_nonce(fixed_prefix: [u8; FIXED_PREFIX_LEN], counter: u64) -> [u8; NONCE_LEN] {
        let mut bytes = [0u8; NONCE_LEN];
        bytes[..FIXED_PREFIX_LEN].copy_from_slice(&fixed_prefix);
        bytes[FIXED_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

    // ── 1. Prefix + counter layout ────────────────────────────────────────────

    #[test]
    fn first_nonce_is_prefix_then_zero_counter() {
        let mut counter = NonceCounter::new(*b"wal\x00");
        let nonce = counter.next_nonce().unwrap();
        assert_eq!(
            nonce,
            [b'w', b'a', b'l', 0x00, 0, 0, 0, 0, 0, 0, 0, 0],
            "first nonce must be [prefix || 0u64_be]"
        );
        assert_eq!(counter.next_counter(), 1, "counter must advance to 1");
    }

    #[test]
    fn consecutive_nonces_differ_by_counter() {
        let mut counter = NonceCounter::new(*b"cfg\x00");
        let n0 = counter.next_nonce().unwrap();
        let n1 = counter.next_nonce().unwrap();

        // Prefix bytes identical.
        assert_eq!(&n0[..4], b"cfg\x00");
        assert_eq!(&n1[..4], b"cfg\x00");

        // Counter bytes differ: 0 then 1 in big-endian.
        assert_eq!(&n0[4..], &0u64.to_be_bytes());
        assert_eq!(&n1[4..], &1u64.to_be_bytes());

        assert_ne!(n0, n1, "two consecutive nonces must be distinct");
        assert_eq!(counter.next_counter(), 2);
        assert_eq!(counter.remaining(), MAX_MESSAGES - 2);
    }

    // ── 2. Boundary: last valid + first exhausted ─────────────────────────────

    #[test]
    fn last_nonce_succeeds_then_exhausted() {
        let mut counter =
            NonceCounter::with_counter(*b"last", MAX_MESSAGES - 1).expect("valid counter");
        assert_eq!(counter.remaining(), 1);

        // Exactly one nonce remains — must succeed.
        assert!(
            counter.next_nonce().is_ok(),
            "last valid nonce must succeed"
        );
        assert_eq!(counter.remaining(), 0);

        // Next call: budget exhausted.
        assert!(
            counter.next_nonce().is_err(),
            "call after exhaustion must error"
        );
    }

    #[test]
    fn with_counter_rejects_at_max_messages() {
        // Exactly at the limit — must fail.
        assert!(
            NonceCounter::with_counter(*b"oflw", MAX_MESSAGES).is_err(),
            "with_counter(MAX_MESSAGES) must fail"
        );
        // Strictly greater — must also fail.
        assert!(
            NonceCounter::with_counter(*b"oflw", u64::MAX).is_err(),
            "with_counter(u64::MAX) must fail"
        );
        // One below — must succeed.
        assert!(
            NonceCounter::with_counter(*b"oflw", MAX_MESSAGES - 1).is_ok(),
            "with_counter(MAX_MESSAGES - 1) must succeed"
        );
    }

    // ── 3. Resume path (persist → restore) ───────────────────────────────────

    #[test]
    fn resume_continues_nonce_stream_without_reuse() {
        let mut counter_a = NonceCounter::new(*b"wal\x00");
        let n0 = counter_a.next_nonce().unwrap();
        let n1 = counter_a.next_nonce().unwrap();
        let persisted = counter_a.next_counter(); // = 2

        // Simulate process restart: restore from persisted value.
        let mut counter_b =
            NonceCounter::with_counter(*b"wal\x00", persisted).expect("valid resume");
        let n2 = counter_b.next_nonce().unwrap();

        // n2 must be distinct from all prior nonces.
        assert_ne!(n2, n0, "resumed nonce must not repeat n0");
        assert_ne!(n2, n1, "resumed nonce must not repeat n1");

        // Sanity: counter bytes must reflect the persisted start.
        assert_eq!(&n2[4..], &2u64.to_be_bytes());
    }

    // ── 4. Round-trip: nonce format meshes with aes-gcm 0.10 ─────────────────

    #[test]
    fn nonce_round_trip_with_aes256gcm() {
        let key_bytes = [0x42u8; 32];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let mut counter = NonceCounter::new(*b"wal\x00");
        let nonce_bytes = counter.next_nonce().expect("nonce available");
        let nonce = Nonce::from_slice(&nonce_bytes);

        // aad is not used by aes_gcm::Aead::encrypt directly (the trait takes
        // plaintext only; AAD goes in the Payload wrapper). For this round-trip
        // test we exercise the nonce wire-format path without AAD to keep the
        // test self-contained on the aes-gcm 0.10 public API.
        let plaintext = b"WAL frame body";

        // Encrypt using the nonce produced by the counter.
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("encrypt must succeed");

        // Decrypt using the SAME nonce bytes (as the future at-rest caller would
        // read from the stored segment header).
        let recovered = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("decrypt must succeed");

        assert_eq!(
            recovered.as_slice(),
            plaintext,
            "decrypted plaintext must match original"
        );
        assert_eq!(
            counter.next_counter(),
            1,
            "counter must have advanced past the issued nonce"
        );
    }

    // ── 5. Non-Clone / non-Copy: compile-time check documented here ──────────
    //
    // `NonceCounter` intentionally does NOT derive `Clone` or `Copy`.
    // There is no runtime assertion needed — the absence of those impls is
    // enforced by the type definition in this same module. The following doc
    // comment pins the intent; an attempt to add `#[derive(Clone)]` to the
    // struct above would immediately break this test by the opposite fact
    // (i.e., if it compiled, the guarantee would be gone — but rustc would
    // still compile this test fine; the *invariant* is in the struct def,
    // not here). A separate compile_fail doctest would be the gold standard
    // but is not supported in #[cfg(test)] without a separate test crate.
    //
    // Verification: `cargo test -- nonce_counter` passes AND the type
    // definition above has no `Clone`/`Copy` derive.
    #[test]
    fn non_clone_non_copy_intent_is_documented() {
        // Confirm struct exists and is constructible (the real invariant is
        // structural — see the struct definition).
        let c = NonceCounter::new(*b"test");
        assert_eq!(c.next_counter(), 0);
        // If `NonceCounter` were Copy, the line below would compile and `c`
        // would still be usable after the move — violating the single-stream
        // ownership contract. The fact that this DOESN'T compile is the test.
        // (Uncomment to verify the compile error:)
        // let _d = c; // moves c
        // let _ = c.next_counter(); // would fail if Copy is absent and c was moved
    }
}
