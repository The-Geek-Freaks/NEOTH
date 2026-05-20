// Secret handling -- Security review P0 + P1 fixes.
//
// SecretString: a String wrapper that
//   - returns "[REDACTED]" from Debug and Display impls
//   - zeroes its memory on Drop (manual impl using zeroize::Zeroize)
//   - on Linux,   attempts to mlock      via libc::mlock
//   - on Windows, attempts to VirtualLock via windows-sys
//   - serializes transparently as String (for YAML/JSON config files)
//   - deserializes from String (with the page-lock applied at construction)
//
// Use everywhere a token, API key, or other secret crosses a struct boundary.
// Replacing `String` with `SecretString` is sufficient to block
// `tracing::debug!("{:?}", config)` from leaking the secret to logs/stderr.
//
// Caveats:
// - On Linux: mlock requires CAP_IPC_LOCK. Most desktop users have a low
//   RLIMIT_MEMLOCK (64 KiB default). NEOTH does not fail on mlock error —
//   it logs a warning. For strong at-rest protection, run with
//   `setcap cap_ipc_lock+ep` or `ulimit -l unlimited` (root).
// - On Windows: VirtualLock requires SeLockMemoryPrivilege OR the page must
//   already be in working set (which it always is for a fresh allocation).
//   Default Windows desktop accounts can lock up to the process's minimum
//   working-set size. NEOTH logs a warning on failure — same fallback as
//   Linux: "secret may swap to pagefile/hiberfil".
// - String can reallocate on mutation. `SecretString` does NOT expose any
//   mutating API, so the buffer address is stable from `new()` to `Drop`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroize;

#[derive(Zeroize, Serialize)]
#[serde(transparent)]
pub struct SecretString(String);

// Manual Clone (not derived) so cloned strings also get mlock applied.
impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl SecretString {
    pub fn new(value: String) -> Self {
        let s = Self(value);
        #[cfg(target_os = "linux")]
        s.try_mlock();
        #[cfg(target_os = "windows")]
        s.try_virtual_lock();
        s
    }

    /// Borrow the underlying secret. Caller MUST NOT log, format with Debug,
    /// or expose via API responses. Treat as if it were the raw token.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Best-effort mlock of the underlying byte buffer (Linux only).
    /// Failure (EPERM, ENOMEM) is logged but not propagated — degrades to
    /// "secret may swap to disk", same as a plain String.
    #[cfg(target_os = "linux")]
    fn try_mlock(&self) {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return;
        }
        // SAFETY: `bytes.as_ptr()` is a valid, properly aligned pointer into
        // the String's heap allocation; `bytes.len()` is the exact buffer
        // length. `libc::mlock` reads the address range only — it does not
        // mutate the pages, it pins them.
        //
        // Invariant: `SecretString` exposes NO `&mut` API. `expose()` returns
        // `&str` and there is no setter, push, append, or replace. The
        // allocation address is therefore stable from `new()` through
        // `Drop::drop`. Any future maintainer adding a mutating API must also
        // re-mlock the new buffer (or, simpler, refuse to add such an API).
        let ret = unsafe { libc::mlock(bytes.as_ptr() as *const _, bytes.len()) };
        if ret != 0 {
            tracing::warn!(
                bytes = bytes.len(),
                error = %std::io::Error::last_os_error(),
                "mlock failed for SecretString — secret may swap to disk. \
                 Run with CAP_IPC_LOCK or raised RLIMIT_MEMLOCK for at-rest protection."
            );
        }
    }

    /// Best-effort munlock before drop (Linux only).
    #[cfg(target_os = "linux")]
    fn try_munlock(&self) {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return;
        }
        // SAFETY: same invariants as try_mlock. munlock on an unlocked or
        // partially-locked region is harmless (returns EINVAL silently).
        unsafe {
            libc::munlock(bytes.as_ptr() as *const _, bytes.len());
        }
    }

    /// Best-effort VirtualLock of the underlying byte buffer (Windows).
    /// Failure is logged but not propagated — degrades to "secret may
    /// swap to pagefile/hiberfil", same as a plain String. Mirrors the
    /// Linux mlock path so the Debug-redacted + Drop-zeroized
    /// invariants are platform-uniform; only the page-pinning differs.
    /// K-Sec-2 / 2026-05-17.
    #[cfg(target_os = "windows")]
    fn try_virtual_lock(&self) {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return;
        }
        // SAFETY: `bytes.as_ptr()` is a valid, properly aligned pointer
        // into the String's heap allocation; `bytes.len()` is the exact
        // buffer length. `VirtualLock` pins the page(s) into the
        // process's working set — it does not mutate the bytes, just
        // marks them as non-pageable. Same invariant as the Linux
        // mlock path: `SecretString` exposes no &mut API so the buffer
        // address is stable from `new()` to `Drop`.
        let result = unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(bytes.as_ptr() as *const _, bytes.len())
        };
        if result == 0 {
            tracing::warn!(
                bytes = bytes.len(),
                error_code = unsafe { windows_sys::Win32::Foundation::GetLastError() },
                "VirtualLock failed for SecretString — secret may swap to pagefile. \
                 Grant SeLockMemoryPrivilege or accept the soft-fallback (Debug + \
                 Drop-zeroize still protect)."
            );
        }
    }

    /// Best-effort VirtualUnlock before drop (Windows). Idempotent +
    /// safe to call on an unlocked region (returns 0 + sets last-error
    /// which we ignore).
    #[cfg(target_os = "windows")]
    fn try_virtual_unlock(&self) {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return;
        }
        // SAFETY: same invariants as try_virtual_lock. VirtualUnlock on
        // an unlocked region returns 0 without UB.
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(
                bytes.as_ptr() as *const _,
                bytes.len(),
            );
        }
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.try_munlock();
        #[cfg(target_os = "windows")]
        self.try_virtual_unlock();
        self.zeroize();
    }
}

// Custom Deserialize so deserialized values get mlock applied on construction.
// `#[serde(transparent)]` on Serialize is enough for output; for input we route
// through `new()` to ensure the same protection.
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak() {
        let s = SecretString::from("ghp_supersecret_token_value_here");
        let formatted = format!("{s:?}");
        assert!(!formatted.contains("supersecret"));
        assert!(formatted.contains("REDACTED"));
    }

    #[test]
    fn display_does_not_leak() {
        let s = SecretString::from("sk-livekey-1234567890");
        let formatted = format!("{s}");
        assert!(!formatted.contains("livekey"));
        assert_eq!(formatted, "[REDACTED]");
    }

    #[test]
    fn expose_returns_value() {
        let s = SecretString::from("plaintext");
        assert_eq!(s.expose(), "plaintext");
    }

    #[test]
    fn deserializes_from_string() {
        let json = r#""hello-secret""#;
        let s: SecretString = serde_json::from_str(json).unwrap();
        assert_eq!(s.expose(), "hello-secret");
    }

    #[test]
    fn serializes_as_transparent_string() {
        let s = SecretString::from("hello");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#""hello""#);
    }

    /// K-Sec-2 / 2026-05-17: Windows page-lock smoke test. Verifies the
    /// constructor → VirtualLock → Drop → VirtualUnlock cycle runs
    /// without panic on Windows. The actual lock success depends on
    /// SeLockMemoryPrivilege which most desktop users lack — we only
    /// check that the best-effort path doesn't blow up.
    #[test]
    #[cfg(target_os = "windows")]
    fn windows_virtual_lock_smoke_does_not_panic() {
        let s = SecretString::from("windows-pagelock-test");
        assert_eq!(s.expose(), "windows-pagelock-test");
        // Drop runs at scope exit — Drop → try_virtual_unlock → zeroize.
        drop(s);
    }

    /// Empty SecretString must not call VirtualLock with length 0 (would
    /// be an error). Smoke test pinning the early-return branch.
    #[test]
    #[cfg(target_os = "windows")]
    fn windows_virtual_lock_empty_secret_short_circuits() {
        let s = SecretString::from("");
        assert!(s.is_empty());
        drop(s);
    }
}
