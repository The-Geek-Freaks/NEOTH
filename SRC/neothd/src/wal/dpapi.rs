//! K-Sec-4 — Windows DPAPI wrap for the WAL HMAC key.
//!
//! Per Security agent's Session-1 pick (2026-05-17). The HMAC key at
//! `~/.neoth/wal/hmac.key` is the foundation of every `0x15
//! COMPACTION_MARKER` — an attacker who copies that key off the box can
//! forge tamper-evidence after editing the WAL. Pre-Sec-4 the key lived
//! in plaintext (mode 0600 on unix, owner-only DACL on Windows). That
//! defeats casual `Explorer → copy` exfiltration but NOT a hand-rolled
//! enumerator running as the same Windows user account (e.g. a malicious
//! VS Code extension Alex installed).
//!
//! ## DPAPI binding choice
//!
//! `CryptProtectData` with NO `CRYPTPROTECT_LOCAL_MACHINE` flag binds
//! the ciphertext to the **current user's master key**. The wrapped
//! bytes are useless outside that user's session — moving the file to
//! another Windows account, another machine, or running the box without
//! the user's login token all defeat decryption. This is exactly the
//! property a HMAC key needs.
//!
//! The trade-off: the key cannot be decrypted offline by `neoth verify
//! --key <archive>` running as a different operator. We accept this —
//! verifying past WAL chains across users isn't a workflow NEOTH
//! supports (each operator has their own audit trail).
//!
//! ## On-disk format
//!
//! ```text
//! +----------------------------+
//! | 14 bytes: "NEOTH_DPAPIv1\n" |  magic header
//! +----------------------------+
//! | N bytes: DPAPI blob        |  CryptProtectData output
//! +----------------------------+
//! ```
//!
//! `load_or_init_key` detects the magic header and routes through
//! [`unprotect`]. Files WITHOUT the header are treated as legacy
//! plaintext and migrated to DPAPI on the next write (e.g. via
//! `neoth keys rotate`).

#![cfg(windows)]

use anyhow::Result;

/// 14-byte magic header that distinguishes a DPAPI-wrapped key file
/// from a legacy plaintext key file. Includes the trailing `\n` so
/// `hexdump` operators see a clean line break before the blob.
pub const DPAPI_MAGIC: &[u8] = b"NEOTH_DPAPIv1\n";

/// Wrap arbitrary bytes via Windows DPAPI bound to the current user's
/// master key. The returned `Vec<u8>` includes the [`DPAPI_MAGIC`]
/// header — callers write the full vector to disk.
///
/// Returns an error when the system call fails (e.g. no Windows user
/// session is available). The error message is intentionally generic —
/// the underlying `GetLastError` code goes into the context chain for
/// debugging but never into a user-visible WAL frame.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData};

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: in_blob points to plaintext slice for the call's lifetime;
    // out_blob receives an OS-allocated buffer that we LocalFree below.
    // dwFlags=0 means user-bound (no LOCAL_MACHINE), the strongest scope.
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        anyhow::bail!("CryptProtectData failed: GetLastError={err}");
    }

    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let mut out = Vec::with_capacity(DPAPI_MAGIC.len() + slice.len());
    out.extend_from_slice(DPAPI_MAGIC);
    out.extend_from_slice(slice);

    // SAFETY: OS contract — every CryptProtectData success path
    // mandates a matching LocalFree on pbData.
    unsafe { LocalFree(out_blob.pbData as _) };
    Ok(out)
}

/// Unwrap bytes produced by [`protect`]. Strips the [`DPAPI_MAGIC`]
/// header, calls `CryptUnprotectData`, returns the recovered plaintext.
///
/// Returns an error if the input lacks the magic header (callers can
/// then treat the bytes as legacy plaintext) OR if the OS rejects the
/// blob (wrong user account, corrupted blob, master key roll).
pub fn unprotect(wrapped: &[u8]) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

    if !is_wrapped(wrapped) {
        anyhow::bail!("input lacks NEOTH_DPAPIv1 magic header");
    }
    let blob_bytes = &wrapped[DPAPI_MAGIC.len()..];

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: blob_bytes.len() as u32,
        pbData: blob_bytes.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: in_blob borrows from `wrapped` for the call duration;
    // out_blob receives an OS-allocated buffer freed via LocalFree.
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        anyhow::bail!(
            "CryptUnprotectData failed: GetLastError={err} \
             (key may be bound to a different user or machine)"
        );
    }

    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let plaintext = slice.to_vec();
    // SAFETY: OS contract requires LocalFree on success.
    unsafe { LocalFree(out_blob.pbData as _) };
    Ok(plaintext)
}

/// True when `bytes` carries the [`DPAPI_MAGIC`] header. Used by
/// `load_or_init_key` to decide between unwrap-via-DPAPI and
/// treat-as-legacy-plaintext.
pub fn is_wrapped(bytes: &[u8]) -> bool {
    bytes.len() >= DPAPI_MAGIC.len() && &bytes[..DPAPI_MAGIC.len()] == DPAPI_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_constant_is_fourteen_bytes() {
        // Pin the magic so a future refactor that changes the header
        // length doesn't silently break on-disk compatibility with
        // already-wrapped keys.
        assert_eq!(DPAPI_MAGIC.len(), 14);
        assert_eq!(DPAPI_MAGIC, b"NEOTH_DPAPIv1\n");
    }

    #[test]
    fn is_wrapped_detects_header_presence() {
        assert!(is_wrapped(b"NEOTH_DPAPIv1\n\x00\x01\x02"));
        assert!(!is_wrapped(b"plain-key-bytes-here"));
        assert!(!is_wrapped(b"NEOTH_DPAPIv1"), "missing trailing newline");
        assert!(!is_wrapped(b""), "empty input");
        assert!(!is_wrapped(b"NEOTH"), "too short to match magic");
    }

    #[test]
    fn roundtrip_preserves_plaintext() {
        // Live DPAPI call. Requires a Windows user session — skip
        // gracefully when none is available (e.g. SYSTEM-context CI).
        let original: Vec<u8> = (0u8..32).collect();
        let wrapped = match protect(&original) {
            Ok(w) => w,
            Err(e) => {
                // No-user-session CI: log + skip rather than fail.
                eprintln!("dpapi protect unavailable: {e}");
                return;
            }
        };
        assert!(is_wrapped(&wrapped));
        // Wrapped form is longer than the magic + plaintext (DPAPI adds
        // its own envelope) — pin that we never accidentally write the
        // plaintext bytes raw after the magic.
        assert!(wrapped.len() > DPAPI_MAGIC.len() + original.len());

        let recovered = unprotect(&wrapped).expect("unprotect must roundtrip");
        assert_eq!(recovered, original);
    }

    #[test]
    fn unprotect_rejects_legacy_plaintext() {
        let legacy = vec![0x42u8; 32];
        let err = unprotect(&legacy).unwrap_err();
        assert!(
            err.to_string().contains("magic header"),
            "expected magic-header error, got: {err}"
        );
    }

    #[test]
    fn unprotect_rejects_corrupted_blob() {
        let mut wrapped = match protect(b"some plaintext") {
            Ok(w) => w,
            Err(e) => {
                eprintln!("dpapi protect unavailable: {e}");
                return;
            }
        };
        // Flip a byte inside the integrity-protected region of the
        // DPAPI envelope. The leading bytes are version + masterkey
        // GUID + provider GUID metadata that DPAPI does NOT mix into
        // its HMAC, so flipping there can roundtrip. The trailing
        // bytes ARE under the HMAC — flip in the last quarter so the
        // OS's integrity check rejects the blob.
        let blob_start = DPAPI_MAGIC.len();
        let target = blob_start + 3 * (wrapped.len() - blob_start) / 4;
        wrapped[target] ^= 0xFF;
        let r = unprotect(&wrapped);
        assert!(
            r.is_err(),
            "corrupted DPAPI blob must fail unprotect, got: {:?}",
            r
        );
    }
}
