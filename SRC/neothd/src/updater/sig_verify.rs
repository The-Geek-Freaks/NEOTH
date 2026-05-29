//! MV-01b prereq #2 — minisign signature verification for the daemon
//! self-update path (senior-dev panel 2026-05-29).
//!
//! NEOTH's release pipeline signs each artifact with **minisign** in CI;
//! this module verifies the `.minisig` companion against the downloaded
//! archive BEFORE [`crate::updater::self_update::atomic_replace_binary`]
//! runs. minisign-verify is pure-Rust (ed25519 + blake2b) — no `ring`,
//! no native-tls, no openssl. The heavier `sigstore`/cosign crate was
//! probed + rejected for pulling native-tls/schannel + untrusted + prost,
//! against NEOTH's rustls-only/no-ring posture.
//!
//! ## Why integrity (SHA-256) is not enough
//!
//! The `.sha256` companion and the archive ship from the same GitHub
//! release, so a compromised release controls both — SHA-256 is a
//! corruption check, not an authenticity control. The minisign public
//! key is pinned at COMPILE TIME via the `NEOTH_RELEASE_MINISIGN_PUBKEY`
//! env (cargo-dist passes it on the release build); an attacker who
//! swaps the release cannot forge a signature without the operator's
//! private key, which never leaves CI secrets.
//!
//! ## Two-tier enforcement
//!
//! - **Manual** (`neoth update --self --apply`): `require = false`. A
//!   missing signature / unprovisioned key WARNS and proceeds (so the
//!   existing manual updater keeps working for releases published before
//!   signing was enabled). A PRESENT-but-INVALID signature always bails.
//! - **Unattended** (daemon auto path): `require = true`. Anything short
//!   of a verified signature hard-bails — no unattended swap without
//!   cryptographic provenance.

/// The minisign public key (base64 of the key line, NOT the full `.pub`
/// file) pinned into the binary at compile time. `None` when the build
/// did not set `NEOTH_RELEASE_MINISIGN_PUBKEY` — i.e. signing is not yet
/// provisioned, in which case the unattended path refuses and the manual
/// path warns.
pub const PINNED_PUBKEY: Option<&str> = option_env!("NEOTH_RELEASE_MINISIGN_PUBKEY");

/// Outcome of a signature check that did NOT hard-fail. The caller logs
/// this and records it in the `0xD2` audit frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    /// Signature present + verified against the pinned key.
    Verified,
    /// No signature companion on the release; allowed only because the
    /// caller passed `require = false` (manual path, pre-signing releases).
    UnsignedAllowed,
    /// A signature companion was present but the binary has no pinned
    /// public key (build didn't set the env); allowed only because the
    /// caller passed `require = false`.
    NoPinnedKey,
}

impl SigStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SigStatus::Verified => "verified",
            SigStatus::UnsignedAllowed => "unsigned_allowed",
            SigStatus::NoPinnedKey => "no_pinned_key",
        }
    }
}

/// Verify a minisign signature over `data`.
///
/// `signature` is the raw `.minisig` companion text (`None` when the
/// release has no signature companion). `require` is the two-tier gate:
/// `true` for the unattended daemon path (any non-verified outcome
/// bails), `false` for the manual operator path (missing sig / no pinned
/// key warns + proceeds; a present-but-invalid sig still bails).
///
/// Returns the [`SigStatus`] for the non-fatal paths; `Err` on a hard
/// failure (invalid signature, or a `require = true` gate that wasn't
/// met).
pub fn check_signature(
    data: &[u8],
    signature: Option<&str>,
    require: bool,
) -> anyhow::Result<SigStatus> {
    let Some(pubkey_b64) = PINNED_PUBKEY else {
        if require {
            anyhow::bail!(
                "unattended self-update requires a signed release, but this \
                 binary has no pinned minisign public key \
                 (NEOTH_RELEASE_MINISIGN_PUBKEY was not set at build time)"
            );
        }
        return Ok(SigStatus::NoPinnedKey);
    };

    let Some(sig_text) = signature else {
        if require {
            anyhow::bail!(
                "unattended self-update requires a signed release, but no \
                 `.minisig` signature companion was published for this asset"
            );
        }
        return Ok(SigStatus::UnsignedAllowed);
    };

    let pubkey = minisign_verify::PublicKey::from_base64(pubkey_b64.trim())
        .map_err(|e| anyhow::anyhow!("pinned minisign public key is malformed: {e}"))?;
    let sig = minisign_verify::Signature::decode(sig_text)
        .map_err(|e| anyhow::anyhow!("release `.minisig` signature is malformed: {e}"))?;
    pubkey
        .verify(data, &sig, false)
        .map_err(|e| anyhow::anyhow!("release signature verification FAILED: {e}"))?;
    Ok(SigStatus::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pinned key is None in the test build (the env isn't set), so
    // these tests pin the unprovisioned-key behaviour — the verified
    // path needs a real keypair + signature which a unit test can't mint
    // without embedding a private key (the signing side lives in CI).

    #[test]
    fn no_pinned_key_warns_when_not_required() {
        // Manual path: no pinned key → allowed (warn), status surfaced.
        let s = check_signature(b"payload", Some("untrusted comment\nRWQ..."), false).unwrap();
        assert_eq!(s, SigStatus::NoPinnedKey);
    }

    #[test]
    fn no_pinned_key_bails_when_required() {
        // Unattended path: no pinned key → hard bail.
        let err = check_signature(b"payload", Some("sig"), true).unwrap_err();
        assert!(
            format!("{err:#}").contains("no pinned minisign public key"),
            "got: {err:#}"
        );
    }

    #[test]
    fn missing_signature_with_no_pinned_key_warns_when_not_required() {
        // Both absent → manual path allows (the pre-signing-rollout case).
        let s = check_signature(b"payload", None, false).unwrap();
        // PINNED_PUBKEY is None in test builds, so the no-key branch wins
        // before the missing-signature branch — that's the correct
        // precedence (no key means we couldn't verify even a present sig).
        assert_eq!(s, SigStatus::NoPinnedKey);
    }

    #[test]
    fn required_always_bails_without_provisioned_signing() {
        // With no pinned key in the test build, require=true must bail
        // regardless of whether a signature blob is present.
        assert!(check_signature(b"x", None, true).is_err());
        assert!(check_signature(b"x", Some("sig"), true).is_err());
    }

    #[test]
    fn sig_status_strings_are_stable() {
        assert_eq!(SigStatus::Verified.as_str(), "verified");
        assert_eq!(SigStatus::UnsignedAllowed.as_str(), "unsigned_allowed");
        assert_eq!(SigStatus::NoPinnedKey.as_str(), "no_pinned_key");
    }
}
