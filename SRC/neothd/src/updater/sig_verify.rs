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
//! env (the release workflow passes it into every native/cross build); an attacker who
//! swaps the release cannot forge a signature without the operator's
//! private key, which never leaves CI secrets.
//!
//! ## Enforcement
//!
//! - **Manual** (`neoth update --self --apply`): signatures are required by
//!   default. The explicit `--allow-unsigned` recovery flag passes
//!   `require = false`; a present-but-invalid signature still always bails.
//! - **Unattended** (daemon auto path): `require = true`. Anything short
//!   of a verified signature hard-bails — no unattended swap without
//!   cryptographic provenance.

/// The minisign public key (base64 of the key line, NOT the full `.pub`
/// file) pinned into the binary at compile time. `None` when the build
/// did not set `NEOTH_RELEASE_MINISIGN_PUBKEY`. Official release CI refuses to
/// build without it; source/dev builds may intentionally have no pinned key and
/// therefore cannot pass a required verification gate.
pub const PINNED_PUBKEY: Option<&str> = option_env!("NEOTH_RELEASE_MINISIGN_PUBKEY");

/// Outcome of a signature check that did NOT hard-fail. The caller logs
/// this and records it in the `0xD2` audit frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    /// Signature present + verified against the pinned key.
    Verified,
    /// No signature companion on the release; allowed only because the
    /// caller explicitly passed `require = false` (`--allow-unsigned`).
    UnsignedAllowed,
    /// A signature companion was present but the binary has no pinned
    /// public key (build didn't set the env); allowed only because the
    /// caller explicitly passed `require = false`.
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
/// release has no signature companion). `require=true` is the default manual
/// and unattended gate; `false` is reserved for the explicit trusted-recovery
/// override. A present-but-invalid signature always bails.
///
/// Returns the [`SigStatus`] for the non-fatal paths; `Err` on a hard
/// failure (invalid signature, or a `require = true` gate that wasn't
/// met).
pub fn check_signature(
    data: &[u8],
    signature: Option<&str>,
    require: bool,
) -> anyhow::Result<SigStatus> {
    check_signature_for_file(data, signature, require, None)
}

/// Verify the signature and, when supplied, bind it to the exact release asset
/// filename carried in minisign's globally signed trusted comment. This blocks
/// a valid signature for an older archive from being replayed under a newer
/// staged-update version record.
pub fn check_signature_for_file(
    data: &[u8],
    signature: Option<&str>,
    require: bool,
    expected_file: Option<&str>,
) -> anyhow::Result<SigStatus> {
    let Some(pubkey_b64) = PINNED_PUBKEY else {
        if require {
            anyhow::bail!(
                "signature verification is required, but this \
                 binary has no pinned minisign public key \
                 (NEOTH_RELEASE_MINISIGN_PUBKEY was not set at build time)"
            );
        }
        return Ok(SigStatus::NoPinnedKey);
    };

    let Some(sig_text) = signature else {
        if require {
            anyhow::bail!(
                "signature verification is required, but no \
                 `.minisig` signature companion was published for this asset"
            );
        }
        return Ok(SigStatus::UnsignedAllowed);
    };

    verify_with_public_key(data, sig_text, pubkey_b64, expected_file)?;
    Ok(SigStatus::Verified)
}

fn verify_with_public_key(
    data: &[u8],
    sig_text: &str,
    pubkey_b64: &str,
    expected_file: Option<&str>,
) -> anyhow::Result<()> {
    let pubkey = minisign_verify::PublicKey::from_base64(pubkey_b64.trim())
        .map_err(|e| anyhow::anyhow!("pinned minisign public key is malformed: {e}"))?;
    let sig = minisign_verify::Signature::decode(sig_text)
        .map_err(|e| anyhow::anyhow!("release `.minisig` signature is malformed: {e}"))?;
    pubkey
        .verify(data, &sig, false)
        .map_err(|e| anyhow::anyhow!("release signature verification FAILED: {e}"))?;
    if let Some(expected_file) = expected_file {
        let expected_comment = format!("file:{expected_file}");
        if sig.trusted_comment() != expected_comment {
            anyhow::bail!(
                "release signature is valid for trusted comment {:?}, expected {:?}; refusing a cross-version/cross-target replay",
                sig.trusted_comment(),
                expected_comment
            );
        }
    }
    Ok(())
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

    #[test]
    fn trusted_comment_binds_signature_to_exact_release_asset() {
        let keypair = crate::updater::sig_keygen::ReleaseKeypair::generate().unwrap();
        let data = b"signed archive";
        let asset = "neoth-v1.0.0-x86_64-unknown-linux-gnu.tar.gz";
        let signature = keypair.sign_minisig(data, "test", &format!("file:{asset}"));

        verify_with_public_key(data, &signature, &keypair.public_key_base64(), Some(asset))
            .unwrap();
        let error = verify_with_public_key(
            data,
            &signature,
            &keypair.public_key_base64(),
            Some("neoth-v1.0.1-x86_64-unknown-linux-gnu.tar.gz"),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("cross-version/cross-target replay"));
    }
}
