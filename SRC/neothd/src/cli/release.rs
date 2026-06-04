//! `neoth release` — DAU-friendly release signing (MAR-02).
//!
//! Generates the project's minisign-compatible signing keypair IN-PROCESS and
//! signs release artifacts — no external `minisign` binary, no install, no
//! interactive password. A maintainer runs `neoth release keygen` once, pastes
//! two values into their CI, and every release is then signed so end-users'
//! NEOTH verifies authenticity before an auto-update (the verify side already
//! ships: `updater::sig_verify`).

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::updater::sig_keygen::{self, ReleaseKeypair};

/// Env var a CI signing step sets (base64 of the 40-byte secret, from a GitHub
/// secret) so `neoth release sign` works without a key file on the runner.
const SECRET_ENV: &str = "NEOTH_RELEASE_MINISIGN_SECRET";

#[derive(Args, Debug, Clone)]
pub struct ReleaseArgs {
    #[command(subcommand)]
    pub action: ReleaseAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReleaseAction {
    /// Generate the project release-signing keypair (maintainers, one-time).
    /// Prints the PUBLIC key (safe to share — goes in CI build env) + the
    /// SECRET (goes in a GitHub secret, never committed).
    Keygen {
        /// Overwrite an existing key. DANGER: invalidates every signature made
        /// with the currently-published public key — only when rotating.
        #[arg(long)]
        force: bool,
    },
    /// Sign a release artifact, writing `<file>.minisig` next to it. The secret
    /// is read from `NEOTH_RELEASE_MINISIGN_SECRET` (CI) or the saved key file.
    Sign {
        /// The artifact to sign (e.g. `neoth-x86_64-unknown-linux-gnu.tar.gz`).
        file: PathBuf,
        /// Optional trusted comment embedded + signed into the `.minisig`.
        #[arg(long)]
        comment: Option<String>,
    },
    /// Print the saved key's PUBLIC key line (paste into CI build env).
    Pubkey,
}

pub fn run_release(args: ReleaseArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let key_path = sig_keygen::default_release_key_path(&home);
    match &args.action {
        ReleaseAction::Keygen { force } => keygen(&key_path, *force, args.output),
        ReleaseAction::Sign { file, comment } => {
            sign(&key_path, file, comment.as_deref(), args.output)
        }
        ReleaseAction::Pubkey => pubkey(&key_path, args.output),
    }
}

fn keygen(key_path: &std::path::Path, force: bool, output: OutputFormat) -> Result<()> {
    let kp = ReleaseKeypair::generate()?;
    sig_keygen::save_secret_key(key_path, &kp, force)?;
    let pubkey = kp.public_key_base64();
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(kp.secret_bytes());

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            // The secret IS included here (operators script `| jq` to provision
            // CI), but it is NEVER logged/audited by the daemon. The plain-text
            // surface warns loudly.
            println!(
                "{}",
                serde_json::json!({
                    "public_key": pubkey,
                    "key_id": kp.key_id_hex(),
                    "secret_key_path": key_path.display().to_string(),
                    "secret_base64": secret_b64,
                })
            );
        }
        OutputFormat::Table => {
            println!("✓ Release signing key generated (key id {}).", kp.key_id_hex());
            println!("  Saved (secret): {}", key_path.display());
            println!();
            println!("Two values go into your release pipeline. Do this ONCE:");
            println!();
            println!("  1) PUBLIC key — safe to share. Set it as a build-time env var so");
            println!("     shipped binaries can verify updates:");
            println!();
            println!("       NEOTH_RELEASE_MINISIGN_PUBKEY={pubkey}");
            println!();
            println!("  2) SECRET — NEVER commit or share. Add it as a GitHub Actions");
            println!("     secret named {SECRET_ENV}:");
            println!();
            println!("       {secret_b64}");
            println!();
            println!("  3) In CI, after building each artifact, sign it:");
            println!("       export {SECRET_ENV}=<the GitHub secret>");
            println!("       neoth release sign neoth-<target>.tar.gz");
            println!("     → writes neoth-<target>.tar.gz.minisig, uploaded alongside the asset.");
            println!();
            println!("End-users' NEOTH then verifies the .minisig before any auto-update —");
            println!("a swapped or tampered release is rejected. (You never touch the");
            println!("`minisign` tool; NEOTH did the keygen + will do the signing.)");
        }
    }
    Ok(())
}

fn sign(
    key_path: &std::path::Path,
    file: &std::path::Path,
    comment: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let kp = load_signing_key(key_path)?;
    let data = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let untrusted = format!(
        "signed by neoth (key {}) — verify with the pinned NEOTH_RELEASE_MINISIGN_PUBKEY",
        kp.key_id_hex()
    );
    let trusted = comment
        .map(|c| c.to_string())
        .unwrap_or_else(|| format!("file:{}", file.display()));
    let minisig = kp.sign_minisig(&data, &untrusted, &trusted);

    let sig_path = PathBuf::from(format!("{}.minisig", file.display()));
    std::fs::write(&sig_path, minisig.as_bytes())
        .with_context(|| format!("write {}", sig_path.display()))?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "signed": file.display().to_string(),
                    "signature": sig_path.display().to_string(),
                    "key_id": kp.key_id_hex(),
                })
            );
        }
        OutputFormat::Table => {
            println!("✓ signed {} → {}", file.display(), sig_path.display());
        }
    }
    Ok(())
}

fn pubkey(key_path: &std::path::Path, output: OutputFormat) -> Result<()> {
    let kp = sig_keygen::load_secret_key(key_path).with_context(|| {
        format!(
            "no release key at {} — run `neoth release keygen` first",
            key_path.display()
        )
    })?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "public_key": kp.public_key_base64(),
                    "key_id": kp.key_id_hex(),
                })
            );
        }
        OutputFormat::Table => println!("{}", kp.public_key_base64()),
    }
    Ok(())
}

/// Load the signing key: the `NEOTH_RELEASE_MINISIGN_SECRET` env (CI) wins over
/// the saved key file (local maintainer), so a CI runner needs no key on disk.
fn load_signing_key(key_path: &std::path::Path) -> Result<ReleaseKeypair> {
    if let Ok(b64) = std::env::var(SECRET_ENV) {
        if !b64.trim().is_empty() {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .with_context(|| format!("{SECRET_ENV} is not valid base64"))?;
            return ReleaseKeypair::from_secret_bytes(&bytes)
                .with_context(|| format!("{SECRET_ENV} is not a valid release secret"));
        }
    }
    sig_keygen::load_secret_key(key_path).with_context(|| {
        format!(
            "no release key: set {SECRET_ENV} (CI) or run `neoth release keygen` (saved at {})",
            key_path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_then_pubkey_then_sign_roundtrips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = sig_keygen::default_release_key_path(dir.path());

        // keygen writes the secret.
        keygen(&key_path, false, OutputFormat::Table).unwrap();
        assert!(key_path.exists());

        // pubkey reads it back.
        pubkey(&key_path, OutputFormat::Table).unwrap();

        // sign a file → a .minisig that verifies against the saved pubkey.
        let artifact = dir.path().join("neoth.tar.gz");
        std::fs::write(&artifact, b"artifact bytes").unwrap();
        sign(&key_path, &artifact, Some("ci"), OutputFormat::Table).unwrap();

        let sig_path = dir.path().join("neoth.tar.gz.minisig");
        assert!(sig_path.exists());
        let kp = sig_keygen::load_secret_key(&key_path).unwrap();
        let sig_text = std::fs::read_to_string(&sig_path).unwrap();
        let pk = minisign_verify::PublicKey::from_base64(&kp.public_key_base64()).unwrap();
        let sig = minisign_verify::Signature::decode(&sig_text).unwrap();
        pk.verify(b"artifact bytes", &sig, false)
            .expect("CLI-produced .minisig must verify");
    }

    #[test]
    fn sign_prefers_secret_env_over_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = sig_keygen::default_release_key_path(dir.path());
        // Generate a key, capture its secret, then point the env at a DIFFERENT
        // key — sign must use the env key.
        let env_kp = ReleaseKeypair::generate().unwrap();
        let env_b64 =
            base64::engine::general_purpose::STANDARD.encode(env_kp.secret_bytes());
        // A file key also exists (different key).
        let file_kp = ReleaseKeypair::generate().unwrap();
        sig_keygen::save_secret_key(&key_path, &file_kp, false).unwrap();

        // SAFETY: test-only env mutation; the assertion runs before any other
        // thread could read it (single-threaded test).
        unsafe { std::env::set_var(SECRET_ENV, &env_b64) };
        let loaded = load_signing_key(&key_path).unwrap();
        unsafe { std::env::remove_var(SECRET_ENV) };

        // The env key won, not the file key.
        assert_eq!(loaded.public_key_base64(), env_kp.public_key_base64());
        assert_ne!(loaded.public_key_base64(), file_kp.public_key_base64());
    }
}
