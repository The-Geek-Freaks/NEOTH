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
    /// ONE-COMMAND DAU setup: generate the keypair AND provision it into the
    /// repo's CI via `gh` (sets the `NEOTH_RELEASE_MINISIGN_SECRET` secret + the
    /// `NEOTH_RELEASE_MINISIGN_PUBKEY` variable). No copy-paste, no GitHub UI.
    /// The secret never prints — it is piped straight to `gh` over stdin.
    Setup {
        /// `owner/name`. Defaults to the `origin` git remote.
        #[arg(long)]
        repo: Option<String>,
        /// Explicitly rotate the published trust root. Also updates the
        /// repository key pin and both bootstrap installers; commit those
        /// source changes before tagging a release.
        #[arg(long)]
        force: bool,
    },
    /// Generate the project release-signing keypair (maintainers, one-time).
    /// Prints the PUBLIC key (safe to share — goes in CI build env) + the
    /// SECRET (goes in a GitHub secret, never committed). Prefer `setup` for
    /// the zero-copy-paste path.
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
    /// Verify an artifact against the public key pinned into this binary.
    /// CI uses this after signing to prove the signing secret and the key baked
    /// into the release binary are the same pair.
    Verify {
        /// Artifact whose bytes were signed.
        file: PathBuf,
        /// Signature path. Defaults to `<file>.minisig`.
        #[arg(long)]
        signature: Option<PathBuf>,
    },
    /// Print the saved key's PUBLIC key line (paste into CI build env).
    Pubkey,
}

pub fn run_release(args: ReleaseArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let key_path = sig_keygen::default_release_key_path(&home);
    match &args.action {
        ReleaseAction::Setup { repo, force } => {
            setup(&key_path, repo.as_deref(), *force, args.output)
        }
        ReleaseAction::Keygen { force } => keygen(&key_path, *force, args.output),
        ReleaseAction::Sign { file, comment } => {
            sign(&key_path, file, comment.as_deref(), args.output)
        }
        ReleaseAction::Verify { file, signature } => {
            verify(file, signature.as_deref(), args.output)
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
            println!(
                "✓ Release signing key generated (key id {}).",
                kp.key_id_hex()
            );
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

/// The build-time env var / repo VARIABLE that pins the verification pubkey.
const PUBKEY_VAR: &str = "NEOTH_RELEASE_MINISIGN_PUBKEY";

#[derive(Debug, Default, PartialEq, Eq)]
struct RemoteReleaseTrust {
    public_key: Option<String>,
    secret_exists: bool,
}

/// ONE-COMMAND setup: generate-or-reuse the key, then provision the repo's CI
/// via `gh`. The secret is piped to `gh` over STDIN — never argv, never printed.
fn setup(
    key_path: &std::path::Path,
    repo: Option<&str>,
    force: bool,
    output: OutputFormat,
) -> Result<()> {
    let slug = match repo {
        Some(r) => r.to_string(),
        None => detect_repo_slug().context(
            "could not detect the GitHub repo from `git remote get-url origin` — \
             pass `--repo owner/name`",
        )?,
    };

    // Inspect the published trust root BEFORE generating key material. A
    // missing local key on a new maintainer machine does not mean that the
    // repository is uninitialised.
    ensure_gh_ready()?;
    let remote = gh_release_trust(&slug)?;
    let repo_root = detect_repo_root();
    let repository_key = repo_root
        .as_deref()
        .map(read_repository_pubkey)
        .transpose()?
        .flatten();
    let rotation_marker = key_path.with_extension("rotation-pending");

    let mut repository_pins_updated = false;
    let kp = if force {
        let repo_root = repo_root.as_deref().context(
            "release-key rotation must run inside the checked-out NEOTH repository so the \
             committed key pin and both bootstrap installers can be updated",
        )?;
        ensure_checkout_matches_repo(&slug)?;
        let kp = if rotation_marker.exists() {
            let kp = sig_keygen::load_secret_key(key_path).context(
                "a release-key rotation is pending but its local secret key is unavailable",
            )?;
            let pending = std::fs::read_to_string(&rotation_marker)
                .with_context(|| format!("read {}", rotation_marker.display()))?;
            anyhow::ensure!(
                pending.trim() == kp.public_key_base64(),
                "pending release-key rotation marker does not match the local key; refuse to \
                 generate another key until the incomplete rotation is recovered"
            );
            kp
        } else {
            let kp = ReleaseKeypair::generate()?;
            sig_keygen::save_secret_key(key_path, &kp, true)?;
            crate::util::atomic_write::atomic_write_private(
                &rotation_marker,
                format!("{}\n", kp.public_key_base64()).as_bytes(),
            )
            .with_context(|| format!("write {}", rotation_marker.display()))?;
            kp
        };
        sync_repository_pubkey_pins(repo_root, &kp.public_key_base64())?;
        repository_pins_updated = true;
        kp
    } else {
        let local = key_path
            .exists()
            .then(|| sig_keygen::load_secret_key(key_path))
            .transpose()?;
        validate_non_rotating_setup(
            local.as_ref().map(ReleaseKeypair::public_key_base64),
            &remote,
            repository_key.as_deref(),
            rotation_marker.exists(),
        )?;
        let kp = match local {
            Some(kp) => kp,
            None => {
                let kp = ReleaseKeypair::generate()?;
                sig_keygen::save_secret_key(key_path, &kp, false)?;
                kp
            }
        };
        if repository_key.as_deref() != Some(kp.public_key_base64().as_str()) {
            let repo_root = repo_root.as_deref().context(
                "initial release-key setup must run inside the checked-out NEOTH repository so \
                 the committed key pin and both bootstrap installers can be updated",
            )?;
            ensure_checkout_matches_repo(&slug)?;
            crate::util::atomic_write::atomic_write_private(
                &rotation_marker,
                format!("{}\n", kp.public_key_base64()).as_bytes(),
            )
            .with_context(|| format!("write {}", rotation_marker.display()))?;
            sync_repository_pubkey_pins(repo_root, &kp.public_key_base64())?;
            repository_pins_updated = true;
        }
        kp
    };
    let pubkey = kp.public_key_base64();
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(kp.secret_bytes());

    gh_set_secret(&slug, SECRET_ENV, &secret_b64)
        .with_context(|| format!("set the `{SECRET_ENV}` GitHub secret on {slug}"))?;
    gh_set_variable(&slug, PUBKEY_VAR, &pubkey)
        .with_context(|| format!("set the `{PUBKEY_VAR}` GitHub variable on {slug}"))?;
    if rotation_marker.exists() {
        std::fs::remove_file(&rotation_marker)
            .with_context(|| format!("remove {}", rotation_marker.display()))?;
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "repo": slug,
                    "key_id": kp.key_id_hex(),
                    "public_key": pubkey,
                    "provisioned": true,
                    "rotated": force,
                    "repository_pins_updated": repository_pins_updated,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "✓ Release signing is set up for {slug} (key id {}).",
                kp.key_id_hex()
            );
            println!("  • GitHub secret   {SECRET_ENV}  — set (the private key; never shown).");
            println!("  • GitHub variable {PUBKEY_VAR}  — set (the public key).");
            if repository_pins_updated {
                println!(
                    "  • Repository/installer public-key pins — updated; commit and push them before tagging."
                );
            }
            println!();
            if repository_pins_updated {
                println!("Commit and push the updated trust pins before creating any release tag.");
            } else {
                println!("The source trust pins already match; no repository edit is required.");
            }
            println!("The next release CI run signs every artifact and");
            println!("end-users' NEOTH verifies it before any auto-update.");
        }
    }
    Ok(())
}

fn validate_non_rotating_setup(
    local_public_key: Option<String>,
    remote: &RemoteReleaseTrust,
    repository_public_key: Option<&str>,
    rotation_pending: bool,
) -> Result<()> {
    anyhow::ensure!(
        !rotation_pending,
        "a release-key rotation is incomplete; rerun `neoth release setup --force` to resume it"
    );
    if let (Some(remote), Some(repository)) = (remote.public_key.as_deref(), repository_public_key)
    {
        anyhow::ensure!(
            remote == repository,
            "published Actions release key does not match the repository pin; refusing to \
             overwrite either without explicit `--force` rotation"
        );
    }
    let Some(local) = local_public_key.as_deref() else {
        anyhow::ensure!(
            remote.public_key.is_none() && repository_public_key.is_none() && !remote.secret_exists,
            "no local release signing key exists, but this repository already has a published \
             release trust root. Recover the existing secret key from the maintainer backup; \
             use `--force` only for an intentional, source-pinned key rotation"
        );
        return Ok(());
    };
    if let Some(remote) = remote.public_key.as_deref() {
        anyhow::ensure!(
            remote == local,
            "local release key does not match the published Actions variable; refusing an \
             implicit trust-root replacement (use `--force` only for intentional rotation)"
        );
    }
    if let Some(repository) = repository_public_key {
        anyhow::ensure!(
            repository == local,
            "local release key does not match NEOTH_RELEASE_MINISIGN_PUBKEY.txt; refusing an \
             implicit trust-root replacement (use `--force` only for intentional rotation)"
        );
    }
    anyhow::ensure!(
        !(remote.secret_exists && remote.public_key.is_none() && repository_public_key.is_none()),
        "a release signing secret exists remotely but no public trust anchor is visible; \
         refusing to overwrite ambiguous key material"
    );
    Ok(())
}

fn detect_repo_root() -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned()))
}

fn ensure_checkout_matches_repo(expected_slug: &str) -> Result<()> {
    let checkout_slug = detect_repo_slug().context(
        "could not verify that the current checkout belongs to the target release repository",
    )?;
    anyhow::ensure!(
        checkout_slug.eq_ignore_ascii_case(expected_slug),
        "target repository `{expected_slug}` does not match the current checkout origin \
         `{checkout_slug}`; run setup inside the checkout that will receive the trust-pin commit"
    );
    Ok(())
}

fn read_repository_pubkey(repo_root: &std::path::Path) -> Result<Option<String>> {
    let path = repo_root.join("NEOTH_RELEASE_MINISIGN_PUBKEY.txt");
    match std::fs::read_to_string(&path) {
        Ok(value) => Ok(Some(value.trim().to_owned()).filter(|value| !value.is_empty())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn gh_release_trust(slug: &str) -> Result<RemoteReleaseTrust> {
    let variables = std::process::Command::new("gh")
        .args(["variable", "list", "--repo", slug, "--json", "name,value"])
        .output()
        .context("run `gh variable list`")?;
    anyhow::ensure!(
        variables.status.success(),
        "`gh variable list --repo {slug}` failed: {}",
        String::from_utf8_lossy(&variables.stderr).trim()
    );
    let variable_rows: Vec<serde_json::Value> =
        serde_json::from_slice(&variables.stdout).context("parse `gh variable list` JSON")?;
    let public_key = variable_rows.iter().find_map(|row| {
        (row.get("name")?.as_str()? == PUBKEY_VAR)
            .then(|| row.get("value")?.as_str().map(str::trim).map(str::to_owned))
            .flatten()
    });

    let secrets = std::process::Command::new("gh")
        .args(["secret", "list", "--repo", slug, "--json", "name"])
        .output()
        .context("run `gh secret list`")?;
    anyhow::ensure!(
        secrets.status.success(),
        "`gh secret list --repo {slug}` failed: {}",
        String::from_utf8_lossy(&secrets.stderr).trim()
    );
    let secret_rows: Vec<serde_json::Value> =
        serde_json::from_slice(&secrets.stdout).context("parse `gh secret list` JSON")?;
    Ok(RemoteReleaseTrust {
        public_key,
        secret_exists: secret_rows
            .iter()
            .any(|row| row.get("name").and_then(serde_json::Value::as_str) == Some(SECRET_ENV)),
    })
}

fn replace_pin_line(contents: &str, prefix: &str, replacement: &str) -> Result<String> {
    let mut replacements = 0usize;
    let mut lines = Vec::new();
    for line in contents.lines() {
        if line.trim_start().starts_with(prefix) {
            replacements += 1;
            lines.push(replacement.to_owned());
        } else {
            lines.push(line.to_owned());
        }
    }
    anyhow::ensure!(
        replacements == 1,
        "expected exactly one `{prefix}` installer pin, found {replacements}"
    );
    Ok(format!("{}\n", lines.join("\n")))
}

fn sync_repository_pubkey_pins(repo_root: &std::path::Path, pubkey: &str) -> Result<()> {
    let key_path = repo_root.join("NEOTH_RELEASE_MINISIGN_PUBKEY.txt");
    let sh_path = repo_root.join("SRC/install.sh");
    let ps_path = repo_root.join("SRC/install.ps1");
    let sh =
        std::fs::read_to_string(&sh_path).with_context(|| format!("read {}", sh_path.display()))?;
    let ps =
        std::fs::read_to_string(&ps_path).with_context(|| format!("read {}", ps_path.display()))?;
    let sh = replace_pin_line(
        &sh,
        "PINNED_MINISIGN_PUBKEY=",
        &format!("PINNED_MINISIGN_PUBKEY=\"{pubkey}\""),
    )?;
    let ps = replace_pin_line(
        &ps,
        "$PinnedMinisignPubkey =",
        &format!("$PinnedMinisignPubkey = '{pubkey}'"),
    )?;
    crate::util::atomic_write::atomic_write(&key_path, format!("{pubkey}\n").as_bytes())
        .with_context(|| format!("write {}", key_path.display()))?;
    crate::util::atomic_write::atomic_write(&sh_path, sh.as_bytes())
        .with_context(|| format!("write {}", sh_path.display()))?;
    crate::util::atomic_write::atomic_write(&ps_path, ps.as_bytes())
        .with_context(|| format!("write {}", ps_path.display()))?;
    Ok(())
}

/// Parse `owner/name` from a GitHub remote URL (https / ssh / token-embedded).
fn parse_repo_slug(remote_url: &str) -> Option<String> {
    let s = remote_url.trim();
    let idx = s.find("github.com")?;
    let rest = &s[idx + "github.com".len()..];
    // After `github.com` comes `:` (ssh) or `/` (https); strip any leading sep.
    let rest = rest.trim_start_matches([':', '/']);
    let rest = rest.trim_end_matches('/').trim_end_matches(".git");
    let mut parts = rest.split('/');
    let owner = parts.next()?.trim();
    let name = parts.next()?.trim();
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

/// Resolve the repo slug from the `origin` git remote.
fn detect_repo_slug() -> Result<String> {
    let out = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .context("run `git remote get-url origin` (is this a git repo with an origin?)")?;
    if !out.status.success() {
        anyhow::bail!("`git remote get-url origin` failed — pass `--repo owner/name`");
    }
    let url = String::from_utf8_lossy(&out.stdout);
    parse_repo_slug(url.trim()).ok_or_else(|| {
        anyhow::anyhow!(
            "could not parse a GitHub `owner/name` from `{}`",
            url.trim()
        )
    })
}

/// Fail early + actionably if `gh` is missing or not authenticated.
fn ensure_gh_ready() -> Result<()> {
    let v = std::process::Command::new("gh").arg("--version").output();
    if v.map(|o| !o.status.success()).unwrap_or(true) {
        anyhow::bail!(
            "the GitHub CLI `gh` is not available. Install it (https://cli.github.com) and run \
             `gh auth login`, then re-run `neoth release setup`. Or use the manual path: \
             `neoth release keygen` prints the two values to paste yourself."
        );
    }
    let auth = std::process::Command::new("gh")
        .args(["auth", "status"])
        .output()
        .context("run `gh auth status`")?;
    if !auth.status.success() {
        anyhow::bail!("`gh` is installed but not authenticated — run `gh auth login` first");
    }
    Ok(())
}

/// `gh secret set <name> --repo <slug>` reading the value from STDIN, so the
/// secret never appears in argv / the process list / shell history.
fn gh_set_secret(slug: &str, name: &str, value: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    // `gh secret set NAME --repo R` reads the value from STDIN when `--body` is
    // omitted — so the secret never appears in argv / the process list.
    let mut child = Command::new("gh")
        .args(["secret", "set", name, "--repo", slug])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn `gh secret set`")?;
    child
        .stdin
        .take()
        .context("gh stdin")?
        .write_all(value.as_bytes())
        .context("pipe secret to gh")?;
    let status = child.wait().context("wait for `gh secret set`")?;
    if !status.success() {
        anyhow::bail!("`gh secret set {name}` exited {status}");
    }
    Ok(())
}

/// `gh variable set <name> --repo <slug> --body <value>` (the value is the
/// PUBLIC key — safe on argv).
fn gh_set_variable(slug: &str, name: &str, value: &str) -> Result<()> {
    let status = std::process::Command::new("gh")
        .args(["variable", "set", name, "--repo", slug, "--body", value])
        .status()
        .context("run `gh variable set`")?;
    if !status.success() {
        anyhow::bail!("`gh variable set {name}` exited {status}");
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

fn verify(
    file: &std::path::Path,
    signature: Option<&std::path::Path>,
    output: OutputFormat,
) -> Result<()> {
    let signature_path = signature
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}.minisig", file.display())));
    let data = std::fs::read(file).with_context(|| format!("read {}", file.display()))?;
    let signature_text = std::fs::read_to_string(&signature_path)
        .with_context(|| format!("read {}", signature_path.display()))?;
    let status = crate::updater::sig_verify::check_signature(&data, Some(&signature_text), true)
        .with_context(|| {
            format!(
                "verify {} against {}",
                file.display(),
                signature_path.display()
            )
        })?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "file": file.display().to_string(),
                "signature": signature_path.display().to_string(),
                "status": status.as_str(),
            })
        ),
        OutputFormat::Table => println!(
            "✓ verified {} against the pinned release key ({})",
            file.display(),
            status.as_str()
        ),
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
    if let Ok(b64) = std::env::var(SECRET_ENV)
        && !b64.trim().is_empty()
    {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .with_context(|| format!("{SECRET_ENV} is not valid base64"))?;
        return ReleaseKeypair::from_secret_bytes(&bytes)
            .with_context(|| format!("{SECRET_ENV} is not a valid release secret"));
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

    // All tests that read or mutate NEOTH_RELEASE_MINISIGN_SECRET must hold this
    // lock for the duration of the env-sensitive section.  cargo test is
    // multi-threaded: without serialisation, sign_prefers_secret_env_over_file's
    // set_var races with load_signing_key in keygen_then_pubkey_then_sign, causing
    // the wrong key to be used for signing → verify fails (observed on Linux CI).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        // Hold ENV_LOCK while calling sign() so no concurrent test can inject
        // NEOTH_RELEASE_MINISIGN_SECRET into our process env and cause
        // load_signing_key to pick up a different key.
        {
            let _guard = ENV_LOCK.lock().unwrap();
            sign(&key_path, &artifact, Some("ci"), OutputFormat::Table).unwrap();
        }

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
    fn parse_repo_slug_handles_https_ssh_and_token_forms() {
        assert_eq!(
            parse_repo_slug("https://github.com/The-Geek-Freaks/NEOTH.git").as_deref(),
            Some("The-Geek-Freaks/NEOTH")
        );
        assert_eq!(
            parse_repo_slug("https://github.com/owner/name").as_deref(),
            Some("owner/name")
        );
        assert_eq!(
            parse_repo_slug("git@github.com:owner/name.git").as_deref(),
            Some("owner/name")
        );
        assert_eq!(
            parse_repo_slug("https://x-access-token:ghp_AAA@github.com/o/n.git").as_deref(),
            Some("o/n")
        );
        // Trailing newline (git output) + slash tolerated.
        assert_eq!(
            parse_repo_slug("https://github.com/o/n/\n").as_deref(),
            Some("o/n")
        );
        // Non-github / malformed → None (caller falls back to --repo).
        assert!(parse_repo_slug("https://gitlab.com/o/n.git").is_none());
        assert!(parse_repo_slug("github.com/onlyowner").is_none());
    }

    #[test]
    fn setup_never_replaces_an_existing_remote_key_from_a_new_machine() {
        let remote = RemoteReleaseTrust {
            public_key: Some("published".into()),
            secret_exists: true,
        };
        let error = validate_non_rotating_setup(None, &remote, Some("published"), false)
            .expect_err("missing local secret must not bootstrap over published trust");
        assert!(error.to_string().contains("already has a published"));
    }

    #[test]
    fn setup_plain_rerun_requires_all_visible_key_anchors_to_match() {
        let remote = RemoteReleaseTrust {
            public_key: Some("same".into()),
            secret_exists: true,
        };
        validate_non_rotating_setup(Some("same".into()), &remote, Some("same"), false)
            .expect("matching local/Actions/repository anchors are idempotent");

        let error = validate_non_rotating_setup(Some("other".into()), &remote, Some("same"), false)
            .expect_err("mismatched local key must fail closed");
        assert!(error.to_string().contains("local release key"));
    }

    #[test]
    fn setup_allows_only_a_genuinely_empty_first_bootstrap() {
        validate_non_rotating_setup(None, &RemoteReleaseTrust::default(), None, false)
            .expect("empty local and remote state may bootstrap");
        assert!(
            validate_non_rotating_setup(None, &RemoteReleaseTrust::default(), None, true,).is_err(),
            "an interrupted rotation must be resumed explicitly"
        );
    }

    #[test]
    fn installer_pin_rewrite_is_exact_and_rejects_ambiguous_input() {
        let rewritten = replace_pin_line(
            "before\nPINNED_MINISIGN_PUBKEY=\"old\"\nafter\n",
            "PINNED_MINISIGN_PUBKEY=",
            "PINNED_MINISIGN_PUBKEY=\"new\"",
        )
        .unwrap();
        assert_eq!(rewritten, "before\nPINNED_MINISIGN_PUBKEY=\"new\"\nafter\n");
        assert!(replace_pin_line("none\n", "PIN=", "PIN=x").is_err());
        assert!(replace_pin_line("PIN=a\nPIN=b\n", "PIN=", "PIN=x").is_err());
    }

    #[test]
    fn sign_prefers_secret_env_over_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = sig_keygen::default_release_key_path(dir.path());
        // Generate a key, capture its secret, then point the env at a DIFFERENT
        // key — sign must use the env key.
        let env_kp = ReleaseKeypair::generate().unwrap();
        let env_b64 = base64::engine::general_purpose::STANDARD.encode(env_kp.secret_bytes());
        // A file key also exists (different key).
        let file_kp = ReleaseKeypair::generate().unwrap();
        sig_keygen::save_secret_key(&key_path, &file_kp, false).unwrap();

        // Hold ENV_LOCK for the entire set_var → load → remove_var window so no
        // other test (keygen_roundtrip) calls load_signing_key while the var is set.
        let loaded = {
            let _guard = ENV_LOCK.lock().unwrap();
            // SAFETY: env mutation is serialised by ENV_LOCK across all tests in
            // this module that touch NEOTH_RELEASE_MINISIGN_SECRET.
            unsafe { std::env::set_var(SECRET_ENV, &env_b64) };
            let result = load_signing_key(&key_path).unwrap();
            unsafe { std::env::remove_var(SECRET_ENV) };
            result
        };

        // The env key won, not the file key.
        assert_eq!(loaded.public_key_base64(), env_kp.public_key_base64());
        assert_ne!(loaded.public_key_base64(), file_kp.public_key_base64());
    }
}
