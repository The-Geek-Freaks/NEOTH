# Runbook — release signing (MAR-02)

NEOTH signs every release artifact so end-users' self-updater can verify
authenticity before swapping a binary. The signing keypair, the CI signing step,
and the verification are all **built into `neoth`** — no external `minisign`
tool, no password. This runbook covers the one-time setup and the **operational
hardening the signing secret demands**.

---

## The model in one paragraph

`neoth release keygen` mints an ed25519 keypair in-process, in minisign-
compatible form. The **public key** is versioned in
[`NEOTH_RELEASE_MINISIGN_PUBKEY.txt`](../NEOTH_RELEASE_MINISIGN_PUBKEY.txt),
mirrored by the `NEOTH_RELEASE_MINISIGN_PUBKEY` Actions variable, and pinned
into release binaries and bootstrap installers. The **private key** is saved
with private permissions at `~/.neoth/release/minisign.key` on the provisioning
maintainer's machine and copied into the GitHub Actions secret
(`NEOTH_RELEASE_MINISIGN_SECRET`) without printing it. CI signs each artifact
(`neoth release sign` → `<asset>.minisig`); the daemon's `updater::sig_verify`
checks that signature against the pinned public key before any update apply.
The recurring network-discovery lane is separately disabled as documented
below. An attacker who swaps a release cannot forge a signature without the
private key.

## Release self-knowledge inputs

The release workflow also builds the Graphify self-knowledge snapshot that is
shipped in every portable archive and native installer. Configure these before
tagging:

- Actions variable `NEOTH_GRAPHIFY_BACKEND`: one of `claude`, `gemini`,
  `openai`, `kimi`, or `deepseek`.
- Actions variable `NEOTH_GRAPHIFY_MODEL`: the exact model identifier used for
  semantic clustering.
- Actions secret `NEOTH_GRAPHIFY_API_KEY`: the credential for that selected
  backend. It is exposed only to the read-only snapshot-build job.

The generator environment is locked by
`packaging/graphify-release/{pyproject.toml,uv.lock}` to Python 3.12.10 and
`graphifyy==0.8.41` plus its required `matplotlib==3.10.8` SVG exporter,
including artifact hashes, and is created under the runner temporary directory
rather than inside the checkout. The same job first exercises the real locked
CLI through AST recovery, clustering, and every required export. It then pins the
workspace MSRV and records the normalized `rustc -Vv` and `cargo -V` identities
used by Graphify's Cargo parser in the hashed generation receipt. Python,
Graphify, Rust, and Cargo are probed again after generation; any drift fails the
release. Generation must start and end at the exact tag HEAD with a pristine
tracked input set. CI then seals the snapshot, re-verifies its closed file set
and provenance after every cross-job transfer, and compiles its source HEAD plus
canonical payload SHA-256 into the Rust release binaries. Containerized cross
builds explicitly pass those same bindings through.

The generator binds Graphify's pinned detector selection to the extraction
manifest. If that detector excludes a sensitive-looking filename that is still
public tracked code, NEOTH recovers only its AST locally before clustering; the
file is never sent to the semantic backend. The receipt permits at most one
such augmentation phase, and both the build-time and Rust runtime verifiers
validate its exact script and arguments.

The platform jobs recursively install the identical snapshot in the supported
portable, Linux package, macOS app, and Windows Setup layouts. The updater
accepts only package-owned locations derived from the installed executable;
the read-only `NEOTH_SELF_KNOWLEDGE_DIR` override is never a write target.
Release baselines are package-owned. Materialized `User Overlays` are
operator-owned and must survive update and uninstall.

### macOS native version ordering

Apple's current bundle contract allows only three numeric `CFBundleVersion`
components. NEOTH therefore maps a native macOS release to
`(major * 100 + minor).patch.slot`: `alpha.0..31` uses slots `0..31`,
`beta.0..31` uses `32..63`, `rc.0..31` uses `64..95`, and the stable release
uses `99`. Major, minor, and patch must each fit `0..99`, and major plus minor
must not both be zero. The same value is written to the app and PackageKit
receipt, so `beta.1 < beta.2 < rc.1 < stable` and the next patch/minor/major
always sorts later. A tag outside this deliberately bounded native mapping
fails in the keyless macOS preflight before signing or publication; CI never
silently collapses arbitrary SemVer prereleases to the stable bundle version.

## Closed public release-asset policy

The workflow does not treat every file emitted by a producer as a public
release asset. `packaging/release_asset_contract.py` defines the exact
version-derived surface: 52 canonical archives, native packages, metadata and
checksum sidecars for the supported matrix. From those names it derives the
53 signable payloads (including `SHA256SUMS`), 54 Cosign inputs (the signable
set plus the public key), and the exact 161-file publication set.

After all producers finish, CI rejects any missing or additional canonical
name and emits `NEOTH_INTERNAL_RELEASE_ASSET_POLICY`. That policy is included
in the SHA-256-bound cross-job transfer, but is never itself published. The
isolated minisign and Cosign jobs consume its closed lists; the checkout-free
publisher accepts only the policy's publication set and uploads those exact
paths rather than filename globs. An accidental extra archive, executable,
metadata file or checksum therefore fails before signing instead of silently
becoming part of NEOTH's public v1 contract.

## One-time setup (maintainer)

> **The canonical `The-Geek-Freaks/NEOTH` repository is already provisioned.**
> Do not run the setup command again merely because you are on a new machine.
> Verify the existing Actions secret/variable and repository pin instead. A
> machine without the original local private-key file cannot safely infer that
> the project needs a new key.

Run setup from the checkout whose `origin` is the target passed to `--repo`.
For a genuinely empty repository with no local key, Actions secret/variable, or
versioned public-key pin:

```
neoth release setup --repo owner/new-repository
```

Plain setup first reads the Actions variable, the visible secret-name list, the
local secret key, and the checked-out repository pin. It supports two
non-rotating states:

1. **Genuinely empty bootstrap:** all four trust-root locations are empty. The
   command generates the first key.
2. **Complete an existing key's provisioning:** the local secret exists, the
   published state is empty or matches it, and the source pin is missing (not a
   conflicting key). The command keeps that local key and fills the missing
   source/published copies.

Any non-empty mismatch fails closed. In particular, a missing local secret must
never bootstrap over an existing Actions or source trust root; recover the
maintainer backup or use the explicit rotation path.

Whenever source synchronization is required, setup verifies that the checkout
`origin` equals the target repository, writes a crash-recovery marker beside
the local secret, and automatically updates all three source pins:

- `NEOTH_RELEASE_MINISIGN_PUBKEY.txt`
- `SRC/install.sh`
- `SRC/install.ps1`

It then sets the GitHub **secret** (`NEOTH_RELEASE_MINISIGN_SECRET`) and
**variable** (`NEOTH_RELEASE_MINISIGN_PUBKEY`) via `gh`, and removes the marker
only after provisioning succeeds. If this sequence is interrupted, rerun
`neoth release setup --repo owner/name --force`: the marker makes that command
resume the same pending key instead of minting another one.

If setup changed any source pin, review the diff, commit it, and **push it before
tagging**. Setup prints that requirement. Only a fully matching
local/Actions/source state legitimately reports that no repository edit is
required. The release contract rejects drift among the three source copies and
the Actions variable.

A new fork cloned from NEOTH is not empty: it already contains the upstream
public-key pin. Give that fork its own trust root with the explicit `--force`
path below, from a checkout whose `origin` points at the fork; then commit and
push the three updated source pins before creating its first release tag.

Verify it landed:

```
gh secret list   --repo The-Geek-Freaks/NEOTH | grep MINISIGN
gh variable list --repo The-Geek-Freaks/NEOTH | grep MINISIGN
```

Both values and the versioned repository key are mandatory. A missing or
different public key stops before the build matrix; a missing secret or mismatched keypair stops before a
GitHub Release is created. CI publishes `NEOTH_RELEASE_MINISIGN_PUBKEY.txt` and
uses the just-built `neoth` to verify every generated `.minisig`.

## Rotation

```
neoth release setup --force
```

This is the only setup path allowed to replace a published trust root. It
generates a NEW key, writes a crash-resumable local rotation marker, updates
`NEOTH_RELEASE_MINISIGN_PUBKEY.txt` plus both bootstrap-installer pins, and then
re-provisions the Actions secret and variable. If the process is interrupted,
rerun the same `--force` command; it resumes the pending key instead of minting
another one. The marker is removed only after provisioning succeeds.

Review, commit, and **push** the three source-pin changes before the next tag.
The command prints that requirement; a local-only pin change is not a completed
rotation. **Caveat:** binaries already shipped
were built with the OLD public key; they will reject artifacts signed by the new
key on the unattended path. Rotate only when you intend that break (e.g. a key
compromise), and announce it.

---

## Hardening — the signing secret is a high-value target

The private key signs anything that ships to every user. Treat the release path
as privileged. Configure the repo accordingly:

### Tags & branches

- [ ] **Protected tags.** Add a tag protection rule for `v*` so only maintainers
      can create/move release tags (Settings → Tags). The release workflow
      triggers on the tag — an unprotected tag is an unprivileged release trigger.
- [ ] **Branch protection on the default branch.** Require PR review + status
      checks before merge; no direct pushes. The signing happens from whatever
      the tag points at.
- [ ] **Maintainer-only release tags.** Restrict who can push `v*` tags to the
      release maintainers (CODEOWNERS / ruleset actor allowlist).

### Secrets & workflow integrity

- [ ] **Actions secrets are protected** — `NEOTH_RELEASE_MINISIGN_SECRET` is a
      repository (or environment) secret, scoped only to the signing step and
      never echoed.
- [ ] **No unreviewed workflow changes before a release.** A PR that edits
      `.github/workflows/release.yml` can exfiltrate the secret. Require review
      from a release maintainer on any workflow change; consider a CODEOWNERS
      entry for `.github/workflows/`.
- [ ] **Pin third-party actions by SHA** (the release workflow already pins
      `action-gh-release` by commit) so a hijacked mutable tag can't run in the
      job that holds the secret.

### Optional but recommended

- [ ] **Environment approval for the release job.** Put the signing step in a
      GitHub **Environment** (e.g. `release`) with a required reviewer, so the
      job that can read the secret pauses for a human approval. This is the
      strongest control: even a malicious tag can't sign without an approver.
- [ ] **Least-privilege `GITHUB_TOKEN`.** The signing job needs only
      `contents: write` (+ `id-token: write` for the cosign keyless step).

---

## How an end-user verifies and the updater enforces authenticity

Signature verification itself is automatic on every supported apply path:

- **Manual** (`neoth update --self --apply`): requires a verified signature by
  default. `--allow-unsigned` is the explicit trusted-recovery escape; a
  present-but-invalid signature still bails. The globally signed minisign
  trusted comment must also equal `file:neoth-<tag>-<target>.<ext>`, binding the
  authenticated bytes to the selected version and platform.
- **Recurring daemon discovery:** currently performs no release, npm or Git
  network probe. The live reload-aware lanes report `SkippedByGate` until each
  concrete transport consumes request-bound authorization and records mandatory
  intent/result WAL. Consequently no unattended download, stage or swap is
  claimed in the current source. The dormant unattended apply boundary still
  refuses anything short of a verified signature; manual update is unaffected.

The binary installers also fail closed: they verify `<asset>.minisig` with the
versioned key, or use Cosign with the exact tagged workflow identity. If Cosign
and minisign are absent, the installers fetch a temporary Cosign version whose
platform digest is copied from the immutable official source recorded in
`packaging/cosign-bootstrap.json`; a mismatch is rejected before execution.
Anyone can verify by hand with `NEOTH_RELEASE_MINISIGN_PUBKEY.txt`; the only
installer escape is the loud `NEOTH_ALLOW_UNVERIFIED_RECOVERY=1` path when that
verifier cannot be downloaded and the artifact was authenticated out of band.
A present but invalid signature or verifier is never bypassed.

---

## Incident response (suspected key compromise)

1. `neoth release setup --force` — mint, source-pin, and provision a fresh key.
2. Review, commit, and push the changed public-key file and both installers.
3. Publish a new release tag so a clean, newly-signed artifact exists.
4. Announce the rotation; advise users to reinstall from a fresh download rather
   than auto-update across the rotation boundary.
5. Audit `.github/workflows/` history + recent Actions runs for the exfiltration
   vector.
