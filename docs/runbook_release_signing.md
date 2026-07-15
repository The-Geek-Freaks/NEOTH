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
checks that signature against the pinned public key before any auto-update. An
attacker who swaps a release cannot forge a signature without the private key.

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

## How an end-user verifies (no action needed by them)

The self-updater does it automatically:

- **Manual** (`neoth update --self --apply`): requires a verified signature by
  default. `--allow-unsigned` is the explicit trusted-recovery escape; a
  present-but-invalid signature still bails. The globally signed minisign
  trusted comment must also equal `file:neoth-<tag>-<target>.<ext>`, binding the
  authenticated bytes to the selected version and platform.
- **Unattended** (daemon auto-update): refuses anything short of a verified
  signature — no swap without cryptographic provenance.

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
