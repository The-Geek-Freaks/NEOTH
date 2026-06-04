# Runbook — release signing (MAR-02)

NEOTH signs every release artifact so end-users' self-updater can verify
authenticity before swapping a binary. The signing keypair, the CI signing step,
and the verification are all **built into `neoth`** — no external `minisign`
tool, no password. This runbook covers the one-time setup and the **operational
hardening the signing secret demands**.

---

## The model in one paragraph

`neoth release keygen` mints an ed25519 keypair in-process, in minisign-
compatible form. The **public key** is pinned into release binaries at build time
(`NEOTH_RELEASE_MINISIGN_PUBKEY`); the **private key** lives only in a GitHub
Actions secret (`NEOTH_RELEASE_MINISIGN_SECRET`). CI signs each artifact
(`neoth release sign` → `<asset>.minisig`); the daemon's `updater::sig_verify`
checks that signature against the pinned public key before any auto-update. An
attacker who swaps a release cannot forge a signature without the private key,
which never leaves CI secrets.

## One-time setup (maintainer)

```
neoth release setup
```

That single command generates the key, sets the GitHub **secret**
(`NEOTH_RELEASE_MINISIGN_SECRET`, piped over stdin — never argv/logs) and the
**variable** (`NEOTH_RELEASE_MINISIGN_PUBKEY`) on the repo via `gh`. Nothing to
copy-paste. (Manual path if you prefer: `neoth release keygen` prints both
values to provision yourself.)

Verify it landed:

```
gh secret list   --repo <owner/name> | grep MINISIGN
gh variable list --repo <owner/name> | grep MINISIGN
```

## Rotation

```
neoth release setup --force
```

Generates a NEW key and re-provisions CI. **Caveat:** binaries already shipped
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
      repository (or environment) secret, never echoed. The workflow pipes it to
      the signer over stdin and never `echo`s it.
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

- **Manual** (`neoth update --self --apply`): a present-but-invalid signature
  bails; a missing signature / unprovisioned key warns and proceeds (so
  pre-signing releases still update).
- **Unattended** (daemon auto-update): refuses anything short of a verified
  signature — no swap without cryptographic provenance.

Anyone can also verify by hand with the public key from
`gh variable get NEOTH_RELEASE_MINISIGN_PUBKEY` against `<asset>.minisig`.

---

## Incident response (suspected key compromise)

1. `neoth release setup --force` — mint + provision a fresh key immediately.
2. Re-release the current version (so a clean, newly-signed artifact exists).
3. Announce the rotation; advise users to reinstall from a fresh download rather
   than auto-update across the rotation boundary.
4. Audit `.github/workflows/` history + recent Actions runs for the exfiltration
   vector.
