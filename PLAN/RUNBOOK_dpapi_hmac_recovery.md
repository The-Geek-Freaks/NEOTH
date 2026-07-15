# Runbook — DPAPI-bound WAL HMAC-key recovery

This runbook covers a Windows installation whose WAL integrity key can no
longer be opened after an account/profile change, machine replacement, restore,
or Windows reinstall. The shipped commands also work on Linux and macOS, but
those platforms store the live key as an owner-only mode-0600 file instead of a
DPAPI blob.

**Live key:** `~/.neoth/wal/hmac.key`

**Primary recovery command:**

```powershell
neoth security rewrap-hmac-key --source X:\neoth-recovery\hmac.key
```

The recovery file contains the raw HMAC secret. Anyone who can read it can
forge WAL compaction markers. Keep it encrypted/offline and mount or copy it
only for backup/recovery.

## What Windows protects

On Windows, NEOTH calls `CryptProtectData` with flags `0`. It deliberately does
**not** use `CRYPTPROTECT_LOCAL_MACHINE`; the blob is bound to the current
Windows user/profile instead of being decryptable by every user on the machine.
Moving only `~/.neoth` to another account or machine therefore does not create a
portable key backup.

The file begins with `NEOTH_DPAPIv1\n`; the remaining bytes are the DPAPI blob.
On Unix, the file contains the key under mode 0600.

Typical Windows failure cases are:

- `~/.neoth` was restored on another machine;
- Windows was reinstalled while the NEOTH directory was retained;
- the installation moved to another local/Microsoft account or user profile;
- the DPAPI master-key material or wrapped file was damaged.

A normal password change is usually handled by Windows. Verify instead of
assuming either success or failure.

## Prevent the failure

The interactive `neoth init` wizard offers a plaintext recovery backup. The
offer defaults to **No** because exporting the secret is sensitive. If accepted,
the wizard:

1. asks for an explicit absolute file path outside `~/.neoth`;
2. initializes the WAL HMAC key securely on a fresh installation;
3. rejects `..`, symlink/junction escapes into `~/.neoth`, directories, and
   existing files;
4. writes through the same `backup-hmac-key` implementation used by the CLI;
5. aborts onboarding on key-generation, path, DPAPI, directory, or write errors.

NEOTH can prove that the path is outside its own home, but cannot prove that it
is on another physical disk. Choose a USB volume, encrypted removable storage,
password manager, or other genuinely independent destination. A sibling folder
on the same system disk is not disaster recovery.

To create a backup after onboarding:

```powershell
neoth security backup-hmac-key --output X:\neoth-recovery\hmac.key
```

The command refuses a path that resolves inside `~/.neoth` and refuses an
existing destination unless `--force` is explicitly supplied. Prefer a new,
epoch-labelled filename over `--force`; overwriting an older backup can destroy
the only key that verifies an earlier WAL epoch.

## Triage

Stop writes before changing a key: stop the foreground `neoth serve` process
with Ctrl-C, exit the GUI, or use the service manager that launched NEOTH.
There is no `neoth stop` or `neoth boot` command.

Run:

```powershell
neoth verify
```

This runbook applies when key loading reports `CryptUnprotectData`, a DPAPI
unwrap failure, or says that `~/.neoth/wal/hmac.key` is bound to another Windows
user/machine. A marker mismatch with a readable key is a different integrity
incident; do not rewrap over it.

Before recovery, preserve a read-only copy of the affected `~/.neoth` directory
when audit history matters.

## Recovery with the raw backup

1. Stop every NEOTH writer as described above.
2. Mount or copy the protected recovery file to the affected machine.
3. Re-bind the same raw key to the current environment:

   ```powershell
   neoth security rewrap-hmac-key --source X:\neoth-recovery\hmac.key
   ```

   On Windows this writes a new current-user DPAPI blob. On Unix it writes the
   live key mode 0600. The command replaces the unreadable live key by design.

4. Verify the complete retained history:

   ```powershell
   neoth verify
   ```

5. Only after verification passes, remove the mounted/working copy and return
   the recovery backup to protected offline storage. Do not delete the only
   disaster-recovery copy.

`rewrap-hmac-key` records an authenticated `0xD9 HMAC_KEY_ROTATED` boundary when
it can. If recording/signing fails, recovery still installs the key, but
`neoth verify --since-rotation` deliberately ignores an unsigned or missing
boundary and verifies the full history. This is fail-safe: it never skips more
history because an audit boundary could not be authenticated.

Because a rewrap restores the original raw key, the primary acceptance check is
the full `neoth verify`, not `--since-rotation`.

## No raw backup

If the original Windows user/profile and machine still work, create the backup
there first, then follow the recovery procedure:

```powershell
neoth security backup-hmac-key --output X:\neoth-recovery\hmac.key
```

If the original DPAPI context is gone, the HMAC secret cannot be reconstructed
from the WAL. This is the intended security property. Two operational choices
remain:

### Preserve evidence and start a clean NEOTH home

This is the honest boundary when the old audit history matters. With every
NEOTH process stopped:

```powershell
$home = Join-Path $env:USERPROFILE ".neoth"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$archive = Join-Path $env:USERPROFILE ".neoth-unverifiable-$stamp"
Move-Item -LiteralPath $home -Destination $archive
neoth init
```

This starts a new installation and preserves the old state separately for
forensics or a future recovery of the original DPAPI environment. It does not
claim continuity between the two audit histories. The move also removes the
live configuration, memories, credentials, and channel state from the new home;
restore only explicitly reviewed configuration, never the unreadable key.

### Rotate only when an audit gap is acceptable

```powershell
neoth keys rotate
neoth keys archives
```

`keys rotate` archives the current key file and generates a new key. On a moved
Windows installation, the archived DPAPI blob remains unreadable outside its
original user/profile. Historical markers therefore remain unverifiable unless
that original environment is recovered.

Current limitation: `keys rotate` does not emit the authenticated `0xD9`
boundary used by `neoth verify --since-rotation`; that verifier consequently
falls back to the full history. Rotation is operational recovery, not proof that
the historical chain is valid and not a clean `--since-rotation` boundary.

When an archived key is readable in its original environment, it can verify the
matching epoch explicitly:

```powershell
neoth verify --key C:\path\to\hmac.key.<unix-ts>.archive
```

## Command contract

| Purpose | Shipped command |
|---|---|
| Verify current WAL markers | `neoth verify` |
| Export raw recovery key | `neoth security backup-hmac-key --output <PATH>` |
| Re-bind raw key to this environment | `neoth security rewrap-hmac-key --source <PATH>` |
| Create a new key and archive the old file | `neoth keys rotate` |
| List archived key files | `neoth keys archives` |
| Verify from the authenticated rewrap boundary | `neoth verify --since-rotation` |
| Verify with a specific readable archived key | `neoth verify --key <PATH>` |

## Audit semantics

- `0x15 COMPACTION_MARKER` contains the HMAC-authenticated WAL range metadata.
- `0xD9 HMAC_KEY_ROTATED` is emitted by `rewrap-hmac-key`; its payload contains
  only metadata and the new-key SHA-256 digest, never the raw key.
- `--since-rotation` accepts a `0xD9` boundary only when its operator signature
  verifies. Forged or unsigned boundaries cannot suppress older verification.
- Backup creation itself is intentionally not recorded with the secret bytes.

Implementation references:

- `SRC/neothd/src/wal/dpapi.rs`
- `SRC/neothd/src/wal/compaction.rs`
- `SRC/neothd/src/cli/security.rs`
- `SRC/neothd/src/cli/verify.rs`
- `SRC/neothd/src/cli/keys.rs`

**Last reviewed:** 2026-07-14
