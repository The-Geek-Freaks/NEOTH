# Runbook — DPAPI-bound HMAC key disaster recovery

**Round-3 v0.4 SC-09 deliverable.** Operator-facing playbook for the
class of Windows-only failures where NEOTH's WAL HMAC compaction key
becomes unreadable because its DPAPI wrapper can't decrypt anymore.

This runbook is for **Windows operators only**. Linux + macOS use
filesystem permissions (0600 + DACL) without the DPAPI layer; recovery
on those platforms is the simpler `chmod 600 ~/.neoth/wal_hmac_key`
scenario.

---

## What DPAPI binding does + why

NEOTH's WAL writer emits periodic **HMAC-SHA256 compaction markers**
(Phase 33b SP-2) so a downstream reader can prove the WAL has not been
tampered with since the last marker. The key for those HMACs lives at
`~/.neoth/wal_hmac_key` (32 random bytes from the OS CSPRNG).

On Windows, K-Sec-4 (Session 2026-05-22) added a DPAPI wrap so the
on-disk key bytes are **encrypted with `CryptProtectData(... ,
CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, ...)`**. The
DPAPI master key is bound to the operator's **user profile + machine**;
Windows derives it from the operator's login credentials + a per-
machine entropy source. A successful `CryptUnprotectData` requires:

1. Same Windows user account that called `CryptProtectData`.
2. Same machine identity (DPAPI machine key from `LSA\Secrets`).
3. Same user-profile integrity (`%APPDATA%` not roamed cross-OS).

When any of those three change, the wrap can't be unsealed +
`neoth wal verify` fails with an opaque "HMAC key unreadable" error.

## Failure modes catalogue

| Scenario                                                                                       | Recovery path                          |
|------------------------------------------------------------------------------------------------|----------------------------------------|
| Operator changed Windows account password (Windows re-wraps DPAPI master on login — usually OK) | Usually no action — re-run `neoth wal verify`. |
| Operator moved `~/.neoth` to a new machine (USB stick / OneDrive sync)                          | DPAPI unwrap fails. **Use this runbook.** |
| Windows reinstalled in place; `%APPDATA%` survived                                              | DPAPI unwrap fails. **Use this runbook.** |
| Operator logged in via Microsoft Account vs local account → switched account type               | DPAPI unwrap fails. **Use this runbook.** |
| Disk imaged + restored to a new identical-hardware machine                                      | DPAPI unwrap fails. **Use this runbook.** |
| Profile corruption (DPAPI master key corrupted by other software)                               | Run `neoth wal verify`; if it fails, **use this runbook**. |
| Operator copied `wal_hmac_key` out via Explorer + back in elsewhere                             | DPAPI unwrap fails — DPAPI ciphertext only valid on origin. |

## Quick-triage: is this you?

```powershell
neothd wal verify
```

If the output mentions any of:
- `HMAC key unreadable`
- `CryptUnprotectData failed`
- `DPAPI unwrap failure (Win32 error 0x80090005)` (NTE_BAD_DATA)
- `WAL compaction marker verification skipped — key inaccessible`

…this runbook applies. If `neoth wal verify` returns OK, the HMAC
chain is intact — no recovery needed.

## Recovery procedures

### Tier 1 — Operator opted into plaintext key backup (preferred)

If you accepted the wizard's **opt-in plaintext key backup** at install
time, you have a USB-stick (or external file) copy of the raw 32-byte
key. Recovery:

1. Locate the backup file (default suggested path:
   `<USB>:\neoth-recovery\wal_hmac_key.plaintext` or wherever you
   chose).
2. Stop the daemon: `neothd stop` (or close the GUI).
3. Copy the backup into place + re-wrap with the new machine's DPAPI:
   ```powershell
   $backup = "X:\neoth-recovery\wal_hmac_key.plaintext"
   $target = "$env:USERPROFILE\.neoth\wal_hmac_key"
   neothd security rewrap-hmac-key --plaintext-source $backup --target $target
   ```
   This subcommand (planned — see SC-09 follow-on) reads the plaintext,
   re-wraps with `CryptProtectData` on the current machine + user, and
   writes the new ciphertext to `~/.neoth/wal_hmac_key`.
4. Re-run `neothd wal verify` — should now succeed; the existing WAL
   segments verify against the recovered key.

### Tier 2 — Operator declined backup, WAL audit history matters

Without a backup the **historical HMAC chain cannot be reconstructed**.
This is by design — the HMAC's tamper-detection property depends on
the key being secret + irrecoverable from disk-only observation. Two
options:

#### Option A — Rotate to a new key, accept the audit-chain gap

The new key starts a fresh HMAC chain; everything before the rotation
becomes unverifiable (treated as "trust-on-first-use" from rotation
onward). Acceptable when:
- You aren't using the HMAC verification for legal-audit purposes.
- The operator's threat model treats the on-machine WAL as trustworthy
  via OS-level access controls (DACL + BitLocker).

Procedure:
```powershell
neothd stop
del "$env:USERPROFILE\.neoth\wal_hmac_key"
neothd boot  # daemon emits a fresh key on next start, DPAPI-wrapped
neothd wal verify --since-rotation
```

The `--since-rotation` flag (planned — SC-09 follow-on; today
`neothd wal verify` skips windows whose key is unreadable) scopes
verification to segments emitted after the new key landed.

#### Option B — Treat WAL history as forensically void, archive + restart

Most defensive option when the threat model treats compaction-marker
verification as load-bearing:

```powershell
neothd stop
# Archive the unverifiable history
$ts = Get-Date -UFormat "%Y%m%dT%H%M%S"
$archive = "$env:USERPROFILE\.neoth\archived_unverifiable_$ts"
mkdir $archive
Move-Item "$env:USERPROFILE\.neoth\wal" $archive
Move-Item "$env:USERPROFILE\.neoth\views.db" $archive
Remove-Item "$env:USERPROFILE\.neoth\wal_hmac_key"
neothd boot  # fresh WAL + fresh views + fresh key
```

The archive directory preserves the prior WAL for forensic inspection
(if you ever recover the original DPAPI environment, you can move it
back) but the live daemon starts clean.

### Tier 3 — Last resort: full reset

When even archival isn't worth keeping (operator wants a clean slate):

```powershell
neothd stop
Remove-Item -Recurse -Force "$env:USERPROFILE\.neoth"
neothd init  # restart from the wizard
```

This wipes every NEOTH artifact (memory tiers, ground truth, channel
state, importer history). Use only when sure.

## Prevention — opt into the plaintext backup at wizard time

The wizard's step-3 (HMAC key generation) prompts:

> _NEOTH protects the WAL HMAC key with Windows DPAPI. If you lose
> access to this Windows account or move the install to a new machine,
> the key becomes unrecoverable + your WAL audit chain breaks._
>
> _Do you want NEOTH to write a plaintext copy of the key to an
> external location now? You'll need to keep this file secret +
> off the local disk (USB stick, password manager, etc.). Answer
> 'yes' for installs where audit-chain continuity across machine
> changes matters._
>
> `[y/N]`

Default `N` — opt-in. Operators who choose `y` get prompted for the
destination path; NEOTH writes the 32-byte raw key + a recovery
checksum + this runbook's URL.

**If you skipped this prompt the first time + want to opt in now,**
use the planned `neothd security backup-hmac-key --output <PATH>`
subcommand (SC-09 follow-on; tracks in PROGRESS_v1_0.md as a
remaining slice of SC-09).

## `neothd wal verify` error message improvement

Pre-SC-09 the verify command surfaced DPAPI failures as the bare
Win32 error code:

```
HMAC marker verification failed (Win32 error 0x80090005)
```

Operators had no path forward from that. SC-09 expands the message to
point at this runbook:

```
HMAC marker verification failed: DPAPI unwrap returned 0x80090005
(NTE_BAD_DATA). This usually means the ~/.neoth/wal_hmac_key was
wrapped on a different Windows account or machine. See
PLAN/RUNBOOK_dpapi_hmac_recovery.md for recovery procedures.
```

The improvement lives in `wal/dpapi.rs` once the runbook URL stabilises
+ the operator-facing message gets the path right.

## Operator-visible audit trail

Every step above emits a WAL event for the audit chain:

| Event                      | Code  | When                                            |
|----------------------------|-------|-------------------------------------------------|
| `HMAC_KEY_GENERATED`       | 0x18  | Wizard step-3 or auto-emit on first daemon boot.|
| `HMAC_KEY_WRAPPED_DPAPI`   | 0x14  | Each successful `CryptProtectData` call.        |
| `HMAC_KEY_UNWRAP_FAILED`   | 0x15  | DPAPI unwrap returns non-zero Win32 error.      |
| `COMPACTION_MARKER`        | 0x15  | Every N frames or T seconds (Phase 33b SP-2).   |

(Event codes are illustrative — confirm with `wal/events.rs` for
the current registry.)

The presence of `HMAC_KEY_UNWRAP_FAILED` frames in the WAL is itself
a useful audit signal: if a future investigator finds them, they know
exactly when the DPAPI binding broke + can correlate with operator-
machine-change events.

## Cross-references

- `PLAN/PROGRESS_v1_0.md` SC-08 — DPAPI wrap implementation (the
  feature this runbook covers recovery for).
- `PLAN/PROGRESS_v1_0.md` SC-09 — this runbook (Round-3 v0.4 deliverable).
- `SRC/neothd/src/wal/dpapi.rs` — the DPAPI wrap/unwrap implementation.
- `SRC/neothd/src/cli/security.rs` — `neoth security audit` aggregator
  surfaces HMAC-key health as one of its checks.
- `~/.claude/CLAUDE.md` hard rules — operator-prompts for high-impact
  recovery operations.

## Future SC-09 follow-on items

The runbook above references three subcommands that **don't ship in
this session's SC-09 closure** but are the next concrete extensions:

1. `neothd security rewrap-hmac-key --plaintext-source <PATH>` —
   used by Tier 1 recovery to re-wrap a backed-up plaintext key
   on the current machine.
2. `neothd security backup-hmac-key --output <PATH>` — operator-
   triggered post-install opt-in for the plaintext backup.
3. `neothd wal verify --since-rotation` — scopes verification to
   segments emitted after the most recent key rotation.

Each is a focused 2-4 hour slice; track in the SC-09 PROGRESS entry.

---

**Last reviewed:** 2026-05-27 (Session 28).
**Maintainer:** Whichever operator next hits a DPAPI unwrap failure
and refines the recovery path through experience.
