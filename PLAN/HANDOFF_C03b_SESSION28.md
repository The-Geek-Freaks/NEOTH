# Handoff — C-03b: Chrome per-OS credential decrypt

**Date:** 2026-05-27 (Session 27)
**Predecessor:** Session 25 shipped C-03 substrate — `credentials/
chrome.rs` has `chrome_login_data_path()` (3 OS) + the `Login Data`
SQLite read + the "deferred to C-03b" warning from `discover_entries`.
Session 27 explicitly did NOT touch this module — C-03b is multi-day
multi-platform work and deserves a focused session per OS.

**Scope:** decrypt the `Login Data` SQLite rows' `password_value`
column on Windows + Linux + macOS. Each OS uses a completely
different crypto path; combining them in one PR is acceptable
because the feature-flag gate cleanly partitions them.

---

## Per-OS algorithm reference

### Windows (DPAPI)

Chrome on Win11 stores passwords as DPAPI blobs. The decrypt path:

```
1. Read `password_value` BLOB from Login Data SQLite
2. Strip first 3 bytes if they equal "v10" or "v11" (newer
   Chrome wraps DPAPI output in an AES-GCM layer using a key
   stored in `Local State`). v10/v11 path: see step 4.
3. Legacy bare DPAPI: call `CryptUnprotectData(blob)` → plaintext.
4. v10/v11 path:
   a. Read `~/AppData/Local/Google/Chrome/User Data/Local State`
      (JSON file)
   b. Extract `os_crypt.encrypted_key` (base64)
   c. Strip "DPAPI" prefix → DPAPI-encrypted AES-256 key
   d. Decrypt that with `CryptUnprotectData` → 32-byte AES key
   e. Each password blob: first 3 bytes = "v10" (or "v11"),
      next 12 bytes = nonce, remainder = ciphertext + 16-byte
      GCM tag. Decrypt with `aes-gcm 0.10`.
```

**Crate picks:**
- `windows-sys = "0.59"` with features `Win32_Foundation`,
  `Win32_Security_Cryptography`
- `aes-gcm = "0.10"` for the v10/v11 envelope
- `serde_json` (already in tree) for `Local State`

**Feature flag:** `chrome-windows` (default-ON on Windows targets
only via `[target.'cfg(windows)'.dependencies]`).

**Estimated effort:** ~1 day. The DPAPI FFI is straightforward;
the v10 envelope is the bulk of the test work.

### Linux (libsecret via secret-service-rs)

Chrome on Linux stores passwords in the Secret Service (GNOME
Keyring / KWallet via DBus). The decrypt path:

```
1. Connect to org.freedesktop.secrets via DBus
2. Unlock the "default" collection (operator login keyring)
3. Look up the item with attributes:
     application = "chrome"
     server      = "" (Chrome stores per-origin, but the symmetric
                     key is application-scoped)
4. Read the secret → 16-byte AES key
5. PBKDF2-SHA1 (iter=1) derive — Chrome legacy uses iter=1
6. AES-128-CBC decrypt each password_value with derived key + IV
   from the blob header
```

**Crate picks:**
- `secret-service = "4"` (pure-Rust DBus client, no C deps for
  secret-service itself, but DBus library deps required: see
  `zbus = "5"` transitive)
- `aes = "0.8"` + `cbc = "0.1"` (already added Session 27 for C-04b)
- `pbkdf2 = "0.12"` (already added)

**System dep:** libdbus-1 (Linux only; usually pre-installed). The
secret-service crate accesses it via `zbus` which uses native UNIX
sockets — no `libdbus` linker dep.

**Feature flag:** `chrome-linux` (default-ON on Linux targets only).

**Estimated effort:** ~1 day. The Secret Service API is well-
documented; main risk is keyring-locked-out scenarios where the
operator's login keyring needs an interactive prompt — handle by
surfacing as `discover_entries` warning, not an error.

### macOS (Keychain via security-framework)

Chrome on macOS stores the symmetric key in the operator's
Login Keychain. The decrypt path:

```
1. Use `SecKeychainFindGenericPassword` to look up:
     service = "Chrome Safe Storage"
     account = "Chrome"
2. Returns 16-byte AES key
3. PBKDF2-SHA1 (iter=1003, "saltysalt" salt, output 16 bytes)
4. AES-128-CBC decrypt each password_value with derived key + IV
   from "v10" / "v11" prefix-byte handling
```

**Crate picks:**
- `security-framework = "3"` (Apple's official binding,
  RustCrypto-adjacent maintenance)
- `aes = "0.8"` + `cbc = "0.1"` + `pbkdf2 = "0.12"` (already added)
- `sha1 = "0.10"` (needs adding — Chrome legacy uses SHA-1 in PBKDF2)

**Feature flag:** `chrome-macos` (default-ON on macOS targets only
via `[target.'cfg(target_os = "macos")'.dependencies]`).

**Estimated effort:** ~1 day. macOS Keychain access can prompt the
operator for confirmation on first use — handle by documenting that
the prompt is expected behaviour, not by silencing it (silencing
would break Apple's security model).

---

## Shared substrate already in tree

`credentials/chrome.rs` already has:

```rust
pub fn chrome_login_data_path() -> Option<PathBuf>;  // 3 OS branches
pub struct ChromeImporter;
impl CredentialImporter for ChromeImporter { ... }
```

Per-OS decrypt functions live in new submodules:

```
credentials/
├── chrome.rs              -- existing substrate, dispatch
├── chrome_windows.rs      -- new, gated #[cfg(all(target_os = "windows", feature = "chrome-windows"))]
├── chrome_linux.rs        -- new, gated #[cfg(all(target_os = "linux", feature = "chrome-linux"))]
└── chrome_macos.rs        -- new, gated #[cfg(all(target_os = "macos", feature = "chrome-macos"))]
```

The dispatcher in `chrome.rs::discover_entries` picks the right
submodule via `cfg!` at compile time. Cross-OS testing in CI is
handled by the existing matrix (Linux + Windows + macOS jobs).

---

## Test strategy

Per-OS unit tests can't run on the wrong OS — gate them with
`#[cfg(target_os = "...")]` so they only run on the matching CI job.

**Windows tests:**
- DPAPI roundtrip with a synthetic blob (Chrome's CryptProtect path
  is symmetric — encrypt a known string then decrypt, compare)
- v10 envelope parse (no real crypto, just byte-slice handling)
- Missing `Local State` file → graceful Err
- `Local State` malformed JSON → graceful Err

**Linux tests:**
- Skip when DBus session not available (CI may not have one). Gate
  tests with a runtime probe + skip-with-explicit-log so the suite
  passes on bare CI but exercises locally.
- AES-CBC roundtrip with a fixed key/iv (reuses the same primitive
  as C-04b)

**macOS tests:**
- security-framework Keychain access requires a real keychain
  database; ship a fixture keychain in `tests/fixtures/c03b/`.
- AES-CBC roundtrip (same as Linux)
- Edge case: PBKDF2 iter=1003 vs iter=1 (Chrome's macOS path uses
  1003 iters, Linux uses 1) — pin both as separate tests so a
  future regression-swap is caught.

---

## Hard rules (carry over)

- **No raw secrets in tracing.** Per C-04b — collapse all crypto-
  fail paths into the same Err shape so audit chains never reveal
  which branch fired.
- **Operator-visible prompts on macOS.** Keychain access prompts
  are Apple's security model; don't try to bypass them with
  `kSecUseAuthenticationUI = kSecUseAuthenticationUIFail` even
  though that's possible — it would surface as a worse failure mode.
- **PROGRESS.md flip in the same commit** as each OS half. Each
  commit can ship one OS independently; don't wait for all three
  to land before flipping the parent C-03b entry.

---

## Suggested ordering for Session 28+

1. **Windows first** (~1d) — most common OS, simplest crypto path
   (DPAPI does the heavy lifting; we just FFI in).
2. **Linux second** (~1d) — Secret Service API is cleaner than
   macOS Keychain; AES-CBC primitive already in tree from C-04b.
3. **macOS third** (~1d) — Keychain integration is the most
   platform-specific; do it last when the dispatcher pattern is
   battle-tested.

Total: ~3 focused days. Each OS gets its own commit + PROGRESS flip.

---

## Quick-reference file index

```
Substrate (already shipped)   SRC/neothd/src/credentials/chrome.rs
Per-OS decrypt modules (new)  SRC/neothd/src/credentials/chrome_{windows,linux,macos}.rs
Feature flag declarations     SRC/neothd/Cargo.toml ([features] section)
Wizard wiring (no change)     SRC/neothd/src/cli/init.rs::step6g_credential_import
Importer trait                SRC/neothd/src/credentials/mod.rs::CredentialImporter
```

---

## Closing note

C-03b is the kind of work where careful platform-by-platform delivery
beats a big-bang attempt at all three at once. The Session 25 substrate
already isolates the dispatch layer from the crypto layer cleanly, so
each OS half is genuinely a 1-day focused commit. Don't combine them
until all three pass their respective CI matrix legs.
