# Handoff — C-04b Phase 2: Firefox `key4.db` master-key extraction

**Date:** 2026-05-27 (Session 27)
**Predecessor:** Session 27 shipped C-04b Phase 1 — `logins.json` parser
+ `decrypt_aes256_cbc_pkcs7` AES-256-CBC primitive + Cargo deps
(`aes 0.8` / `cbc 0.1` / `pbkdf2 0.12` / `subtle 2`). The substrate at
[`credentials/firefox.rs`](../SRC/neothd/src/credentials/firefox.rs)
has profile-root discovery (3 OS), `profiles.ini` parse, default-profile
picker, and `FirefoxImporter` returning zero entries with an honest
"Phase 2 lands Session 28" warning.

**Algorithm correction shipped Session 27:** the Session 26 handoff
line "AES-256-GCM decrypt the `login.json` blobs" was wrong. Firefox /
NSS has used **AES-256-CBC** since the format-4 `key4.db` switch
(NSS 3.40+). Session 27 module-doc + Cargo.toml comment document this
explicitly.

---

## What's still open

Phase 2 wires the AES-CBC primitive to real ciphertext from a live
Firefox install. **Chunk 1 (ASN.1 envelope decode) shipped Session 27;**
chunks 2 + 3 remain (~6-7h). Both are testable independently.

### 1. ASN.1 SECITEM envelope decode — ✅ shipped Session 27 (chunk 1)

Module at [`credentials/firefox_envelope.rs`](../SRC/neothd/src/credentials/firefox_envelope.rs).
Exposes:

- `FirefoxAlgorithm` enum (Aes256Cbc / TripleDesCbc / Unsupported(String))
- `FirefoxEnvelope { key_id, algorithm, iv, ciphertext }`
- `parse_firefox_envelope(b64) -> Result<FirefoxEnvelope, EnvelopeError>`
- `EnvelopeError` taxonomy (10 variants — every structural failure
  surfaces a distinct enum variant; importer collapses them to one
  Err shape before reaching the audit chain)

8 unit tests with hand-rolled BER fixtures pin the wire format.
Cargo dep added: `simple_asn1 = "0.6"`.

**Reference (for chunk 2 callers):** every `encryptedUsername` /
`encryptedPassword` field in `logins.json` is base64 of an ASN.1
BER SEQUENCE:

```
SEQUENCE                              -- PKCS#7 EncryptedData
  OCTET STRING (key_id, 16 bytes)     -- ref to key4.db row
  SEQUENCE                            -- AlgorithmIdentifier
    OID 2.16.840.1.101.3.4.1.42       -- AES-256-CBC
    OCTET STRING (16-byte IV)
  OCTET STRING (ciphertext)           -- PKCS#7-padded
```

**Crate pick:** `simple_asn1 = "0.6"` — minimal pure-Rust BER reader,
~400 LOC dep. Alternative: `rasn = "0.12"` (heavier but ASN.1
ergonomics are nicer). Either crate is fine for this single-shape
parse; `simple_asn1` keeps the dep graph lighter.

**New function shape:**

```rust
pub struct FirefoxEnvelope {
    pub key_id: Vec<u8>,
    pub algorithm_oid: String,
    pub iv: [u8; 16],
    pub ciphertext: Vec<u8>,
}

pub fn parse_firefox_envelope(b64: &str) -> Result<FirefoxEnvelope, String>;
```

**Tests:** synthesise a SECITEM by hand-rolling the BER bytes (8 KAT
vectors covering: canonical shape / wrong-OID / truncated outer
sequence / short IV / empty ciphertext / extra trailing bytes /
non-OCTET-STRING key_id / negative-tag).

### 2. `key4.db` master-key extraction (~5-6h, hardest chunk)

`key4.db` is a SQLite database with two relevant rows in the `metaData`
+ `nssPrivate` tables:

- `metaData.item1`: 16-byte SALT for PBKDF2
- `metaData.item2`: 16-byte CHECK_STRING ciphertext ("password-check")
- `nssPrivate.a11`: ASN.1 envelope wrapping the master key

**Crypto flow** (Firefox/NSS source: `softokn/legacy/sftkdb.c` +
`softokn/legacy/keydbm.c`):

```
1. operator_pw_utf8 = primary password (empty string if none set)
2. masking_key = PBKDF2-SHA256(operator_pw, salt, iters=10000, len=32)
3. check_plaintext = AES-256-CBC-decrypt(metaData.item2, masking_key)
   if check_plaintext != "password-check\x02\x02": wrong password
4. master_key_envelope = parse_asn1(nssPrivate.a11)
5. master_key = AES-256-CBC-decrypt(envelope.ciphertext, masking_key, envelope.iv)
```

**Crate uses:** `rusqlite` (already in tree), `pbkdf2 0.12` (just added),
`sha2 0.10` (already in tree), `hmac 0.12` (already in tree),
`subtle 2` (just added — for the constant-time check_string compare).

**New function shape:**

```rust
pub fn extract_master_key(
    key4_db_path: &Path,
    primary_password: &str,
) -> Result<[u8; 32], MasterKeyError>;

pub enum MasterKeyError {
    Sqlite(String),
    WrongPassword,
    KeyEnvelopeMalformed(String),
    CryptoFail,
}
```

**Tests:** the hardest test fixture problem. Three approaches in order
of preference:

1. **Synthetic key4.db**: generate a known-password key4.db with a
   helper script (Python `pyasn1` + `sqlite3` stdlib is ~50 lines)
   and check it into `tests/fixtures/c04b/`. Documented in fixture
   README. Single fixture per test scenario (empty-password /
   strong-password / wrong-password-rejection / multi-key-rows).
2. **Mock the SQLite reads**: factor `extract_master_key` to accept
   a trait `Key4DbReader` that test code can stub. Less faithful but
   no fixture files needed.
3. **Live integration test gated by env-var**: `FIREFOX_KEY4_DB_PATH`
   + `FIREFOX_PRIMARY_PASSWORD` for local dev runs. CI skips.

Recommend (1) + (3): synthetic for CI, live for local verification.

### 3. Wire up FirefoxImporter::discover_entries (~1h)

Once (1) + (2) ship, the importer flow is straightforward:

```rust
async fn discover_entries(&self) -> Result<DiscoveredCredentials, String> {
    let profile = pick_default_profile(...)?;
    let logins = parse_logins_json(&read("logins.json"))?;
    let master_key = extract_master_key(&profile.join("key4.db"), &operator_pw)?;

    let entries: Vec<_> = logins.logins.iter().filter_map(|l| {
        let env_u = parse_firefox_envelope(&l.encrypted_username).ok()?;
        let env_p = parse_firefox_envelope(&l.encrypted_password).ok()?;
        let username = decrypt_aes256_cbc_pkcs7(&master_key, &env_u.iv, &env_u.ciphertext).ok()?;
        let password = decrypt_aes256_cbc_pkcs7(&master_key, &env_p.iv, &env_p.ciphertext).ok()?;
        Some(CredentialEntry { hostname: l.hostname.clone(), username, password, ... })
    }).collect();

    Ok(DiscoveredCredentials { source: ImportSource::WizardPrompt, entries, warnings: vec![] })
}
```

**Operator-password prompt:** the importer needs the primary password.
The wizard step at [`cli::init::step6g_credential_import`](../SRC/neothd/src/cli/init.rs)
already has a dialoguer plumbing pattern — extend it with an
optional "Firefox primary password (leave empty if none set)" prompt
when the Firefox importer is in the chain. Skip the prompt in
non-interactive runs.

---

## Hard rules (carry over)

- **No raw secrets in logs.** The SC-17 redactor is upstream — the
  wizard pipeline already produces a `RedactedCredentialImportPayload`
  so the daemon-side audit chain never sees plaintext. Don't add
  `tracing::info!(password = %p, ...)` anywhere in this flow.
- **Constant-time compare** on the `check_string`. Use
  `subtle::ConstantTimeEq` — a `==` compare leaks via timing-side
  channel if the operator's password is brute-forced by a local
  attacker.
- **Padding-oracle hygiene.** The Phase 1 `decrypt_aes256_cbc_pkcs7`
  already collapses unpad-fail + downstream-parse-fail into the same
  generic Err. Don't differentiate those at any caller — the audit
  chain MUST not reveal which branch fired.
- **PROGRESS.md flip in the same commit.** When Phase 2 ships, update
  the C-04 entry to `[x]` with the commit hash and a sentence on
  each of the three chunks.

---

## Quick-reference file index (Session 27 additions)

```
C-04b crypto deps          SRC/neothd/Cargo.toml (aes/cbc/pbkdf2/subtle)
logins.json types          SRC/neothd/src/credentials/firefox.rs::FirefoxLoginsJson
                                                  ::FirefoxLoginEntry
JSON parser                SRC/neothd/src/credentials/firefox.rs::parse_logins_json
AES-256-CBC primitive      SRC/neothd/src/credentials/firefox.rs::decrypt_aes256_cbc_pkcs7
NIST KAT test              SRC/neothd/src/credentials/firefox.rs::tests::
                              decrypt_aes256_cbc_pkcs7_known_answer_test
Padding-oracle defence     SRC/neothd/src/credentials/firefox.rs::tests::
                              decrypt_aes256_cbc_pkcs7_wrong_key_returns_err
```

---

## Closing note

C-04b is unusual in that the hardest part (key4.db ASN.1 + SQLite +
PBKDF2 verification) sits in the middle of the dep chain — the primitive
at the top (AES-CBC) and the wiring at the bottom (importer) are both
short. Phase 1 shipped the easy ends. Phase 2 is one focused 1-1.5d
session of ASN.1 BER parsing + SQLite SECITEM extraction. Don't try
to chunk it further across multiple Claudes — context loss between
the ASN.1 layer + the PBKDF2 layer + the AES layer wastes more time
than it saves.
