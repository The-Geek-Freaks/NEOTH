# Gold Waves 21–23 — named Telegram onboarding and macOS SQLite-path repair

**Receipt status:** **LOCAL VALIDATION COMPLETE.** Eleven Rust/Slint source
files build on W20 `080131b4320ac3935d1f5d05e242295e5c3625a8`. Publication
identity is the Git commit containing this receipt. No native GUI acceptance,
macOS CI, full CI, or cross-platform acceptance is claimed.

## W21 — one named Telegram account

`neoth channel account add telegram --account <id> --telegram-user-id <id>
--token <secret>` creates or replaces only that explicit map entry. The
account-specific `set-credentials` action takes a strict private-stdin envelope
with an exact account, positive Telegram user ID, and token; unknown fields are
rejected. The candidate's exact authenticated account is probed before commit.
The paired policy/credential transaction and named dynamic-key CAS reject stale
state with a retry error. Output is secret-free; a reload error reports the
truthful committed-storage state.

## W22 — Settings account actions

Settings → Channels reuses its existing modal for Telegram **Add account** and
per-account **Edit**. Add is available for a valid map and the exact fresh
Telegram state, alongside the explicit legacy Configure route; no default is
inferred and no migration is automatic. Edit targets the selected canonical
account; token and allowed user ID must be entered again. The UI sends its
account request only through private stdin and accepts only an exact,
secret-free acknowledgement for that account. Invalid maps stay CLI-repair-only.

## W23 — physical SQLite display path

The existing bound-directory capability retains its logical display path and
adds a physical trusted display path for SQLite `NOFOLLOW` consumers. The
existing-only recall reader uses that physical path only for SQLite while
retaining the same bound-home, leaf no-follow, and identity-revalidation checks.
Related credential-transfer and hygiene-store child bounds carry the physical
path forward. This repairs the macOS `/var` to `/private/var` alias condition;
macOS CI is still required.

## Completed local evidence

| Gate | Result |
| --- | --- |
| Final Clippy | **PASS** — 5m28s; 204.39 GiB minimum free; 11.04 GiB peak |
| TestBuild | **PASS** — 6m38s; 200.47 GiB minimum free; 15.16 GiB peak |
| Unit selection | **PASS** — 602/0/0 in 17.72s; catalogue 14,401 |
| Binary | SHA-256 `60BCA821635018CA6562280BE32D7A613EF8CBA77C257233BAC200C16833974F`; 280,314,880 bytes |
| GUI check | **PASS** — 2m32s; 209 GiB minimum free; 6.56 GiB peak |
| Headless GUI | **PASS** — 353/0/0 in 1.30s; build 4m51s; 204.73 GiB minimum free; 10.74 GiB peak |
| 13 other contract targets | **PASS** — 157/0/0; build 17.51s; 213.72 GiB minimum free; 1.49 GiB peak |
| 14 integration targets | **PASS** — 510 total |
| Python checks (19 + 11 + 8) | **PASS** |
| Formatting, GUI lint, and GUI self-test | **PASS** |
| CLI reference generation | **PASS** — 20 generated lines |

The GUI check does not link a GUI test monolith; it retains 13 known existing
`trusted_probe_supervisor` warnings. The receipt covers 155 source inputs, 15
executables, and 19 staged paths:
[source manifest](verification/gold-wave21-23-source-manifest.json) and
[test matrix](verification/gold-wave21-23-test-matrix.json).

## Release boundary

After publication, the root workflow will dispatch an exact-head full CI that
includes the macOS physical-path repair; no current macOS pass is claimed.

## Explicit limits

The compound does not add account removal or retirement, pairing, importer
custody, a GUI legacy-migration wizard, native GUI acceptance, physical delivery,
or non-Telegram account families. P1-16 remains open; counts stay 1,324 total /
1,010 complete / 312 open / 2 partial (314 raw; 313 pre-tag blockers).
