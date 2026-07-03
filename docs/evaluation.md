# Evaluating NEOTH — the skeptic's path

You don't know the author. Good — you shouldn't have to. NEOTH's claims are
mechanisms, and mechanisms can be checked. This page is the 15-minute path
from "unknown repo" to "I verified the core claims myself, on my machine."

No account, no telemetry, no phone-home. Everything below runs locally.

## 0. Build it from source (5 min)

Don't trust a bootstrap script you haven't read? Fine — both installers are
short and reviewable ([SRC/install.sh](../SRC/install.sh),
[SRC/install.ps1](../SRC/install.ps1)), or skip them entirely:

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH/SRC
cargo install --path neothd
neoth doctor
```

`neoth doctor` tells you what state you're in and how to fix it — that's the
first claim tested (setup errors get explanations, not stack traces).

## 1. Verify the local-first claim (3 min)

```bash
neoth preset activate fully-local
neoth preset apply fully-local
neoth privacy audit --last 30d
```

The audit lists every provider call, profile write, and channel egress.
Fully-local mode should show zero cloud destinations. This is not a settings
toggle you have to believe — it is an audit log you read.

## 2. Verify the audit trail is tamper-evident (2 min)

```bash
neoth verify
neoth wal show --last 20
```

Every sensitive action lands in an append-only, HMAC-chained WAL.
`neoth verify` recomputes the chain — corrupt or edit a frame and it fails.
The trust anchor is a key on **your** disk, not a promise in a README.

## 3. Verify consent gates fail closed (2 min)

```bash
neoth profile pending     # nothing enters your profile without approval
neoth plugin ledger       # every plugin capability that was actually used
neoth wal show --type plugin_cap_denied   # over-level calls, refused + logged
```

Boundary crossings — cloud calls, profile extraction, channel egress, plugin
capabilities — are denied by default and audited in both directions
(grant and refusal). Details: [privacy.md](privacy.md).

## 4. Watch it watch itself (2 min)

```bash
neoth babel status
neoth babel windows
```

NEOTH scores its own event stream for collapse risk — seven variables per
rolling window, pre-registered failure definitions, self-calibrating
threshold with a reported Brier score. No other assistant ships an
instrument for its own degradation. The full model, including the open
research protocol behind it, is in [babel-index.md](babel-index.md).

## 5. Read the honest parts (1 min)

Credibility is also what a project admits:

- The README comparison marks unfinished things **Partial** or **Goal**, not Yes.
- [PLAN/PROGRESS_v1_0.md](../PLAN/PROGRESS_v1_0.md) tracks the live status of
  every claimed line item.
- [SECURITY.md](../SECURITY.md) has a real disclosure path.
- Dual-use security skills ship enabled and documented, with the one-line
  config to disable them — stated in the README, not buried.

## If something fails

That's data — [file it](https://github.com/The-Geek-Freaks/NEOTH/issues).
A reproducible failed check on this page is the most valuable issue you can
open against a project that claims verifiability.
