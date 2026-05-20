# Contributing to NEOTH

NEOTH is early-stage. The codebase is small and the design docs in `PLAN/` are detailed. Read `PLAN/00_DESIGN_v1.1_FINAL.md` before submitting anything non-trivial.

## Dev Setup

**Requirements:**
- Rust 1.86+ (MSRV)
- A Telegram bot token for integration tests
- Optional for Phase 2+ work: a GPU with 3 GB+ VRAM for local Qwen3-4B-INT4

```bash
git clone https://github.com/owner/neoth
cd neoth

# Build
cargo build

# Run tests
cargo test

# Run with local config
cp config/freedom.example.yaml ~/.neoth/freedom.yaml
TELEGRAM_BOT_TOKEN=<your-token> cargo run --bin neothd
```

**Environment variables:**
```
ANTHROPIC_API_KEY=...       # or use claude CLI OAuth
GEMINI_API_KEY=...          # Phase 2, Right hemisphere
OPENAI_API_KEY=...          # Phase 2, Corpus Callosum
TELEGRAM_BOT_TOKEN=...      # required for channel tests
NEOTH_CONFIG_DIR=...        # override ~/.neoth/ (useful for testing)
```

**Lint and format:**
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo audit           # supply-chain check
```

CI runs all three. PRs that break lint are auto-rejected.

## Branch Policy

- `main` — always builds, always passes `cargo test`
- `feature/<name>` — your work branch, PR target is `main`
- `fix/<issue-number>-<short-desc>` — bug fixes
- No force-push to `main`. Ever.
- Rebase your branch on `main` before opening a PR.

## Commit Convention

Conventional commits, mandatory:

```
<type>: <description>

<optional body — explain the why, not the what>
```

Types: `feat` `fix` `refactor` `docs` `test` `chore` `perf` `ci`

Examples:
```
feat: add WAL segment rotation on 256 MiB threshold
fix: prevent PROFILE_DELTA re-promotion after redaction
test: add adversarial test for council unanimous-wrong case
chore: update tokio to 1.40
```

One logical change per commit. If your PR has 14 commits that all say "wip", squash before opening.

## Test Policy

- **80% coverage on new code.** Check with `cargo tarpaulin --out Html`.
- **TDD preferred.** Write the test, watch it fail, implement, watch it pass.
- **13 anti-pattern tests are mandatory.** These live in `tests/anti_patterns/` and enforce Framework v4.1 constraints. Do not delete or disable them. They test:
  1. Stateful Tool (tools must be stateless)
  2. Self-Modifying Tool
  3. Goal-Seeking Tool
  4. Meta-Decision-Making Tool
  5. Emergent Tool Composition
  6. Refusal Bypass
  7. Scope Inflation
  8. Strong Emergence
  9. Black-Box without Introspection
  10. Magic Scale Assumption
  11. Closed-Loop Ecology
  12. Level Confusion
  13. Bateson-III Claims

- **Integration tests** for channels require a live bot token. Mark with `#[ignore]` if they'd break CI without credentials. Run locally with `cargo test -- --ignored`.

- **WAL tests:** `cargo test wal_` runs the WAL-specific suite. The Day-30 acceptance criterion is: 10k events × 10 queries × p95 < 30 ms × 100/100 keyword-find. Any PR touching the WAL must not regress this benchmark.

## PR Template

When you open a PR, fill in:

1. **What:** one sentence describing the change
2. **Why:** link to issue or explain the motivation
3. **Tests:** what tests were added or updated
4. **Anti-patterns:** confirm none of the 13 anti-pattern tests were broken (`cargo test anti_pattern`)
5. **Breaking changes:** yes/no. If yes, describe migration path.

PRs without test coverage on new code will not be merged.

## Architecture Deep-Dive

If you're working on something non-trivial, read the relevant spec first:

| Area | Spec file |
|------|-----------|
| Overall design | `PLAN/00_DESIGN_v1.1_FINAL.md` |
| Tool/Pipeline/Ecology framework | `PLAN/tool_framework_v4_1.md` |
| WAL (wire format, compaction, HLC) | `PLAN/SPEC_wire_header_v2_slim.md`, `PLAN/SPEC_wal_lifecycle.md` |
| Memory / profile learning | `PLAN/SPEC_proactive_learning.md` |
| Local inference (Qwen) | `PLAN/SPEC_local_inference.md` |
| Council governance | `PLAN/SPEC_council_governance.md` |
| Channels (Telegram/WhatsApp/Slack) | `PLAN/SPEC_channels.md` |
| WASM plugins | `PLAN/SPEC_skill_plugin_system.md` |
| Profile claim guard | `PLAN/SPEC_profile_claim_guard.md` |

## First Issue

Look for `good first issue` label on GitHub. Good starting points:
- Adding a doc test to an existing module
- Improving error messages in the CLI
- Writing a missing unit test for a WAL utility function

Not a good first issue: anything touching WAL compaction, HLC ordering, or council governance. Those require reading the full spec first.

## License

By contributing, you agree that your contributions will be licensed under the same MIT OR Apache-2.0 dual license as the project.
