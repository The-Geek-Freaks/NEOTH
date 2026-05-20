## Summary

<!-- One paragraph. What does this PR do and why? -->

## Type of change

<!-- Check all that apply -->
- [ ] `feat:` new feature
- [ ] `fix:` bug fix
- [ ] `refactor:` code change with no behaviour change
- [ ] `perf:` performance improvement
- [ ] `test:` adding or fixing tests
- [ ] `docs:` documentation only
- [ ] `chore:` build, deps, CI
- [ ] `ci:` CI/CD pipeline change

## Design alignment

- [ ] I have checked [PLAN/00_DESIGN_v1.1_FINAL.md](../PLAN/00_DESIGN_v1.1_FINAL.md) and this PR is consistent with the current architecture.
- [ ] If this PR deviates from the design, I have explained why in the summary above.

## Anti-pattern checklist (G.1–G.13)

<!-- Based on the ADVERSARIAL review findings. Strike through items that don't apply. -->
- [ ] G.1 — No unbounded channel / queue growth introduced
- [ ] G.2 — No lock held across an `.await` point
- [ ] G.3 — No `unwrap()` / `expect()` on recoverable errors in production paths
- [ ] G.4 — No silent error swallowing (`let _ = ...` on fallible ops)
- [ ] G.5 — No hardcoded secrets, tokens, or personal data
- [ ] G.6 — WAL writes are crash-safe (fsync before rename, CRC intact)
- [ ] G.7 — No new `unsafe` block without a `// SAFETY:` comment
- [ ] G.8 — No blocking I/O called from async context (`std::fs` in tokio task)
- [ ] G.9 — Memory layer mutations go through the WAL (no direct state patch)
- [ ] G.10 — OAuth token refresh paths handle expiry before the token expires
- [ ] G.11 — No uncapped retry loop (exponential backoff + jitter + max attempts)
- [ ] G.12 — Plugin host sandbox boundary is not widened without review
- [ ] G.13 — All new public API surface has doc-comments

## Test plan

- [ ] `cargo fmt --all -- --check` passes locally
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes locally
- [ ] `cargo test --release` passes locally
- [ ] New behaviour is covered by unit or integration tests
- [ ] If E2E path changed: tested manually with a real channel message
- [ ] No regressions in existing tests

## Breaking changes

<!-- List any breaking changes to config schema, CLI flags, or IPC protocol. -->
None

## Related issues

<!-- Closes #, Fixes #, or N/A -->
