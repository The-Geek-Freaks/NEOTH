# Contributing to NEOTH

NEOTH's product promise is narrow and important: a private AI buddy that normal
users can start, and pros can operate deeply.

Good contributions make that promise clearer, safer, faster, or easier to
verify.

## Before you start

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH/SRC
cargo test --workspace
```

For non-trivial changes, read the relevant doc first:

| Area | Start with |
| :-- | :-- |
| Product/architecture | `docs/architecture.md` |
| CLI behavior | `docs/cli-reference.md` |
| Privacy/memory | `docs/privacy.md`, `docs/profile.md` |
| Channels | `docs/channels.md` |
| Providers/local models | `docs/providers.md`, `docs/local-models.md` |
| Plugins | `docs/plugins.md` |
| Internal release planning | `PLAN/PROGRESS_v1_0.md` |

## Development checks

Run the narrowest useful check while you work, then the full checks before a
PR:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

If you touch setup, channels, providers, plugins, WAL, or privacy behavior, run:

```bash
neoth doctor
neoth privacy audit --last 30d
neoth wal verify
```

## Pull requests

Keep PRs small. One behavior change per PR is ideal.

Include:

1. What changed.
2. Why it changed.
3. How you tested it.
4. Any privacy/security impact.
5. Any migration or compatibility note.

## Coding rules

- Match the existing Rust style and module boundaries.
- Prefer root-cause fixes over patches around symptoms.
- Do not hide errors with broad catch-all handling.
- Do not add ambient plugin or tool power without capability checks.
- Do not make cloud fallback invisible.
- Do not break the no-YAML happy path for normal users.

## Commit style

Use conventional commits:

```text
feat: add channel wiring doctor explanation
fix: keep redacted profile fact from re-promotion
docs: tighten privacy quickstart
test: cover provider fail-closed routing
```

## License

By contributing, you agree that your contribution is licensed under the same
MIT OR Apache-2.0 dual license as NEOTH.
