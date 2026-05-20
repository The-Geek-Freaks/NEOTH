# ADR-001 — Slint as the GUI framework

**Status**: Accepted (backfilled 2026-05-16; the choice was made
informally during R-A5 research and shipped in `SRC/neothd-gui/`
without a formal record. This ADR documents the rationale so future
contributors have the constraint set in writing.)

## Context

NEOTH ships an operator-facing wizard GUI in addition to the CLI. The
target audience is a single solo operator on their own laptop, not a
multi-tenant web app. The wizard must:

1. Run on **Linux + macOS + Windows** from one Rust codebase.
2. Bundle as a **single binary** alongside the daemon — no separate
   runtime install, no Electron-style Chromium download.
3. Keep the **build pipeline pure-Rust** so the existing
   `scripts/cargo-msvc.ps1` wrapper + the cross-compile matrix in
   `.github/workflows/release.yml` work without per-platform
   toolchain bolt-ons.
4. Stay **honest about the dep posture** — NEOTH's "never phones home"
   invariant in `tests/no_outbound_network.rs` forbids any UI layer
   that opens HTTP back-channels to a remote service for theming,
   telemetry, or live updates.
5. Be **operator-tinkerable** — the wizard markup should be readable
   by a human who wants to fork it, not a generated artifact from a
   visual designer.

R-A5 research evaluated four contenders: Tauri, egui, Iced, and
Slint.

## Decision

We use **Slint** (version 1.x) as the GUI framework.

The wizard lives in `SRC/neothd-gui/`:
- `ui/main.slint` — markup, ~400 lines today.
- `src/main.rs` — Rust binding, ~440 lines today.
- `build.rs` — compiles the `.slint` markup into Rust at build time.

Slint's domain-specific language describes UI components declaratively
and compiles down to native widgets. The Rust binding exposes typed
property setters / event callbacks, so the wizard's state is read +
written from idiomatic Rust without an FFI dance.

## Consequences

**Positive**:
- Single binary, no runtime install. Operators run `neothd-gui` the
  same way they run `neothd`.
- Cross-compiles via the existing release matrix (Linux x86_64 / musl /
  aarch64; macOS x86_64 / arm64). Windows builds work locally with
  vcvars (no GTK / GLFW build-toolchain pain).
- `.slint` files are diff-friendly text — operators reading the
  wizard markup can find + edit specific screens without a designer.
- Slint's license is GPLv3 / royalty-free commercial / paid commercial
  — NEOTH ships under MIT OR Apache-2.0 + uses the GPLv3 path. The
  combined-work obligation is documented in `LICENSE-NOTES.md` (TBD).
- No web tech in the dep tree — no Chromium, no V8, no Node toolchain.
  Bundle size stays under 20 MB on Linux x86_64 (vs Tauri's ~80 MB
  with Chromium-WebView2 and Electron's ~150 MB).

**Negative**:
- Smaller ecosystem than web-based UI. Operators looking for a third-
  party Slint component library find a handful; React's component
  catalog is vastly larger.
- Theming requires writing Slint, not CSS. Operators familiar with
  web styling have a learning curve.
- The Slint debugger / inspector story is less mature than Chromium
  DevTools. We compensate with structured `tracing` logs from the
  Rust binding so debugging the wizard's state is grep-able.
- Accessibility (screen readers, keyboard navigation) lags behind
  Tauri-via-system-WebView in 2026. Acceptable for v0.1 (operator is
  on their own laptop, single-user); revisit when shipping public
  builds intended for accessibility-required environments.

**Operator-facing trade-offs**:
- The wizard is the *only* GUI surface today. The chat REPL stays
  CLI-driven (`neoth chat`), the daemon stays headless (`neothd
  serve`). Operators who want a chat GUI install a separate frontend
  (Open Web UI, LibreChat, etc) — NEOTH stays the operator-local
  backend.
- Future ADR-002 may add a system-tray binding (`tray-icon` crate +
  Slint window). Keeping the Slint choice means that surface lands
  in the same crate without re-tooling.

## Alternatives considered

### Tauri

Mature, large ecosystem, system-WebView based. **Why not**: drags in
WebView2 on Windows + WebKit on macOS + WebKitGTK on Linux — the
Linux story in particular fights the operator's distro libraries
(libwebkit2gtk version drift breaks builds across Ubuntu LTS releases).
Bundle size 60-80 MB. Operator-tinkerability is fine (HTML+JS) but
adds a runtime distinct from the daemon's pure-Rust posture.

### egui (immediate-mode)

Pure Rust, tiny bundle, easy to embed. **Why not**: immediate-mode
fundamentally re-renders on every frame. Wizard screens with text
inputs feel laggy on low-end laptops; the GPU draw loop kicks even
when the operator is idle. Mismatch for an operator-tinkering tool
that should stay quiet.

### Iced (Elm-style)

Pure Rust, retained-mode, Elm-architecture inspired. Reasonable
ecosystem (Iced is widely used). **Why not**: API churn — major
versions still break significantly between releases. Slint's API has
been stable since 1.0 (Apr 2023), Iced is still pre-1.0 as of the
research call. NEOTH ships a long-lived operator surface; API
churn is real cost.

### Cross-compile UI elsewhere (Flutter / Compose Multiplatform)

**Why not**: drags in the Dart VM / JVM runtime respectively. Breaks
the "single Rust binary" goal + the no-extra-runtime-install
constraint.

## References

- R-A5 research notes: `memory/neoth-research-synthesis.md` (Slint
  rationale + bundle-size comparison).
- Slint license posture: `https://slint.dev/pricing` (GPLv3 / royalty-
  free commercial / paid commercial).
- Wizard implementation: `SRC/neothd-gui/`.
- Master Open Items, G-1..G-12 in `PLAN/PROGRESS.md`.
