# Baileys Sharp dependency correction — 2026-09-13

The bridge pins production dependency `sharp` to `0.35.4`, so both the
direct resolution and the Baileys peer use the corrected version.
Baileys remains `7.0.0-rc13`; no bridge protocol or account state changed.

GitHub Dependabot alert 28 identifies `sharp < 0.35.4` in
`bridges/whatsapp-baileys/pnpm-lock.yaml`; the first patched version is
`0.35.4`. Source: [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c).

The lockfile changes are confined to Sharp, its platform/libvips packages
and its WASM runtime dependency. The corresponding libvips packages move
from `1.3.2` to `1.3.3`; the WASM runtime moves from `1.11.2` to `1.11.3`.

Verification on Windows, Node `22.22.1`, pnpm `10.32.1`:

- `pnpm install --frozen-lockfile`: pass.
- `pnpm test`: 14 passed, zero failed; the systemd environment test is
  skipped on Windows.
- `pnpm list sharp --depth Infinity`: direct and Baileys peer both `0.35.4`.
- In-process encode and decode of a generated 2×2 PNG: pass; runtime
  reports Sharp `0.35.4`, libvips `8.18.6`, PNG width/height `2/2`.
- Parent review found no unrelated package upgrades; `git diff --check`
  passes.

This is local dependency and bridge regression evidence. It does not claim
deployment, live WhatsApp delivery, Linux HEIF execution, or completion of
the R3-10 release gate. No alert was dismissed or ignored.
