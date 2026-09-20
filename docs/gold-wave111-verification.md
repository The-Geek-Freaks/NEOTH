# W111 — IRC transport and secondary-filter configuration parity

This bounded R4-07 batch exposes the existing `irc_port`, `irc_tls` and
`irc_allowed_nick` settings through the typed channel CLI and its GUI form.
The mandatory authenticated IRCv3 services account remains the authorization
boundary. A nickname filter is additional, never a substitute for the account.

## Implemented source behavior

- `--irc-port` accepts whole-number ports `1..=65535`. Zero and out-of-range
  values cannot become an ephemeral or truncated listener/connection port.
- `--irc-tls true|false` preserves explicit false separately from an absent
  value. The GUI offers current/default, enabled and disabled choices.
- `--irc-allowed-nick` trims a nonblank nick and rejects whitespace/control
  characters in it. Its role remains an additional nick filter.
- Omission or blank public fields retain existing settings on credential
  replacement; a fresh configuration keeps runtime defaults (`6697`, TLS on,
  no nick filter). Explicit channel removal clears the settings, including a
  settings-only record, and reports that state as removed.
- The form gains its previously missing required authenticated services-account
  input in the existing fifth credential slot. This makes the GUI capable of
  satisfying the unchanged account requirement already enforced by the builder.
- Private JSON admits these keys only for IRC. Optional null means absence;
  strings or numbers cannot masquerade as TLS booleans. GUI credentials still
  travel through the existing zeroizing stdin request and fixed command argv.

## Evidence boundary

Implementation and independent review are complete; remote execution is pending. All dynamic validation is
GitHub-hosted under the workstation stability restriction. Real CLI parsing,
strict envelope validation, persistence staging/removal, tri-state mapping and
request/argv regressions are required before acceptance. Source forwarding and
Slint compilation do not establish native GUI event-loop, layout, accessibility
or an actual IRC server connection result.

The already-running full CI `35534405981` and preview `35534407998` cover
`7909081e`, preceding both LINE and this IRC batch. Current-source native gates
and a fresh actual-binary generated CLI-reference snapshot remain required.
No R4-07 checkbox or backlog count closes on this source slice.

The pure GUI builder carries its three IRC inputs in a small typed value to
keep the function signature below the strict-lint argument limit. Slint's
existing generated source contains a 16-argument callback, so the new 14-argument
forwarding is not barred by a general tuple-arity limit; only fresh remote
compilation can establish acceptance of this exact source.

Independent six-file source review found no blocking issue. The current CLI
reference needs regeneration for the three new IRC flags and corrected
services-account help; it is not treated as current until the actual binary
export is imported and the ordinary docgen gate is run.

## Remote formatting follow-up

W111 source `1644e74b` passed Code Quality `35536941852`; Preflight `35536941930` requested only Rustfmt layout corrections in four Rust files. The follow-up applies the exact remote hunks without local formatter execution. Fresh static gates, a generated IRC CLI reference, strict Clippy and native acceptance remain required. Earlier-source macOS completed 16821 tests: 16818 passed, three failed and 23 were skipped. The failures are generated-reference drift and two diagnosed MCP/GUI fixture defects queued as W113. Windows tests and the preview GUI build remain running.
