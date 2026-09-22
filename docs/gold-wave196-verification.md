# GOLD Wave 196: n8n installer pin and prerequisite verification

## Source boundary

`SRC/neothd/src/installers/n8n.rs` renders only the reviewed immutable
`docker.io/n8nio/n8n@sha256:9f693fd5565539efd5e75ad168526c8041a6af516d9e50bc4d9cb1c9c5031523`
reference or `npm install -g n8n@2.40.5`. The npm path is eligible only when
both `npm` is on `PATH` and `node --version` parses as a complete stable version with major 24 or
higher, matching the recorded `engines.node: >=24.0.0` metadata.

`SRC/neothd/src/cli/init/steps_channel.rs` applies that prerequisite in both
the interactive and non-interactive wizard paths before passing npm availability
to `InstallStrategy::recommend`. Docker retains precedence when present.

## Focused tests added or updated

- `docker_install_command_uses_canonical_image_and_port`
- `npm_install_command_is_global_install`
- `node_version_gate_rejects_unsupported_or_malformed_versions`
- `node_version_gate_accepts_node_24_and_newer`

## Validation limitation

These tests, Cargo, rustfmt, code parsers, and runtime probes were deliberately
not executed in Wave 196 because of the active BSOD hold. This note is static
source evidence only. It does not prove managed installation, npm tarball
integrity verification, authentication/readiness, service lifecycle, or
recursive dependency pinning.

The grouped Hosted lane requires these four identities in addition to the previous
34. It retains each behavior failure and fails after all selected tests; discovery
and compile failures remain immediate. The W195 extractor digest follow-up and
W191 real-WAL authorizer fixture repair are included with this batch.
