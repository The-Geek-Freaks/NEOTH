# W352 managed-browser operator CLI

W352 exposes only two explicit operator commands:

```text
neoth browser status
neoth browser install
```

`status` is a local, read-only verification of the reviewed managed-browser
artifact for the current platform. Its output intentionally says
`artifact_status`; it does not claim that a browser process, CDP endpoint, or
rendered-fetch runtime is ready. When `managed_browser.enabled` is false, it
reports the disabled policy without inspecting an artifact.

Both `status` and a default-off `install` read only the
`managed_browser` policy from public `freedom.yaml` bytes. They do not parse
or migrate legacy credentials, take the credential transaction lock, or create
lock artifacts. The full runtime configuration loader is reached only after the
public default-off gate admits an installation.

`install` is an explicit one-shot request. It first requires the default-off
`freedom.yaml` setting:

```yaml
managed_browser:
  enabled: true
```

With the setting absent or false, the command fails before it constructs an
external-HTTP authorizer, opens a WAL route, downloads anything, or writes an
artifact. With the setting true, it delegates only to the reviewed current-
platform installer with the canonical NEOTH home and an external-HTTP
authorizer explicitly bound to that same home. The one-shot cancellation token
is initially open and is closed by Ctrl-C; the installer observes it through
its download, extraction, marker, and publication boundaries.

The CLI has no browser launch, CDP connection, URL navigation, ambient-browser
fallback, automatic update, or generation-prune command. Successful install
output reports the verified artifact metadata and whether the artifact was
newly installed or already verified.

Focused source fixtures for hosted execution:

- `cli::browser::tests::browser_parser_accepts_exact_status_and_install_actions`
- `cli::browser::tests::disabled_status_does_not_inspect_or_claim_runtime_readiness`
- `cli::browser::tests::enabled_status_reports_unverified_artifact_without_starting_a_browser`
- `cli::browser::tests::read_only_policy_loader_uses_defaults_for_a_missing_file_without_lock_artifacts`
- `cli::browser::tests::read_only_policy_loader_preserves_existing_legacy_credential_source_without_locks`
- `cli::browser::tests::disabled_install_fails_before_authorizer_or_installer_delegation`
- `cli::browser::tests::cancelled_enabled_install_reaches_real_explicit_home_wal_authorizer_then_stops`

No local compiler, formatter, test, runtime, or download was run under the
active BSOD hold. GitHub-hosted compilation and the focused tests remain the
required acceptance evidence.
