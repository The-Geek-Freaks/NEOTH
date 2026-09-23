# Paperless API status

`neoth paperless prepare` creates the selected instance home's `paperless`
directory. Use `neoth paperless prepare --directory PATH` for an exact explicit
destination whose parent already exists. Preparation writes only `ownership.json`,
`compose.yaml` and `paperless.env.example` through a sibling staging directory.
An existing matching preparation is reused; foreign files, modified owned files,
symlinks and reparse points are refused. Operator `paperless.env` and `state/`
are preserved. Preparation does not download images or run Docker.

The Compose file pins Paperless 3.2.1, Valkey and PostgreSQL by the OCI index
digests admitted in `docs/verification/paperless-oci-v3.2.1/`. It binds the web
service to loopback and requires operator-supplied credentials and a port via
`paperless.env`; the example contains no generated or default secrets. The
PostgreSQL 18 state mount uses `/var/lib/postgresql`. Modern and standalone
Compose command previews render only validation with `config`.

Status reports the default instance's staging observation separately from API
readiness. Preparing an explicit alternative directory does not change that
default. `artifact_verified` remains false: admitted registry metadata and a
prepared directory do not establish running-image identity or lifecycle jobs.

Run `neoth paperless status` to check the configured local Paperless API.
For a machine-readable result, use `neoth --output json paperless status`
or `neoth --output jsonl paperless status`.

The command reads `paperless_url` and `paperless_token` through the existing
NEOTH credential backend, including the configured keychain. It does not take
a token on the command line. This diagnostic supports literal loopback HTTP
origins with an explicit port, such as `http://127.0.0.1:8000` or
`http://[::1]:8000`. Other configured origins return `unsupported_endpoint`.
Existing document ingest, consult and quarantine commands keep their behavior.

A successful check first confirms that the profile endpoint rejects an
unauthenticated request, then authenticates with the stored token and validates
the documented Paperless profile response. It requests the reported version
from `/api/status/` only after the authenticated profile check succeeds.

- `authenticated_api_ready`: profile and stable-release version checked.
- `authenticated_status_permission_required`: profile authentication succeeded,
  but the token lacks system-status permission. API readiness is true and the
  version remains unknown.
- `not_configured` / `credentials_missing`: supply the endpoint and token through
  the existing NEOTH credential configuration before checking again.
- `unauthorized`: the configured credential was rejected.
- `authentication_not_enforced`, `invalid_response`, `redirect_rejected`,
  `response_too_large`, `timeout`, `transport_error` or `unsupported_version`:
  readiness is false. The response includes a fixed status code rather than
  server bodies, headers, credentials or profile details.

The entire HTTP sequence has a five-second deadline. Responses are limited to
32KiB, redirects and ambient HTTP proxies are disabled, and the collected profile buffer
is cleared after parsing. Only stable three-component numeric release versions
are projected. Upstream API shapes were inspected at Paperless-ngx commit
`c63afb47b27951cb6c61e68b6d77a5fd0eedd686`.

`artifact_verified` is always false in this diagnostic. An authenticated API and
a reported version do not attest the running image digest or an owned managed
installation. P2-20 remains open for pinned recursive artifact verification and
install/update/repair/rollback/data-preserving-uninstall jobs. The older TCP scan
now reports `port_open_unverified` and cannot mark Paperless as already running.

W515 source review covers the actual async CLI entry, the shared stored-credential
loader, the bounded authenticated HTTP probe, eight HTTP cases, four CLI cases
and the legacy port-only false-positive regression. The13selected cases are
registered in the hosted lane; execution is pending at publication.
The tests include a real stored-credential/HTTP path and verify that profile
`auth_token` and personal fields never enter the public readiness result.
No local executable validation ran under the workstation BSOD hold.

W540 adds seven new portable preparation/CLI regressions, one Unix symlink
regression, and selects six existing installer/instance-path tests. The CLI
integration exercises preparation followed by actual instance-scoped status;
the file tests verify byte-preservation of operator environment and state.
Independent static review is complete; hosted execution is pending at source
publication. P2-20 remains open.
