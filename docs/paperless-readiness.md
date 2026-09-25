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

`ownership.json` also records the immutable Paperless OCI contract identifier
and its admitted coverage. The currently admitted contract is
`index_and_child_metadata_only`: it binds the exact receipt and all three OCI
index pins, but does not claim config or layer-byte verification. A stale or
different contract marker is unowned and is refused without changing the
operator `paperless.env` or `state/`. `neoth paperless prepare` reports this
contract and coverage in both structured and table output. It still never pulls
or inspects Docker images.

Separately from that preparation-ownership coverage, the pinned Paperless, Valkey
and PostgreSQL OCI artifacts were recursively hash-verified — the OCI index,
platform manifests, config blobs and compressed layer bytes — recorded in
`docs/verification/paperless-oci-v3.2.1/recursive-blob-receipt.json`
(`artifact_blob_bytes_verified: true`). The managed installer compiles that
receipt in and checks the flag before it verifies engine images. That acquisition
retained, decompressed, extracted or ran nothing and performed no signature
verification; it is candidate provenance that does not by itself set
`artifact_verified`.

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
installation. Recursive OCI config and compressed layer bytes are already
hash-verified (see the recursive-blob receipt above); what P2-20 still requires is
artifact signature admission and binding verified artifacts to
install/update/repair/rollback/data-preserving-uninstall jobs — the update, repair
and rollback jobs are not yet implemented. The older TCP scan now reports
`port_open_unverified` and cannot mark Paperless as already running.

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

## Managed safe uninstall and reinstall

`neoth paperless uninstall` removes the three exact managed container IDs from
the last successful installation. It retains all six named volumes, staged
configuration, API credentials, the original install receipt and the recorded
volume-set generation. It also retains the Docker network. It does not remove an
arbitrary Paperless deployment.

Install and uninstall share one nonblocking operation lock. A second operation
reports `paperless_operation_in_progress`. Uninstall records its progress before
each exact-ID removal. If a removal response is lost, a retry only advances after
Docker proves that ID absent; an uncertain or still-present outcome stops without
issuing another removal. `neoth paperless status` includes `safe_uninstall` while
preserving its existing readiness fields.

After a completed uninstall, `neoth paperless install` reuses the retained data
volumes. A later uninstall binds to the new install receipt and new container
IDs. Invalid or mismatched receipts stop before removal. Purging retained data
is not part of this command.

Fresh managed installs record one shared generation for all six data volumes
and schema-2 install and uninstall receipts. A retained reinstall verifies the
same generation before reusing the volumes. Earlier schema-1 installations with
unlabelled volumes keep their normal install and safe-uninstall behavior; they
receive no generation retroactively. A corrupt or lost generation record, or a
missing member of an already completed volume set, stops reinstall before it
can recreate volumes.

The implementation and regression tests are reviewed; hosted native and real
retained-document acceptance remain separate gates. Do not treat a successful
volume-name inspection as proof that document bytes survived.
## Explicit retained-data removal

After a completed safe uninstall, `neoth paperless purge` previews the six
receipt-bound volumes and prints an exact confirmation phrase. Running
`neoth paperless purge --confirm "<phrase from the preview>"` permanently removes
that volume set. The preview and a wrong confirmation do not select Docker or
write purge custody. Schema-1 legacy installations are ineligible for this action.

Purge requires all original containers absent, matching generation labels on
all six volumes, and no attached containers. Each removal is recorded before
Docker dispatch. After an uncertain result, recovery only advances when that
exact volume is observed absent; it never repeats an uncertain removal.
Configuration, credentials, snapshots and lifecycle receipts remain preserved.
Repeating a completed purge rechecks absence and returns the existing receipt.

A fresh installation after purge still requires the separate generation-rotation
follow-up; the current installer refuses to recreate the deleted completed set.
The purge source has independent static review. Native execution and the real
six-volume product canary remain pending for this change.
