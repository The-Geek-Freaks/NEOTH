# Compiled NEOTH n8n bootstrap acceptance

The manual main-only `n8n-product-bootstrap.yml` workflow builds and invokes
the real public CLI: `neoth --output json n8n install --bootstrap-owner --port
5681`. The runner supplies an isolated empty NEOTH_HOME and a private unlocked
Secret Service session. Owner setup, API-key minting, Docker lifecycle and
credential publication are performed by the compiled product.

The Python observer checks one Ready setup job, matching bootstrap/runtime
custody and manifest, exact Docker identity, removed bootstrap container, and
unauthenticated denial plus authenticated workflow-list success. It invokes
the same install command again, then rechecks job, custody, status, runtime and
HTTP behavior. A bounded Docker event interval rejects new create/start/exec
activity for that job. This checks successful-repeat idempotence; it does not
stand in for crash/cancellation recovery tests.

The captured key is read from the product's job-specific Secret Service entry
into memory for the HTTP probe. No header file, raw key, cookie, or owner
password is included in logs or uploaded artifacts. Commands have output and
time bounds. The receipt binds the binary, helpers, workflow, test file, lockfile
and direct bootstrap Rust sources to the GitHub commit.

Cleanup requires exact runtime and volume ownership, proven absence, removal
of four job-bound bootstrap secrets, and deletion of the isolated home.
`docker_cleanup_proven` records the Docker result; `cleanup_proven` requires all
three cleanup stages. Failed partial installation with incomplete identities
retains its custody and cannot claim cleanup. Only the redacted receipt is
uploaded, never NEOTH_HOME or the keyring. A pre-Python session failure gets a
coarse failure receipt as well.

Eleven helper regressions and the real product execution are registered
for GitHub. The first run passed nine helper tests and the CLI build but failed the first install command; the new redacted diagnosis and two additional helper tests await a fresh isolated run. The workstation BSOD hold remains
absolute: no local compiler, parser, test or product runtime ran. This lane is
separate from the already accepted pinned-image/template execution canary.
All-thirteen managed workflow import, nine remaining starter adapters,
container-to-host reachability, weekly archive persistence and Paperless
acceptance remain open.
