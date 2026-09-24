# Wave 937 — isolated n8n bootstrap hosted canary

This manually dispatched, main-only GitHub Actions job is a disposable
feasibility gate for the pinned n8n image.  It is not product bootstrap
acceptance, does not exercise the NEOTH CLI, and does not establish production
owner/API-key recovery behavior.

The job creates a fresh labeled Docker volume and an exact labeled bootstrap
container with `--network none`, no published port, and only a temporary
non-secret `N8N_LISTEN_ADDRESS=127.0.0.1`.  The bootstrap request sequence runs
inside its namespace through `docker exec -i -u node … node -e <constant>`.
Owner password and browser ID enter only over stdin; the setup response's
session cookie and the minted raw API key remain only in process memory.  They
are never command arguments,
Docker environment, workflow output, logs, artifacts, or receipts.

After exactly one owner setup and key-mint attempt, the job stops and proves
the exact bootstrap container absent before it creates a new final container
on the same volume with a dynamically allocated `127.0.0.1` mapping.  It then
waits for `/healthz/readiness` to return 200 with `status: ok`, before it
checks the documented workflows API through that actual host-published mapping,
both without credentials (401/403) and with the captured key (200 plus a
workflows data envelope).  The host probe is a bounded Python standard-library
connection from the runner directly to `127.0.0.1` and the assigned port, so it
proves the host mapping without an additional container.  Its API key remains
only in the canary process memory.
Before and after handoff, a constant Node program reads the owned volume's
n8n config and compares only a SHA-256 of its `encryptionKey`.  It never emits
the key and the canary does not invent or inject `N8N_ENCRYPTION_KEY`.

The canary never retries owner setup or key creation.  A transport loss after
either request is dispatched, or a malformed successful response, records the
redacted `unknown_effect_stage` in the receipt and fails once; it never remints,
lists/deletes by label, or claims that a zero list result proves non-commit.
The exact-owned containers and volume are disposable canary resources, so they
may still be removed after such an unknown result once their custody is proven.
Cleanup targets only exact inspect IDs and a volume whose labels match this
run/attempt custody.  Docker daemon health plus the canonical exact `No such
object` / `No such volume` response is required to prove absence; arbitrary
nonzero inspect exits are never absence.  A passed functional sequence is
downgraded to failure if cleanup cannot prove container and volume removal.

The uploaded receipt is intentionally compact and source-bound: Git SHA,
script/workflow SHA-256 hashes, pinned image digest plus local image ID,
upstream commit, runtime Node version, completed stages, HTTP statuses, a hash
of the raw key, and any redacted failure or unknown-effect stage.  It contains
no response bodies, identifiers usable as
credentials, owner details, cookies, or raw key material.

Run it from the **main** branch through the Actions UI.  A green run proves
only the hosted pinned-image feasibility assumptions needed before product
bootstrap work: isolated container-loopback access, exact REST wire success,
volume handoff, and final authenticated API reachability.  It does not prove
the future production transaction, cancellation/restart recovery, user-facing
credential retrieval, or long-term n8n compatibility.

The script independently refuses to run unless GitHub Actions provides the
exact `refs/heads/main` ref, a 40-hex commit SHA, and positive numeric run ID
and attempt values.  This check occurs before it creates a receipt, a volume,
or any Docker resource; direct local invocation has no fallback mode.

W964 acceptance: run36062653422 at e8443cec passed all seven helper tests
and all seven ordered lifecycle stages. Root verified the source and artifact
bindings in [the feasibility receipt](verification/gold-wave964-n8n-bootstrap-feasibility.json).
The product CLI bootstrap, restart/cancellation recovery and workflow imports
remain separate open gates.
