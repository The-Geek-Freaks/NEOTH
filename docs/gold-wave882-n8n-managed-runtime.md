# Wave 882 — managed n8n runtime custody

`neoth n8n install --api-key-stdin` creates exactly one `n8n-instance`
integration job. It does not call the ordinary adoption entry point and does
not enqueue, return, fail, or acknowledge a second job. The shared publisher
works on the already Running managed job and publishes config/key custody plus
authenticated pre/post-commit probes on that same receipt.

Before Docker can create a process, NEOTH atomically writes
`n8n-managed-runtime.v2.json` with CreateIntent for the active job, immutable
manifest, pinned image, `neoth-n8n`, loopback port, and named volume. A
validated inspect upgrades it to Bound with the exact container ID. Ready
custody remains durable after normal config/key finalization.

The runtime permits only the reviewed immutable OCI reference and exact Docker
identity: `127.0.0.1:<port>:5678`, `neoth_n8n_data` mounted at
`/home/node/.n8n`, image digest, managed label, and exact active-job label.
Name and labels alone grant no removal authority. A found container with
absent, foreign, mismatched, or Ready custody is retained for repair.

Cancellation and failure remove only the persisted exact ID and re-inspect
that exact ID. They retain an `AbsentVerified` tombstone through credential
rollback and terminal transition. Thus a crash cannot erase the only process
authority before durable compensation. Unknown inspection, removal failure,
or failed tombstone persistence keeps the active job and custody; cancellation
is never acknowledged in that state.

Restart recovery uses the same bounded exact-ID Docker path. It accepts an
Absent result or removes only a fully matching owned container. Daemon,
context, or identity ambiguity keeps the lease for repair and never emits the
ordinary adoption `n8n-no-owned-process` receipt. Docker output is bounded and
represented only by opaque hashes; ambient `DOCKER_HOST` and `DOCKER_CONTEXT`
are removed and an explicit local host is selected. Loopback health is preliminary; authenticated
`/api/v1/workflows` pre/post-commit probes establish readiness.

This slice still needs an existing n8n API key through standard input. It does
not claim first-boot owner/API-key provisioning, 13 workflow imports, or
Paperless acceptance, so GOLD-LF-002-09 remains open.

## Validation boundary

The active workstation BSOD hold prohibits local Cargo, formatter, tests,
Docker, parser, Node, Python, and runtime execution. Targeted GitHub checks
are still required; this document makes no local green claim.

W907 validates HostConfig.PortBindings for stopped containers and requires any
runtime port mapping to agree. Extra mappings or mounts reject ownership.
W909 preserves queued jobs after ambiguous CreateIntent write errors; a matching
queued intent proves no Docker command could have run and recovers without a
Docker call. CLI completion is successful only for Ready.
W906 and W910 independent static reviews approved the source. Hosted selection
contains25 new tests plus23 existing adoption/custody regressions; these are
registered, not yet executed for this change.