# Code-map lifecycle

NEOTH keeps repository code-map snapshots in the instance-local
`code_map.db`. A snapshot is bound to the selected repository's canonical
physical root, root identity, and index/graph generations. Repository context
consumers use that evidence; a map for a different repository is never a
fallback.

## Inspect a repository

Run the command from the repository, or pass the repository root explicitly:

```text
neoth code-map status
neoth code-map status C:\work\my-repository --output json
```

`status` is read-only. It does not create the database, run migrations,
rebuild a map, or repair a damaged store. Its result identifies whether the
selected root is absent, unmapped, incomplete, fresh, stale, recovering, or
corrupt, and includes an actionable next command.

An absent map is normal on a first use. Create it with:

```text
neoth code-map refresh C:\work\my-repository
```

## Check enrichment readiness

In the Coding panel, choose **Check enrichment readiness**, or use Buddy's
**Check codegraph enrichment readiness** action. The result describes the
configured NEOTH home and its managed roots. The adjacent repository status
continues to describe only the selected root.

The check distinguishes disabled enrichment, available prerequisites, and an
unavailable or invalid configuration, registration, or snapshot. It reads the
same readiness evidence as Doctor, using the GUI's resolved local CLI identity
for the generated registration. It does not call an MCP tool, enrich a response,
change configuration, refresh a map, or repair data. A ready result means a
future eligible call may attempt enrichment; that call still needs its normal
authorization and freshness checks. A newer check or configuration revision
supersedes an older pending result.

## Refresh and rebuild

`refresh` checks the selected root before writing. It creates a first index
when none exists and rebuilds a stale or incomplete snapshot. A fresh snapshot
is reused without advancing its generation.

```text
neoth code-map refresh
neoth code-map refresh C:\work\my-repository
neoth code-map refresh C:\work\my-repository --force
```

Use `--force` only when an operator wants a manual rebuild even though the
current snapshot is fresh. `persist` remains available for existing scripts;
`refresh --force` is the lifecycle-aware manual escape hatch.

Every successful refresh emits a receipt containing the selected canonical
root, its identity digest, refresh cause and outcome, prior and published
generations, source fingerprint, and attempt identifier. JSON and JSONL output
serialize that same receipt for automation.

Ctrl-C requests cooperative cancellation and waits for the blocking refresh to
finish before the command returns. A cancelled or failed refresh does not claim
that a new generation was published.

## Edge confidence

Each graph edge retains an evidence tier and its corresponding ordinal:

| Evidence tier | Confidence ordinal |
| --- | --- |
| `inferred` | 50 |
| `resolved` | 100 |

These ordinals express evidence strength, not statistical probabilities. The
schema-8-to-9 migration assigns existing edges `inferred` / 50. Resolving a
regex-derived edge's endpoint does not upgrade its evidence tier. An invalid
stored tier/ordinal pair is rejected before traversal.

Impact traversal preserves shortest-hop ordering and the existing depth-only
score. A path's confidence is its weakest edge. When a bounded same-depth
frontier must choose between paths, stronger evidence takes precedence and
existing deterministic ties remain stable. A deeper resolved path cannot
outrank a nearer inferred path merely because of its confidence.

## Corrupt database recovery

Neither `status` nor a normal refresh alters a corrupt database. Preserve the
forensic copy and explicitly authorize recovery:

```text
neoth code-map refresh C:\work\my-repository --repair-corrupt
```

The lifecycle service preserves the existing corrupt database before creating a
replacement, and labels the resulting receipt as an explicit corrupt-store
repair. Do not delete `code_map.db` manually; its preserved copy is useful for
diagnosis.

## Daemon-managed roots

The lifecycle is disabled unless configured with explicit managed repository
roots. A managed root receives a first-index check at startup, bounded
filesystem invalidation, debounce, and a refresh after source changes. Watcher
silence is never considered proof that a snapshot is fresh: request consumers
retain their bounded hash/fingerprint verification.

```yaml
code_map:
  lifecycle:
    enabled: true
    managed_roots:
      - C:\work\my-repository
    debounce_millis: 500
    reconciliation_interval_secs: 300
```

Roots must be absolute physical directories. NEOTH accepts at most eight and
rejects aliases, duplicates, and overlapping parent/child roots before a
watcher starts. `debounce_millis` accepts 50–60000 and
`reconciliation_interval_secs` accepts 30–3600.

On restart, the service reconciles any durable in-flight attempt before it
accepts new watcher work. It either records a recovered completed publication
or performs one recovery refresh. The selected roots remain explicit; a daemon
does not guess a repository from its process working directory or from another
persisted map.

## Doctor

`neoth doctor` includes a read-only `code-map lifecycle` check. It reports the
same absent, unmapped, incomplete, stale, corrupt, and recovery states with the
exact `status`, `refresh`, or `--repair-corrupt` command that resolves the
condition. Use:

```text
neoth doctor --explain "code-map lifecycle"
```

to display the operator runbook without running the full diagnostics.
