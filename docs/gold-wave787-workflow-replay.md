# W787 — operator workflow replay

`neoth eval` has two separate evaluation paths. The existing offline suite
runner remains available:

```text
neoth eval <suite.json> [--json] [--max-steps N] [--preset NAME]
```

It evaluates the supplied `EvalCase` suite locally. It does not become a live
provider replay merely because workflow replay is available.

Workflow replay uses explicit subcommands:

```text
neoth eval capture <input.json> --out <corpus.json>
neoth eval run <corpus.json> [--out-dir <directory>] [--json]
```

## Capture and corpus

`capture` accepts one operator-curated input object with `schema_version: 1`,
`episode_id`, `prompt`, and `expected_contains`; `skill` is optional. It writes
a new versioned corpus and refuses to overwrite an existing destination.

A corpus is bounded to 64 episodes and 2 MiB. Every episode has a unique ID,
bounded nonempty fields, and a non-slash prompt. The parser rejects unknown
fields. It does not inspect WAL, history, attachments, repositories, provider
endpoints, tool configuration, loops, or scoring overrides.

Run replay only with a corpus the operator deliberately prepared. Corpus text,
replies, report JSON, and report Markdown are private local artifacts.

## What `run` does

`run` validates the whole corpus before it loads configuration, requests
provider consent, constructs a provider, creates a temporary replay root, or
starts a provider request. It then loads the normal effective configuration and
uses the normal interactive provider/consent path once per episode.

Each episode prepares a contained chat turn. Conversation state, replay WAL,
and workspace are placed under a newly created temporary
`neoth-workflow-replay-<uuid>` root. The actual operator home remains the
provider-consent and provider cost/usage-audit home. An explicitly selected
skill is resolved from that actual home through its authority-bound snapshot;
the report records its exact routed ID and content hash. A replay-home skill
file cannot replace that selection.

The turn is direct and bounded to its initial provider completion. The replay
MCP scope is an active empty allowlist, so every tool is denied before tool
lookup or transport. Hooks, post-provider recovery, fallback, profile/session
work, council, and loop routes are not entered. The report states
`external_tools: "deny_all"`; it does not manufacture tool-attempt counters.

Without `--out-dir`, reports stay under the temporary replay root. With
`--out-dir`, the command writes `workflow-replay-report-v1.json` and
`workflow-replay-report-v1.md` to the supplied directory. `--json` also prints
the JSON report. A failed or errored episode makes the command fail after it
writes the report.

## Scoring and report provenance

The only scorer is case-insensitive `contains-v1`: the accepted terminal
provider body must contain the episode's `expected_contains` text. Ordinary
stdout, notices, stream presentation, a missing terminal, or provider errors
never pass an episode.

The report includes these provenance fields:

- the exact corpus SHA-256 and `contains-v1` scorer;
- `config.fingerprint_sha256`, computed from the NUL-delimited operational
  projection: provider, model, request limit, scorer, and deny-all tool scope;
- `config.effective_public_config_sha256`, the lowercase SHA-256 of the
  secret-free `FreedomConfig::public_yaml()` UTF-8 bytes;
- per-episode response SHA-256 and, when a skill routed, the exact selected
  snapshot `selected_skill` and `selected_skill_content_sha256`;
- containment statements for the transient home/workspace and the sole
  actual-home provider consent/cost usage audit.

`source_revision` uses build metadata in this order:
`NEOTH_SOURCE_HEAD`, `GITHUB_SHA`, then `VERGEN_GIT_SHA`. A local development
build with none of these values reports `"unknown"`. That fallback identifies
an unbound local report; the release witness gate rejects it and requires the
exact candidate source SHA.

The optional W793 release witness consumes a separately supplied local
corpus/report pair and emits only content-free evidence. It does not upload the
corpus, prompts, expectations, replies, provider labels, selected skill IDs,
or raw report.