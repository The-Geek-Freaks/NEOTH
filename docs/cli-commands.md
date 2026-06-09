# NEOTH CLI reference

> **Generated** from the clap command tree by `neoth completions --reference`.
> Do not edit by hand — it is the authoritative, drift-proof list of every
> command + flag. Regenerate with
> `NEOTH_REGEN_CLI_DOCS=1 cargo test -p neothd cli_commands_md_is_up_to_date`.
> For the operator *guide* (with prose + workflows) see
> [cli-reference.md](cli-reference.md); for the journey see
> [operator-journey.md](operator-journey.md).

`neoth` — neoth knows.

---

## `neoth adr`

Architecture Decision Records — list / extract. Phase 31 R-21

- `--dir <DIR>` — Override the `~/.neoth/adr/` location (mostly for tests)

### `neoth adr extract`

Scan a file (or stdin with `-`) for decision markers and write any extracted ADRs

- `<PATH>` — Path to a markdown / text file. Use `-` to read from stdin
- `--dry-run <DRY_RUN>` — Print extracted ADRs without writing them

### `neoth adr list`

List every ADR in number order

## `neoth agents`

Inspect sub-agents loaded from `~/.neoth/agents/*.toml` + built-ins (code-reviewer, security-reviewer, planner, critic)

### `neoth agents list`

Print every loaded sub-agent (built-in + operator), sorted by name

### `neoth agents show`

Dump the full TOML-style record for a single agent including the system prompt. Useful for reviewing what a name actually does before typing `/agent <name>`

- `<NAME>`

## `neoth arxiv`

Search ArXiv for papers (A-24)

### `neoth arxiv search`

Search ArXiv. Query syntax: `all:keyword`, `ti:title`, `au:author`, `cat:cs.CL`, `AND` / `OR` / `ANDNOT`

- `<QUERY>` — The query string
- `--limit <LIMIT>` — Max results (1-50)

## `neoth autonomy`

View or set the operator autonomy level (`strict | standard | elevated | full | custom`) in freedom.yaml. `show` prints the current level; `set <level>` persists a new one without re-running the wizard

### `neoth autonomy set`

Set the autonomy level in freedom.yaml. Persists immediately; takes effect on the next command / daemon config reload

- `<LEVEL>` — One of: `strict` | `standard` | `elevated` | `full` | `custom`

### `neoth autonomy show`

Print the current autonomy level (read from freedom.yaml)

## `neoth backup`

Write a tar.gz backup of `~/.neoth/` state. Phase 33c BS-2

- `--out <PATH>` — Output path for the `.tar.gz`. Defaults to `~/.neoth/backups/neoth-<UTC-timestamp>.tar.gz`
- `--no-wal <SKIP_WAL>` — Skip raw WAL segments. Default behaviour bundles them — the WAL is the source of truth + the operator-flow audit (2026-05-19) flagged "default-without-WAL produces inconsistent restores where views.db cursors reference segments that don't exist". Pass `--no-wal` to opt out (saves disk, but restored host needs to re-index from scratch)
- `--no-credentials <SKIP_CREDENTIALS>` — Exclude `credentials.yaml` (API keys, channel tokens) from the tarball. By default it IS bundled — otherwise a restore is missing every key — but the archive is plaintext, so backup prints a warning and `--no-credentials` lets you opt out (e.g. when the archive will live on untrusted storage)
- `--home <DIR>` — Override the ~/.neoth source dir (mostly for tests)

## `neoth calendar`

EM-02b — CalDAV calendar. `list` reports VEVENTs in the configured collection; `add` PUTs a new event (gated + audited like every external write). Uses the same `caldav_{url,username,password}` as `neoth todo`

### `neoth calendar add`

Add (PUT) a new event. Gated + audited (`0xC8`) like every external write; idempotent by `(summary, start)` so a re-run never duplicates

- `<SUMMARY>` — Event title (SUMMARY)
- `--start <START>` — RFC-3339 / iCal start, e.g. `2026-05-30T09:00:00Z` or `2026-05-30` (date-only = all-day)
- `--end <END>` — RFC-3339 / iCal end. Defaults to `start`
- `--location <LOCATION>` — Optional LOCATION
- `--description <DESCRIPTION>` — Optional DESCRIPTION
- `--url <URL>` — Override the calendar collection URL
- `--yes <YES>` — Skip the interactive confirm (non-interactive write)

### `neoth calendar list`

List VEVENTs in the configured CalDAV calendar collection. Read-only

- `--url <URL>` — Override the calendar collection URL (else `credentials.yaml::caldav_url` / `NEOTH_CALDAV_URL`)

## `neoth catalog`

LLM-provider model catalog (K-Models-Discovery, Session 14). `refresh` queries every configured provider's list-models endpoint + caches results at `~/.neoth/models_catalog.json`. `list` / `show` print cached entries. `defaults` reports the recommended model per provider — the wizard reads this on next `neoth init` run. `clear` wipes the cache to force a full rediscovery

### `neoth catalog clear`

Wipe the cached catalog. Next `refresh` rebuilds from scratch

### `neoth catalog defaults`

Print the recommended-default model per provider — what the wizard / `freedom.yaml::provider_model` resolves to when the operator never types an explicit id

### `neoth catalog list`

Print every cached model, grouped by provider

- `--include-deprecated <INCLUDE_DEPRECATED>` — Include models the provider has flagged as deprecated / scheduled for sunset. Off by default — the wizard never surfaces deprecated entries either
- `--provider <PROVIDER>` — Show only this provider's models (e.g. `anthropic_api`). Omit to list every cached provider. The JSON shape is identical — just narrowed to the one key — which drives the GUI per-role model picker via a clean `--output json` subprocess call (MV-01c)

### `neoth catalog refresh`

Run discovery against every configured provider + persist the updated catalog. Idempotent — running twice in a row hits each provider's list-models endpoint once per run

- `--stale-only <STALE_ONLY>` — Only refresh providers whose cache entry is older than the TTL. Useful when running the daily cron job

### `neoth catalog show`

Print one provider's full catalog with metadata

- `<PROVIDER>` — Provider key (`anthropic_api`, `openai_api`, `gemini_api`, `aws_bedrock`, `openai_compat`, …)

## `neoth channel` _(hidden)_

Manage channels (Telegram, WhatsApp, etc.) (Day 7+)

### `neoth channel add`

Add a channel (e.g. telegram)

- `<CHANNEL>`

### `neoth channel list`

List configured channels

### `neoth channel remove`

Remove a channel

- `<CHANNEL>`

### `neoth channel test`

Test a channel connection

- `<CHANNEL>`

## `neoth chat`

One-shot LLM round trip. Loads freedom.yaml, sends prompt, prints reply. Both request and response are persisted as WAL events

- `<MESSAGE>` — Message to send. If omitted, NEOTH reads from stdin until EOF
- `--model <MODEL>` — Override the configured model for this single call
- `--system <TEXT>` — Inject a one-shot system prompt for this call
- `--config <PATH>` — Override the freedom.yaml path (mostly for tests)
- `--wal-segment <PATH>` — Override the WAL segment path (mostly for tests)
- `--temperature <T>` — Sampling temperature for backends that honour it (local_qwen today). Greedy / argmax when ≤ 0.0. Range [0.0, 2.0]. Cloud providers set their own default; the flag is silently ignored when the dispatcher has no path to forward it
- `--top-p <P>` — Top-p (nucleus) sampling cutoff for local_qwen. `1.0` keeps every token; `0.9` is a common balance. Ignored when `--temperature` is `0`/unset (greedy mode short-circuits before top-p applies)
- `--sampling-seed <SEED>` — Optional RNG seed for reproducible sampling. Pair with `--temperature > 0` to make a non-greedy call replayable. Unused on cloud providers
- `--resume-from <HASH>` — Round-3 v0.4 QU-11 / ARS-6 — resume a prior session from a `MODE_CHECKPOINT` (WAL `0x9A`) snapshot. Takes the 12-char checkpoint hash (or any unique prefix) printed by the prior session at checkpoint-emission time. NEOTH looks up the snapshot via `recall::reconstruct::reconstruct_from_checkpoint`, prints a one-line resume banner ("resuming session X / phase Y / provider Z"), and prepends a typed RESUME-CONTEXT block to the chat's system prompt so the assistant knows the prior pipeline shape. Full pipeline-state rehydration (re-scoping MCP servers, restoring council hemisphere routing) lands as a follow-up — this surface unblocks the operator-facing `chat resume from <hash>` workflow today

## `neoth checkpoint`

SC-02 — named checkpoints over the rollback snapshot primitive. `save <label>` tags the most recent pre-mutation snapshot; `list` shows them; `restore <label>` resolves the name + delegates to the rollback `apply` path

### `neoth checkpoint list`

List saved checkpoints

### `neoth checkpoint restore`

Restore the state captured by a named checkpoint (delegates to the rollback `apply` path with `--confirm`)

- `<LABEL>` — Checkpoint label saved via `neoth checkpoint save`

### `neoth checkpoint save`

Tag the most recent pre-mutation snapshot with a name. The snapshot must already exist (run a mutation first, e.g. `neoth config set`)

- `<LABEL>` — Checkpoint label: `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}`
- `--description <DESCRIPTION>` — Optional human description
- `--force <FORCE>` — Overwrite an existing checkpoint with the same label

## `neoth cloud`

Mirror the session archive into the operator's cloud-client local folder (R-8). NEOTH writes into `<dest>/<subdir>/`; the cloud vendor's desktop client (Dropbox / GDrive / OneDrive / iCloud) handles the actual upload. `status` shows the wired destination + last sync state, `sync` runs a pass right now

### `neoth cloud status`

Print the configured destination + last-sync state

### `neoth cloud sync`

Run one sync pass right now. Idempotent; re-runs skip unchanged files

- `--dest <PATH>` — Override `freedom.yaml::cloud_archive_dest` for this run
- `--subdir <NAME>` — Override `freedom.yaml::cloud_archive_subdir`. Defaults to `"NEOTH"`
- `--dry-run <DRY_RUN>` — Dry-run: list files that *would* be copied; don't write

## `neoth cluster`

Cluster status + routing-plan rehearsal (R-7)

### `neoth cluster confirm`

Confirm a discovered peer + add to the registry. Phase 4 of the SPEC — Phase 2 mDNS / Phase 3 Tailscale surface candidates; this command writes them in atomically

- `<PUB_KEY>` — 64-char lowercase-hex of the peer's pub key. Strict validation: must be exactly 64 chars of [0-9a-f]. Required unless `--interactive` is passed
- `--label <LABEL>` — Operator-readable label. Required unless `--interactive`. In interactive mode the label is taken from the discovered peer's announce TXT record
- `--addr <ADDR>` — Reachable socket address. Required unless `--interactive`. In interactive mode the addr is taken from the discovered peer's announce. Phase 6 gossip overrides
- `--via <VIA>` — Transport that surfaced the peer. Defaults to "manual" (operator typed the pub_key in directly)
- `--hostname <HOSTNAME>` — SL-01c: optional network hostname to record for the peer so you can later reference it by a memorable name (`neoth cluster revoke <hostname>`) instead of the 64-char pub_key. Not collected in `--interactive` mode — re-confirm with `--hostname` to set it
- `--interactive <INTERACTIVE>` — Interactive picker: run a mDNS scan first, render a numbered list of discovered peers, prompt operator for a selection, then confirm the pick. Skips the positional pub_key + --label + --addr requirement (values come from the selected announce). Tailscale candidates are excluded from the picker — they don't carry a pub_key
- `--interactive-timeout <INTERACTIVE_TIMEOUT>` — Scan timeout for `--interactive`. Default 10s

### `neoth cluster disable`

Disable cluster auto-discovery

### `neoth cluster discover`

SPEC Phase 2 mDNS scan — spawn the `mdns-sd` daemon for `--timeout` seconds, print every authenticated announce the listener sees. Does NOT write to cluster.yaml — use `neoth cluster confirm <pub_key>` after reviewing the output

- `--timeout <TIMEOUT>` — How long the scan runs before printing the final summary. Default 10s — long enough for one announce cycle from typical-cadence peers
- `--force <FORCE>` — Scan even when the operator's announce policy resolves to No (mdns disabled, untrusted SSID, or SSID unknown). Without this flag the discover surface prints the policy verdict + suggested fix and exits without browsing — the safe-by-default path mirrors the Q2-ratified announce gate

### `neoth cluster enable`

Enable cluster auto-discovery (writes `freedom.yaml::cluster.mdns.enabled = true`)

### `neoth cluster list`

SPEC `cluster_auto_discovery` Phase 4: list confirmed peers from `~/.neoth/cluster.yaml`

### `neoth cluster plan`

Run the routing policy against a synthetic load table to show what `pick_peer` would decide. Useful for sanity-checking the `LeastLoaded` selection logic without spinning up a real cluster

- `--peers <SPEC>` — Synthetic peers: `name:tokens_per_sec,name:tokens_per_sec,...`
- `--policy <POLICY>` — Policy override for this invocation. `local-only` or `least-loaded`. Defaults to `least-loaded` when peers are supplied, `local-only` otherwise

### `neoth cluster revoke`

Remove a confirmed peer by pub_key OR unique prefix

- `<PUB_KEY>`

### `neoth cluster status`

Print the active policy + known peer state

### `neoth cluster topology`

SL-02: cluster topology view — confirmed peers + per-peer last-seen age + a recent/stale/uncontacted status, table or `--output json`. Read-only over `~/.neoth/cluster.yaml`. Live health/TPS/RTT/stability are daemon-in-memory only and surface in a follow-on (SL-02b) — this view renders the persisted registry data the operator can see from any one-shot

## `neoth code`

V11 coding workflow — autonomous software-engineering entry point

- `<PROMPT>` — Free-text coding request. Wrapped in `<operator_request>` by the decomposer prompt — no further escaping needed. Optional only so `--run-pending` (which decomposes nothing) can run without one
- `--db <PATH>` — Override `views.db` path. Defaults to `~/.neoth/views.db`
- `--source-channel <SOURCE_CHANNEL>` — Source channel label for the kanban session (`cli` / `chat` / `telegram` / `discord` / ...). Defaults to `cli`
- `--no-assign <NO_ASSIGN>` — Skip the auto-classify + auto-assign step. Useful for operator-in-loop review of the decomposition before any hemisphere binding
- `--dispatch <DISPATCH>` — Pick #6 Phase 3 (2026-05-20): after decomposition + assign, actually run the workers. Without this flag the command stops at "decomposed into N tasks" and the operator drives dispatch manually (`neoth kanban move …`). With `--dispatch`, we build a `HemisphereWorkerSet` from the freedom.yaml provider bindings and call `dispatch_session()` once. Q1 patch-safety placeholder applies — workers store patches, do not apply
- `--apply <REPO_ROOT>` — Pick #6 Phase 4 (2026-05-21): also APPLY each worker- produced patch inside a task-scoped git worktree per the Chorus verdict (Strategy B). Requires a dispatch path — EITHER `--dispatch` (fresh decomposed session) OR `--run-pending` (existing Backlog sessions); `--run-pending` is itself a dispatch path, so it accepts `--apply` directly. The value is the operator's repo root; the worktree lands at `<repo_parent>/.neoth-task-<task_id>/` and is left in place on success so the operator can inspect / cherry-pick. Without `--apply` the dispatcher only stores patches (Phase-3 behaviour preserved). The dispatch-path requirement is enforced in `run_code` (clap's `requires` can't express "one of A or B")
- `--run-pending <RUN_PENDING>` — QU-10b / SP-A1: skip decomposition and instead drive the dispatcher across EVERY session that still has a Backlog task. Picks up pending work created outside a one-shot `neoth code "..."` (deferred dispatch, tasks added to an existing session). Pairs with `--apply <repo>` to apply patches in worktrees just like the single-session path. Operator-driven — no daemon loop

## `neoth code-map`

Repository code-map (K-Repo-Map Phase 1, Session 14 Pick #13). `scan` walks the operator's project root, classifies files by language, counts LOC + bytes. Honours .gitignore / .neothignore. Phase 2 adds tree-sitter symbol extraction; Phase 3 persists into a `~/.neoth/code_map.db` SQLite for recall integration

### `neoth code-map load`

Phase 3a — read a previously persisted snapshot back from `~/.neoth/code_map.db`. PATH is the canonical scan root that `Persist` recorded. Useful for inspection without re-scanning

- `<PATH>` — Root directory key whose snapshot to load. Defaults to canonicalised cwd
- `--full <FULL>` — Emit the FULL file list. Default prints summary only

### `neoth code-map persist`

Phase 3a (Session 14 Pick #22) — scan PATH (or cwd) and persist the resulting `RepoMap` into `~/.neoth/code_map.db`. Idempotent: a re-run against the same root replaces the prior snapshot atomically. Phase 3b consumes this DB for recall-time context injection

- `<PATH>` — Root directory to scan + persist. Defaults to cwd
- `--max-files <N>` — Hard cap on total files counted. Defaults to 50000
- `--max-file-bytes <BYTES>` — Hard cap on per-file byte size. Defaults to 2 MiB
- `--include-hidden <INCLUDE_HIDDEN>` — Include hidden directories. Default behaviour skips them
- `--symbols <SYMBOLS>` — Extract + persist top-level symbol declarations alongside each file entry. Default off (lighter scan)

### `neoth code-map relevant`

Phase 3b (Session 14 Pick #25) — given a free-text PROMPT, query the persisted code map for files that look relevant. Ranks by identifier-symbol matches first, path-keyword overlap second. Use this to inspect what Phase 3c would inject as a `<repo-context>` block without firing the actual chat

- `<PROMPT>` — Free-text prompt to score against the persisted map
- `--max <N>` — Max files to return. Default 5

### `neoth code-map scan`

Walk the repository at PATH (default: cwd), classify by language, count LOC + bytes. Honours .gitignore / .neothignore semantics. Bounded by --max-files + --max-file-bytes caps

- `<PATH>` — Root directory to scan. Defaults to current working dir
- `--max-files <N>` — Hard cap on total files counted. Defaults to 50000
- `--max-file-bytes <BYTES>` — Hard cap on per-file byte size. Files above this contribute to `oversize_skipped`. Defaults to 2 MiB
- `--include-hidden <INCLUDE_HIDDEN>` — Include hidden directories (.git, .cache, etc.). Default behaviour skips them
- `--full <FULL>` — Emit the FULL file list, not just the summary report. Required to consume the per-file `RepoFile` shape from scripts. Default prints only the summary
- `--symbols <SYMBOLS>` — Extract top-level declarations (functions, classes, etc.) per code file. Adds a `symbols` array to each `RepoFile` in `--full` JSON output. Default off — symbol extraction re-reads + regex-scans every code file in the repo

### `neoth code-map search`

Phase 3a — find every persisted file that declares a symbol matching NAME exactly. Searches across every root the DB has snapshots for

- `<NAME>` — Symbol name to look up

## `neoth completions`

Emit a shell-completion script. `neoth completions zsh > _neoth`, `neoth completions bash > /etc/bash_completion.d/neoth`, etc

- `<SHELL>` — Target shell. `bash | zsh | fish | powershell | elvish`. Omit when using `--reference`
- `--reference <REFERENCE>` — Emit the generated markdown CLI reference (every command + flag, straight from the clap tree) instead of a shell-completion script. `neoth completions --reference > docs/cli-commands.md`

## `neoth connect`

UX-01 — discover messaging channels + how to connect them. Read-only post-wizard on-ramp: shows which channels (Telegram, Slack, WhatsApp, …) are connected + the steps to wire the rest

- `<CHANNEL>` — Show one channel's status + its detailed multi-line on-ramp (e.g. `neoth connect telegram`). Omit to list every channel

## `neoth consent`

Manage first-run outbound-LLM consent (V03-08). `list` shows recorded grants, `show <provider>` reports state for one provider, `grant <provider>` records consent, `revoke <provider>` removes it. Cloud-bound provider calls bail until consent is recorded

### `neoth consent grant`

Record consent for sending operator text to a cloud provider

- `<PROVIDER>`

### `neoth consent list`

List recorded consent grants under `~/.neoth/consent/`

### `neoth consent revoke`

Remove a previously recorded consent grant

- `<PROVIDER>`

### `neoth consent show`

Show consent state for a single provider

- `<PROVIDER>`

## `neoth cost`

Estimate the cost of a provider call BEFORE dispatching it (C-14)

- `<PROMPT>` — Prompt text to estimate. Use `-` to read from stdin
- `--provider <NAME>` — Override the active provider for the estimate. Defaults to `freedom.yaml::provider_kind`
- `--model <MODEL>` — Override the active model for the estimate. Defaults to `freedom.yaml::provider_model`

## `neoth council`

Council (smartest-wins) configuration + introspection (Pick #14, Session 14). `show` prints the active config block; `tune` atomically mutates it (`--selection-mode`, `--self-reflect`, `--refine-threshold`, `--max-calls`, `--daily-usd-cap`); `weights` inspects the memory-routing acceptance history per `(topic_hash, hemisphere_role)` from `~/.neoth/routing_weights.json`

### `neoth council budget`

KF-08: show the council per-message budget posture — the configured cap (`freedom.yaml::council`) plus the last debate's live runtime usage from `~/.neoth/council_budget.json` (written by the chat-layer council wrapper after each debate)

### `neoth council inspect`

SPEC-03: inspect every council WAL frame for one debate, keyed by the `prompt_hash` (the 16-hex xxh3 shown by `council list`). There is no opaque debate-id — the prompt_hash IS the linkage key

- `<PROMPT_HASH>` — The 16-hex `prompt_hash` copied from `council list`

### `neoth council list`

SPEC-03: list recent council decisions from the WAL audit trail (`0x60..=0x64` frames — synthesis / partial-refusal / skip / winner / diversity-warning) across every segment. Read-only

- `--limit <N>` — Max rows, most-recent first. Default 50; `0` = all
- `--since-unix <TS>` — Only show events at/after this unix timestamp (seconds)

### `neoth council replay`

KF-01 — Council Replay Glass: reconstruct ONE debate as a chronological NARRATIVE timeline (convened → who refused → winner depth → diversity warning) from the WAL audit frames, keyed by `prompt_hash`. Richer than `inspect`'s raw frame list. NOTE: the hemispheres' actual response PROSE is NOT persisted in the WAL (only content hashes + metadata, for privacy), so replay reconstructs the debate STRUCTURE — WHAT the council did — not the verbatim text

- `<PROMPT_HASH>` — The 16-hex `prompt_hash` copied from `council list`

### `neoth council show`

Print the active `council` config block from freedom.yaml

### `neoth council suppress`

SPEC-03: persistently disable the council smart-trigger by writing `freedom.yaml::council.disabled = true`. Every turn then takes the single-hemisphere path (both CLI + channels) until you clear it with `--off`. The durable twin of `NEOTH_COUNCIL_DISABLE=1`

- `--off <OFF>` — Clear the suppression (`council.disabled = false`)

### `neoth council tune`

Atomically modify the `council` config block in freedom.yaml. Each flag is optional; only the ones you pass get updated

- `--selection-mode <MODE>` — Set selection mode. Values: `legacy_majority` (default; v0.1 behaviour), `consensus_or_best` (Verdict::Consensus wins on agreement, else quality-score), `best_always` (always pick by quality score)
- `--self-reflect <SELF_REFLECT>` — Toggle self-reflect refinement pass. `true` enables the threshold-gated, depth=0-only second-call refinement
- `--refine-threshold <T>` — Composite quality score threshold below which the refinement pass fires (range [0.0, 1.0]; default 0.90)
- `--max-calls <N>` — Hard cap on LLM calls per user message (BudgetToken schema field; default 15)
- `--daily-usd-cap <USD>` — Daily USD budget cap (set to 0 to disable)
- `--dry-run <DRY_RUN>` — Print what would change without writing freedom.yaml

### `neoth council voices`

GOLD-WIRE-04: list the available council voices — the specialist framings a hemisphere can debate as (set per slot via `freedom.yaml::inference.<slot>.voice`). Read-only

### `neoth council weights`

Inspect the memory-routing weights. Each row records a `(topic_hash, hemisphere_role)` pair's Hebbian-decayed acceptance count. Read-only

- `--top-n <N>` — Operator-readable cap on rows printed. Defaults to 20
- `--role <ROLE>` — Filter to one hemisphere role: `left`, `right`, `cerebellum`. Default: all three

## `neoth credential`

Manage `credentials.yaml`: `list` shows which credential keys are set (NAMES only, never values); `import --file <path>` merges a credentials.yaml-shaped file in (set fields overwrite; absent fields untouched). Never prints secret values

### `neoth credential import`

Merge a credentials.yaml-shaped file into `~/.neoth/credentials.yaml`. Set fields in the imported file overwrite existing ones; absent/empty fields are left untouched. Never prints secret values

- `--file <FILE>` — Path to a YAML file with the same shape as `credentials.yaml`
- `--dry-run <DRY_RUN>` — Preview only: report which keys WOULD be added vs overwritten (names only, never values) and write nothing

### `neoth credential list`

List which credential keys are currently set. Prints KEY NAMES ONLY — never the secret values

## `neoth cron`

Fire a scheduled job NOW, out of band of the daemon scheduler: `cron run <id>` loads jobs.yaml, runs the job through the configured provider (real call + delivery), writing the same WAL frames the scheduler does. Refused while `neoth serve` owns the WAL

### `neoth cron run`

Fire one job by id immediately, out of band of the scheduler. Makes a real provider call and (if the job has a delivery channel) delivers the result. Refused while `neoth serve` is running

- `<ID>` — The job `id` from jobs.yaml
- `--file <FILE>` — Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`

## `neoth ctx`

Ctx-mode parity — persistent indexed knowledge with hybrid FTS5 search

- `--search <QUERY>` — Run a hybrid search and print hits
- `--index <PATH>` — Index a file from disk. The file path is recorded; label defaults to the file stem unless overridden with `--label`
- `--index-stdin <INDEX_STDIN>` — Index whatever arrives on stdin. Requires `--label`
- `--label <LABEL>` — Explicit label for `--index` / `--index-stdin`. Defaults to the file stem
- `--category <CATEGORY>` — Category bucket for the indexed source
- `--content-type <TYPE>` — Content type marker (prose / code / log / …). Defaults to "prose"
- `--stats <STATS>` — Print schema + counts
- `--doctor <DOCTOR>` — Run health probe (FTS5, trigram tokenizer, journal_mode)
- `--purge <PURGE>` — Purge mode. Use with `--label`, `--category`, or `--all`
- `--all <ALL>` — Purge scope: every source. Mutually exclusive with `--label`/`--category`
- `--limit <LIMIT>` — Maximum hits returned by `--search`

## `neoth doctor`

Run operator health checks (freedom/credentials/db/wal/hmac/quota/...). Exit code non-zero on any FAIL. CI-friendly: `neoth doctor --quiet`

- `--home <DIR>` — Override `~/.neoth/` for tests
- `--quiet <QUIET>` — Suppress per-check output; print only the final summary line + use exit code for CI
- `--explain <NAME>` — V03-07: print operator-facing documentation for the named check (what it tests, common failures, fix steps) instead of running the full diagnostic suite. Combine with `--output json` for scripted runbook lookups. Pair with `--list-checks` to see what's available
- `--list-checks <LIST_CHECKS>` — V03-07: print the list of check names recognised by `--explain`. Useful for tab-completion + operator-side runbook generation

## `neoth dream`

Compose dreams now (SPEC-12 / R-02): `dream now` runs one dreaming pass over the recent window on-demand — embed + cosine-cluster the window's episodes into themed Dream records under `~/.neoth/dreams/` — instead of waiting for the nightly cron. Emits `0xF4 DREAM_COMPOSED`

### `neoth dream now`

Compose dreams over the recent window right now (default: last 24h)

- `--window-secs <WINDOW_SECS>` — Look-back window in seconds. Default 86400 (24h)
- `--max-events <MAX_EVENTS>` — Max events to embed + cluster this pass. Default 500

## `neoth ecology`

CH-13 / F4-01 — Ecology self-adaptation diagnostics. `correlation` reports providers that won many consecutive outer-council debates (a low-dissent fitness signal). Read-only + deterministic

### `neoth ecology channel-weights`

KF-05 — report the per-channel Hebbian acceptance weights (which channels' messages most often produce a successful reply). Read-only

- `--home <DIR>` — Override the NEOTH home (mostly for tests)

### `neoth ecology correlation`

Report council-winner correlation: providers that won many consecutive outer-council debates (a low-dissent fitness signal). Read-only

- `--min-streak <MIN_STREAK>` — Minimum consecutive-win streak to report. Defaults to `freedom.yaml::ecology.correlation_min_streak` (5)
- `--wal-dir <DIR>` — Override the WAL directory (mostly for tests)

### `neoth ecology genealogy`

F4-01 Phase 3 — tool genealogy: an inventory of the tools NEOTH actually exercises (MCP tools + plugins, by recorded use-count) plus installed skills as available-but-untraced nodes. Read-only + deterministic

- `--wal-dir <DIR>` — Override the WAL directory (mostly for tests)
- `--home <DIR>` — Override the NEOTH home for the installed-skill inventory
- `--top <TOP>` — Show only the top-N most-used tools. Default: all

### `neoth ecology status`

Maturity matrix for the Ecology layer — what is read-only/beta vs experimental/review-gated, and the scheduler's enabled state. The Ecology layer is NOT "stable self-improvement"; this is the honest label

### `neoth ecology winner-chain`

F4-01 — council winner-chain: the measured win-distribution over the `0x63` winner frames (per provider+role, with avg/last score + the selection-mode mix). Read-only + deterministic — every field is in-frame

- `--wal-dir <DIR>` — Override the WAL directory (mostly for tests)
- `--top <TOP>` — Show only the top-N winning voices. Default: all

## `neoth email`

EM-01b — inbound email. `fetch` pulls newest UNSEEN inbox messages over IMAP (non-destructive `BODY.PEEK[]`) and triages each through the sanitizer→threat pipeline. Live socket needs the `imap_fetch` build feature; `--dry-run` works on every build

### `neoth email fetch`

Fetch newest UNSEEN inbox messages over IMAP (non-destructive `BODY.PEEK[]`) and triage each through the sanitizer→threat pipeline

- `--limit <LIMIT>` — Max number of newest UNSEEN messages to pull (clamped to 200)
- `--username <USERNAME>` — IMAP username (the email address for Gmail). Falls back to `NEOTH_IMAP_USERNAME`
- `--host <HOST>` — IMAP host (default Gmail)
- `--port <PORT>` — IMAP TLS port (default 993)
- `--dry-run <DRY_RUN>` — Show the resolved connection (host/port/user/auth-kind) WITHOUT connecting, authenticating, or fetching. Never prints the secret
- `--include-seen <INCLUDE_SEEN>` — Re-process messages already in the local seen-state table (P1c dedup). By default a re-fetch SKIPS mail NEOTH already triaged (UNSEEN + `BODY.PEEK[]` would otherwise re-pull it forever); pass this to triage them again (e.g. after enabling the tie-breaker)

### `neoth email trust`

P1a — manage the trusted-sender domain allowlist (`freedom.yaml::email.trusted_domains`). A trusted sender is FLAGGED in the triage output + audit, but its mail is STILL fully sanitized + threat-scored ("trusted but still sanitized")

#### `neoth email trust add`

Add a domain to the trusted-sender allowlist

- `<DOMAIN>` — Domain (e.g. `acme.com`). Matches exactly + as a subdomain

#### `neoth email trust list`

List the trusted-sender domains

#### `neoth email trust remove`

Remove a domain from the trusted-sender allowlist

- `<DOMAIN>` — Domain to remove

## `neoth events`

Browse the WAL event-type registry. Self-documenting audit trail — `neoth events` lists every code NEOTH writes, `--code 0xNN` looks up a single byte, `--band 0x90` filters to memory-tier events

- `--code <0xNN>` — Filter by event-type byte (hex or decimal). Without it: list all
- `--band <0xN0>` — Restrict to one band. Accepts the band-low byte: `0x10` etc
- `--grep <SUBSTR>` — Case-insensitive substring filter on the event name or description. Combines with `--band` (intersection). `--grep profile` filters the registry to every profile-related row across all bands

## `neoth export`

GDPR-style operator data export — JSONL or markdown dump of every row NEOTH stores about the operator, plus a copy of the archive. Phase 33c BS-8

- `--out <DIR>` — Output directory. Default: `~/.neoth/exports/neoth-export-<UTC>/`
- `--since <DATE>` — Filter to events at-or-after this date. Format `YYYY-MM-DD`. Defaults to "everything ever recorded"
- `--format <FORMAT>` — Output format. `jsonl` = one event per line (default, lossless). `md` = human-readable digest grouped by day
- `--home <DIR>` — Override the `~/.neoth/` home dir (mostly for tests)

## `neoth fact-check`

GOLD-WIRE-11 — fact-check a claim. Decomposes the text into atomic propositions, classifies each (verifiable / plausible / opinion / suspect) with deterministic heuristics (no LLM call), and prints a `clean` / `needs_framing` / `needs_revision` verdict. `neoth fact-check "NEOTH was released in 2026."`

- `<CLAIM>` — The claim / statement to fact-check. Multi-sentence input decomposes to one proposition per sentence; each is classified independently

## `neoth feedback`

G-03 — `feedback summary [--window 7d]`: aggregate the operator self-correction (`0xBB`) signals into an actionable report (count, top correction patterns, pressure level). The consumer side of the self-correction loop; the same aggregate drives the profile-adapt cron's sustained-pushback self-dev proposal

### `neoth feedback summary`

Aggregate recent operator-correction (`0xBB`) signals into a report: count, top correction patterns, pressure level. The consumer side of the G-03 self-correction loop

- `--window <WINDOW>` — Look-back window, e.g. `7d`, `48h`, `3600` (bare seconds). Default 7d

## `neoth fetch`

Fetch a URL + return its text content (A-21)

- `<URL>` — URL to fetch. Only http(s) schemes accepted
- `--jina <JINA>` — GOLD-ADOPT-26 — fetch via the Jina Reader proxy (https://r.jina.ai), which renders JS-heavy / bot-blocked pages to clean Markdown. The last-resort path when the plain fetch returns thin or empty content
- `--selector <SELECTOR>` — GOLD-ADOPT-04 — extract the text of elements matching this CSS selector from the fetched page (e.g. `--selector "h1.title"`). The selector is cached per host; if the site later changes and the selector breaks, an adaptive fingerprint re-find heals it. Mutually exclusive with `--jina`

## `neoth fs`

`fs read <path>` — read a file through the PC-01 OS-tool gate: allowlist (`freedom.yaml::tools.os.allowed_paths`, default deny-all) + autonomy gate + WAL audit (`0xA8`/`0xA9`). The gated alternative to an ungated filesystem read

### `neoth fs read`

Read a file through the gated OS-tool surface. Permitted only when the path is under `freedom.yaml::tools.os.allowed_paths` (default deny-all) AND the autonomy level allows it (Strict confirms ⇒ blocked here, since this path has no interactive prompt). WAL-audited (`0xA8`/`0xA9`)

- `<PATH>` — File to read

### `neoth fs write`

Write a file through the gated OS-tool surface (PC-01 write slice). Permitted only when the target's canonical PARENT is under `freedom.yaml::tools.os.allowed_write_paths` (SEPARATE from the read allowlist; default deny-all) AND the autonomy level allows it (Strict denies, Standard confirms ⇒ blocked here without a TTY, Elevated/Full allow). WAL-audited (`0xAA`/`0xAB`). Best-effort atomic (temp + rename)

- `<PATH>` — File to write (its parent dir must exist + be write-allowlisted)
- `<CONTENT>` — Content to write

## `neoth github`

GitHub workflow shim — wraps the operator's `gh` CLI (A-3 + A-4)

### `neoth github issue-create`

Create an issue

- `--repo <OWNER/REPO>`
- `--title <TITLE>`
- `--body <BODY>`

### `neoth github issues`

List issues

- `--repo <OWNER/REPO>`
- `--state <STATE>`
- `--limit <LIMIT>`

### `neoth github pr-review`

Post a review (comment / approve / request-changes)

- `<NUMBER>`
- `--repo <OWNER/REPO>`
- `--verdict <VERDICT>` — Review verdict: `comment` / `approve` / `changes`
- `--body <BODY>`

### `neoth github pr-view`

View a single PR (number, title, body, head/base, stats)

- `<NUMBER>`
- `--repo <OWNER/REPO>`

### `neoth github prs`

List pull requests

- `--repo <OWNER/REPO>`
- `--state <STATE>`
- `--limit <LIMIT>`

## `neoth glossary`

NOOB-UX-2 glossary screen. `neoth glossary` prints the operator-readable cheat sheet for NEOTH-specific terms (plugin / channel / council / provider / WAL / autonomy / hemisphere / skill / mode / groundtruth / profile)

- `--term <TERM>` — Filter to a single term (case-insensitive substring match). `--term skill` shows all rows matching "skill"

## `neoth goal`

Goal/Grind dispatch-loop nudges (GOLD-ADOPT-22)

### `neoth goal grind`

Set the relentless grind objective (the model won't stop early until the dispatch-loop iteration cap)

- `<TEXT>` — The grind text

### `neoth goal off`

Clear both goal and grind

### `neoth goal set`

Set the one-shot goal (replaces any existing goal)

- `<TEXT>` — The goal text the model must verify before finishing

### `neoth goal show`

Show the active goal + grind (the default — also runs with no subcommand via the wrapper)

## `neoth groundtruth`

Manage hard-stored ground-truth facts (Phase 28c R-24)

- `--db <PATH>` — Override the views.db path. Defaults to `~/.neoth/views.db`

### `neoth groundtruth add`

Add a new statement

- `<STATEMENT>` — The fact. Stored verbatim (trimmed)
- `--scope <SCOPE>` — Scope tag. `global` | `host:<name>` | `session:<id>` | custom

### `neoth groundtruth ask`

Run the bilingual Q&A pass — re-entrant version of the wizard step. Operator can run any time after `neoth init`

- `--lang <LANG>` — Override the primary language for the prompts (defaults to freedom.yaml::language_primary, then `en`)

### `neoth groundtruth import-agent`

Import ground-truth rows from another agent's memory store. Phase 28c R-24 GT-8

- `<KIND>` — Which foreign agent format. `hermes | openclaw | openhuman | veronica | jsonl`
- `<PATH>` — Path to the foreign store. SQLite files for hermes/openhuman, markdown directory for openclaw, JSONL file for veronica/jsonl
- `--dry-run <DRY_RUN>` — Print parsed claims without inserting any rows

### `neoth groundtruth import-infra`

Scan the local network and persist discovered hosts as ground-truth rows tagged `host:<name-or-ip>`. Phase 28c R-24 GT-7

- `--arp <ARP>` — Use the local ARP table (`arp -a` / `ip neigh`)
- `--nmap <SUBNET>` — Run `nmap -sn <subnet>`. Requires nmap on PATH
- `--include-mac <INCLUDE_MAC>` — Collect MAC addresses. Default OFF per privacy spec
- `--aggregate-guests <AGGREGATE_GUESTS>` — Roll anonymous hosts into a per-subnet summary row
- `--dry-run <DRY_RUN>` — Print discovered hosts without inserting any rows

### `neoth groundtruth import-text`

Import claims from a markdown / text file. Each atomic claim becomes one `idx_groundtruth` row. Phase 28c R-24 GT-6

- `<PATH>` — Path to the file. Pass `-` to read from stdin
- `--scope <SCOPE>` — Scope tag for every row in this batch
- `--raw <RAW>` — Skip the heuristic extractor, dump raw lines into the table (one row per non-empty line). Useful for already-curated lists
- `--dry-run <DRY_RUN>` — Print extracted claims without inserting. Useful for previewing

### `neoth groundtruth list`

List active ground-truth rows

- `--scope <SCOPE>` — Filter by scope (default `global`). Pass `*` to list every scope
- `--limit <LIMIT>` — Max rows to return

### `neoth groundtruth revoke`

Revoke an existing row by id. Row stays in the table for audit but stops appearing in recall

- `<ID>` — Row id (`neoth groundtruth list` shows ids)

## `neoth gui`

Launch the NEOTH desktop GUI (`neothd-gui`). Thin launcher: resolves the separate GUI binary (next to `neoth`, else via PATH) and spawns it. `--locate` resolves + prints the path without launching. Prints the install command if the GUI binary isn't present

- `--locate <LOCATE>` — Resolve + print the `neothd-gui` binary path (and whether it was found beside `neoth`) WITHOUT launching it. Diagnostic / scriptable / headless-safe — the launch path needs a display the CI box lacks

## `neoth gui-stream` _(hidden)_

Persistent NDJSON request/response channel for `neothd-gui` (B — persistent-stdio-stream, Session 30). The GUI holds this process open and sends `{"id":N,"method":"board"}` lines on stdin, reading one JSON board snapshot per line on stdout — collapsing the previous 4-subprocess-per-2s-tick board refresh into one warm in-process query. READ-ONLY (board queries only); mutations stay on their gated subprocess paths. Not intended for direct operator use. See `cli/gui_stream.rs`

- `--db <PATH>` — Override the `views.db` path. Defaults to `~/.neoth/views.db`. The GUI passes nothing — the default mirrors what the one-shot `kanban` subcommands resolve

## `neoth hardware`

Consolidated hardware probe — CPU + RAM + accelerator (CUDA / Metal / OpenVINO / CPU) + ffmpeg/CLI presence + cached model detection. Drives the onboarding wizard's "this is what your machine can do" screen. `--output json` for scripting

## `neoth hemispheres`

Per-hemisphere provider configuration (Left/Right/Cerebellum). `show` displays the current binding; `set --role X --provider Y` mutates `freedom.yaml::inference.<role>` atomically; `test --role X` builds the adapter without making a live LLM call. See `PLAN/SPEC_hemisphere_provider_selection.md`

### `neoth hemispheres preset`

Apply a named hemisphere preset to `freedom.yaml` non-interactively (GOLD-ADOPT-12) — the same presets the `neoth init` wizard offers. Writes atomically + emits a 0x1F HEMISPHERE_REBOUND audit frame per changed role (with a pre-mutation rollback snapshot)

- `<NAME>` — Preset to apply: `local` / `local-reasoning` / `local-abliterated` / `single`
- `--vram <VRAM>` — (local-abliterated) override detected VRAM in MiB instead of probing
- `--count <COUNT>` — (local-abliterated) how many hemispheres run local — default = the most the VRAM supports

### `neoth hemispheres set`

Rebind one hemisphere role to a provider. Writes `~/.neoth/freedom.yaml` atomically and emits a WAL 0x1F HEMISPHERE_REBOUND audit frame immediately into `~/.neoth/wal/hemisphere-rebind-<ts>.wal`

- `--role <ROLE>` — Role to rebind: `left` / `right` / `cerebellum`
- `--provider <PROVIDER>` — Provider name: `claude_cli` / `anthropic_api` / `openai_api` / `openai_compat` / `gemini_api` / `local_qwen` / `local_ouro` / `aws_bedrock` / `azure_openai`
- `--model <MODEL>` — Model identifier (e.g. `claude-opus-4-7`, `gpt-4o`)
- `--key <KEY>` — API key (when the provider needs one)
- `--endpoint <ENDPOINT>` — Endpoint URL (for `openai_compat`)

### `neoth hemispheres show`

Show the current per-hemisphere provider binding

### `neoth hemispheres test`

Sanity-check the provider bound to a role. Default behaviour: build the adapter + report load latency only. Pass `--question "X"` to additionally fire a live LLM round-trip against the bound provider — the smallest possible end-to-end smoke-test per hemisphere. Pair with `--dry-run` to print what would be sent without making the call (useful for cost-sensitive cloud providers)

- `--role <ROLE>`
- `--question <QUESTION>` — Optional question to send live to the bound provider. Without this flag the command is build-only
- `--dry-run <DRY_RUN>` — When set with `--question`, print what would be sent + resolved provider/model without making the LLM call

## `neoth hooks`

Inspect TOML hooks loaded from `~/.neoth/hooks/*.toml` (Phase 29 R-15)

### `neoth hooks list`

List every parsed hook, grouped by pipeline stage. `--enabled` filters to enabled-only (default behaviour shows every hook so the operator can see which ones are toggled off)

- `--enabled <ENABLED>`

### `neoth hooks trace`

AR-02 (Session 24) — walk the WAL and surface hook-lifecycle frames (`HOOK_FIRED` 0x80 / `HOOK_BLOCKED` 0x81 / `HOOK_REPLACED` 0x82 / `HOOK_ERROR` 0x83) within the last `--since` window. Read-only; no daemon needed; runs against any segment (default `~/.neoth/wal/000001.wal`, override with `--segment`)

- `--since <SINCE>` — Time window. Accepts `30s`, `5m`, `2h`, `1d`. Default `2h`
- `--limit <LIMIT>` — Cap on rows surfaced (after filter). Default 200
- `--segment <SEGMENT>` — Override the WAL segment path. Defaults to `~/.neoth/wal/000001.wal`

### `neoth hooks validate`

Parse every hook file + verify the matcher regex (if any) compiles. Returns non-zero on any failure so CI can gate config changes

## `neoth hysteria`

Inspect + test the Hysteria encrypted-egress transport (R-3)

### `neoth hysteria render-config`

Render `~/.neoth/freedom.yaml::hysteria` as the YAML the subprocess would receive on disk. No spawn, no probe — pure preview so operators can verify before `neothd serve`

### `neoth hysteria status`

Print the current config + binary location + a SOCKS5 probe result. Operator-facing summary

### `neoth hysteria test`

TCP-probe the SOCKS5 port from freedom.yaml. Exits non-zero if the probe fails, so it composes in shell scripts: `neoth hysteria test && echo ok`

## `neoth identity`

Cross-channel identity (SPEC-11): `identity list` shows each resolved person (UUID v7) + their channel aliases; `identity merge <keep> <fold>` unifies two identities the resolver minted separately. Identities are produced automatically as channel messages arrive

### `neoth identity list`

List resolved cross-channel identities + their channel aliases

- `--channel <CHANNEL>` — Only show identities with an alias on this channel

### `neoth identity merge`

Merge two identities: every alias of <victim> is reassigned to <canonical>, then <victim> is deleted. Use when the same person was minted twice (they messaged from two channels before being linked)

- `<CANONICAL>` — The identity to KEEP (a UUID from `neoth identity list`)
- `<VICTIM>` — The identity to FOLD IN + delete (a UUID)

### `neoth identity pubkey`

Show THIS operator's X25519 transfer public key (base64) — share it so another NEOTH can `neoth transfer export --dest <this>` an encrypted memory bundle to you. The key is auto-managed at `~/.neoth/wal/transfer.key`

## `neoth ingest`

Multimodal asset ingest pipeline

- `<PATH>` — File to ingest. Extension drives the kind: `.pdf` → pdf, `.png|.jpg|.jpeg|.webp|.gif` → image, `.wav|.mp3|.flac|.ogg|.m4a` → audio, `.mp4|.mov|.mkv|.webm` → video, `.docx|.pptx|.xlsx|.odt|.ods|.odp|.epub|.rtf` → document
- `--db <PATH>` — Override the views.db path. Defaults to `~/.neoth/views.db`
- `--wal-segment <PATH>` — Override the WAL segment path the audit events land in. Defaults to `~/.neoth/wal/000001.wal` — the same surface `neothd serve` writes to
- `--no-persist <NO_PERSIST>` — Skip the embedding persistence pass — useful when running the pipeline against fixtures in tests or when the operator is just inspecting the metadata
- `--no-audit <NO_AUDIT>` — Skip emitting `INGEST_EXTRACTED` / `EMBED_PERSISTED` WAL audit events. Useful for batch reprocessing where the audit trail is already known

## `neoth init`

Interactive onboarding wizard. Sets up ~/.neoth/ config

- `--non-interactive <NON_INTERACTIVE>` — Run without interactive prompts. All values via flags. On a TTY, `neoth init` defaults to interactive; pass this to force non-interactive mode (e.g. inside CI or cloud-init)
- `--gui <GUI>` — Skip the GUI/CLI mode-selection prompt and hand off to the GUI surface. The CLI wizard prints launch instructions for `neothd-gui` and exits — the GUI binary owns its own onboarding flow with the same freedom.yaml backing
- `--cli <CLI>` — Skip the GUI/CLI mode-selection prompt and stay in the terminal wizard. Useful for scripted bring-up that pipes answers in OR for power users who never want the GUI option surfaced. Mutually exclusive with `--gui`
- `--accept-license <ACCEPT_LICENSE>` — Accept license without prompt. Required with --non-interactive
- `--experience-level <LEVEL>` — NOOB-UX (Session 26) — operator's experience level override. `beginner | intermediate | advanced`. Skips the step1c prompt when set. Drives whether tech-deep wizard prompts surface or silently default. Non-interactive runs default to `beginner`
- `--operator-id <ID>` — Operator identity (2-32 chars, [a-zA-Z0-9_-])
- `--language <BCP47>` — Primary language as BCP-47 code
- `--code-language <BCP47>` — Code language as BCP-47 code (default: same as --language)
- `--role <ROLE>` — Operator role. Listed values only; custom labels must be set via `neoth profile set --role <label>` after init
- `--provider <KIND>` — LLM provider kind
- `--provider-binary <PATH>` — Path to CLI binary (for claude_cli)
- `--provider-key <KEY>` — API key. Prefer env NEOTH_PROVIDER_KEY
- `--provider-endpoint <URL>` — Custom API endpoint (for openai_compat)
- `--provider-model <MODEL>` — Override default model
- `--telegram-token <TOKEN>` — Telegram bot token. Prefer env NEOTH_TELEGRAM_TOKEN
- `--telegram-user-id <USER_ID>` — Restrict Telegram bot to a single user ID
- `--autonomy <LEVEL>` — Autonomy level non-interactive override (Phase 28b R-23). `strict | standard | elevated | full | custom`. Defaults to `standard` when the wizard runs without a TTY
- `--inference-mode <MODE>` — Inference topology non-interactive override (D14b). `single | triplet | custom`. Defaults to `single` when the wizard runs without a TTY
- `--accelerator-override <ACCEL>` — Accelerator override (D14b). `cuda | metal | openvino | cpu`. Defaults to the auto-detected best fit; this flag bypasses detection
- `--embedding-provider <PROVIDER>` — Embedding-provider non-interactive override (D14b). `local_qwen | openai_api | anthropic_api | gemini_api`
- `--council-depth <N>` — E-2 Phase 4 (Session 14 Pick #23) — operator-pinned council recursion depth. `0`/`1` = flat (default). `2` = 3×3 = 9 leaf calls per user message. `3` = 27 leaf calls. `4` = 81 leaf calls (the `MAX_HEMISPHERE_COUNCIL_DEPTH` cap). Values above 4 clamp silently. Operators raising this above 1 in non- interactive mode get a one-line stderr warning instead of the interactive confirm screen — there's no terminal to draw it on
- `--enable-plugin <ID>` — E-21 step 7c non-interactive override (D-102 deferred follow-up). Pre-activate a discovered WASM plugin by id without the interactive multiselect — repeat the flag for each id to activate. Unknown ids are warned but don't fail the wizard. CI / cloud-init operators use this to flip plugins to Active during scripted bring-up; everyone else uses the interactive step or `neoth plugin enable <id>` afterwards
- `--download-qwen-weights <DOWNLOAD_QWEN_WEIGHTS>` — NOOB-UX-6 (Workstream B) — pre-download the LocalQwen model weights inside the wizard. Without this flag the wizard surfaces the `huggingface-cli download …` command and lets the operator run it later; with it the wizard offers to spawn the download synchronously (interactive confirms once more before spawning; non-interactive records the opt-in + surfaces the command to run)
- `--install-obsidian <INSTALL_OBSIDIAN>` — O-1 (Workstream B) — opt into the Obsidian-install wizard step. With no flag the wizard skips Obsidian in non-interactive mode; with the flag the wizard renders the OS-specific install command + records the opt-in. Interactive mode prompts independently of this flag
- `--bootstrap-vault <BOOTSTRAP_VAULT>` — O-2 (Workstream B) — bootstrap a fresh NEOTH-Vault under the operator's `~/Documents/NEOTH-Vault/`. Writes the curated `.obsidian/` config + templates from `installers::obsidian_vault::bootstrap_files`. Non- interactive: skipped without this flag; with it, the vault is created at the default path. Interactive: prompted with operator-pickable path
- `--install-n8n <INSTALL_N8N>` — N-1 (Workstream B) — opt into the n8n install wizard step. Non- interactive: skipped unless this flag is set. Interactive: prompts + auto-picks Docker over npm when both are available
- `--import-memory <PATH>` — E-16 (Workstream B) — prior-AI memory import. Path to an `import-manifest.yaml` declaring your prior-AI memory stores (see the `neoth-migrate` examples). When set, the wizard records the import intent + surfaces the `neoth-migrate dry-run` / `apply --confirm` runbook against the manifest. Heavyweight migrations stay operator-triggered — the wizard never auto-applies. Non-interactive only honours the flag; interactive prompts for the path independently
- `--force <FORCE>` — Re-run full wizard even if already initialized
- `--dry-run <DRY_RUN>` — Print what would be written, write nothing
- `--output-json <OUTPUT_JSON>` — Output final config as JSON to stdout

## `neoth installer`

W-05b — package-manager fallback chain runner. `--dry-run` (default) prints the per-pkg-manager argv preview the wizard's step6h already shows. `--execute` actually invokes the chain (winget→choco / apt→dnf→pacman / brew) until one handle succeeds. Operator-explicit because the execute path runs sudo apt install / winget install on the host

### `neoth installer apply`

Execute the fallback chain against `pkg`. Tries each handle in order until one returns `is_success`

- `<PKG>` — Package id (same as DryRun)
- `--yes <YES>` — Required for the execute path — running `sudo apt install` etc. without explicit operator confirm would violate the AGENTER no-destructive-ops-without- confirm rule
- `--verbose <VERBOSE>` — Print every handle's outcome, not just the winner

### `neoth installer dry-run`

Print the install argv for every handle in the host's fallback chain. Pure-fn — no subprocess fires

- `<PKG>` — Package id to render commands for (e.g. `Docker.Docker` on winget, `docker.io` on apt)

## `neoth jobs`

List + validate scheduled jobs defined in `~/.neoth/jobs.yaml`

- `--list <LIST>` — Print the table of configured jobs with next-fire times
- `--validate <VALIDATE>` — Parse + validate jobs.yaml without printing the table. Exits non-zero on the first invalid job
- `--preview <ID>` — AR-04 (Session 24) — dry-run one job by id: prints the next 3 fire times, the predicted EUR token cost via the existing cost predictor, and whether the operator's current autonomy level would allow / confirm / block the call when it eventually fires. No WAL writes, no provider calls, no scheduler side effects — purely diagnostic. Pairs with `--file` for inspecting a draft jobs.yaml before commit
- `--file <PATH>` — Override the jobs.yaml path. Defaults to `~/.neoth/jobs.yaml`

## `neoth kanban`

V11 coding workflow — operator-facing kanban CLI

- `--db <PATH>` — Override the `views.db` path. Defaults to `~/.neoth/views.db`

### `neoth kanban archive`

Archive a session (status=done or abandoned)

- `<SESSION_ID>`
- `--status <STATUS>`
- `--summary <SUMMARY>`

### `neoth kanban assign`

Assign a task to a hemisphere + optional worker provider

- `<TASK_ID>`
- `<HEMISPHERE>` — `left` / `right` / `cerebellum` / `unassigned`
- `--worker <WORKER>`

### `neoth kanban comment`

Append a comment to a task

- `<TASK_ID>`
- `<BODY>`
- `--author <AUTHOR>` — Comment author label. Defaults to `operator`

### `neoth kanban list`

List active sessions (not archived)

- `--all <ALL>` — Include archived + done sessions in the listing

### `neoth kanban move`

Move a task between status columns

- `<TASK_ID>`
- `<STATUS>` — Target status: `backlog` / `todo` / `in_progress` / `review` / `done` / `blocked` / `archived`

### `neoth kanban review`

V11 Pick #10 — review a REVIEW-status task. Default mode is "check only" (`--check`, prints whether the task is auto- promotable + the blocker reason if not). `--promote` actually transitions REVIEW → DONE when `test_summary.all_green()` is true. `--all <session_id>` sweeps every REVIEW task in a session in one pass

- `<TASK_ID>` — Task id to check / promote. Omit when using `--all`
- `--promote <PROMOTE>` — Promote the task (or every eligible task in a session) when the auto-promote check passes. Without this flag, the command runs in check-only mode + prints the verdict without touching state
- `--all <SESSION_ID>` — Sweep every REVIEW task in a session instead of one task

### `neoth kanban show`

Show every task in a session grouped by status column

- `<SESSION_ID>`

### `neoth kanban task`

Show one task's detail + its comment thread

- `<TASK_ID>`

### `neoth kanban watch`

Scan the WAL directory for kanban event frames + render the activity feed. Default is one-shot (print the last `limit` entries + exit). `--follow` keeps the process attached to the directory + tails new frames as the WAL writer lands them, rescanning every `--interval-ms`. Exits on Ctrl+C

- `--wal-dir <WAL_DIR>` — Override the WAL directory. Defaults to `~/.neoth/wal`
- `--limit <LIMIT>` — Print at most this many entries (newest-last). In `--follow` mode this caps the initial backlog dump; subsequent deltas are not capped because each tick's delta is typically tiny
- `--follow <FOLLOW>` — Stream new kanban frames as the WAL writer lands them. Re-scans the WAL directory every `--interval-ms` + prints only entries newer than the last printed frame's HLC timestamp. Exits cleanly on Ctrl+C
- `--interval-ms <INTERVAL_MS>` — Re-scan cadence in milliseconds for `--follow`. Default 1500ms — close to operator real-time without hammering the disk during an idle session. Ignored without `--follow`

## `neoth keys`

HMAC key management — show / rotate / list archived keys. Phase 33b SP-2 follow-up. Rotation is non-destructive: archived keys still verify historical compaction markers

- `--key <PATH>` — Override the key path (mostly for tests). Default `~/.neoth/wal/hmac.key`

### `neoth keys archives`

List archived keys with their timestamps

### `neoth keys rotate`

Archive the current key and generate a new one. Old key kept at `<path>.<unix-ts>.archive` for verifying historical markers

- `--dry-run <DRY_RUN>` — Print what would happen without changing any files

### `neoth keys show`

Show path, byte length, mode. Does NOT print the key bytes

## `neoth lease`

SL-01a — capability leases. Grant a paired peer or a plugin a TTL-bounded scoped capability (`grant <to> <scope> --ttl 1h`), `list` active grants, or `revoke <id>`. Each mutation is audited (`neoth wal show --type lease_granted`). Foundation for cluster task delegation (SL-01) + proactive bounded writes (G-01)

### `neoth lease grant`

Grant a subject a TTL-bounded scoped capability. `neoth lease grant <peer-or-plugin> <scope> --ttl 1h`

- `<GRANTED_TO>` — Subject: a paired peer pub-key-hex or a plugin id
- `<SCOPE>` — Capability scope: `read` / `write_neoth_home` / `channel_send` / `cluster_task_accept` / `mcp_tool:<id>`
- `--ttl <TTL>` — Lease lifetime, e.g. `1h`, `30m`, `7d`, `3600` (bare = seconds)

### `neoth lease list`

List active leases (expired ones are pruned + audited first)

### `neoth lease revoke`

Revoke a lease by id (full id or a unique prefix)

- `<ID>` — Lease id (or unique prefix) from `neoth lease list`

## `neoth mcp`

Model Context Protocol (MCP) client operations. `list` shows configured servers from `~/.neoth/mcp_servers.yaml`; `tools <server>` spawns the server + dumps its tool catalogue; `call <server> <tool> [--args JSON]` invokes one tool

### `neoth mcp call`

Invoke a single tool. `--args` accepts a JSON object; defaults to `{}` when omitted

- `<SERVER>`
- `<TOOL>`
- `--args <ARGS>`

### `neoth mcp list`

List configured MCP servers from `~/.neoth/mcp_servers.yaml`. Pure config read; no child processes are spawned

### `neoth mcp tools`

Spawn a server + dump its `tools/list` response

- `<SERVER>` — Server id from the config

## `neoth memory`

Inspect the assembled NEOTH.md operator context

- `--show <SHOW>` — Print the full assembled context with source-attribution headers
- `--paths <PATHS>` — Print only the source paths, one per line
- `--size <SIZE>` — Print byte sizes per block and the total
- `--tier <TIER>` — Filter recall by memory tier (Phase 28a R-22 MT-5)
- `--archive <YYYY-MM-DD>` — List archived session MD files for the given day (YYYY-MM-DD)
- `--forget <TOPIC>` — GDPR retroactive wipe — delete every row in hot/warm/long-term plus embeddings plus revoke ground-truth assertions where the text matches the topic (LIKE pattern, case-insensitive). Use `--confirm` to execute; without it the command dry-runs and prints what would be deleted
- `--confirm <CONFIRM>` — Required to actually execute `--forget`. Without it the command is a preview only
- `--physical <PHYSICAL>` — C-15: also physically redact matching frames in every WAL segment (zero the payload bytes, set `EventFlags::REDACTED`, recompute CRC, fsync). Operator-controlled GDPR-grade erasure; the default `--confirm` path only wipes the SQLite tiers + emits the TOMBSTONE_REQUESTED audit anchor. Requires `--confirm`
- `--dimension <DIMENSION>` — Compute the fractal-dimension D_mem across the four memory tiers (EXP-FD-0 from `PLAN/FRACTAL_DIMENSION.md`). Pure read, no behaviour change. Prints the per-tier byte counts + the regressed log-log slope + an honest verdict on whether D_mem is meaningful for this operator's data
- `--rebuild-index <REBUILD_INDEX>` — V10-08 — rebuild the HNSW embedding index from scratch by scanning all rows in `idx_embedding`. Writes the snapshot to `<neoth_home>/embeddings.hnsw`. Use after a database restore or when the snapshot is missing or corrupted. Safe to interrupt: the snapshot is written atomically (temp-file + rename)
- `--limit <LIMIT>` — Max rows for `--tier` recall
- `--db <PATH>` — Override the views.db path for `--tier`

## `neoth migrate`

Apply schema migrations to `~/.neoth/views.db`. `neoth serve` runs migrations automatically on startup; this command exposes them offline + supports `--dry-run` and `--to <version>`

- `--db <PATH>` — Override the views.db path (mostly for tests)

### `neoth migrate list`

List registered migrations + current db version

### `neoth migrate rollback`

V03-04: revert `~/.neoth/` from a `neoth backup` tarball. Defaults to the most-recent backup in `~/.neoth/backups/`; pass `--from <path>` to pick a specific one. Use when a schema migration made views.db inconsistent and you want to fall back to a known-good snapshot

- `--from <PATH>` — Specific backup tarball to restore. Defaults to the newest-mtime file matching `neoth-*.tar.gz` under `~/.neoth/backups/`
- `--home <DIR>` — Override `~/.neoth/` target dir (mostly for tests)
- `--force <FORCE>` — Overwrite the target dir even if it's non-empty. Required when the daemon has live files (the common case post-migration)

### `neoth migrate run`

Apply migrations up to the highest registered version (or `--to N`)

- `--to <N>` — Stop at this schema version (advanced; default = run to latest)
- `--dry-run <DRY_RUN>` — Print the plan without modifying the database

### `neoth migrate wal`

Workstream F (CT-10/E-20/V1x-06) — re-encode WAL segments

- `--to-v2 <TO_V2>` — Re-encode all v1 segments as v2 zstd-3 compressed
- `--wal-dir <DIR>` — Override the WAL directory (default `~/.neoth/wal/`)
- `--dry-run <DRY_RUN>` — Print which segments would be re-encoded without writing anything

## `neoth mode`

QM-3 mode-registry surface — list / show / match operator-facing view of every named mode the bundled + user-installed skills ship

### `neoth mode list`

List every registered mode (sorted by id)

### `neoth mode match`

Match an arbitrary message against the registry's trigger phrases and report which mode would activate

- `<TEXT>` — The message to match

### `neoth mode show`

Show one mode's full shape

- `<ID>` — Mode id (e.g. `research_lit_review`, `paper_full`)

## `neoth models`

Manage the local model caches under `~/.neoth/models/`

_Aliases:_ `neoth model`

### `neoth models list`

Print every known model + whether its artifacts are cached

### `neoth models prune`

Delete a model's cache directory. No-op when the directory is absent

- `<NAME>` — Model id. Known: `clip`, `whisper`

### `neoth models pull`

Download a model's artifacts into `~/.neoth/models/<flat>/`. `neoth model fetch <name>` is an accepted alias for this

_Aliases:_ `neoth models fetch`

- `<NAME>` — Model id. Known: `clip`, `whisper`
- `--repo <REPO>` — Override the HF repo (otherwise the default for the chosen name is used)

### `neoth models recommend`

Recommend the best LOCAL model(s) for this machine's VRAM and print ready-to-run `ollama pull` commands (GOLD-ADOPT-10/11/13). Quantized (Q4/Q8), abliterated-first, newest/best resolved live from HuggingFace

- `--vram <VRAM>` — Override detected VRAM (MiB) instead of probing the GPU. Useful on headless boxes or to preview a different tier
- `--class <CLASS>` — Lineage to prefer. `abliterated` (default — uncensored) or `standard`
- `--offline <OFFLINE>` — Skip the live HuggingFace lookup; use the verified curated repos only (offline / air-gapped)

## `neoth monitor`

HO-07 alert sidecar summary. `status` reads the WAL + crash.log and prints a 3-row table of WAL-CRC / crash / channel-silence alert counts. Exit code 1 when any alert fired in the look-back window

- `--home <DIR>` — Override `~/.neoth/` for tests
- `--hours <HOURS>` — Look-back window in hours (default 24)
- `--json <JSON>` — Print JSON instead of the table

## `neoth n8n`

Inspect the n8n integration (READ-ONLY): `status` reports the webhook base URL n8n POSTs to + whether the `n8n` binary is on PATH; `workflows` lists the NEOTH starter workflows bundled in the binary

### `neoth n8n status`

Report n8n integration status: the webhook base URL n8n POSTs to, whether the `n8n` binary is on PATH, and the bundled-workflow count

### `neoth n8n workflows`

List the NEOTH workflows bundled in the binary (slug / name / description) that an operator can import into n8n

## `neoth obsidian`

One-way sync of the session archive into an Obsidian vault. Phase 13 R-5. Idempotent — re-runs skip unchanged files

- `--archive-root <DIR>` — Override the NEOTH archive root (mostly for tests). Defaults to `~/.neoth/archive/`

### `neoth obsidian days`

List archive days that have at least one session MD file

### `neoth obsidian init`

Scaffold a fresh NEOTH-Vault: creates the directory, drops a minimal `.obsidian/` config + a README, and pre-creates the `NEOTH-sessions/` subdir so `sync` lands without operator configuration. Safe to re-run — existing files are left alone

- `--vault <PATH>` — Vault path to create. Defaults to `~/Documents/NEOTH-Vault/` on every platform (the path Obsidian itself uses by default when the operator clicks "Create new vault")

### `neoth obsidian sync`

One-way copy: NEOTH archive → vault. Idempotent

- `<VAULT>` — Path to the operator's Obsidian vault root
- `--subdir <SUBDIR>` — Subdirectory inside the vault for NEOTH sessions. Defaults to `NEOTH-sessions/`. Created on demand
- `--dry-run <DRY_RUN>` — Print which files would be copied without writing anything

## `neoth os`

`os launch <program>` — launch a program through the PC-01 OS-tool gate: exec-allowlist (`freedom.yaml::tools.os.allowed_exec_paths`, exact canonical match, default deny-all) + autonomy gate (Full-only auto-allow) + WAL audit (`0xAC`/`0xAD`). No arguments, no shell. The gated alternative to an ungated process spawn

### `neoth os launch`

Launch a program through the gated OS-tool surface. Permitted only when the program canonicalizes to EXACTLY one `freedom.yaml::tools.os.allowed_exec_paths` entry (default deny-all) AND the autonomy level allows it (Strict denies; Standard + Elevated confirm ⇒ blocked here without a TTY; only Full auto-allows). Launched with NO arguments and NO shell. WAL-audited (`0xAC`/`0xAD`)

- `<PROGRAM>` — Absolute path to the executable to launch (must be an exact entry in `tools.os.allowed_exec_paths`)

## `neoth ouro`

Inspect the Ouro thinking-models provider (O-3)

### `neoth ouro fetch`

Auto-download the operator-chosen Ouro checkpoint via hf-hub. First-time download is ~3 GB BF16; subsequent runs hit the disk cache instantly. Equivalent to running `neoth init --force --provider local_ouro` then a one-off `neoth chat` — but skip the chat round-trip when you just want the weights cached (e.g. before running `cargo test ... ouro` integration suites)

- `--checkpoint <CHECKPOINT>` — Override the default checkpoint (`ByteDance/Ouro-1.4B-Thinking`). Must match an entry from `neoth ouro list`

### `neoth ouro list`

List every supported ByteDance Ouro checkpoint with size + thinking flag + recommended-use note

### `neoth ouro status`

Show the operator's currently-configured Ouro state (read from `~/.neoth/freedom.yaml`)

## `neoth paperless`

Paperless OCR ingest + consult. Subcommands: `ingest`, `consult`. Operator surface for the SC-16/PL-02/PL-03 vertical slice

- `--vault <PATH>` — Override the vault root. Defaults to `~/Documents/NEOTH-Vault`
- `--subdir <NAME>` — Override the subdir inside the vault. Defaults to `NEOTH`

### `neoth paperless consult`

PL-03 keyword scan — find paperless docs that match an operator question

- `<QUESTION>` — The operator's question (e.g. "what was the Acme invoice from May")
- `--max <MAX>` — Cap on returned matches. Default 5

### `neoth paperless ingest`

Ingest one OCR document through the SC-16 sanitizer + write the Obsidian note under `<vault>/<subdir>/Paperless/<id>.md`

- `<DOC_ID>` — Document id (filesystem-safe; no `/`/`\`/`.`/`..`)
- `--text <TEXT>` — OCR text passed directly on the command line. Mutually exclusive with `--text-file`
- `--text-file <PATH>` — Path to a file containing the OCR text
- `--source <SOURCE>` — Source enum: `paperless_ngx` / `tesseract_direct` / `paperless_ai` / `manual_upload`. Default `paperless_ngx`

## `neoth permissions`

Inspect the autonomy-gate decision matrix (Phase 28b R-23). `show [--level X]` prints the active level + per-action decisions across all 5 levels (strict / standard / elevated / full / custom). `check <action>` runs a single permission evaluation against the configured level for any of the 8 `Action` variants

### `neoth permissions check`

Run a single permission evaluation against the configured level. `<action>` names match the snake-case wire form: `read`, `write_neoth_home`, `write_outside_home`, `exec_scripts`, `exec_arbitrary`, `paid_provider_call`, `channel_send`, `dangerous_target`. `--eur` and `--target` are honoured only when the action variant carries them

- `<ACTION>`
- `--eur <EUR>`
- `--target <TARGET>`
- `--subject <SUBJECT>` — SL-01a-b: evaluate as this subject (a peer pub-key-hex or a plugin id). When set, an active capability lease in `~/.neoth/leases.json` that covers the action upgrades a `Confirm` decision to `Allow` — exactly as the autonomy gate would at runtime. Lets the operator verify "does peerX's lease let them do this right now?" before trusting it

### `neoth permissions show`

Print the active autonomy level + the decision table for every action variant at every level. With `--level <L>`, only that level's column is rendered (handy for "what would `strict` block?")

- `--level <LEVEL>`

## `neoth plugin`

D-102 (Session 21) — WASM plugin activation management. Newly discovered plugins default to PENDING and don't auto-instantiate until the operator opts in. `list` shows discovered plugins + their state, `enable <id>` flips to Active, `disable <id>` to Disabled, `pending` lists only the Pending entries

### `neoth plugin disable`

Flip a plugin to `disabled`. Idempotent

- `<ID>`

### `neoth plugin enable`

Flip a plugin to `active`. Idempotent — already-active plugins return success without rewriting freedom.yaml

- `<ID>` — Plugin manifest id (matches the directory name under `~/.neoth/plugins/<id>/`)

### `neoth plugin ledger`

KF-09 — per-plugin capability usage ledger. Scans the WAL for the plugin audit frames (`0xC4 PLUGIN_HOSTCALL` writes via `emit_event`, `0xC6 PLUGIN_CAP_USED` reads via `recall_top`) and aggregates a per-plugin-per-capability call count + volume — so an operator can see WHAT each plugin actually exercised. Read-only; works on a slim daemon too (it reads historical frames, no wasm host needed)

- `<ID>` — Restrict to one plugin id. Omit for all plugins

### `neoth plugin list`

List every discovered plugin + its operator activation state. Plugins NOT yet listed in freedom.yaml::plugins.wasm.activations show as `pending` (the default for any newly discovered id)

### `neoth plugin pending`

Show only the discovered-but-not-yet-decided plugins. Operator review queue

### `neoth plugin test`

UX-07 — pre-deployment plugin verification. Reads `<path>/plugin.toml` + `<path>/plugin.wasm`, validates the manifest, and (when the daemon was built with the `wasm-plugin-host` feature) runs a sandboxed `neoth_run` invocation in a fresh wasmtime Store with the manifest's fuel + memory budgets applied. Reports the `InvocationOutcome` so the operator sees pass/fail without touching `~/.neoth/plugins/`

- `<PATH>` — Directory containing `plugin.toml` + `plugin.wasm`
- `--capture-wal <CAPTURE_WAL>` — UX-07b — capture the WAL frames (`0xC4`/`0xC6`/`0xC7`) the invocation emits into a throwaway tempdir WAL and surface them in the report. Requires the `wasm-plugin-host` feature; without it the flag is inert (the slim build can't live-invoke). The live WAL is never touched

### `neoth plugin verify`

SC-03 — verify a plugin directory against the operator's integrity policy (revocation list + pinned hash + author signature) WITHOUT instantiating it. Reads `<path>/plugin.toml` + `plugin.wasm` + optional `plugin.wasm.minisig`, then applies `freedom.yaml::plugins.wasm` (`author_pubkey` / `require_signature` / `revoked_ids` / `pinned_hashes`). Prints PASS/FAIL + reason and exits non-zero on FAIL so CI / a pre-install check can gate on it

- `<PATH>` — Directory containing `plugin.toml` + `plugin.wasm` (+ optional `plugin.wasm.minisig`)

## `neoth preset`

QM-8 Phase 1: named provider+config preset bundles. `list` enumerates saved bundles; `show <name>` dumps one; `activate <name>` marks a bundle active; `deactivate` clears the marker; `delete <name>` removes (idempotent). Source: `~/.neoth/presets.yaml`

### `neoth preset activate`

Mark a preset as the active bundle. Future loads apply it

- `<NAME>`

### `neoth preset apply`

QM-8 Phase 1.5: merge a preset's values INTO `freedom.yaml`. Atomic write — survives a mid-write crash via `.tmp` + rename. Fields the preset doesn't set are left untouched in `freedom.yaml`, so manual edits between switches survive

- `<NAME>`

### `neoth preset deactivate`

Clear the active marker without deleting any preset

### `neoth preset delete`

Remove a preset entry (idempotent — missing name is Ok)

- `<NAME>`

### `neoth preset list`

List every saved preset + the active one (if any)

- `--json <JSON>` — Emit machine-readable JSON (`{presets:[{name,active}], active}`) — consumed by the GUI preset selector (SPEC-05). Default: a table

### `neoth preset show`

Show one preset's full body as YAML

- `<NAME>`

## `neoth privacy`

L-08 privacy audit. `neoth privacy audit` reports — before you send a prompt — whether the next call hits a cloud provider, whether profile-learning is on, which channels are configured, and how WAL frames are sealed

- `--last <DURATION>` — Show sensitive WAL events in the last window — provider calls, channel egress, profile extractions — e.g. `--last 30d`, `7d`, `24h`, `1h`, `30m`. Omit for the config-posture-only view. This is the durable answer to "what actually left my device recently?"

## `neoth proactive`

Proactive proposal management (OB-03). Subcommands: `list`, `accept`, `reject`, `show`, `sync-vault`. NEOTH NEVER edits operator CONFIG behind their back — for config/cron proposals `accept` only flips status + the operator copy-pastes the draft YAML into the live config + runs `neoth reload`. A `kind=Skill` proposal (KF-04 idle forge) is the exception: `accept` ADOPTS it, writing the manifest live to `~/.neoth/skills/<id>/` (additive + the skill system still gates loading)

- `--home <DIR>` — Override the NEOTH home dir (mostly for tests). Defaults to `~/.neoth`

### `neoth proactive accept`

Mark a proposal Approved. For a **Skill** proposal (KF-04 idle forge) this ADOPTS it — the draft manifest is written live to `~/.neoth/skills/<id>/skill.yaml` (the operator's accept is the per-command GO; the skill system still gates loading). For config/cron proposals NEOTH never edits operator config: the operator copy-pastes the draft YAML into the live config + runs `neoth reload`

- `<ID>`
- `--note <NOTE>`

### `neoth proactive list`

Print staged proposals

- `--status <STATUS>` — Filter: `pending` / `approved` / `rejected` / `all`

### `neoth proactive reject`

Mark a proposal Rejected. Stays on disk for the audit log

- `<ID>`
- `--note <NOTE>`

### `neoth proactive show`

Print one proposal's full content + audit fields

- `<ID>`

### `neoth proactive sync-vault`

Render proposals into `<vault>/<subdir>/Proposals/<id>.md`

- `--status <STATUS>`
- `--vault <PATH>`
- `--subdir <NAME>`

## `neoth profile`

Inspect the user profile materialised from `idx_profile` (Phase 2 SPEC_proactive_learning §1). `show [--field X]` lists every applied claim; `summary` collapses to one row per field — highest-confidence non-superseded claim. Read-only

### `neoth profile approve`

ADV-03 item 4 Phase 6: pop a pending row + run `apply_delta` against it. Emits `EVENT_TYPE_PROFILE_DELTA_APPROVED` (0xB6) + the regular `PROFILE_DELTA` (0xB0) frame for each claim

- `<EXTRACTION_ID>` — Extraction id from `neoth profile pending`. The string in the leftmost column

### `neoth profile conflicts`

AR-05 (Session 24) — surface profile fields that have more than one active claim with mismatched `value_json`. Two claims for `identity.location` (`"Berlin"` vs `"Munich"`) both with `superseded_at IS NULL` is the canonical case the extractor produces when context windows disagree

- `--limit <LIMIT>` — Cap on conflict groups returned. Each group is one field with N >= 2 mismatched active claims

### `neoth profile conflicts-resolve`

AR-05 (Session 24) — resolve a conflict by marking every active claim EXCEPT the chosen `extraction_id` as superseded. The kept row stays active; the others record `superseded_at = now_unix` so the audit trail shows which extraction won and when

- `<FIELD>` — Dot-path field with the conflict, e.g. `identity.location`
- `--keep <KEEP>` — `extraction_id` of the claim to KEEP active. Every other active claim on this field gets `superseded_at = now`

### `neoth profile decline`

ADV-03 item 4 Phase 6: drop a pending row + emit `EVENT_TYPE_PROFILE_DELTA_DECLINED` (0xB7) so the audit trail records the operator's no-decision. Optional `--reason` makes the audit frame self-explanatory at replay time

- `<EXTRACTION_ID>` — Extraction id from `neoth profile pending`
- `--reason <REASON>` — Optional one-line note recorded in the 0xB7 audit payload

### `neoth profile drift`

HO-09 / V1x-03 — profile baseline DRIFT detection. Compare the current active claim set against a baseline (an operator-captured working baseline, else the `0xB3` migration anchor) and report what was added / removed / retained + a drift ratio

#### `neoth profile drift baseline`

(Re)capture the operator-resettable working baseline to the current active claim set. Overwrites any prior working baseline

#### `neoth profile drift report`

Compare current claims against the baseline + print the drift report. Flags when the drift ratio exceeds `freedom.yaml::drift_alert.threshold`. This is the default action

#### `neoth profile drift reset`

Clear the working baseline file. The next `report` falls back to the immutable `0xB3` migration anchor (if one exists)

### `neoth profile knobs`

UX-04 — show the active *behavioural* knobs (the resolved preset's verbosity / formality / clarifying / disclaimer-trim plus the autonomy level), each with the concrete command or file to change it. Complements `show` (which lists profile *claims*); this is "how is NEOTH tuned + how do I retune it?"

### `neoth profile migrate-require-approval`

ADV-03 item 4 Phase 6: explicit migration command for operators with a pre-Session-24 `freedom.yaml` that doesn't carry the `profile.require_approval` field. The serde default is `true` so they're already gated, but this command surfaces that fact + writes the field explicitly so the audit-trail of operator intent is unambiguous

- `--disable <DISABLE>` — When set, force the value to `false` instead of `true` — for operators who explicitly DO NOT want the gate

### `neoth profile pending`

ADV-03 item 4 Phase 6: list every profile delta the daemon queued in `idx_profile_pending` while running in tty-less mode. Operators resolve each row with `approve <extraction_id>` (write to `idx_profile`) or `decline <extraction_id>` (drop the row). `--limit` caps the output for terminals

- `--limit <LIMIT>`

### `neoth profile preset`

P-02 (Workstream B follow-up, Session 22) — manage profile presets that shape tone / verbosity / clarifying behaviour

#### `neoth profile preset apply`

Activate a preset. Writes the marker file at `~/.neoth/profile/active_preset.txt`; chat dispatch reads it on next run to compose the preset's `system_addendum` into the system prompt

- `<NAME>` — Preset name. One of: lowkey / formal / deepdive / tutor / opsec

#### `neoth profile preset list`

List every built-in preset with its operator-readable description

#### `neoth profile preset show`

Show the decoded `PresetData` for one preset (system_addendum + verbosity + formality + ask_clarifying + trim_disclaimers)

- `<NAME>` — Preset name. One of: lowkey / formal / deepdive / tutor / opsec

### `neoth profile redact`

Mark a profile field as `never_recreate=true` so the extractor pipeline can't propose a new claim against it. GDPR-style redaction; pairs with `neoth memory --forget <topic>` (which also wipes existing rows). `--reason` is recorded for audit

- `<FIELD>` — Dot-path field, e.g. `identity.location`. Use `neoth profile show` to see what's currently in idx_profile
- `--reason <REASON>` — Operator note explaining why the redaction was added

### `neoth profile redactions`

List redaction rows from `idx_profile_redactions` — fields the operator has marked `never_recreate` so the extractor pipeline can't re-introduce them. Active rows first, revoked rows next

### `neoth profile run`

Manually drive the 6-stage profile pipeline. Pick a single trigger via `--trigger-event <id>` OR batch-run against the last N inbound events via `--last-n <count>`. Either flag is required (not both). `--last-n` is the cron-friendly mode: `0 */6 * * * neoth profile run --last-n 20` extracts from the last 20 inbound messages every six hours

- `--trigger-event <TRIGGER_EVENT>` — Event id from `idx_episode` to slice the conversation window around. Mutually exclusive with `--last-n`
- `--last-n <LAST_N>` — Run the pipeline against the most-recent N RAW_TEXT / CHANNEL_INGRESS events in `idx_episode`. Mutually exclusive with `--trigger-event`
- `--turns-back <TURNS_BACK>` — How many prior turn-pairs to include in the window. Default 2 matches `profile_learn.yaml`
- `--extensions-file <EXTENSIONS_FILE>` — Optional path override for `profile_extensions.toml`. When omitted, the default operator path is loaded

### `neoth profile seed-baseline`

P-10 Phase-3 — emit the one-shot `PROFILE_BASELINE_SNAPSHOT` (`0xB3`) drift anchor: a SHA-256 digest of every active profile claim, written once to the WAL so future drift queries diff against it. Exactly-once — a second run bails when a prior `0xB3` frame is already in the WAL. Refuses while the daemon is live (single-writer safety)

- `--dry-run <DRY_RUN>` — Build + print the snapshot payload without writing the WAL frame

### `neoth profile show`

List every active profile claim. With `--field`, filter to one dot-path. Limited to N rows for large profiles

- `--field <FIELD>`
- `--limit <LIMIT>`

### `neoth profile summary`

One row per field — highest-confidence non-superseded claim. This is what the extractor's `existing_profile_summary` input would render in the prompt to keep the LLM grounded

### `neoth profile unredact`

Revoke an existing redaction by id. The field becomes eligible for re-extraction again. `--id` is from `neoth profile redactions`

- `--id <ID>` — Redaction row id (from `neoth profile redactions`)

## `neoth provider`

LLM provider catalogue (C-1 Session 13). `list` enumerates all supported `InferenceProvider` variants + their implementation status + the OpenAI-compatible endpoint examples that the `openai_compat` adapter covers. `show <id>` prints details for one provider. `add` / `test` / `remove` are reserved for a future session — operators configure providers via `neoth init` or `neoth hemispheres set` today

_Aliases:_ `neoth providers`

### `neoth provider add`

Add a new LLM provider (reserved — use `neoth init`)

### `neoth provider known`

List well-known OpenAI-compatible endpoints (DeepSeek, xAI Grok, Mistral, Moonshot Kimi, Z.ai GLM, Groq, OpenRouter, Together, Fireworks, Perplexity, plus local Ollama / LM Studio / vLLM) with their endpoint URL, default model, and doc link

### `neoth provider list`

List every supported LLM provider with status + compat-endpoint examples

### `neoth provider remove`

Remove a provider (reserved — use `neoth init`)

- `<PROVIDER>`

### `neoth provider show`

Show details for one provider by id (e.g. `claude_cli`, `openai_compat`)

- `<PROVIDER>`

### `neoth provider test`

Show where a provider is wired into the hemispheres (live round-trip: `neoth hemispheres test --role <r> --live`)

- `<PROVIDER>`

## `neoth quota`

Per-provider quota visibility — show backoff windows + daily counters, reset a provider, record an estimated cap

### `neoth quota reset`

Reset the daily counter + clear any active backoff window for a single provider. Operator override — use sparingly. The 429 will re-trigger on the next call if the remote is still rate-limited

- `<PROVIDER>`

### `neoth quota set-cap`

Record an operator-observed daily request ceiling. Telemetry-only — NEOTH never refuses a call based on `--cap`; the only gating signal is an active 429 backoff window

- `<PROVIDER>`
- `<CAP>`

### `neoth quota status`

Show per-provider quota state. With `--provider X`, filter to one

- `--provider <PROVIDER>`

## `neoth recall`

Search the SQLite recall views for matching text. Runs the indexer once before querying

- `<QUERY>` — Search string. Matched case-insensitively against episode text via LIKE. Optional when `--similar-to` is used instead
- `--limit <LIMIT>` — Max hits to return
- `--db <PATH>` — Override the views.db path
- `--wal-segment <PATH>` — Override the WAL segment path the pre-query indexer scans
- `--no-index-pass <NO_INDEX_PASS>` — Skip the pre-query indexer pass — useful if `neoth serve` is already running and tailing the WAL
- `--include-dreams <INCLUDE_DREAMS>` — R-02 Phase 2: include dream-pipeline matches at the top of the result set. Scans `~/.neoth/dreams/*.jsonl` over the last `--dreams-lookback-days` days and prepends up to `--dreams-max-hits` dream rows matching the query
- `--dreams-lookback-days <DREAMS_LOOKBACK_DAYS>` — How many days back to scan for matching dreams. Honoured only when `--include-dreams` is set
- `--dreams-max-hits <DREAMS_MAX_HITS>` — Max dream rows to prepend. Honoured only when `--include-dreams` is set
- `--similar-to <PATH>` — Cross-modal similarity query — compute the CLIP embedding of the image at this path, then return the top-N cached embeddings by cosine similarity. Bypasses the text recall pipeline entirely. Requires `neoth models pull clip` to have already cached the checkpoint
- `--similar-to-text <TEXT>` — Cross-modal text-to-image query — encode the prompt through the CLIP text tower, then look up the top-N similar embeddings. Mutually exclusive with `--similar-to`
- `--similar-kind <KIND>` — Optional kind filter for `--similar-to{,-text}`. Defaults to `image`. Use `any` to search across every stored kind
- `--citation-check <TEXT>` — QM-18 citation-check: run the offline citation-extraction + contamination heuristics against the supplied text and report findings. Bypasses recall search entirely; no DB / no WAL / no network. Use `--citation-check -` to read from stdin

## `neoth recall-score`

ARCH-05/SPEC-08 — score the legacy-AI→NEOTH recall-parity gate over grader sheets: inter-rater kappa + kappa-adjusted weighted-harmonic parity + per-query CRITICAL divergences (emits `0x3E`). Exits non-zero on FAIL. `recall-score --grades a.jsonl --grades b.jsonl [--goldset g.jsonl]`

- `--grades <GRADES>` — Grader-sheet JSONL file(s) (each line a GraderGrade: query_id, grader_id, system, 5×Likert). Pass one per grader; all are merged. Need ≥ 2 graders
- `--goldset <GOLDSET>` — Optional goldset JSONL — validated + its query count reported (the scoring runs off the grades, not the goldset)
- `--no-audit <NO_AUDIT>` — Don't emit `0x3E` WAL frames (dry scoring; the report still prints)

## `neoth refusal`

Test the Schicht-0 mirror-refusal detector against arbitrary text. `classify <text>` runs the deterministic classifier; `patterns` dumps the pattern dictionaries the classifier uses

### `neoth refusal cause`

R-06 2026-05-17: classify the CAUSE of a refusal — orthogonal to `classify` which reports the surface class. Returns one of {safety_policy, capability_gap, privacy, operator_policy, unknown} plus the matched patterns + confidence

- `<TEXT>` — The text to classify

### `neoth refusal classify`

Classify `<text>` against the refusal detector. Prints the classification + confidence + the matched patterns so operators can see exactly which signals fired

- `<TEXT>` — The text to classify. Quote shell-special characters

### `neoth refusal disable`

R-06: disable a specific LOWKEY reframing. Atomically rewrites `freedom.yaml::refusal_recovery.disabled_reframings`. Use for third-party deployments where e.g. `operator_authority` (LOWKEY pentester-context prepend) is not appropriate

- `<ID>` — Reframing id (snake_case): `operator_authority`, `narrow_scope`, `step_decomposition`, `meta_discussion`, `academic_framing`, `historical_framing`

### `neoth refusal enable`

R-06: re-enable a previously-disabled reframing. Removes the id from `freedom.yaml::refusal_recovery.disabled_reframings`

- `<ID>` — Reframing id (snake_case)

### `neoth refusal history`

SPEC-10: audit trail of past automated reroutes. Scans every WAL segment for `0x19 REFUSAL_REROUTED` frames and prints them most-recent first. Read-only; no daemon required. The WAL stores only xxh3 hashes of the refusal + reframed prompt (never raw text), so the hashes shown are the audit anchor, not plaintext

- `--limit <LIMIT>` — Show at most this many reroutes (most-recent first). `--limit 0` shows the entire history

### `neoth refusal patterns`

Print the static pattern dictionaries the classifier uses, in table or JSON form. Useful for "why didn't my refusal text trigger?" debugging

### `neoth refusal reframings`

R-06: list the 6 LOWKEY reframings with their description, applicable causes, and per-id enabled/disabled status from `freedom.yaml::refusal_recovery.disabled_reframings`

### `neoth refusal test`

SPEC-10: dry-run the recovery selection for a refusal WITHOUT calling a provider. Classifies the cause, lists the ordered reframing chain `try_recover` would attempt (honouring the operator's `disabled_reframings`), and — when `--prompt` is given — shows the reframed prompt the first applicable reframing produces. Pure: no LLM, no WAL

- `<TEXT>` — The refusal text to classify + plan recovery for
- `--prompt <PROMPT>` — Optional original prompt to reframe — shows the exact rewritten prompt the first applicable reframing emits

## `neoth release`

MAR-02 — DAU-friendly release signing. `keygen` mints the project signing keypair in-process (no `minisign` tool); `sign` produces a `.minisig` the updater verifies; `pubkey` reprints the public key for CI

### `neoth release keygen`

Generate the project release-signing keypair (maintainers, one-time). Prints the PUBLIC key (safe to share — goes in CI build env) + the SECRET (goes in a GitHub secret, never committed). Prefer `setup` for the zero-copy-paste path

- `--force <FORCE>` — Overwrite an existing key. DANGER: invalidates every signature made with the currently-published public key — only when rotating

### `neoth release pubkey`

Print the saved key's PUBLIC key line (paste into CI build env)

### `neoth release setup`

ONE-COMMAND DAU setup: generate the keypair AND provision it into the repo's CI via `gh` (sets the `NEOTH_RELEASE_MINISIGN_SECRET` secret + the `NEOTH_RELEASE_MINISIGN_PUBKEY` variable). No copy-paste, no GitHub UI. The secret never prints — it is piped straight to `gh` over stdin

- `--repo <REPO>` — `owner/name`. Defaults to the `origin` git remote
- `--force <FORCE>` — Rotate: replace an existing local key (then re-provision CI)

### `neoth release sign`

Sign a release artifact, writing `<file>.minisig` next to it. The secret is read from `NEOTH_RELEASE_MINISIGN_SECRET` (CI) or the saved key file

- `<FILE>` — The artifact to sign (e.g. `neoth-x86_64-unknown-linux-gnu.tar.gz`)
- `--comment <COMMENT>` — Optional trusted comment embedded + signed into the `.minisig`

## `neoth reload`

Pick #37 (Session 14, Agent #4 design-consensus): trigger the running `neoth serve` daemon to re-read `freedom.yaml` and atomically swap its live `Arc<FreedomConfig>` via `arc-swap`. Touches a sentinel file `~/.neoth/.reload-requested`; the daemon polls for it on every ingress tick. Immutable fields (`operator_id`, `provider_kind`, `telegram_user_id`) cause a `CONFIG_RELOAD_REJECTED` audit frame + the prior config stays live. Tunable fields (`council.*`, `code_map.*`, `claude_cli.tmux.*`, autonomy level, …) reload without a daemon restart

- `--home <DIR>` — Override `~/.neoth/` (mostly for tests)

## `neoth restore`

Restore a previously-written backup into `~/.neoth/`

- `<ARCHIVE>` — Path to the `.tar.gz` to restore
- `--home <DIR>` — Target directory. Defaults to `~/.neoth/`
- `--force <FORCE>` — Overwrite the target if it's non-empty

## `neoth review`

AI code review (GOLD-ADOPT-15) — wraps OpenCodeReview (`ocr`)

- `--from <FROM>` — Source ref to diff from (branch/merge-base mode), e.g. `main`
- `--to <TO>` — Target ref for the diff (defaults to the current branch when `--from` is set)
- `-c, --commit <SHA>` — Review a single commit (or tag) against its parent
- `-b, --background <TEXT>` — Optional requirement / business context to steer the review
- `-p, --preview <PREVIEW>` — Preview which files would be reviewed — no LLM calls (free, fast)
- `--agent <AGENT>` — Agent mode: summary only, no human progress lines (for piping)
- `--repo <DIR>` — Repository root (defaults to the current directory)

## `neoth risk-confirm`

GOLD-ADOPT-23 — open a TTL-bounded risk-confirm window so the next risk-gate-blocked tool call proceeds. Sugar over the `operator` risk-override lease; auto-expires. `neoth risk-confirm --ttl 10m` (add `--egress` to also lift an egress block)

- `--ttl <TTL>` — How long the confirm window stays open — `10m`, `300s`, `1h`, or a bare number of seconds. Default `10m`
- `--egress <EGRESS>` — Also lift the egress block (outbound to a non-allowlisted destination), in addition to the dangerous-command block
- `--egress-only <EGRESS_ONLY>` — Lift ONLY the egress block (leave dangerous commands gated)

## `neoth rollback`

B-Rollback / CDX-02: query pre-mutation snapshots captured in the WAL. `list` walks every `*.wal` segment and renders the `PRE_MUTATION_SNAPSHOT` (0xF2) frames so operators see which mutations were captured + when. Per-MutationKind restoration dispatcher ships in a follow-up

### `neoth rollback apply`

Restore the prior state captured in one snapshot. Dispatches on `MutationKind`: `file_write` writes the captured bytes back to the target path. Other kinds bail with a "not yet implemented" diagnostic since their restoration semantics are adapter-specific (a `channel_send` restoration would require platform-specific delete-or-edit; an `mcp_tool_invoke` would need a compensating call)

- `--to <OFFSET>` — Snapshot offset (from `neoth rollback list`)
- `--segment <PATH>` — Segment path the snapshot lives in (from `neoth rollback list`). Together with `--to` uniquely identifies a snapshot
- `--confirm <CONFIRM>` — Required to actually restore. Without it the command is a preview only — prints what would be restored + skips the write

### `neoth rollback list`

List every `PRE_MUTATION_SNAPSHOT` (0xF2) frame in the operator's WAL segments. Pure read — no mutations

- `--kind <KIND>` — Optional `MutationKind` filter (`file_write`, `channel_send`, `mcp_tool_invoke`, `sql_mutation`, `config_write`, `other`). Case-insensitive
- `--limit <LIMIT>` — Show at most N most-recent snapshots (default: 50)

## `neoth schema`

Inspect the live SQLite schema in `~/.neoth/views.db`. Lists tables + row counts; `--columns` shows the PRAGMA table_info per table

- `--db <PATH>` — Override the views.db path (mostly for tests)
- `--columns <COLUMNS>` — Show column details per table (name, type, nullable, default)

## `neoth search`

Web search via Brave / Tavily (A-20)

- `<QUERY>` — Query string
- `--provider <NAME>` — Provider override: `brave` or `tavily`
- `--api-key <KEY>` — API key override. Defaults to `credentials.yaml::web_search_key` or the `NEOTH_WEB_SEARCH_KEY` env variable
- `--limit <LIMIT>` — Max results (1-20)

## `neoth security`

Round-3 v0.4 SC-04 — operator-facing security posture aggregator. `neoth security audit` runs every available security check (HMAC key + WAL segment health + memory drift + credential sidecar) and prints a pass/warn/fail checklist. Exit code 1 iff any check FAILed; warnings don't change exit

### `neoth security audit`

One-shot security posture report — runs every available check + prints a pass/warn/fail checklist. Exit code 0 on all-clear, 1 if any check FAILed (warnings don't change exit). Matches the `neoth doctor` semantics

- `--home <DIR>` — Override the `~/.neoth` home dir (mostly for tests)
- `--permissions-lookback-hours <HOURS>` — Lookback window for the permission-decisions check, in hours. Default 24h covers operator's last day of activity
- `--drift-display-cap <N>` — Cap on drifting-row display per severity bucket. Doesn't affect the summary counts

### `neoth security backup-hmac-key`

SC-09 (Session 28) — export the WAL HMAC compaction key to `<output>` in plaintext for disaster-recovery purposes (machine swap, Windows reinstall, DPAPI unwrap failure)

- `--output <PATH>` — Plaintext destination path. The file is written mode-0600 (Unix) so it's only readable by the operator account. Refused if the path already exists unless `--force` is also passed (defence against silent overwrite of an older backup)
- `--force <FORCE>` — Overwrite `--output` if it already exists. Without this flag the command fails fast — accidentally re-running this command with the same `--output` shouldn't blow away an older backup taken at a different rotation
- `--home <DIR>` — Override the `~/.neoth` home dir (mostly for tests). Defaults to the operator's actual `~/.neoth`

### `neoth security rewrap-hmac-key`

SC-09 Tier-1 recovery — re-wrap a plaintext HMAC key backup for THIS machine/user and install it, OVERWRITING the current key

- `--source <PATH>` — Path to the plaintext HMAC key backup (produced by `neoth security backup-hmac-key`). Its bytes are re-wrapped for the current machine/user and installed over the live key
- `--home <DIR>` — Override the `~/.neoth` home dir (mostly for tests). Defaults to the operator's actual `~/.neoth`

### `neoth security safe-mode`

GR-10 — single-glance view of the active safety RAILS: which protective defaults are ENGAGED vs which the operator has RELAXED (autonomy, private inference, proactive/cluster transport, OS-tool allowlists, plugin signatures, model downloads). Read-only — the single source of truth for "what is protecting me right now" without spelunking `freedom.yaml`. Always exits 0 (it is a status view, not a pass/fail gate)

- `--home <DIR>` — Override the `~/.neoth` home dir (mostly for tests)
- `--json <JSON>` — Emit JSON instead of the human-readable table

## `neoth self-dev`

P-04 proactive self-development workflow. `review` lists pending proposals; `accept <id>` applies + emits 0x1D SELF_DEV_ACCEPTED; `decline <id>` records refusal + emits 0x1E SELF_DEV_DECLINED; `propose --from-profile <p>` generates proposals from a recorded BehaviouralProfile + emits 0x1C SELF_DEV_PROPOSED per proposal. Local store at `~/.neoth/self_dev/proposals.json`

### `neoth self-dev accept`

Accept a proposal by id (operator types e.g. `neoth self-dev accept switch_preset-a1b2c3d4`). Emits `EVENT_TYPE_SELF_DEV_ACCEPTED` (0x1D) when a WAL writer is available; otherwise records the decision in the local proposals.json only + warns

- `<ID>`

### `neoth self-dev decline`

Decline a proposal. Reason `"declined"` (explicit) or `"timeout"` (operator never reviewed)

- `<ID>`
- `--reason <REASON>`

### `neoth self-dev propose`

Generate proposals from a `BehaviouralProfile` JSON. Operator- facing demonstration command: write the JSON via `neoth profile stats > profile.json` (future) or hand-craft for testing, then `neoth self-dev propose --from-profile profile.json` materialises the proposals + emits `EVENT_TYPE_SELF_DEV_PROPOSED` (0x1C) per proposal

- `--from-profile <FROM_PROFILE>`
- `--current-preset <CURRENT_PRESET>` — Treat the operator as currently on this preset for the proposal engine. Defaults to "lowkey" per the recommended-default hard rule

### `neoth self-dev review`

List every pending proposal. `--min-confidence` filters by the engine's confidence estimate (0.0..=1.0)

- `--min-confidence <MIN_CONFIDENCE>`

## `neoth serve`

Run the daemon. Reads ~/.neoth/freedom.yaml, opens the WAL, awaits SIGTERM / Ctrl+C, drains cleanly on shutdown

- `--config <PATH>` — Override the path to freedom.yaml. Defaults to ~/.neoth/freedom.yaml
- `--wal-segment <PATH>` — Override the WAL segment path. Defaults to ~/.neoth/wal/000001.wal
- `--allow-clock-rollback <ALLOW_CLOCK_ROLLBACK>` — Override the clock-rollback guard. Use only when restoring from a backup or recovering from a VM snapshot rewind — operator promises the timestamps in the WAL are intentional. Phase 33c BS-5

## `neoth skills`

List installed skills + probe the router with a test message

_Aliases:_ `neoth skill`

- `--list <LIST>` — Print the table of installed skills
- `--test <MESSAGE>` — Run the router against an arbitrary message and report the match
- `--run-tests <SKILL_ID>` — Run the RED/GREEN scenario suite for a skill. Loads `~/.neoth/skills/<id>/tests/*.yaml`, runs each scenario twice (without and with the skill's system prompt), reports pass/fail. Requires a working provider in `freedom.yaml`. Phase 33+ (obra/ superpowers Item #3 port)
- `--install <PATH>` — QM-11 install a skill from a local directory containing `skill.yaml`. Validates the manifest BEFORE copying; refuses to replace an existing install unless `--force` is set
- `--uninstall <SKILL_ID>` — QM-11 uninstall the named skill from `~/.neoth/skills/<id>/`. Idempotent — missing id is reported as such, not an error
- `--force <FORCE>` — QM-11: force replacement when `--install` would overwrite an existing skill of the same id
- `--create <CREATE>` — UX-06 — create a new skill manifest via an interactive wizard (or `--create-*` flags / `--non-interactive`). Writes a validated `~/.neoth/skills/<id>/skill.yaml` — no Rust required
- `--create-id <ID>` — UX-06 non-interactive: skill id (kebab-case, `[a-zA-Z0-9_-]`)
- `--create-description <DESC>` — UX-06 non-interactive: one-line description
- `--create-keywords <KW,...>` — UX-06 non-interactive: comma-separated trigger keywords
- `--create-system-prompt <PROMPT>` — UX-06 non-interactive: system prompt text
- `--non-interactive <CREATE_NON_INTERACTIVE>` — UX-06: skip interactive prompts even on a TTY (drives `--create` from the `--create-*` flags only)
- `--enable <SKILL_ID>` — GOLD-ADOPT-14 — activate a skill that ships disabled (e.g. the imported `pm-*` skills): adds it to `freedom.yaml::skills.enabled` (clearing any disable). Persists across restarts + binary upgrades
- `--disable <SKILL_ID>` — GOLD-ADOPT-14 — deactivate a bundled skill: adds it to `freedom.yaml::skills.disabled` (clearing any enable). `disabled` always wins, so this also overrides a prior `--enable`

## `neoth slack`

Slack pre-flight (A-7). `test` validates xoxb + xapp tokens by calling `auth.test` + `apps.connections.open` and reports the WSS URL Phase-2 socket-mode loop will dial

### `neoth slack send`

Send a one-shot message to a Slack channel via `chat.postMessage`. Uses `credentials.yaml::slack_bot_token`. `channel` accepts an id (`Cxxxxxx`), a DM id (`Dxxxxxx`), or `#channel-name` (Slack resolves server-side). Returns the message timestamp (Slack's `ts`) so operators can correlate with later edits/reactions

- `--channel <CHANNEL>` — Channel id or `#name`
- `--message <MESSAGE>` — Message body (UTF-8, Slack mrkdwn supported)

### `neoth slack test`

Auth-test the configured Slack tokens. Reads `credentials.yaml::slack_bot_token` + `slack_app_token`, calls Slack's `auth.test` + `apps.connections.open`, and reports the result. Phase-2 socket-mode loop will dial the WSS URL this returns

## `neoth slash`

Inspect slash commands loaded from `~/.neoth/commands/*.toml` plus the built-ins (`/help`, `/recall`, `/status`, ...)

### `neoth slash list`

Print every loaded slash command (built-in + operator-defined), sorted by name

### `neoth slash show`

Render a single slash command with its prompt template + help text

- `<NAME>`

## `neoth status`

Daemon-state snapshot — WAL bytes, tier counts, channels, autonomy. Phase 33c BS-1. Pure read, no IPC, no daemon required

- `--home <DIR>` — Override the `~/.neoth/` home dir (mostly for tests)
- `--prometheus <PROMETHEUS>` — Print as Prometheus text format instead of the default table. Useful when the operator wants to scrape NEOTH from a Prometheus instance running on the same host

## `neoth supervisor`

MV-01b #3 — install/remove the OS-native process supervisor (systemd user unit / launchd LaunchAgent / Windows Task) that keeps `neoth serve` running + auto-restarts it so self-update can activate a new binary. `neoth supervisor loop` is the built-in restart wrapper the Windows task targets. User-scoped, no root/admin

### `neoth supervisor install`

Install the OS-native supervisor (systemd user unit / launchd LaunchAgent / Windows Task) + enable it. User-scoped, no root/admin. After install, set `supervisor.enabled: true` in freedom.yaml (the wizard does this automatically) so the self-update task knows a supervisor is present

### `neoth supervisor loop`

Built-in restart wrapper (the Windows Task Scheduler target): spawn `neoth serve`, relaunch unless it exits with the deliberate-stop code. Blocks forever

### `neoth supervisor status`

Show the host's supervisor kind + whether it's installed + the freedom.yaml flag

### `neoth supervisor uninstall`

Disable + remove the supervisor unit

## `neoth telemetry`

Opt-in anonymous version-check telemetry (E-18 Workstream N)

### `neoth telemetry off`

Flip `freedom.yaml::telemetry.enabled = false`

### `neoth telemetry on`

Flip `freedom.yaml::telemetry.enabled = true`. Operator MUST run this explicitly; default state is off

### `neoth telemetry preview`

Print the exact payload that would be sent so the operator can audit BEFORE flipping `enabled` on

### `neoth telemetry send-now`

Build the payload + POST it once + print the outcome. Honours `telemetry.enabled` unless `--force` is passed

- `--force <FORCE>` — Dry-run a send even when `telemetry.enabled = false`. Useful for testing the endpoint without committing to daemon-boot pings

### `neoth telemetry status`

Print resolved endpoint + on/off + opt-in posture. Default when no subcommand is given

## `neoth todo`

Todoist task management (TD-01). `list` / `add <content>` / `close <id>` via the Todoist REST v2 API. Token from `--token`, `credentials.yaml::todoist_token`, or `NEOTH_TODOIST_TOKEN`

- `--provider <PROVIDER>` — Task backend. `todoist` (static API token) or `google` (Google Tasks via OAuth refresh)
- `--token <TOKEN>` — Todoist REST v2 API token (provider `todoist` only). Overrides `credentials.yaml::todoist_token` and `NEOTH_TODOIST_TOKEN`. Get it from Todoist → Settings → Integrations → Developer
- `--dry-run <DRY_RUN>` — TD-02 (CalDAV write): show what WOULD be created/completed without sending the request or emitting the audit frame
- `--yes <YES>` — TD-02 (CalDAV write): skip the interactive confirmation for the network mutation (needed for scripts at Strict/Standard autonomy). The write is still WAL-audited

### `neoth todo add`

Create a task: `neoth todo add "buy milk"`

- `<CONTENT>` — Task content (the title shown in the backend)

### `neoth todo close`

Close (complete) a task by its backend id

- `<ID>` — Task id (from `neoth todo list`)

### `neoth todo list`

List active (open) tasks

## `neoth tour`

NOOB-UX-5 first-launch tour. `neoth tour` walks the operator through chat / memory / consent / privacy-audit / where-to-go

- `--step <ID>` — Show one tour stop only. Stops: `chat` / `memory` / `consent` / `audit` / `next`. Without this flag, prints every stop in order (the full guided tour)

## `neoth transfer`

Recipient-encrypted, operator-signed memory bundles (A3-01): `transfer export --dest <x25519_pubkey_b64>` seals the last N days of hot-tier memory (ephemeral X25519 ECDH → AES-256-GCM, ed25519-signed, size-capped, `0xF5`-audited); `verify` / `inspect` / `import` handle a received bundle. Share your receiving key via `neoth identity pubkey`

### `neoth transfer export`

Export a recipient-encrypted, signed memory bundle

- `--dest <DEST>` — Recipient's X25519 public key (base64) — from their `neoth identity pubkey`
- `--out <OUT>` — Output path. Default `~/.neoth/exports/transfer-<unix>.json`
- `--days <DAYS>` — Look-back window in days. Default 7
- `--dry-run <DRY_RUN>` — Show what WOULD be exported without writing or auditing

### `neoth transfer import`

Decrypt a received bundle with the managed transfer key + recover the memory dump (written to `--out` or `~/.neoth/imports/`)

- `<FILE>` — Path to the `.json` bundle
- `--out <OUT>` — Where to write the recovered plaintext JSON. Default `~/.neoth/imports/import-<unix>.json`
- `--pubkey <PUBKEY>` — Expected sender's ed25519 public key (base64) — import refuses a bundle that doesn't verify against it when given

### `neoth transfer inspect`

Print a bundle's metadata (schema, recipient, signer, sizes) — no decrypt

- `<FILE>` — Path to the `.json` bundle

### `neoth transfer verify`

Verify a received bundle (schema + recipient + signature) WITHOUT decrypting. `--pubkey` pins the expected sender's ed25519 key for true attribution

- `<FILE>` — Path to the `.json` bundle
- `--pubkey <PUBKEY>` — Expected sender's ed25519 public key (base64) to verify against

## `neoth trust`

GR-03 — one read-only view of NEOTH's trust posture: the live autonomy level + what it gates, the HMAC-chained WAL ledger size (+ optional `--verify-chain` integrity check), and which recovery levers are armed right now. Ties together `verify`/`wal`/`autonomy`/ `recover` without mutating anything

- `--wal-dir <DIR>` — Override the WAL directory (mostly for tests)
- `--home <DIR>` — Override the NEOTH home (key-presence probes; mostly for tests)
- `--verify-chain <VERIFY_CHAIN>` — Also run the full HMAC chain verification inline (heavier — walks every compaction marker, like `neoth verify`). Off by default; the surface otherwise reports ledger SIZE + a pointer to `neoth verify`

## `neoth tts`

Text-to-speech synthesis (A-45). `speak` writes audio bytes to a file via ElevenLabs (cloud) or piper-rs (Phase 2 local)

### `neoth tts speak`

Synthesise speech to an audio file

- `<TEXT>` — Text to synthesise. Use `-` to read from stdin
- `--out <PATH>` — Output file path. Format inferred from provider (.mp3 for ElevenLabs, .wav for piper)
- `--provider <PROVIDER>` — `elevenlabs` (default, live in v0.1) or `piper` (Phase 2 deferred)
- `--voice <VOICE>` — Voice id for the chosen provider
- `--api-key <API_KEY>` — API key override. Defaults to `NEOTH_TTS_KEY` env var

## `neoth tweaks`

Inspect operator customisation loaded from `~/.neoth/tweaks.toml` (Phase 32 R-20). `show` dumps statusline / theme / model default / persona override + the prompt-snippet list. `snippet <id>` renders one named snippet so it can be inspected or copied

### `neoth tweaks show`

Dump the parsed `~/.neoth/tweaks.toml` contents. Missing file => shows defaults so the operator can copy-paste a starting point

### `neoth tweaks snippet`

Render a named prompt snippet by id. Useful when the operator keeps reusable openings (`/snippet morning-greet`) and wants to inspect them without grepping the file

- `<ID>`

## `neoth undo`

UX-03 — show the last N state-mutating WAL frames + how to reverse each. Read-only discovery; the confirm-gated auto-reverser is a separate step

- `--limit <LIMIT>` — How many recent mutating frames to show / index into (newest at the bottom)
- `--wal-dir <WAL_DIR>` — Override the WAL directory (default `~/.neoth/wal`). Mainly for tests + operators with a relocated WAL

### `neoth undo apply`

Reverse the Nth listed mutation (1-based index from `neoth undo`). Confirm-gated unless `--yes`. Only frame types with a wired, safe inverse are auto-reversed; others print the manual command

- `<N>` — 1-based index into the `neoth undo` list (same `--limit`)
- `--yes <YES>` — Skip the interactive confirmation prompt

## `neoth update`

Check or apply updates for NEOTH-managed CLIs (claude-cli, antigravity-cli, codex)

- `--check <CHECK>` — Probe every component and print a report. Default when no mode flag set
- `--apply <APPLY>` — Probe, then update any component where installed != latest. When combined with `--self`, runs the full daemon self- update (download → SHA-256 verify → extract → atomic replace) instead of the per-component CLI update
- `--list <LIST>` — Print the static list of components NEOTH knows how to update
- `--self <SELF_CHECK>` — V03-09 (2026-05-20): check whether a newer NEOTH daemon release is published on GitHub. Without `--apply` this is probe-only (Phase 1). With `--apply` runs the full Phase 2b flow: download → SHA-256 verify → extract → atomic replace. Pass `--self-repo owner/name` to point at a fork; default is `The-Geek-Freaks/NEOTH`
- `--self-repo <OWNER/REPO>` — Override the GitHub `owner/repo` slug for the self-check
- `--allow-unsigned <ALLOW_UNSIGNED>` — Accept an UNSIGNED release on `--self --apply`. By default the updater requires a verified minisign signature (supply-chain integrity). Releases published before signing was enabled (no pinned key / no `.minisig`) need this flag — only pass it from a trusted network; an unsigned binary could be tampered in transit

## `neoth updater`

U-01..U-04 updater status + check entry. Subcommands: `status`, `check`. Renders the most recent `UpdaterTaskResultPayload`s (the WAL 0x45 frames) as a readable table. The actual update pipeline (U-01 binary self-update, U-02 skills+plugins, U-03 CLI versions) wires in follow-up commits — today's surface is the status view

### `neoth updater check`

Bootstrap entry. Today's slice prints a friendly hint — the actual check pipeline lands with U-01..U-03

### `neoth updater status`

Print the most recent updater task results in a readable table

- `--wal-segment <PATH>` — Path to a specific WAL segment to scan for `0x45 UPDATER_TASK_RESULT` frames. Defaults to `~/.neoth/wal/000001.wal`
- `--from-jsonl <PATH>` — Path to a JSONL file containing one `UpdaterTaskResultPayload` per line. Overrides the WAL scan when set; used by tests + operator dry-runs

## `neoth usage`

QM-9 Phase 1: render the persisted usage log as a human-readable or JSON rollup. Aggregates the last 24h by default; `--days N` widens the window; `--since-unix … --until-unix …` pins an explicit range. Source files: `~/.neoth/usage/YYYY-MM-DD.jsonl`

- `--days <DAYS>` — How many days back to aggregate (default 1)
- `--format <FORMAT>` — Output format: `table` (default) or `json`
- `--since-unix <SINCE_UNIX>` — Optional explicit start unix timestamp (overrides --days)
- `--until-unix <UNTIL_UNIX>` — Optional explicit end unix timestamp (overrides --days)
- `--currency <CURRENCY>` — Display currency: USD (default) / EUR / GBP / CHF / JPY / CNY. Storage canonical stays USD; this only affects the rendering. Operator can also pin in `freedom.yaml::usage_currency`

## `neoth verify`

Verify HMAC compaction markers across the WAL. Phase 33b SP-2. Reads every segment, recomputes the tag over each window, and reports any mismatches

- `--wal-dir <DIR>` — Override the WAL directory (mostly for tests)
- `--key <PATH>` — Override the HMAC key path
- `--segment <PATH>` — Verify only this specific segment file
- `--since-rotation <SINCE_ROTATION>` — SC-09 — verify only segments at/after the last HMAC-key rotation (`0xD9 HMAC_KEY_ROTATED`, written by `neoth security rewrap-hmac-key`). Markers in earlier segments were signed with a key that has since been replaced; skipping them avoids spurious failures after a key recovery. With no rotation recorded, verifies the full history (with a note)

## `neoth wal`

Read-only WAL segment inspector. `stats <file>` counts frames per event-type; `show <file>` pretty-prints frames (offset, code, importance, ts_ns, payload hash). Works on backups too

### `neoth wal export`

KF-03 — export a tamper-evidence `.neoth-proof` bundle covering every frame in a time window, plus the HMAC compaction marker(s) sealing those bytes. A third party re-checks integrity offline (`neoth wal verify-proof`). `--sign` uses the operator's auto-managed ed25519 proof key (generated on first use; no minisign tool / keygen / password)

- `--window <WINDOW>` — Window: a duration back from now (`24h`, `7d`, `30m`, `3600`) or a UTC RFC3339 range (`2026-05-01T00:00:00Z..2026-05-02T00:00:00Z`)
- `--out <PATH>` — Output path. Default: `~/.neoth/exports/neoth-<unix>.neoth-proof`
- `--verify-chain <VERIFY_CHAIN>` — Re-verify each included compaction marker's HMAC against the local key at export time (sets `chain_verified`). Off by default so an operator without the key can still export the metadata bundle
- `--wal-dir <DIR>` — WAL directory override (tests / inspecting a backup)
- `--sign <SIGN>` — KF-03 — ed25519-sign the bundle with the operator's auto-managed signing key (`~/.neoth/wal/signing.key`, generated on first use, no prompt). Embeds the signature + public key so a third party can run `neoth wal verify-proof`. Off by default (an unsigned metadata bundle still carries the SHA-256 self-integrity digest)

### `neoth wal proof-key`

PROOF-KEY-01 — inspect the operator's proof signing key (the ed25519 key `wal export --sign` uses, `~/.neoth/wal/signing.key`). READ-ONLY — never generates the key (use `wal export --sign` to create it on first use). `rotate` is a follow-on

#### `neoth wal proof-key export-pub`

Print ONLY the base64 public key (pipe it to an auditor so they can `wal verify-proof --pubkey <key>`). Exits non-zero if no key exists yet

#### `neoth wal proof-key show`

Print the proof signing key's public key + on-disk path (or report that no key exists yet)

### `neoth wal show`

Pretty-print frames, newest first. With no `<segment>`, scans EVERY `~/.neoth/wal/*.wal` segment so an operator can audit the whole chain without naming a file. `--type` filters to one event type — this is how an operator proves a guarantee, e.g. `neoth wal show --type plugin_cap_denied` (every denied plugin hostcall) or `--type provider_fallback_attempted` (every 429 failover)

- `<SEGMENT>` — Segment file. Omit to scan ALL `~/.neoth/wal/*.wal`
- `--type <TYPE>` — Filter to ONE event type. Accepts a name (`plugin_cap_denied`), hex (`0xC7` / `c7`), or decimal. See `neoth events` for names
- `--limit <LIMIT>` — Show at most this many (the most recent). `--last` is an alias
- `--skip <SKIP>` — Skip this many of the most-recent frames before showing

### `neoth wal stats`

Count frames per event type + report header validity + total bytes

- `<SEGMENT>` — Path to the segment file (`~/.neoth/wal/NNNNNN.wal`)

### `neoth wal verify-proof`

KF-03 — verify a `.neoth-proof` bundle: re-check the SHA-256 self-integrity digest, then (if signed) the ed25519 signature. Prints a plain-language verdict + exits non-zero on tamper / bad signature. Pass `--pubkey <base64>` (the operator's out-of-band-shared key) for TRUE attribution; without it the signature is only self-consistency- checked against the key embedded in the file

- `--proof <PATH>` — Path to the `.neoth-proof` file
- `--pubkey <BASE64>` — Operator's expected signing public key (base64), pinned out-of-band

## `neoth webhook`

Webhook HTTP server. Subcommand: `serve`. Starts the `paperless::webhook_server` so n8n + future MCP plugins can drive the paperless slice via real HTTP requests. Required `--token` (or `NEOTH_TOKEN` env) for Bearer auth on every non-healthz route; refuses to start unauthenticated unless `--allow-no-auth` is explicitly passed

### `neoth webhook serve`

Start the paperless webhook HTTP server. Runs until SIGTERM / Ctrl+C

- `--bind <BIND>` — Bind address. Defaults to `127.0.0.1:8765` — the `NEOTH_HTTP_BASE` the n8n starter workflows POST to
- `--vault <PATH>` — Vault root the handler writes to
- `--subdir <SUBDIR>` — Subdir under the vault. (Per-request override still works; this is the server default.)
- `--token <TOKEN>` — Required bearer token. Operators set `NEOTH_TOKEN` in env or pass via `--token`. Empty disables auth (testing only — refuses to start unless `--allow-no-auth` is also passed)
- `--allow-no-auth <ALLOW_NO_AUTH>` — Explicit opt-in for unauthenticated mode. Without this, a missing `--token` is a hard error so operators don't accidentally expose `/paperless/ingest` to the LAN

