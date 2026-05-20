# CLI Reference

All `neoth` commands. Run `neoth help` or `neoth <command> --help` for options.

---

## Status and daemon control

```
neoth start
```
Start the Neoth daemon. Loads all adapters and begins listening on configured channels.

```
neoth start --daemon
```
Start in background. Logs to `~/.neoth/neoth.log`.

```
neoth stop
```
Stop the daemon gracefully. Waits for in-flight requests to complete.

```
neoth status
```
Show whether the daemon is running, uptime, active channels, WAL size, disk usage.

```
neoth status --pid
```
Print the daemon PID only. Useful for scripting (`kill -HUP $(neoth status --pid)`).

---

## Chat (CLI mode)

```
neoth chat "<message>"
```
Send a message and get a response in the terminal. No daemon required.

```
neoth chat
```
Start an interactive REPL session. Exit with Ctrl+D or `exit`.

---

## Recall

```
neoth recall "<query>"
```
Search past conversations for content matching the query. Returns ranked results.

```
neoth recall "<query>" --since 7d
```
Limit results to the last 7 days.

```
neoth recall "<query>" --limit 5
```
Return at most 5 results.

```
neoth recall "<query>" --format json
```
Output as JSON. Useful for scripting.

---

## Profile

All profile commands. Profile learning is a Phase 2 feature.

```
neoth profile show
```
Show active profile (fields with confidence >= 0.1), formatted.

```
neoth profile show --raw
```
Show all fields with confidence scores and evidence event IDs.

```
neoth profile show --pending
```
Show claims held pending approval (when `require_approval: true`).

```
neoth profile redact <field>
```
Remove a field permanently. Example: `neoth profile redact identity.location`.

```
neoth profile redact health
```
Remove an entire category.

```
neoth profile redact --all
```
Remove all profile data. GDPR right-to-delete.

```
neoth profile redact <field> --allow-relearn
```
Remove the field but allow it to be re-learned from future conversations.

```
neoth profile pause
```
Stop profile learning for the current session.

```
neoth profile pause --scope=day
```
Stop for the rest of the day.

```
neoth profile pause --scope=forever
```
Stop indefinitely until `neoth profile resume`.

```
neoth profile resume
```
Re-enable profile learning after a pause.

```
neoth profile approve
```
Approve all pending profile claims (when `require_approval: true`).

```
neoth profile approve <id>
```
Approve a specific pending claim.

```
neoth profile reject <id>
```
Reject a specific pending claim permanently.

```
neoth profile export
```
Export active profile as JSON to stdout.

```
neoth profile export --format=md
```
Export as Markdown.

```
neoth profile export --confidence-floor=0.7
```
Export only fields with confidence >= 0.7.

```
neoth profile inspect <event_id>
```
Show extraction reasoning for a specific WAL event: hash, token counts, delta summary.

---

## Skills

```
neoth skill list
```
Show all installed skills with status (enabled/disabled) and trigger mode.

```
neoth skill install <path>
```
Install a skill from a directory containing `skill.yaml`.

```
neoth skill enable <skill_id>
```
Enable a skill.

```
neoth skill disable <skill_id>
```
Disable a skill without removing it.

```
neoth skill inspect <skill_id>
```
Show the rendered template, token count, and trigger configuration.

```
neoth reload-skills
```
Hot-reload all skills and identity files (soul.md, claude.md). Does not restart the daemon.

---

## Plugins

```
neoth plugin list
```
Show installed plugins with permission level and hook registrations.

```
neoth plugin enable <plugin_id>
```
Enable a WASM plugin (Phase 2). Requires daemon restart.

```
neoth plugin disable <plugin_id>
```
Disable a WASM plugin. Requires daemon restart.

```
neoth plugin inspect <plugin_id>
```
Show plugin manifest, hooks, and permission level.

---

## Channels

```
neoth channel list
```
Show configured channels and their status (connected / not configured / error).

```
neoth channel telegram status
```
Show Telegram adapter status: polling active, last message time, error count.

```
neoth channel telegram clear-webhook
```
Remove any registered Telegram webhook (needed before switching to polling mode).

---

## Council (Phase 2)

```
neoth council list
```
List recent council debates.

```
neoth council list --since 7d
```
List debates from the last 7 days.

```
neoth council invoke --task "<description>"
```
Manually trigger a council debate.

```
neoth council invoke --task "<description>" --file <path>
```
Include file content as context for the debate.

```
neoth council inspect <verdict_id>
```
Show full transcript of a council debate.

```
neoth council suppress --until tomorrow
```
Pause automatic council triggers until tomorrow midnight.

```
neoth council budget set max_debates_per_day <n>
```
Adjust the daily debate cap.

---

## Quota

```
neoth quota status
```
Show LLM provider request counts, health status, and council budget remaining.

```
neoth quota reset <provider>
```
Reset quota tracking for a provider. Debug use only.

---

## WAL

```
neoth wal stats
```
Show WAL size, segment count, oldest and newest events, compaction status.

```
neoth wal verify
```
Check all WAL segments for CRC errors. Reports corruption but does not fix.

```
neoth wal recover --from-checkpoint <file>
```
Recover from a specific checkpoint file after corruption.

```
neoth wal compact --force
```
Run compaction immediately (normally runs nightly at 03:30).

```
neoth wal prune --older-than 90d
```
Remove WAL segments older than 90 days that have been compacted.

---

## Identity

```
neoth identity list
```
Show all known identities (user UUIDs) with channel bindings.

```
neoth identity show <uuid>
```
Show details for a specific identity: channels, first/last seen.

```
neoth identity merge <uuid1> <uuid2>
```
Merge two identities. All events from uuid2 are reassigned to uuid1.
uuid2 is tombstoned. Irreversible — confirm before running.

---

## Privacy

```
neoth privacy audit --last 30d
```
Show where LLM requests went in the last 30 days (local vs cloud, per provider).

---

## Freedom and settings

```
neoth freedom show
```
Print the active freedom.yaml contents with current hash.

```
neoth freedom check scopes.security_research
```
Show the current value of a specific freedom.yaml field.

---

## Migration and cutover (Phase 3)

```
neoth migrate status
```
Show migration status if upgrading from a previous version.

```
neoth cutover --phase 3
```
Run the Phase 3 cutover procedure (operator-auth + profile seed migration).

```
neoth rollback
```
Roll back to the previous WAL snapshot. Requires a recent snapshot to exist.

---

## Model management (Phase 2)

```
neoth model list
```
Show available and downloaded models with sizes.

```
neoth model fetch qwen3-4b-int4
```
Download Qwen3-4B-INT4 from HuggingFace. Verifies SHA-256 on completion.

```
neoth model fetch qwen3-4b-int4 --resume
```
Resume a partial download.

```
neoth model verify qwen3-4b-int4
```
Verify SHA-256 and run a 10-token smoke test.

```
neoth model remove qwen3-4b-int4
```
Delete the model file from disk.
