# W185 CLI and Buddy implementation

The existing media-cache verbs remain unchanged. W185 adds a nested,
daemon-owned Ollama family:

```text
neoth models ollama status [--output json]
neoth models ollama pull <exact-tag> [--output json]
neoth models ollama update <exact-tag> [--output json]
neoth models ollama prune <exact-tag> [--output json]
neoth models ollama cancel <operation-id> [--output json]
neoth models ollama retry <operation-id> [--output json]
neoth models ollama --config <freedom.yaml> status [--output json]
```

The CLI discovers `LocalModelsIpcClient` from the selected NEOTH home
and sends only private IPC requests: status, start, or exact-operation cancel.
It does not create a controller, issue HTTP, or provide an endpoint/model-path
override. If the daemon private service is absent, each `models ollama` command
fails visibly and asks the operator to start `neoth serve`.

`--config` belongs only to the nested `ollama` action. A supplied
`freedom.yaml` selects its parent directory as the private IPC home, exactly
as `neoth serve --config` does; a relative bare filename resolves to `.`.
Without it, the CLI uses `FreedomConfig::default_neoth_home()`, including the
existing `NEOTH_HOME` override. Other `models` commands keep their existing
home behavior. The GUI uses its inherited `NEOTH_HOME` environment to select
the same nondefault instance and has no separate selector in this slice.

JSON `status` is the core `LocalModelsSnapshot` without a second CLI schema.
Mutation JSON is the core `LocalModelActionAck`, including its snapshot. Table
output is a projection of those same DTOs: endpoint, observation time, active
operation, exact model/digest/size, readiness, acknowledgement action and ID.

`buddy status` adds `local_models`. When private IPC is available, that field
is byte-equivalent to the same `LocalModelsSnapshot` projection used by the
CLI. When it is unavailable, Buddy still returns its normal status and sets:

```json
{"kind":"unavailable","detail":"local-model daemon IPC unavailable"}
```

The fallback asserts no readiness and carries no raw transport error. There is
no duplicate Buddy mutation path; actions remain under `models ollama`.

Ready remains the core invariant: a model-specific inference probe succeeds
and a fresh matching `/api/ps` digest follows it. TCP reachability, tags,
`/api/show`, an operation exit, or a stale loaded row do not establish Ready.
Mutable work is daemon single-flight. Retry uses the retained exact action and
model; cancel names the daemon-generated exact operation ID.

Source parser and action-mapping tests are colocated with `cli/models.rs`.
They are unexecuted under the BSOD hold. This note is implementation context,
not W185 acceptance or release proof; hosted daemon/IPC/inference acceptance
is still required.
