# W185 core controller regression tests

`SRC/neothd/src/daemon/local_models/tests.rs` is the controller regression
module.  It drives `LocalModelController` over a real Tokio loopback TCP
listener (`loopback_fixture::LoopbackOllamaFixture`), which serves Ollama-like
`/api/tags`, `/api/ps`, `/api/chat`, `/api/pull`, and `/api/delete` routes.

| Test | Contract boundary |
| --- | --- |
| `ready_requires_exact_chat_then_fresh_matching_ps_digest` | `Ready` follows the model-specific chat request only when a subsequent `/api/ps` has the exact tag digest. |
| `restart_does_not_revive_a_previous_ready_observation` | Restart replaces persisted Ready/loaded observations with Unavailable until a new observation completes. |
| `mutation_admission_is_rejected_while_a_real_probe_is_in_flight` | A separate real TCP server blocks `/api/chat`; mutation admission is refused during the actual probe and no pull is sent. |
| `critical_admission_persistence_failure_sends_no_mutation_request` | An injected durable-admission failure returns no operation id and starts no HTTP mutation. |
| `failed_or_mismatched_probe_never_marks_model_ready` | A failed inference request or mismatched fresh loaded digest stays explicitly unready. |
| `inventory_uses_tag_name_when_ollama_omits_model` | `/api/tags.name` is the controlled selector fallback when `model` is absent. |
| `pull_requires_terminal_success_and_fresh_target_inventory` | A pull needs a success frame and a fresh exact target inventory row; a missing fresh row or EOF without success is an InterruptedUnknown post-send outcome that cannot Retry. |
| `cancel_requires_the_exact_active_id_and_retains_uncertainty` | Only the owned active id can abort/reap its request; abort leaves `InterruptedUnknown`, not invented remote success. |
| `prune_refuses_absent_or_loaded_targets_and_proves_exact_fresh_absence` | Absent and loaded selectors do not reach delete; completion requires a fresh absence of the exact selector. |
| `retry_requires_an_exact_retained_failed_action_and_never_runs_implicitly` | Retry resolves only a retained failed receipt to its stored action/model, and no failed pull restarts by itself. |
| `refresh_cannot_restore_stale_ready_while_a_mutation_is_active` | Refresh retains the active mutation state instead of restoring a previous Ready row. |
| `bounded_http_response_is_rejected_before_inventory_is_accepted` | A response over the controller byte cap is rejected rather than admitted as inventory. |
| `nested_action_payload_rejects_unknown_fields` | The nested action DTO rejects unrecognized request fields. |

No Cargo, compiler, parser, formatter, test, runtime, Git, or network command
was run from this worktree under the BSOD hold.  The core includes this module
through `#[cfg(test)] mod tests;`; the hosted acceptance pass remains the
evidence boundary for end-to-end daemon/CLI/GUI behavior.
