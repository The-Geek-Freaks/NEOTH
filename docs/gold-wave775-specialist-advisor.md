# W775 specialist-advisor operator assessment

The D6 advisor reads only this optional local file:

`~/.neoth/specialist_assessments.json`

It combines that assessment with the preceding 30 days of local `usage_log`
rollups. `100` calls in that exact rolling window is the current observed-
volume policy. This file does not train a model, change provider selection, or
change routing. It only permits a proactive recommendation when all checklist
facts are explicitly confirmed.

Use schema version 1 and one row for each closed workflow label. The allowed
labels are `chat_turn`, `chat_post_reply`, `deep_research`, `session_naming`,
`background_session`, `council_deliberation`, `mcp_agent_loop`,
`n8n_provider_call`, `cluster_delegated`, `history_compaction`,
`teacher_escalation`, `refusal_recovery`, and `scheduled_maintenance`.
`unclassified` is deliberately excluded because it is a heterogeneous fallback
bucket and can never become a specialist candidate.

```json
{
  "schema_version": 1,
  "assessments": [
    {
      "workflow": "chat_turn",
      "outcome_checkable": "confirmed",
      "expert_agreement": "confirmed",
      "model_succeeds_sometimes": "confirmed",
      "not_lucky_guess": "confirmed",
      "multi_step_committed": "confirmed",
      "owns_tools_and_schemas": "confirmed",
      "asymmetric_error_costs": "confirmed",
      "data_stays_local": "confirmed"
    }
  ]
}
```

Each evidence value is exactly `confirmed`, `unknown`, or `rejected`.
`unknown` yields an assessment request; `rejected` or insufficient observed
volume yields no candidate. `ok_count` in the usage log never substitutes for
`model_succeeds_sometimes` because it means provider completion, not semantic
correctness.

The file is capped at 64 KiB and 64 rows. Unknown fields, invalid enum values,
unknown workflow labels, duplicate workflow rows, non-version-1 files, or an
unreadable/oversized file reject the full assessment. The advisor then emits no
candidate. A malformed assessment does not stop the independent G-02 profile
claim producer. Queued D6 items expire after seven days so an old 30-day-window
observation is never delivered late.
