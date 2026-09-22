# Wave 213 Council role admission

W213 adds an optional closed role policy to the existing inference
configuration. It authorizes the concrete provider and final wire model selected
for a Council hemisphere. It never selects another provider. An absent policy
preserves compatibility; a present policy denies omitted roles. Unknown fields,
roles and providers, duplicate roles and invalid exact model patterns are rejected.

```yaml
inference:
  role_policy:
    rules:
      - role: left
        provider: local_ollama
        model: qwen3:8b
      - role: right
        provider: openai_api
        model: gpt-5
      - role: cerebellum
        provider: local_ollama
        model: qwen3:8b
```

The model names are examples; they must match the actual resolved wire model.
Omitting a rule's model permits any concrete model for that rule's provider.
The policy identity hashes the complete normalized rule set, so changes to any
role invalidate an older retained policy decision.

Primary and recursive Council builders bind their actual selected slot provider
and role. Recursive leaves retain their own inner role. A preliminary check
avoids acquiring a circuit attempt for an already rejected candidate; the
authoritative check occurs at leaf authorization after wire-model resolution.
The decision survives into the permit and durable lifecycle audit as
`hemisphere_role`, `hemisphere_provider`, `hemisphere_model` and
`hemisphere_policy`, without prompt content.

Complete, stream and event-stream boundaries compare the final request model
and current policy with that retained decision before entering raw transport.
The Claude tmux first and retry calls repeat the check after slot/session
readiness and optional retry authorization, before preparing the next send.
The actual effect-start callback shares the permit's retained role decision;
it rechecks current policy before consuming AllowOnce consent. This also closes
the wait between effect intent and subprocess/cold-session/pane start. A role
rejection after durable request audit gets the known
`role_dispatch_policy_changed` terminal in the Claude start paths.

The daemon keeps the handler's accepted topology, budget and channel authority
fixed. A separate reload controller checks only role-policy liveness. The
construction policy must first admit the candidate, and the current accepted
policy identity must still match it. A newer permissive policy cannot grant an
old handler a new capability. Only `inference.role_policy` is hot reloadable;
other inference fields remain restart-bound. CLI commands retain their fixed
per-command configuration.

## Verification boundary

Grouped251 `35772612247` on `7689717b` executed every selected test: 250 passed,
including all 12 W213 and all three W214 cases. All 52 source paths, identities,
matrix and lock match that source. The sole failure was the production-callsite
scanner treating the external role test module as production. The module now
declares its actual file-wide `#![cfg(test)]`; the scanner recognizes only this
explicit first substantive attribute, never a filename or comment. A focused
regression preserves detection of unguarded calls. Production allowlisting is
unchanged. The correction needs a fresh Hosted result.

The post-publication actual-start correction passed independent bounded source
review. Its new regression changes the accepted role policy after effect intent,
requires the start to abort and proves AllowOnce remains available. It awaits
Hosted execution. Core/CLI run `35772615830` on `7689717b` passed after the three
Copilot constructor fixes; it precedes this actual-start correction.

Grouped248 `35771699017` on `889d3df8` failed before execution: three existing Copilot token tests still called the extended transport-only permit constructor with four arguments. The fixtures now explicitly pass no role decision as the fifth argument. No W213 test result is claimed; a fresh Hosted run is required.


Twelve source regressions cover strict configuration, compatibility, complete
policy digests, allowed and denied raw calls, persisted audit identity, final
model rejection, accepted reload after durable authorization, direct request
mutation after permit construction and role-only reload versus topology change.
They are pending execution on GitHub-hosted runners. Independent bounded source
review passed after the retry, reload, moved-value and test-lifetime fixes.
The grouped lane now selects 248 tests. The inventory binds 529 source paths,
795 universal native and 92 GUI test identities, with platform extras unchanged.
No local executable checks ran.

W212 run `35769179702` on `0d501bad` is separately admitted: 236/236 actual
tests passed with exact identities, all 47 source paths, matrix and Cargo.lock
bound to the run. This is prior-batch evidence, not W213 acceptance.

Council currently constructs role providers directly and has no ordinary-chat
fallback wrapper. W213 does not introduce a new selection strategy. Ordinary
chat, its fallback candidates, background/sub-agent consumers and GUI policy
controls remain follow-up work for GOLD-LF-P2-15. No Road checkbox is closed by
this slice. Road remains 1324 total / 1015 checked / 307 open / 2 partial;
cross-platform, GUI and release gates remain open.
