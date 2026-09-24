# W805 — Verifiability Routing

D7 adds explicit request-scoped routing to `neoth chat`.

- `--workflow <closed-label>` is required to bind D7. Unknown and `unclassified` labels fail before configuration or provider construction.
- `--changing-facts` requires that workflow binding and binds the request exactly once to the existing later `/research` slash consumer. It does not create a second retrieval, search-key, HTTP, consent, or audit path. The daemon plain-chat shortcut excludes every D7-bound request.
- `verifiability_routing` is default-off. It names only existing hemisphere roles; a local-specialist decision requires an explicit local resolved slot, while a frontier decision requires an explicit non-local resolved slot.
- Strict D6 assessment loading supplies all evidence. Missing, malformed, duplicate, unknown, disabled, and unusable cases preserve the configured route.
- A HumanStdout handoff is emitted only when `outcome_checkable` or `expert_agreement` is explicitly rejected. `owns_tools_and_schemas`, `data_stays_local`, and other specialist criteria do not claim a workflow is unverifiable.
- High-volume local-specialist routing still requires all eight D6 fields. Rare frontier routing requires confirmed outcome-checkability and expert agreement and does not require specialist-only evidence.

Provider selection is pinned through the existing Left-primary fallback builder, preserving its consent, residency, quota, WAL, and token-cap controls. The replay entry points do not call the public D7 planning consumer, so replay cannot trigger retrieval or other D7 effects.

The focused connected checks cover the typed HumanStdout handoff, both local-specialist and frontier slot pinning into the Left-primary builder, alternate-ingress Incognito rejection before a runtime writer, and the actual `/research` no-key terminal with an outer-provider call counter. The no-key test fails before runtime setup on hosts configured with a real search key or keyless SearXNG; it cannot silently skip and report a passing result. Hosted acceptance uses the isolated no-key environment.
