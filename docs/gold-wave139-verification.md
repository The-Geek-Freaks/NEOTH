# W139 — observed registry-context compile repair

Full CI `35580547601` on `0c2c2a2a` reached the production library and failed
with E0412 at `pipeline/enriched_request.rs:190`: the W136 field referred to
`RenderedUntrustedContext` without importing that type. Gold smoke and SSH
feature jobs independently reported the same error. The known-broken full
run is confirmed cancelled.

The field now uses `crate::pipeline::RenderedUntrustedContext`, the existing
public re-export from `pipeline/mod.rs`. This only resolves the intended type;
the registry payload, retention, authority and tests are unchanged. Fresh
hosted compilation and behavioral execution remain required.

Preflight `35580411011` and Code Quality `35580410277` passed on the prior
`0c2c2a2a` source. Those static results do not prove compilation. The separate
Windows preview `35575775478` uses older `85658d48`; its CLI build completed
and its GUI build was still running at diagnosis, so it does not validate W136.

No local compiler, formatter, parser, test, fixture, product or GUI was run.
No Road checkbox or count changes are attributed to this repair.
