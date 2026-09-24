# Sealed outbound HTTP execution and truthful Citation terminals

The external HTTP authorizer now owns the only production send for its consumers. A private built request binds method, URL and exact body bytes; gate, IFC and required intent precede deferred DNS validation and the send. Response processing remains inside the same lifecycle so status, body limits, streaming, decoding and archive digest checks complete before a success terminal is written.

Citation preserves data-free Timeout versus ProviderUnavailable transport outcomes. Invalid/oversized/truncated bodies, invalid records, unexpected statuses and 429 return failure through the lifecycle. A rate-limit cooldown is installed only after its failure terminal persists. A valid 404 NotFound or fully validated record produces success. Released-research failures retain the existing opaque provider-neutral contract.

Nine new HTTP/Citation regressions cover the actual internal transport and audit sink. W933 independently reviewed the final seven consumer files after W928 repaired the initially discovered premature Citation success. Hosted formatting, compilation and exact Linux/Windows behavior are still required; ADOPT31-C7 remains open.

W932 also repairs two compiler findings from Core36056598545: direct CLI matches the new IFC denial explicitly, and the MCP budget wrapper forwards its trusted provenance instead of replacing it with compatibility provenance. A tenth registered regression exercises that real wrapper and proves rejection before fixture process calls. Root reviewed the final function bodies and exact diff.
