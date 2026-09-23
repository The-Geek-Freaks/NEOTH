# W495 local-model Resources acceptance

GOLD-LF-P1-19 is functionally accepted from full-CI run35871801240 at
bc9db76c4ff72bfff9fa3674f20d904ead12fc76 with reviewed source carry through
2636215c54a0127dfc8bce5990f979542fc7deff. Root verified33 unique identities:
33 passing macOS terminals and32 applicable Windows terminals. Both artifact
hashes and all65 exact testcase/class pairs were checked, excluding failures,
errors and skips. Duplicate panel names in unrelated harnesses are not counted.

The selection covers18 bounded HTTP controller cases,9 private IPC cases,
2 CLI parsing/home-binding cases, daemon lifecycle,2 GUI schema/readiness parsers,
and the real W185 callback. W185 is Linux/macOS-specific; GUI145 atd938 also
independently passed it. Ready requires a successful model-specific chat probe
and a fresh loaded-model digest match. Tests cover progress, exact cancellation,
errors and uncertain outcomes, update/pull, fresh-inventory prune, retry binding,
persistence failure before and after effects, restart and shutdown/drain.

Disk use comes from artifact size; VRAM comes from Ollama's reported value.
RAM is visibly unknown without an authoritative measurement. Buddy consumes the
same typed snapshot. GUI operations require typed acknowledgements and fresh
operation-bound readback rather than a successful process exit alone.

All15 original implementation/fixture paths were compared. Nine carry exactly;
the six changed containers have recorded scoped carry: unrelated audit RPC and
cluster additions, formatting, equivalent predicates/let-chains, and unrelated
fixture registration. The W185 callback slice remains byte-identical.

Evidence: [acceptance receipt](verification/gold-wave495-p119-acceptance.json).
This accepts the functional criterion, not a complete release or clean-machine
installation. No local executable verification ran under the BSOD hold.
