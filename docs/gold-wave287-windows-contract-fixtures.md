# W287 Windows contract-fixture repair

FullCI run `35814256249`, Windows job `107032289409`, executed run head `ce0ecba215e40a2233a08f178bb60223ab1901bc` and failed three test assertions after nextest compilation succeeded.

## Doctor count fixture

The runtime count was `64` while `check_docs_listed_count_matches_runtime_contract` pinned `63`. Git blame identifies `af0e056f` (`feat: diagnose authenticated context import control-plane status`) as the addition of `checks::context_import::DOCS` to `DOMAIN_DOCS`. Its one documented `context import control-plane` entry is intentional and brings the enumerated source total to 64. The test pin and its ledger comment now record that entry.

## Native grep hook fixture

`PreToolUseArguments::from_json` serializes the argument object with `serde_json::to_string`. Windows path separators are escaped in that JSON summary. The old test looked for the unescaped `canonicalize().to_string_lossy()` path, which cannot occur as a raw substring when the separator is serialized as `\\`.

The test now derives the exact JSON-string fragment from the canonical admitted-file and repository-root path, checks both fragments, and prints the expected fragment plus actual summary when either assertion fails. This keeps the assertions tied to the retained canonical admission and bounded JSON summary; it does not remove either path check.

## Connector-control source contract

The durable-order source contract still requires `runtime.reserve_apply_outcome(apply_key)` before the capability-bound plan read. The implementation uses `runtime.plan_import_with_preview(Path::new(&request.relative_path))`, whereas the old textual fixture searched for the pre-preview API `plan_import`. The fixture now names the preview API and retains its reserve-before-read, recovery-query-before-removal, removal-before-commit, receipt-replay, and outcome-response checks.

No executable, parser, compiler, formatter, test, Cargo command, Git mutation, workflow operation, or CI rerun was performed for W287.
