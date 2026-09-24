# Offline decision rubric and focused Gold acceptance

`neoth eval` now supports explicitly labelled offline decisions with different
costs for false alarms and missed violations. It uses supplied labels and a
deterministic verifier; it does not guess ground truth from response wording or
change live council ranking.

Set the error multipliers in an operator configuration:

```yaml
council:
  offline_rubric:
    false_alarm_multiplier: 1.0
    missed_violation_multiplier: 7.0
```

Both defaults are `1.0`. Values must be finite and within `0.0..=1000.0`.
The labelled suite explicitly selects this file:

```text
neoth eval decisions.json --rubric-config freedom.yaml --json
```

Each labelled case has exactly one verifier (`expect_contains` or
`verify_command`) and `rubric_labels` with `expected` and `observed`, each
`clear` or `violation`. The verifier convention is explicit: passing observes
`clear`; failing observes `violation`. Its result must match the supplied
`observed` label. A verifier error is an unclassified error.

The final evaluation compares that observation with `expected`. Correctly
detecting a violation passes. Missing an expected violation fails, as does a
false alarm. A zero multiplier changes cost only and cannot make a wrong
decision pass. For example, this single case is a missed violation and fails
with seven weighted error units:

```json
[
  {
    "id": "missed-violation",
    "description": "Detector cleared an operator-labelled violation",
    "prompt": "Recorded offline decision",
    "answer": "clear",
    "expect_contains": "clear",
    "rubric_labels": { "expected": "violation", "observed": "clear" }
  }
]
```

JSON and Markdown include the evaluated decision count, each error-class
count, effective multipliers, total weighted error units and unclassified
errors. These units are dimensionless, not inference charges. Setup errors,
contradictory observations and step-cap skips contribute no invented class or
cost. Missing rubric configuration and ambiguous labelled verifiers fail
before the verifier can run. Unlabelled suites retain their existing behavior
and do not load a rubric configuration.

The new implementation and regression cases passed independent source review.
Hosted compile, CLI export and behavior checks remain pending for this change;
the documentation example is not a claim of local execution.

The preceding Group1171 run `35988891507` at `ddb5cd16` was independently
verified: all 1,171 selected tests passed, with 221 fixture-source hashes and
two input bindings. That evidence closes the original F1/F2/F3 media sampling,
deduplication and fallback criteria, D3 prompt-tax attribution, and B2's
consumed seven-section review prompt. B1/B4 Windows checks and D2's selected
GUI checks remain tracked separately. The earlier catalogue-stdin failure is
resolved by redirecting the exact test subprocesses to `/dev/null`.

The next Group1204 selection adds existing WorkerContract, all-fourteen Fabric
bundle/router, and training-export tests, plus the new rubric and its legacy
evaluation regressions. Existing implementations are not represented as new
product features. The separate C9 field-name documentation uses the pinned
upstream specification and does not alter stored WAL fields; see
[the audit crosswalk](specs/audit-compliance-alignment.md).

No local compiler, formatter, test or product runtime was started.
