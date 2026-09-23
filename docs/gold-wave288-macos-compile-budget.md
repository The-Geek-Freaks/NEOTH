# W288 macOS hosted compilation budget

FullCI run `35814256249`, attempt 1, source
`ce0ecba215e40a2233a08f178bb60223ab1901bc`, stopped macOS job `107032289482`
at its configured compilation timeout:

```text
The action 'Compile nextest workspace test binaries' has timed out after 100 minutes.
```

The final observability sample still showed an active compiler. The terminal log
contains no Rust compiler error. This proves a time-budget failure; it does not
prove compilation would eventually succeed with any particular larger budget.

The macOS matrix keeps one Cargo build job and a separate 30-minute test window.
Its compile allowance changes from 100 to 150 minutes, and the overall job from
140 to 190 minutes, preserving the existing ten-minute setup margin. Rust source,
test selection and Windows/Linux budgets are unchanged by W288.

Evidence is retained under
`work/gold-20260906/wave288-macos-compile-diagnosis/`. A fresh hosted macOS result
is required before any build or test acceptance. No local compilation or test
execution occurred.
