# W157 - hosted strict-lint expectation repair

GitHub CI 35604563909 tested source ff146652e6ef230bd500206978f183e5040644d6.
Linux quality job 106348405427 passed workspace formatting and slim-core
Clippy, then full-workspace Clippy rejected an unfulfilled `dead_code`
expectation at `SRC/neothd/tests/gui_channel_status.rs:12`.

The repair removes only that obsolete expectation. The production `gui_action`
module remains imported through the same path; no test, assertion, production
behavior or warning policy is weakened. The separate parser-specific
`clippy::len_without_is_empty` expectation remains unchanged.

Complete hosted job log SHA-256:
`73F76CD26F7082679F5BEFDBC583D58239F25215BB59D944E6B8E6FC1C004B0D`.

The independent review and exact staged-source receipt are retained under
`work/gold-20260906/wave157-hosted-quality/`. All executable validation remains
GitHub-hosted. Fresh strict Clippy and native tests are required; this source
repair closes no Road checkbox. Concurrent W153 implementation is excluded
from this commit and from the running ff146652 native and preview jobs.
