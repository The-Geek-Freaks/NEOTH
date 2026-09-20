# W123 — observed test-fixture compile repair

Full CI `35541897416` on source `927f6894908aa96305219a5fe6a2a6e576fc77cc`
reported `E0308` in the W118 CLI inventory regression. Its call supplied
three-element account tuples, while the existing fixture helper accepts
`(&str, u64)` pairs. The correction uses that actual helper contract and retains
the paired enabled/disabled policy and secret-free projection assertions.

The diagnostic was captured from completed SSH-feature job `106161002823`.
Its feature compilation passed before test compilation failed. Nine component
jobs succeeded, including the CUDA job whose unsupported-runner compile step was
skipped; that result is not CUDA compilation evidence. The known-uncompilable
full run was cancelled and read back as completed/cancelled. Linux, Windows and
macOS native tests from that run are not passes. Earlier run `35538895227` was
also read back as cancelled.

Windows preview `35541731629` remains useful for the older `927f6894` product
source because this failure is in a test-only configuration. Its artifact and
acceptance results cannot validate later W121 product changes.

The repair requires fresh remote test compilation and runtime execution. No
local compilation, parser, formatter or tests ran. Source review and the exact
source/test bindings are recorded with the combined W121–W123 batch. Roadmap
counts remain 1324 total / 1015 checked / 307 open / 2 partial.
