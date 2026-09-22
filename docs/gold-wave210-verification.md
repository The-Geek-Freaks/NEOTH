# Wave 210 explicit local BGE-M3 embedding core and CLI

W210 adds `embed.model: qwen3_q8 | bge_m3`. The default preserves the existing
Qwen/Ouro route. Explicit BGE-M3 is local-only: missing or corrupt artifacts,
an incompatible generic embedding provider, or a failed native model load
produce an unavailable result without selecting Qwen or a cloud provider.
Instance-scoped chat and daemon consumers resolve the cache in their own home.

The official source is `BAAI/bge-m3` at immutable revision
`5617a9f61b028005a4858fdac845db406aefb181`. The manifest binds ten artifacts
to exact byte lengths and SHA-256, including the official 2,271,145,830-byte
`pytorch_model.bin`. Candle 0.8.4 reads that checkpoint natively. There is no
Python runtime or substituted community checkpoint in the product. The model
uses XLM-R, CLS pooling, 1,024 dimensions and finite L2-normalized output.

`neoth models bge-m3 list|status|pull|repair|prune` extends the existing model
lifecycle. Artifact selection is fixed; repository/revision overrides are
rejected. Pull and repair use the existing durable D7/D8 download lifecycle,
verify the pinned bytes and validate native loading before completion. Status
is a cheap structural cache snapshot and labels cached artifacts separately
from runtime readiness. Full hashing and tensor work use blocking workers.

Focused source regressions cover configuration, routing, the official JSON
array artifact, missing/truncated artifacts, download authority, output
invariants, CLI selection and failed load completion. The dedicated manual
GitHub workflow acquires the model through the product CLI and runs the exact
ignored official-model test. It uploads source-bound receipts and logs only;
model weights stay on the hosted runner.

Independent integrated static review passed after repairing readiness, blocking
work, terminal replay and tokenization boundaries. Hosted compile, focused
behavior and official-model execution remain pending. GUI/Buddy lifecycle
parity is the following W211 batch. `GOLD-LF-P2-24` remains open; this source
slice does not establish full native-platform or release acceptance. The
workstation remains under the absolute local BSOD hold, with no local compiler,
Cargo, formatter, code/model parser, tests or product/runtime execution.
