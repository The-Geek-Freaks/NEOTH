# W568 / W570 / W572 — recursive Paperless provenance and staging contract

The acquisition lane now streams every config and compressed layer referenced
by the selected amd64/arm64 manifests. Each stream must match the exact manifest
size and SHA-256. Bytes are hashed and discarded; nothing is extracted, stored
as an image, installed or run. Dedupe stays within registry/repository/digest.

Bounds:1MiB configs,512MiB layers,96 distinct blobs,2GiB total,300 HTTP requests,
at most2 redirects per blob,30-second socket timeout and30-minute monotonic
acquisition deadline checked before and after every read. The hosted job has a
40-minute deadline and1200-second CPU bound. Token/manifest redirects remain
disallowed; blob redirects use the explicit HTTPS CDN set and drop credentials.
A rejected CDN diagnostic contains at most its canonical hostname, never a
signed URL, query, path or token. The receipt binds head/script/workflow/tests/
docs hashes and records verified bytes; artifact_verified remains false.

Source review found and fixed the canonical descriptor boundary, redirect-aware
request budget and late-EOF deadline.13 focused Python cases include the actual
selector/index/child/config/layer path, equal-size corrupt bytes, short/long
streams, limits, dedupe, stripped credentials and deadline/redirect rejection.
Independent review approved. Initial run35938744354 at6fe578b4 passed its then-
selected contract tests, but acquisition rejected an unknown CDN. It provides
no accepted recursive blob receipt; the diagnostic/final-fixture rerun is pending.

The W570 staging view exposes the exact metadata contract identity and current
coverage. The ownership marker moves to schema2, binding the admitted receipt
and coverage while Compose keeps its immutable three index pins. An older or
mismatched preparation is refused without touching operator environment/state.
Independent Rust review approved; two additional native cases join Group951.
Native selection is1228 plus Windows25/Linux40/macOS39; GUI remains148Linux.
These source changes do not complete P2-20 install/update/rollback/readiness.

W572 admitted core35938019476 atc21e29b1: slimClippy, all core test targets,
public CLI build and export passed. The exact SHA-bound reference now includes
Obsidian bridge commands. W570 postdates that compile source. Group951 must
supply its new behavior and the W559/W566 behavior evidence. No local executable
validation, formatter, image download or container execution occurred.
