# W430 — source-bound hosted formatting import

Preflight run `35876157640` on `d0833c063db2845dd442bd8121bc7439cb02e9dc`
reported only rustfmt differences in the two W422 audit-RPC input-bundle files.
Root verified `source-head.txt`, every artifact SHA-256, both full before Git
blob IDs against the committed source and worktree, and both after blob IDs.
The exact hosted patch was applied to `cli/serve.rs` and `cli/serve_tasks.rs`.
No local formatter ran; no behavioral source changed. The active W428 core/
workspace-Clippy job may carry through this formatting-only delta. A new hosted
preflight remains required for the published source.
