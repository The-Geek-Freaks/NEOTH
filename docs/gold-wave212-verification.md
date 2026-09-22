# Wave 212 embedding generation isolation

W212 binds every episode embedding to one concrete local model generation.
Selecting another embedding model requeues eligible historical episodes; an
unavailable new model cannot expose old vectors as current results. Historical
vectors remain durable until replacement or the existing consent/forget path.

The additive v44 migration labels historical rows `legacy-unknown-v0`; it never
infers provenance from a model label or dimension. BGE generations bind the
immutable repository revision, dimension and pooling algorithm. Qwen binds the
actual config, tokenizer and weights digests before and after load, and rejects
changed disk inputs behind a warm model. Ouro binds its verified load receipt,
dimension and quantization mode.

A sealed local provider retains its exact config path and selection. Claims,
writes, episode recall, index rebuild and consolidation use the same config
authority lock as `FreedomConfig::update_at`, before any SQLite transaction.
Embedding inference happens outside those locks; a late result rechecks current
selection before committing. A stale capability cannot reactivate its model.
Wrong response models, dimensions and non-finite vectors are rejected.

SQLite and HNSW scopes separate episodes from media and bind model, generation
and dimension. Media queries use the production CLIP repository identity and
preserve their optional source-kind filter. A media scope cannot request
episodes. Legacy, mismatched or internally inconsistent snapshots fall back to
scoped SQLite. Forget invalidates a retained snapshot before rebuilding it.
Consolidation accepts only one current generation and rejects invalid dot inputs.

The daemon refreshes its provider after accepted config changes, retries an
unavailable provider after a bounded 30-second backoff and processes at most
64 pending episodes per tail pass even without new WAL frames. Backfill, chat,
consolidation and model probing retain the exact accepted config path.

## Verification boundary

Hosted run `35767413693` on `02a10972` executed all 236 selected cases:
232 passed, four failed normally. All 17 new W212 tests passed. All 47 source
paths, identities, matrix and lock matched the run. Core test type-check and
public CLI build `35767417912` passed; its source/SHA-bound generated CLI
reference matches the checked-in file. Preflight `35767604603` passed after
the exact Hosted formatting import at `9ea97d56`.

The four failures exposed outdated fixture assumptions. The explicit 42-to-43
migration remains tested, while the later normal open now expects the current
schema. Forget proves the surviving media row remains in the rebuilt snapshot
and neither forgotten vector remains. The two kind-filter regressions now
build a broader media snapshot, preserving their proof that a mismatched query
uses SQLite; a matching scoped snapshot is correctly allowed. Those corrections
require a fresh Hosted run and do not weaken the original data-bound assertions.

Seventeen new regressions cover generation sealing, actual artifact digests,
additive migration, requeue, config-switch fencing, invalid responses, media
separation, legacy/malformed snapshot rejection, scheduling and consolidation.
Fourteen existing HNSW/forget regressions join the targeted hosted lane; their
fixtures now use the production media identity and the generation-aware episode
writer. The original consent revoke test retains its deeper SQLite fallback
assertion after filtering a revoked stale HNSW hit.

The inventory contains 526 source paths, 783 universal native identities and
92 GUI identities, with unchanged platform extras, 19 audio identities and
24 macOS custom harness identities. The grouped lane selects 236 exact cases;
the two official BGE model tests remain separate. Static review and whitespace
checks do not replace the pending hosted build and behavior results.

W211 Grouped205 run `35763682082` on `54c57b192f6c53c02ec540680752160cb5dc9b9b`
is admitted: 205 actual executions passed, with all 46 source paths, exact test
identities, matrix and Cargo.lock matched to that commit. Core/CLI also passed.
Full CI `35765595152` on `c4176c54` passed formatting and several feature lanes;
Linux slim Clippy reported 33 diagnostics, under separate narrow repair. Other
native jobs were still running when this batch was prepared.

GOLD-LF-P2-24 and release gates remain open. Road counts remain 1324 total,
1015 checked, 307 open and 2 partial. No local compiler, Cargo, formatter,
code/model parser, tests, fixtures, product/GUI/audio probes or model downloads
ran under the workstation BSOD hold.
