# GOLD W299 — receipt-bound Graphify CodeGraph witness

## Delivered contract

A newly published Graphify generation now contains the ordered closed artifact
set `GRAPH_REPORT.md`, `GRAPH_TREE.html`, and `CODEGRAPH_WITNESS.json`.
`CODEGRAPH_WITNESS.json` is generated from the same
`ScopedRebuildSnapshot` that authorizes publication; it is not copied from
Graphify output and is never reconstructed from an ambient database during
wiki ingest.

The witness records the canonical repository identity, source fingerprint, and
the equal positive index, CallGraph, ImportGraph, and TypeHierarchy
generations. `CURRENT` repeats and is checked against all four generation
values before its receipt can be used. It contains bounded, ordered
ImportGraph edges, TypeHierarchy declarations/edges, bounded persisted
CallGraph edges, and one fixed
non-user-controlled forward-BFS projection. The projection declares its
`callees` direction, depth (2), result ceiling (64), text ceiling (16 KiB),
deterministic seed, and rows. An over-budget graph or BFS refuses preparation;
therefore the old `CURRENT` pointer remains visible.

Both publisher and wiki ingest hash the witness as a named receipt artifact.
They parse a closed schema, reject non-canonical JSON, re-check root,
fingerprint, all four generations, canonical import/type content, fixed BFS
parameters, and re-derived BFS rows. Wiki pointers identify whether the
CodeGraph witness is present and include its import/type generation binding.

## Compatibility and migration

`GraphifyGenerationReceipt` and `CURRENT` deserialize absent
`native_import_generation` and `native_type_generation` as zero. A complete
legacy `REPORT+TREE` receipt with both values zero remains valid, readable, and
ingestable; its historical generation ID is preserved. A receipt with positive
import/type values must carry the three-artifact W299 manifest. Thus existing
visible generations are not invalidated, while no new publication can advance
`CURRENT` without the witness.

## Focused source fixtures

- `graphify_publish::tests::publication_seals_scoped_codegraph_witness_with_fixed_bfs_provenance`
  builds a real scoped snapshot over Rust calls and type declarations plus a
  Python import/type fixture, publishes it, validates the persisted witness,
  and checks the sealed BFS projection.
- Existing `wiki::ingest` graphify fixtures retain the pre-W299 two-artifact
  receipt path and consequently exercise the compatibility branch. New
  current-generation receipts are rejected before scope replacement when the
  witness is missing, swapped, oversized, malformed, or provenance-mismatched.
- Existing bounded import/type persistence and MCP fixtures remain the direct
  seams for cross-language, type-cycle, stale-generation, and bounded-query
  behavior. W299 consumes those persisted authorities rather than duplicating
  their graph algorithms.

## Validation boundary

No local Cargo, compiler, Rust parser, formatter, test, runtime, or model
operation was run under the active BSOD hold. `git diff --check` is the only
local verification planned for this source/documentation change. Hosted build
and the focused Rust fixtures remain required before acceptance.
