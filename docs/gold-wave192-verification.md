# W192 bundled Skill resource materialization

`drawio_diagram` now embeds its complete 11-file sibling package: manifest,
six Python scripts, three data files, and the built-in style. The authority
admitted runtime loader materializes these bytes only under the current
`NEOTH_HOME/bundled-skill-resources/drawio_diagram/<sha256>/` cache. The cache
is content-addressed, bounded to 16 files and 2 MiB, verifies every existing
file byte-for-byte, rejects link-like paths and path escapes, and never writes
under the operator-controlled `skills/` install namespace.

Only runtime loading materializes this cache. Read-only inventory creates no
cache and omits resource-dependent Drawio rather than advertising a synthetic
path whose siblings do not exist. Runtime materialization retains Drawio's
synthetic `<bundled>` `Skill.path`; the verified cache root is sealed,
non-serialized runtime metadata rendered only with the selected Skill prompt.
The immutable bundled content hash is computed from bundled bytes only, so a
per-home cache path cannot change pin or replay identity. The Skill remains
`RuntimeSkill::from_trusted_bundled`; materialization creates no installed
override or new execution authority.

The package supplies files only. Python, Graphviz/draw.io, and network/runtime
availability remain separate prerequisites and are not certified by this batch.
Source regressions `w192_runtime_bundled_drawio_has_verified_materialized_siblings`
`w192_corrupt_materialized_cache_is_refused_without_overwrite`, and
`w192_symlinked_resource_cache_namespace_is_refused` cover the real
runtime loader/materializer path and fail-closed cache reuse. The regression
set also covers stable hashes across two homes, the actual read-only loader's
no-write behavior, and the actual runtime loader's retained bundled
provenance/resource metadata. An interrupted matching UUID stage is retained
as evidence and blocks further materialization for that digest; it is never
reused, overwritten, or cleaned by this path, bounding crash residue to one
package until operator inspection.
The focused source suite also forces simultaneous pre-publication writers and
checks that every caller reuses the same final package with no losing-stage
residue.
Materialization is serialized by a private capability-bound per-package lock;
waiters retry for at most five seconds and revalidate the lock binding before
returning. Existing interrupted stages still fail closed for operator recovery.
No local Rust, formatter, parser, test, fixture, product, GUI, or audio command
ran under the BSOD hold. Hosted compile and focused fresh/tamper/symlink loader
tests remain required before admission.
