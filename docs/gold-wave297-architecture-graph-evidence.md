# W297 — architecture import and type evidence

The architecture skill now consumes at most one persisted import witness and
one persisted direct type-hierarchy witness beside its existing CallGraph cycle
scan. The consumer accepts them only when index, call graph, import graph, and
type hierarchy share one positive complete root generation. It reads the root
fence and all persisted graph evidence in one SQLite read snapshot, then repeats
the existing freshness and generation checks before prompt injection.

The rendered Block-D context is deterministic, sanitizer-filtered, and reports
separate cycle and evidence truncation states. An import/type cap never claims a
partial relation is complete or that call cycles were omitted. Other skills still
receive no architecture recall.

This changes only the private prompt consumer; it does not publish or redesign
Graphify artifacts.
