# W87 - macOS compile concurrency from measured runner pressure

In [CI 35070262418](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35070262418),
macOS job `104710011774` reached its 100-minute compile deadline at 09:28:46 UTC.
The completed job log records that timeout and a successful interrupted-cache
save at 09:30:32 UTC. Its test-execution step did not run, so this is no macOS
test verdict.

The per-minute observer recorded peak swap use of 6,164.12 MiB out of 7,168 MiB,
with sustained paging and active compiler processes near the deadline. These
observations support a narrower concurrency experiment. They do not establish
an OOM termination or a Rust compiler diagnostic. Dev/test debug information was
already disabled; adding that setting again would not address a missing option.

W87 changes only macOS Cargo build concurrency from two to one, with its matching
contract expectation and build-cadence explanation. Four test threads, the
100/30/140-minute compile/execution/job bounds, Rust 1.91, locked full workspace
test selection, debug settings and observability remain intact. Existing complete
and interrupted cache namespaces are preserved so the just-saved compatible
objects remain available. Cargo still checks freshness and must finish every
required binary; cache recovery itself is not acceptance.

The [source manifest](verification/gold-wave87-source-manifest.json) binds the
same 290 inputs. The [test matrix](verification/gold-wave87-test-matrix.json)
retains the 48 native and 6 GUI identities covering W79-W85. Rust product sources
are unchanged from the W85 commit. The next full CI must supply their current
runtime proof, including macOS compilation and actual test execution.

Portable preview `35080018852` independently builds the earlier `c736c376`
snapshot, which has the same Rust product sources and the W86 preview settings.
It remains separate from full CI and installed/release acceptance. ROAD and
PROGRESS retain their checkbox states: 1324 total / 1015 checked / 307 open /
2 partial, raw309 / pre-tag308. No local compiler or linker ran.
