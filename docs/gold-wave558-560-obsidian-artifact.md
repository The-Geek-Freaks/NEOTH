# W558/W560: pinned Obsidian plugin artifact source

The package at SRC/neothd/assets/obsidian_archive_bridge defines an actual
Obsidian Plugin entry and manifest for neoth-archive-bridge version0.1.0.
It visibly reports not-paired/sync-disabled and provides a read-only count of
notes under the existing CLI default NEOTH-sessions/. It does not treat every
Daily note as NEOTH-owned, mutate notes, register watchers or contact a service.
Pairing and synchronization still require a live native owner and remain open.

The dedicated main-only hosted workflow pins Node22.14.0, Obsidian SDK1.8.7,
TypeScript5.8.3 and esbuild0.25.10. On the initial build it generates the dependency
lock remotely, then uses npm ci, typechecks, bundles and runs three contract tests
including instantiation of the built export against a bounded fake Obsidian API.
Future builds keep the imported lock and verify the tracked bundle for drift.
This contract is not an actual Obsidian application acceptance test.

Every stage retains its actual log and numeric exit, with125denoting not-run.
Source provenance includes the workflow. Generated bundle, manifest, lock and
checksums are uploaded separately from source and logs. Root will verify hashes
and source identity before importing generated files. No local build, Node or
parser was used, and no generated artifact is hand-authored. Native installation
will ship in the next separately reviewed batch once those artifacts exist.

Independent review found a source-test capitalization mismatch; the assertion
now uses the actual NEOTH-sessions/ default. The workflow's receipt directory is
initialized from RUNNER_TEMP at runtime, avoiding the prior invalid job context.

W560 imports the exact GUI format patch from run35935063648/source829c37c3,
artifact10782528643, ZIP SHA256
b5b060d15fe198ec973ea077fdb26939eb485489cbc2339e5c138a7a5aa827af.
Root checked contained hashes and full before/after Git blobs. No local formatter.

P2-21 and the full Road remain open at1044checked/278open/2partial; WS-LF37/81.
Native1215, Group934+GChat4, GUI148Linux/144macOS are unchanged. A source package,
mocked plugin test or installer status cannot by itself close pairing, sync,
offline or clean-machine Obsidian acceptance.
