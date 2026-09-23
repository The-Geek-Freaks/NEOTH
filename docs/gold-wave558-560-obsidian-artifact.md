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

## Hosted artifact admission and W562 reference

Run35935325488 at77d914b7 passed typecheck, bundle build and3/3contract tests.
Root verified six source identities, three artifact ZIP hashes, seven zero exit
receipts, three actual TAP terminals, and manifest/lock/bundle hashes before
import. The permanent receipt is verification/gold-wave558-obsidian-artifact.json.
Generated main.js SHA256:8ee567873369753ca47608765ff1c694a5cce6efff14dfabe4ad29a088e78e89.
Generated lock SHA256:81e476084a0376c8f298e0d5a28bab2bea90eebccee5e99cd5ed7cb6bbcb6bcd.

Core35934260205 atce7394ba passed slimClippy, core test-target check and CLI
build/export. Artifact10783021689 ZIP SHA256
ca1f9eb7eaaaca43d3e88cf1d90ea65e5c604a01bb4d5529c5c1303622e4c74d
contains reference20f8b75b1a14adbf026b81fec8f43d0e5ac4104a0cf9b2a05cd6faee953d091f,
now imported with paperless prepare. The entire published neoth source tree,
Cargo manifest and lock are unchanged through77d914b7, so scoped CLI carry is
verified. Native lifecycle edits in the working tree were excluded from this
publication and need their own updated export after completion.
