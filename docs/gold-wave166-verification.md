# W166 — pinned OpenClaw channel inventory

Status: integrated source independently approved. GOLD-LF-001-01 remains open
until GitHub-hosted contract tests pass. This document does not
establish adapter availability, schema-leaf completeness or migration acceptance.

The primary ledger is `plans/001-openclaw-channel-migration-parity.md`. It pins
OpenClaw commit `4c667aac8859114bd8f0a589ac6cd1de8bfe1474` and records 31 rows:
29 public surfaces, the official ClickClack channel omitted from the public
index, and the synthetic QA-only channel. The established importer inventory
contains 26 manifest-backed keys: 24 public channels plus ClickClack and QA.
Voice Call, WebChat, WeChat, Yuanbao and Zalo ClawBot account for the five
additional public surfaces. Missing adapters remain separate implementation work.

The compiled inventory belongs inside the separately publishable custody crate.
It must retain the pinned upstream paths, byte lengths and hashes, exact row
order, closed roles and dispositions, aliases, and the 26-key importer relation.
Planned adoption targets must remain distinct from current importer mappings
and the production registry. QA cannot acquire a production target. External
plugin references remain quarantined until their own source and release gates.

The import inspection and document-loading entry points validate the bundled
contract before interpreting an operator's configuration. An inconsistent local
contract must not silently reclassify an unsupported channel as supported.
The custody package alone owns the inventory and upstream evidence witness.
The integration contract consumes its public read-only APIs; there is no
cross-package file include or dependency on work-directory evidence. The
obsolete Migrate mirror is removed and its relocation is documented.

Seven custody regressions exercise the bundled contract, ClickClack and QA
classification, current importer/registry claims, manifest drift, alias
collisions and evidence hash/source commit rejection. One integration contract
binds all 31 rows to the upstream witness, actual importer aliases and production
registry. Full source-schema extraction is
GOLD-LF-001-02 and remains separate. Runtime adapter and migration release tests
remain separate as well. No local compiler, formatter, fixture or test runs are
permitted under the workstation stability constraint.

The historical independent review retains its original CRLF hashes. A separate
LF-DIGEST-REBINDING.json receipt records the six LF normalizations and the two
updated bundled JSON digest constants. No behavioral edit is concealed by that
receipt. The canonical source manifest and test matrix bind the published bytes.

Admission contains 374 source inputs and 386 universal native test identities;
the existing three Windows-only, four Unix-only, 71 universal GUI, 15 Linux/macOS
component and seven optional adapter identities remain. The macOS custom
catalog remains at 20 names until W167/W168 are separately admitted. Hosted
JUnit must confirm the new custody and integration suite identities.
