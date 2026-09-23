# Gold Wave 304: retention v2 fixture authority

The retention v2 fixtures settle real Daily archive, admission-state, and
optional Obsidian-note effects before exercising retention recovery.  Daily
settlement now acquires the same capability-bound admission gate as production,
which rejects an ambient `TempDir` home on platforms where it is not a private
authority.

The fixture roots therefore use the canonical test root and create one private
child home with platform-native authority: mode `0700` on Unix and the native
private-directory constructor on Windows.  Both the NEOTH home and the
Obsidian vault use this fixture so the test continues through the real gate,
archive transaction, and note authority.

No production gate, retention policy, or acceptance assertion was relaxed.
Wave 304 only replaces invalid fixture authority for the existing retention v2
cases, including the bounded bulk settlement fixture.

Local Cargo, compiler, formatter, parser, and test commands were not run under
the active BSOD hold.
