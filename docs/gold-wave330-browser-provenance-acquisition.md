# Gold Wave 330 - hosted CFT provenance acquisition

W330 adds a manual, main-only Linux hosted workflow for the W325 Chrome for
Testing headless-shell pin: version `154.0.8037.57`, revision `1689415`, and
only `win64`, `linux64`, `mac-x64`, and `mac-arm64`. A lightweight official
Known Good Versions read confirmed the exact version, revision, and official
URLs before this workflow was written.

The hosted job reads bounded official metadata, rejects redirects and any URL
outside the exact `storage.googleapis.com/chrome-for-testing-public` paths,
then downloads the four archives serially with a 512 MiB per-archive cap. It
does not unpack or execute them. It validates ZIP member paths, duplicates,
symlinks, member-count, per-member and aggregate size limits; hashes the archive and the one
expected headless-shell executable by streaming that ZIP member. It records
the bounded ZIP inventory plus every LICENSE/NOTICE/COPYRIGHT candidate's
full streamed SHA-256 and metadata. Bounded text is retained until the shared
budget is exhausted; later or larger notice text is explicitly marked omitted
or truncated. Receipt JSON files also have an 8 MiB cap.

The uploaded receipt contains only `cft-provenance.json`, bounded notices,
`SHA256SUMS`, and the checked-out source head. Browser archives, executables,
and unpacked members are removed on the runner and are never uploaded.
The provenance JSON also records UTC acquisition start/completion plus the
GitHub server, repository, run ID, run attempt and SHA; it rejects a GitHub
SHA that differs from the checked-out source head.

This records observed official TLS artifacts and their SHA-256 values. It is
not a vendor-signature verification, a runtime acceptance test, an installer,
or a managed-browser parent acceptance result. It supplies the provenance
prerequisite for later review of an explicit install manifest. It does not
claim complete notice text capture or licensing acceptance.
