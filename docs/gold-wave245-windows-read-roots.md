# W245 — Retain Windows share roots for descriptor-bound reads

W239's component-wise no-follow reader initially recognized only Disk and
VerbatimDisk roots. Ordinary allowlisted reads previously also accepted UNC
shares, so that narrowing would reject valid existing operator configurations.
The root extractor now retains the exact Disk, VerbatimDisk, UNC or VerbatimUNC
prefix plus its root component. It never converts a share into a local drive,
normalizes away the verbatim namespace, or uses a device/pipe namespace.
Relative and drive-relative paths remain invalid. Each descendant directory and
the final file still pass the existing no-follow and reparse checks.

The Windows-only case
`os_tools::gate::tests::read_capability_root_preserves_windows_drive_and_share_namespaces`
checks four supported spellings and three refusals. This is a path-contract
fixture; it is not proof of a live SMB server or network-share mount. The existing
Windows canonical-drive descriptor/read fixture remains separately required.

Local verification is bounded source/Git only because the BSOD hold is active.
Native Windows Hosted execution remains pending; no local process or share was
opened to validate this change.
