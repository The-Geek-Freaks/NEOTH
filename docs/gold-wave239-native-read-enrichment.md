# W239 native `fs read` enrichment

W239 adds one deliberately narrow direct-operator vertical: `neoth fs read
<path> --codegraph-enrichment --repository-root <absolute-root>`.  It does not
create a provider-native tool, modify MCP catalogue/configuration authority, or
implement CRG-05's Grep, Glob, or Bash labels.  Parent CRG-05 therefore remains
open.

The ordinary `neoth fs read <path>` path keeps the existing `read_os_file`
compatibility wrapper and byte-for-byte JSON shape.  The new flag pair is
rejected before file admission unless both are supplied and the root spelling is
absolute.  It also requires the existing default-off
`code_map.outline_enrichment` master switch; the command flag alone cannot add a
sidecar.

For the opt-in path, execution order is fixed:

1. existing OS allowlist and autonomy admission emits its normal audit decision;
2. a single `PreToolUseContext` with origin `DirectCliOsFileRead` is admitted and
   the configured bounded PreToolUse hook set runs;
3. only a continuing hook result consumes the opaque OS admission and runs the
   existing same-fd, size-capped UTF-8 reader;
4. after a successful file read, an eligible code-map sidecar is freshness
   checked again and then appended as bounded untrusted supplemental output.

Allowlist/autonomy denial performs no target-file descriptor acquisition. The
opt-in admission resolves every parent through no-follow directory handles and
opens the final file without following symlinks or Windows reparse points before
holding that unopened-for-content descriptor across PreToolUse. Typed-hook
block, cancellation, or deadline expiry drops it without consuming file bytes
or invoking the reader. The split in `os_tools::gate` preserves the old wrapper
while preventing the new route from accepting a replacement target between
preflight and invocation.

The sidecar is only eligible when the operator's local generated
`neoth-codegraph` descriptor is exact, the requested root is canonical and
contained, the target is one current indexed regular file, and the matching
snapshot is complete and fresh.  It renders `native_origin:
direct_cli_os_file_read`; it never calls itself a provider or MCP result.  A
changed root after the file read suppresses the sidecar and preserves the
original file content.

Focused source fixtures added for hosted execution:

- `os_tools::gate::tests::read_preflight_binds_descriptor_then_invoke_enforces_same_fd_budget`
  proves the opaque split and post-admission byte budget.
- `os_tools::gate::tests::admitted_read_consumes_original_descriptor_after_path_replaced`
  is Unix-only and proves a post-admission pathname replacement cannot change
  the file whose bytes are consumed.
- `os_tools::gate::tests::preflight_refuses_final_symlink_swap_before_descriptor_open`
  is Unix-only and proves a final-component swap to an outside symlink is
  rejected before any file content is consumed.
- `os_tools::gate::tests::preflight_refuses_parent_symlink_swap_before_descriptor_open`
  is Unix-only and proves the same refusal when an ancestor is replaced before
  the target descriptor is opened.
- `os_tools::gate::tests::preflight_reads_canonicalized_windows_drive_path`
  is Windows-only and proves the canonicalized verbatim drive namespace reaches
  the no-follow descriptor path.
- `cli::fs::tests::w239_real_fs_caller_keeps_default_master_off_output_unenriched`
  proves the real caller retains file output with the master switch off.
- `cli::fs::tests::w239_real_fs_caller_appends_native_sidecar_only_for_fresh_indexed_target`
  runs the real direct caller against a generated local descriptor and a fresh
  indexed target.
- `cli::fs::tests::w239_real_fs_caller_denial_stops_before_typed_native_read`
  proves an OS allowlist refusal does not progress to native read admission.
- `cli::fs::tests::w239_real_fs_caller_cancellation_stops_before_native_read`
  proves cancellation stops the direct route before invocation.
- `cli::fs::tests::w239_real_fs_caller_zero_deadline_drops_admission_without_consuming_bytes`
  proves an elapsed typed deadline drops the held descriptor without consuming
  its bytes.
- `mcp::codegraph_server::tests::w239_native_fs_read_plan_uses_real_descriptor_and_drops_stale_sidecar`
  uses a real generated descriptor/indexed root and proves the post-read stale
  recheck omits the sidecar.

The source fixtures include Unix-specific namespace-swap regressions and a
Windows-specific canonical-drive regression; the shared implementation rejects
Windows reparse points. They were not executed locally under the active Windows
BSOD hold; GitHub-hosted selected native and core gates are the required next
evidence.
