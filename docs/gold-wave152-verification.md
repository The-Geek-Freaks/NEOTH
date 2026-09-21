# W152 - hosted Windows regression repair

GitHub CI 35591362095 built the Windows test binaries from
cee40a6c61e9b140aafb836583e0ace663114e53. Job 106306340140 then ran
11,237 of 16,882 tests: 11,217 passed (one reported leaky), 20 failed,
22 skipped. The configured fail-fast threshold ended the run; the remaining
tests did not execute. This is failed integration evidence, not a Windows pass.

The repairs preserve the actual contracts:

- Nine retained Skill-cap regressions shared a test-only factory with an invalid
  bundled-source path marker. The fixture now uses the required bundled marker;
  the product admission guard and all effect/audit assertions remain.
- The global-tightening regression now creates an explicit current global Deny.
  Strict mode correctly means Confirm for arbitrary execution and could not
  satisfy this fixture's intended Deny assertion.
- Codegraph registration expects its current twelve-tool inventory. The import
  generation fixture uses actual files in its published root. The two stdio
  generation requests explicitly select depth 2, matching their accepted policy;
  the omitted request field had defaulted to 5 and was correctly rejected.
- Python class-header parsing discards inline comment tails, including bounded
  multiline headers. The Rust local-item fixture expects function-local impls
  to remain outside the file hierarchy and retains declaration/duplicate checks.
- The strict provider-callsite inventory classifies the unchanged IRC
  Client::stream call as protocol input. W128 changed adjacent registration
  state, which changes this deliberately context-sensitive fingerprint.
  Only that reviewed digest is updated; the strict count and inventory remain.

Prompt tests now identify exactly the canonical auto-recall memory envelope while preserving full-prompt control rejection. The channel fixture uses canonical home WAL segments, and the installed-Skill delegation fixture uses its declared keyword trigger; explicit slash-command system precedence is unchanged.
Their precise corrections and all affected source hashes are bound by the
canonical test matrix and source manifest. All twenty observed test identities
are required in the next hosted native run.

No compiler, formatter, parser, test, product, GUI or model was executed on the
local workstation. Source review, whitespace checks and metadata hashing do not
establish runtime success. The current full Linux/macOS/Windows matrix and
native GUI fixtures must pass on the final integrated source before acceptance.
