# W200: observed Linux lint and fallback-fixture shutdown repair

Full-CI run `35726117022` on `0d18bb17`, Linux job `106740070079`, reported
eight strict Clippy errors. Five explicit drops of the non-owning RunCallBudget
wrapper were removed; real provider/HTTP/WAL ownership drops and joined WAL
error handling remain. Two redundant references to an already borrowed cap-std
Dir were removed. The loader uses then_some for its existing optional Home
borrow. No diagnostic is suppressed and no test is removed.

Grouped run `35724290786` on `7f2b8636` compiled and passed the first fourteen
identities, then stalled inside the W191 fallback fixture. Its downloaded log
ends at that exact fifteenth test. Source inspection found that FallbackProvider
retained a WAL sender while the fixture waited for the writer task to terminate.
The fixture now drops the provider before the original sender and bounds its
WAL join at ten seconds. Independent review confirmed ownership and unchanged
request/audit assertions. The obsolete run was cancelled and its partial source,
selection, execution log and cancellation result retained; it is not a pass.

The next grouped lane binds sixty identities through an explicit per-wave count
map, keeps exact discovery and source-hash checks, and adds a 180-second timeout
to each behavior invocation with ten seconds for forced cleanup. Independent
failures continue to be collected; missing discovery or compilation still stops
immediately, and any failed/timed-out identity fails the final result.

Evidence is under `work/gold-20260906/wave200-hosted-lint/` and the adjacent
W197 evidence directory. New Hosted format, compile, lint and behavior results
remain required. Other jobs of full-CI `35726117022` remain active and are not
cancelled by this source repair. No local executable validation ran.
