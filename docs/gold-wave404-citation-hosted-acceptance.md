# W404 — hosted citation acceptance

`W404 citation hosted acceptance` is a manual, main-only GitHub Actions lane for
`GOLD-LF-P1-12`. It is deliberately separate from the broad release and GUI
matrices. The lane has one Linux worker, `CARGO_BUILD_JOBS=1`, pinned Rust 1.91,
and an isolated cache namespace for a completed focused result.

## Native receipt

Every dispatch records its checked-out Git head and SHA-256/byte bindings for
the workflow, runner, lockfile, and all canonical P1-12 production
source paths. The runner refuses a dispatch whose
`git rev-parse HEAD` differs from `GITHUB_SHA`.

It embeds the historical W155 49-identity source-only selection in the committed runner and
adds the current exact-head cache-boundary identity
`tools::citation_lookup::tests::missing_cache_namespace_is_a_read_only_offline_miss`.
The result is exactly 50 selected tests: 47 library tests, including the two
Unix-only cache/private-namespace tests, and three real
`citation_cli_contract` binary integration tests.

For each identity, the lane first uses Cargo's exact discovery form and requires exit status zero plus one matching `name: test` line. Failed or timed-out discovery prevents execution. It then runs the same selected Cargo filter once with `--exact --test-threads=1` and requires that exact test's sole `... ok` terminal plus one one-pass summary. The first native discovery/build for each Cargo harness and the optional production-CLI build may each run for 1,500 seconds; later calls in the same harness have a 300-second bound, and each live CLI probe has a 45-second bound. Every timeout retains partial logs and its structured receipt terminal.
The artifact preserves every per-test discovery/execution log, the ordered
selection, actual terminals, failures, and unstarted identities. A job
submission, a compiled binary, or an incomplete list is therefore not an
acceptance result.

## Optional public-provider probes

The `live_probes` workflow input defaults to `false`. When explicitly enabled,
the lane builds the production `neoth` binary and makes exactly three bounded
public DOI requests through `neoth citation lookup`:

- Crossref — `10.1038/nature12373`
- OpenAlex — `10.1038/nature12373`
- Semantic Scholar — `10.1038/nature12373`

Each probe uses its own fresh runner-temporary `NEOTH_HOME` containing only
`autonomy: elevated`. This is the ordinary production configuration and
`ExternalHttpAuthorizer::interactive` path: it retains the normal policy gate,
mandatory audit/WAL lifecycle, fixed provider URL, timeout, redirect policy and
cache behavior. The lane does not inject a test authorizer, preconfirmation,
credential, provider token, or fixture listener.

The live receipt requires the explicit claim, provider, canonical DOI, and one
matching attempt. A found result must additionally carry a live provenance
record and a recomputed claim/record binding matching the Rust domain-separated digest contract. A typed timeout, rate limit, provider-unavailable result, not
found, permission denial, invalid query, or offline cache miss is kept as a
truthful unavailable receipt; it sets `coverageEstablished: false` for that
provider and must never be read as successful live-provider coverage. The
workflow records those outcomes without retrying the request. A malformed receipt, binding failure, or nonzero exit for a found record is a structured per-provider contract failure; the lane continues through the remaining bounded probes, writes the aggregate receipt, then fails.

This Linux evidence can carry the native P1-12 proof only. It does not assert
current-head macOS W155 callback execution, rendered GUI accessibility, or a
blanket full-release matrix; those remain distinct evidence rungs where the
Road criterion requires them.
