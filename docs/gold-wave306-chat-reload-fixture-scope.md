# Gold Wave 306 - normal chat reload fixture scope repair

Hosted Core run `35827159275` passed production Clippy and reported two
test-target `E0505` errors in the W292 normal-chat reload fixtures. Each test
pins a provider future while it waits for a durable request acknowledgement,
accepts a changed reload policy, then asserts that the raw transport is
blocked. The pinned future borrows its provider until its destructor runs.

Each fixture now puts its pending future, acknowledgement wait, reload,
release, await, and unchanged assertions in an inner lexical scope. That scope
ends before the provider, WAL writer, and writer join handle are dropped. This
matches the hosted W295 Cron fixture repair and preserves the original
admission, reload, rejection, call-count, and request-frame assertions.

No local compiler, formatter, parser, test, runtime, or fixture execution was
run under the BSOD hold. Hosted test-target validation remains required.
