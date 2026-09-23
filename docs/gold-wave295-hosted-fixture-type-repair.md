# Gold Wave 295 - hosted fixture type repair

Hosted Core `1d6` run `35824016472` passed strict production Clippy but failed
the test-target type check with two `TempDir::join` calls and one provider
borrow lifetime error.

The receipt fixture paths now derive from `TempDir::path()`. In the Cron
ack-before-reload fixture, the pending provider future, durable-ack gate,
reload, release, await, and assertions share an inner lexical scope. The
future is therefore dropped before the provider and WAL writer are dropped and
drained. The assertion that changed policy blocks raw transport after durable
ack and reload remains unchanged.

No local compiler, formatter, parser, runtime, or fixture execution was run
under the BSOD hold. Hosted validation remains required.
