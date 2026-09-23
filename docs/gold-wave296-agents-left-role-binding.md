# Gold Wave 296: `neoth agents` Left role binding

The standalone `neoth agents run` fan-out already creates its provider through
the canonical Left fallback-chain factory. Wave 296 retains that origin once at
the shared `ProviderCallAuthorizer` constructed by `run_fan_out`.

The binding uses the configured Left slot provider, falling back to the legacy
single-provider identity only when the topology leaves the slot implicit. It
retains an `Arc` of the command's selected configuration snapshot and does not
introduce a CLI role option, model-derived role, provider rebuild, or live
reload path.

`ProviderSubAgentWorker` receives the resulting `AuthorizedProvider` unchanged.
Consequently its primary response, structured QA request, one bounded retry,
and every fallback candidate reach the same Left authorization boundary before
their raw transport and WAL lifecycle effect.

Local Cargo, compiler, formatter, parser, and test commands were not run under
the active BSOD hold.
