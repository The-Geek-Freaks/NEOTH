# WebChat CLI onboarding

W710 makes the existing local WebChat discoverable when interactive init skips
Telegram. It shows the actual sequence: enable `companion.enabled`, start
`neoth serve`, then mint a one-time browser link with `neoth companion webchat`.
The handoff continues to use the same daemon home and authenticated RPC.

`neoth onboarding-status` now includes a separate `webchat` configuration field
in JSON and a matching table row. `disabled` and `configured_needs_serve` describe
configuration only; `neoth status` remains the live listener-readiness authority.
Existing provider/channel readiness and configuration-error handling are
unchanged. No browser handoff is minted just to inspect onboarding status.

Two selected regressions exercise the real config evaluation, snapshot
projection, JSON serialization and markdown renderer. They also verify that
turning on Companion does not turn an unavailable provider or external channel
into a ready one. Portable native1353 and Group1083 include these tests.

Independent source review passed. Execution of the new cases is pending on
GitHub. No local compiler, formatter, parser, test or runtime was used. This
slice does not close GOLD-LF-P1-15: registry/account lifecycle, GUI/Buddy
onboarding, migration, clean-machine qualification and WebSocket parity remain.

The prior W708 publication59e2d5eb passes Preflight35973509291. Its Core35973521304
and Group1081/35973525383 remain separate source-bound verification runs. Earlier
3ed5622b stopped with two compile diagnostics and executed no grouped tests;
W708 corrected those JoinHandle<()> awaits without changing assertions.
