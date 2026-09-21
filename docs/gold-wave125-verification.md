# W125 — portable corrupt-state receipt acceptance

Windows preview `35541731629` on source `927f6894` completed native CLI compilation
in 46m14s, companion compilation in 29s, and GUI compilation in 77m52s. The latter
fits the reviewed 90-minute bound. Lifecycle acceptance then stopped on a strict
PowerShell access to an absent `failure_diagnostic` JSON property. The uploaded
acceptance receipt records that exception; it is not a portable acceptance pass.

The production lifecycle receipt deliberately omits `failure_diagnostic` when
its optional value is absent. `corrupt_repair_required` returns before repair
and has no failure diagnostic; the actual `failed` outcome sets that field.
The helper now looks up the property explicitly and requires its absence for
the expected no-implicit-repair outcome. It retains the exact outcome and
unchanged-corrupt-database hash checks. No default success, production change,
timeout extension or skipped acceptance step is introduced.

The receipt artifact was retrieved into the existing AGENTER work directory.
The failed run did not publish a qualified portable product artifact. Fresh
GitHub preview execution must complete lifecycle and diff-impact acceptance;
the successful older compilation does not validate newer GUI source. No local
PowerShell parser, test, compiler, formatter, product or GUI execution ran.
