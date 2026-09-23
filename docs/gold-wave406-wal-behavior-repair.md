# W406 WAL behavior repair

Group810 found two assertion-level failures in the new authenticated leaf
redaction coverage. The missing journal target must be rejected through its
exact no-follow basename with an OS `NotFound` cause. The original structural
fixture used arbitrary text as a rollover payload, so full authenticated-chain
validation rejected JSON before it reached the redactor. It now uses the
production cross-segment rollover schema with a topic-bearing `reason` field.

The repaired checks retain the behavioral contract: the exact journal-named
missing child appears in the recovery error, retains `NotFound`, and its
prepared journal stays on disk; structural-frame staging returns the specific
structural refusal and publishes no bytes. No production fail-open or generic
fallback was added. Hosted validation remains pending under the local BSOD
hold.
