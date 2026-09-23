# W355: enabled Daily-retention consumers

This slice adds the two missing caller-level regressions for Daily retention execution v2. Hosted execution remains required before acceptance.

Two fixture regressions configure `daily_retention_execution` with version 2,
`enabled: true`, and a seven-day quarantine grace through the strict
`ReflectTopics` YAML file. Each then reaches the existing production consumer
without mocking the executor:

- the quiet `reflect digest --daily` path in `cli/reflect.rs`;
- the scheduled period-tick path in `daemon/reflection_cron.rs`.

Each fixture admits one exact expired Daily archive and one current archive,
then saves the matching period records in the versioned hygiene state. It
asserts one durable retention effect receipt, absence of the expired active
archive after quarantine, presence of the current active archive, and retention
of both period records in hygiene state. The latter proves the expired archive's
yearly-synthesis input remains available after its active archive is
quarantined.

No production retention logic, policy horizon, batch size, or timeout changes
are part of this slice. Local Rust execution is intentionally omitted under the
active BSOD hold; only text and Git checks are allowed.
