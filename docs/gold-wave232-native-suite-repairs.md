# W232 — Repair actual native-suite regressions

Full CI35782661515 on74334d4b completed the Windows compilation and ran the
actual workspace suite. Windows job106931734783 reported17530 passed,3 failed,
24 skipped and1 leaky over1698.419seconds. There were no test timeout failures.
These three failures remain relevant to the current source.

## Watcher registration

The read-only waiter-isolation fixture used one yield before deciding that two
network-created waiters were registered. It now calls the production
wait_for_change helper against the real owner/watch state and waits for both
watch receiver registrations before checking that they remain pending. The
same real dispatch then publishes one accepted mutation and both waiters must
observe its exact sequence. Separate native transport tests retain long-poll
client deadline and next-mutation delivery coverage. Production behavior is
unchanged; no assertion was removed.

## Test-only provider module classification

The production transport/lifecycle source gates incorrectly scanned the
module-level test-only role_dispatch_tests.rs as production. Both existing
prefix helpers now exclude a source beginning with the exact #![cfg(test)]
module gate. Production modules and the existing inline-test boundary remain
covered. Both affected scanner tests are explicitly selected in Grouped394.

## Buddy source assertion

The Buddy probe callback is present but rustfmt separates its surface and
operation arguments across lines. The assertion now scopes the actual probe
callback, normalizes whitespace and verifies the ordered function/arguments
through model.to_string(), accepting Rust's legal trailing comma. Root review
caught and repaired an initial trailing-comma mismatch in the new assertion.
The production callback is unchanged. This existing identity is already part
of the separate GUI116 selection and requires a new-source GUI run.

## Evidence boundary

Independent focused review passed. The repairs have not yet passed Hosted
execution. Native inventory remains842, GUI94, source535 with unchanged platform
extras. The waiter is already selected; adding two scanner names makes394
focused native cases. No local compiler, formatter, parser, test or GUI ran.

The same full CI's macOS build completed and its native test step failed;
macOS failure details are being inspected separately. A green full native
matrix is still required. No Road checkbox closes from these source repairs.
