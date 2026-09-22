# W185 first Hosted result — f091d5fe

Preflight 35679412294 and core check 35679420073 found the same missing
closing parenthesis in the loopback fixture's request-model extraction at
local_models.rs:630. The exact `and_then` delimiter is repaired; no behavior
assertion was removed. Preflight also reported GUI formatting; a fresh Hosted
formatter pass after parsing succeeds is still required. No local parser,
compiler, formatter or test was run.

The W186 resolver workflow separately restores the pre-existing borsh 1.6.1
pin after run 35679007670 found normal resolution upgrading it to 1.8.1.
Identity/MSRV gates remain strict. Pre/post-resolution evidence is retained
before the gate. Neither change closes a Road item.
