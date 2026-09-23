# Gold wave 348 research WAL fixtures

Group687 run `35843153480` at `571b0e032b93081292293cbf4e2fa42afeee12b7` ran 687 selected
fixtures: 685 passed and two W329 research lifecycle fixtures failed.

Both controlled providers implemented `complete` but declared no default model.
The real cost-authorizing provider checks model resolution before dispatching a
raw call, so the successful fixture failed at synthesis before its second
controlled call and the interruption fixture failed before its intended
post-effect provider failure.

Both test-only providers now declare the same deterministic fixture model.
They still use the real `run_research_at` dispatch, cost authorization, home
bound WAL writer, lifecycle receipt decoding, and terminal replay refusal.
No production provider selection or WAL behavior changed.

The interrupted fixture also expected an `"interrupted"` audit event that the durable lifecycle never writes. `research_runs::fail_interrupted` records `"interrupted_unknown_effect"` after a post-effect failure, so the fixture now asserts that persisted contract. This is an audit-label correction only; production lifecycle, producer, WAL, and replay behavior remain unchanged.

No local Cargo, compiler, parser, formatter, test, or runtime command ran under
the BSOD hold. Hosted rerun evidence remains required.
