# Wave 215 sub-agent session Skill registry

`neoth agents run` captures the admitted Skill registry before constructing its
provider fan-out. The capture uses the same accepted configuration through a
one-shot reload controller, the exact instance config path and an
authority-bound registry snapshot for that epoch. Existing dependency and
enabled-state admission, evaluation suppression and guarded registry rendering
remain the canonical implementation.

The production worker requires and owns the resulting `RenderedUntrustedContext`
for the duration of one run. Primary, QA, retry and retry-QA requests append that same envelope to
their own system prompts. The strict QA response contract and bounded
provider-only worker instructions remain present. The existing prompt budgeting
path sees the complete composed system text. Both complete primary and QA
systems must satisfy the existing system-byte limit before the first provider
call; the registry is never silently truncated. Config, Skills, WAL, provider
construction and persisted results all use the supplied instance home.

This is the CLI fan-out session boundary. It does not invent a chat subject or
Council role, reload running worker prompts, enable host tools or grant a Skill
invocation capability merely by listing metadata. Only test fixtures can build
a worker without a captured registry. Standalone QA used by self-improve remains
a separate consumer outside this CLI fan-out slice.

## Verification boundary

Independent bounded source review passed. Three source tests exercise actual
installed Skill authority with enabled/disabled/eval admission at a custom
config path, the identical envelope in four real provider requests, and
QA-specific aggregate overflow with zero provider calls. One further regression
in the concurrent W213 correction proves role revocation after effect intent
blocks actual start without spending AllowOnce. The grouped lane selects 255
tests; inventory is 530 source paths / 802 universal native / 92 GUI identities,
with platform extras unchanged. A subsequent scanner-scope regression brings
the current grouped count to 256 and native inventory to 803, retaining 530
source paths. The standalone self-improve QA API delegates to the same optional-
registry QA implementation as the worker, preserving the two reviewed production
provider-call sites. Source/SHA-bound formatting from run `35774197387` is imported.

Core/CLI run `35772615830` on `7689717b` passed test-target type-check and public
CLI build. Its source/SHA-bound CLI reference is imported, including all seven
Buddy embedding actions. This is prior-source evidence; W215 and the actual-start
correction still need their own Hosted compile and behavior checks. The batch
does not close the broader GOLD-LF-P2-10 row or release gates. No local compiler,
formatter, code parser, tests or runtime operations ran under the BSOD hold.
