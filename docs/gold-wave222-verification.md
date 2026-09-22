# W222 — Direct CLI registry retention through a reachable fallback

The new exact fixture
`cli::chat::tests::direct_cli_fallback_keeps_the_admitted_skill_registry_after_real_publication_b`
enters public `run_chat_with` and reaches the existing normal CLI enrichment,
authorization, provider fallback and WAL completion path. It uses in-process
provider fixtures, not an external provider transport.

Installed Skill A has a signed install incarnation and explicit active authority.
A real ReloadController-bound SkillRegistry produces the exact expected metadata
envelope through `session_registry_context`. The config has no pinned mismatch
or eval suppression; CLI and expected resolver use the same active-files input.
The metadata must exclude the Skill instruction body.

The primary provider records the actual dispatched Request, publishes Skill B
and config B with a real reload controller, re-authorizes the changed package
and reloads its registry. It then emits the existing typed QuotaError. The
actual FallbackProvider has one allowed hop and reaches its second provider.
This is a reachable quota path; it does not attempt to retry W206's deliberately
terminal mirror response.

The fixture requires one primary and one fallback call, equal prompt and full
system bundles, the exact pre-admitted A registry envelope in both requests,
absence of B from fallback, and the fallback's independently selected model.
It separately verifies accepted epoch advancement and that newly acquired live
registry B excludes A. The active CLI turn keeps its own original snapshot.
The fixture finishes through the normal WAL-draining path.

Independent source review passed. No local compiler, formatter, parser, test
or runtime execution ran. Hosted Grouped275 selects this exact identity; source
inventory remains 532 paths, universal native count becomes 817. GUI selections
remain 94 + 22 Linux/22 macOS extras and 26 custom macOS cases.

This adds actual CLI-path regression coverage; execution is still pending.
It does not close all P2-10 surface acceptance or claim external delivery.
Full CI35782661515 continues on74334d4b. Its Linux slim-core Clippy stage has
nine new diagnostics under repair; Windows/macOS jobs are not cancelled.
Road remains1015 checked/307 open/2 partial.
