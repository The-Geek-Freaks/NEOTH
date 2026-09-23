# Gold Wave 292: normal-chat Left role binding

Normal interactive chat retains the existing canonical `HemisphereRole::Left`
origin. The provider factories already create normal chat through the configured
Left topology; Wave 292 carries that identity through the prepared turn rather
than accepting a role from CLI input, RPC input, a model name, or a provider
name.

A binding is minted whenever the selected Left topology has a provider identity.
It retains the selected Left provider and the accepted configuration snapshot,
including when the current snapshot has no role policy; a daemon can therefore
recheck a policy enabled after admission. A missing Left provider identity is
rejected when a role policy is active. Sparse compatibility fixtures without a
provider identity retain the historical unbound path.

The shared direct dispatch and post-reply/recovery dispatch both apply the same
retained binding before every concrete leaf. This includes fallback leaves: a
429 may select another transport leaf, but it never changes the original
normal-chat authority. A denied leaf does not reach the raw provider or mint a
provider request lifecycle.

Standalone CLI retains its fixed preparation snapshot. Daemon plain and GUI
turns receive the `DaemonChatRuntime` accepted `ReloadController`; it is used
only for the role-policy final fence so an accepted policy change before a raw
send revokes the leaf. The existing daemon provider admission and SkillRegistry
ownership remain unchanged.

No CLI/config flags were added. P2-15 remains open until the broader Gold
acceptance evidence is run. Local Cargo, compiler, formatter, parser, and test
commands were intentionally not run while the active BSOD hold remains in
effect.

The seven selected behavior fixtures cover an allowed leaf, provider and model
denials before the request lifecycle, retained compatibility binding, both
leaves of a real 429 fallback, and accepted policy reloads after durable request
acknowledgment (including no-policy to active-policy). Independent source review
passed; hosted behavior remains pending. Post-reply binding is source-reviewed:
the existing W206 terminal mirror ends recognized refusal recovery before any
abliterated raw leaf, so this batch does not claim a raw recovery execution or
weaken that terminal rule to manufacture one.
