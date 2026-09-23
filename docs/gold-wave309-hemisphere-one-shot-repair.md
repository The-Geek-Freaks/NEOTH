# Gold Wave 309 - hemisphere one-shot audit repair

Hosted Core run `35828611235` failed during production Clippy with three related
type errors in the W301 direct hemisphere test path. The
`ProviderCallOneShot` audit handle was shadowed with a role-bound
`ProviderCallAuthorizer`. That discarded the handle methods needed to derive
the ephemeral-consent authorizer and to finalize the audit after the provider
call.

The audit handle now remains named `provider_audit`. The role-bound
`authorizer` is derived from
`provider_audit.authorizer_with_ephemeral_consent(ephemeral_consent)` and is
passed to `AuthorizedProvider`; the original
`provider_audit.finish(provider)` remains the terminal audit operation.

The analogous profile and coding constructions were inspected read-only. No
matching shadowed one-shot handle was found, so no broader mutation was made.
No local compiler, formatter, parser, test, runtime, or fixture execution was
run under the BSOD hold. Hosted validation remains required.
