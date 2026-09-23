# Gold Wave 308: adversarial sub-agent role origin

The standalone sub-agent worker retains the canonical Left origin established
by the `neoth agents` fan-out construction. Operator task data, agent text,
and request-contract fields can contain delimiter-like prompt injection and
claims to switch to Right or an alternative provider; none of those strings is
an application role input.

The W308 worker regression uses the production W296 Left binding helpers and a
real `ProviderSubAgentWorker` plus `dispatch_parallel`. Its allowed case
decodes the sent typed primary envelope, confirms the hostile operator task is
preserved as untrusted data, and confirms the raw transport and each provider
request lifecycle carry Left and `openai_api`. Its denied case configures an
otherwise allowed Right policy while Left remains denied; hostile Right text
cannot mint a raw call or provider-request lifecycle.

This covers application dispatch authority and request provenance. It does not
claim to evaluate the semantic behavior of a language model when it reads the
hostile text.

Local Cargo, compiler, formatter, parser, and test commands were not run under
the active BSOD hold.
