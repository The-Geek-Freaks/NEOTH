# Gold Wave 301 — direct role CLI binding

`neoth hemispheres test --role <left|right|cerebellum>` already selects an
explicit role before provider construction. Its one-shot authorizer now retains
that parsed role, the exact selected slot provider identity, and one cloned
configuration snapshot through `with_role_dispatch`.

Profile extraction is a fixed analytic Left route. Its CLI batch authorizer
now retains Left and the Left slot identity from the same configuration snapshot
that built the provider. This changes authorization only: command flags,
provider routing, model canonicalization, WAL segment ownership, one-shot
finalization, and terminal batch handling remain unchanged.

Focused tests must use a real mock provider and WAL writer: an allowed selected
role reaches exactly one raw mock call and preserves its existing WAL terminal
effect; a role-policy mismatch reaches zero raw calls and produces the typed
role denial before extraction or the live hemisphere request.
