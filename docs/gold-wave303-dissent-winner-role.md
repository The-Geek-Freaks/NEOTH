# Gold Wave 303 - Council dissent winner role binding

The Council dissent loop rebuilds a provider for the selected winner. Before
entering that loop, it now binds the retained `winner.role` and the configured
provider identity from that role's selected slot to the copied authorizer.
The binding uses a fixed configuration snapshot. It does not infer a role from
the winner model, and it does not change the Council budget, retry behavior,
or session-canary guard.

The focused W303 tests drive the existing loop authorization boundary with a
counting mock leaf and WAL writer. The allowed Right-winner fixture requires a
Right lifecycle request with `hemisphere_role: right`; the denied Right policy
fixture requires zero raw calls and zero provider-request frames.

No local compiler, formatter, parser, runtime, or fixture execution was run
under the BSOD hold. Hosted validation remains required.
