# Gold Wave 305 - reviewed raw callsite fingerprint repair

Hosted Group564 run `35826131329` reported one mismatch in
`production_raw_complete_stream_surface_is_reviewed`. The complete actual and
expected maps differ only at `cron/runner.rs`: the recorded surface had three
call sites with digest
`3f50cf36eb2cdbc5611b5a256bee6ffb74266caf898ec80b73d1b2d8d556b546`,
while the hosted source has six with digest
`217e48199e588e644d2b5f2fd432295f687ca50bacf1f365612ee4b0cfd69d4d`.

The three added calls are the W289 Cron role-authority fixtures. Each calls an
`AuthorizedProvider` constructed with `cron_role_authorizer`: the admitted
leaf proves the direct authorized route, the denied-model leaf proves that
policy blocks before a provider effect, and the durable-ack/reload leaf proves
an accepted reload blocks before the raw send. They are therefore reviewed
provider call sites, not unrelated same-named methods.

Only the corresponding table record is updated. The running workspace may
contain later changes in other callsite-bearing files; hosted validation must
recompute the full digest map on the published source. No local compiler,
formatter, parser, test, runtime, or fixture ran under the BSOD hold.
