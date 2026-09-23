# Gold Wave 269: native enrichment readiness status

When an operator explicitly supplies --codegraph-enrichment with its required
absolute repository root, neoth fs read and neoth fs grep add the bounded
codegraph_enrichment_status field to JSON output and one matching Table line.

The status is diagnostic only. It neither authorizes the file operation nor
starts an index, opens a new target file, re-runs the retained-descriptor read,
or changes the selected codegraph sidecar policy.

- master_disabled: the existing code_map.outline_enrichment master switch
  prevented a sidecar plan.
- unavailable: the requested attempt had no eligible native plan from the
  existing descriptor/root checks.
- stale: the existing post-read comparison observed an identity, generation,
  completeness, or persisted freshness mismatch. Other post-read failures are
  unavailable, not inferred as stale.
- applied: the existing plan remained fresh and attached its native sidecar.
- no_matching_lines: an eligible native plan was suppressed because the
  retained-descriptor fs grep scan found no literal
  matches, so both hook and codegraph sidecars remain absent.

The status is omitted when enrichment was not explicitly requested. It carries
no raw local error details, symbol claims for match lines, provider/MCP
provenance, or CRG-05 closure claim.

No local compiler, formatter, parser, test, fixture, or runtime command ran
under the BSOD hold. Hosted validation remains required.