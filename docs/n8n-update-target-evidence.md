# n8n update-target evidence

The manual `n8n-update-target-evidence.yml` GitHub workflow verifies the fixed
2.40.7 candidate independently of the installed 2.40.5 runtime. Run it from
`main` and inspect its retained artifact before admitting any target.

The subject is
`oci://ghcr.io/n8n-io/n8n@sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34`.
Its source is commit `09b3ce6f9889c889e13cf3747f6f6c68eebdeeb6`
on `refs/heads/release/2.40.7` in `n8n-io/n8n`.

The gate checks GitHub's standard Sigstore public-good attestation verification
against the expected repository, signer workflow, source ref, source commit and
SLSA v1 predicate, rejecting self-hosted runners. It also checks the final
versioned GitHub release/tag and fetches the immutable OCI index from GHCR and
Docker Hub. Both raw bodies and digest headers must match the fixed SHA-256;
the bodies must agree and contain exactly the expected Linux amd64 and arm64
child descriptors.

The workflow runs the helper's stdlib regression suite, records each gate's
exit status, hashes the exact producer inputs and public evidence, and uploads
failure evidence as well as successful receipts. Anonymous registry tokens
are kept in memory. No caller-selected version, trust root or image is accepted.

This evidence covers the signed subject and observed immutable registry
metadata. It does not resolve mutable registry version tags, pull image layers,
prove Docker platform selection, start n8n, migrate data or change the current
installer pin. An admitted target still needs a separate product gate that
starts the target on an isolated volume and preserves the old source bytes
through migration, readiness and authenticated cutover.
