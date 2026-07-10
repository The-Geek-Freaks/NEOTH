---
tags: [neoth, preload, obsidian, wiki, memory, ground-truth]
aliases: ["NEOTH Preload Manifest", "L6 Vault Template"]
source: neoth-preload
status: seed
neoth_preload: true
neoth_scope: l6-vault
neoth_trust: operator-attested
neoth_chunking: markdown-heading
created: 2026-07-06
---

# NEOTH Preloaded Knowledge

This vault is intended to be an operator-curated seed corpus for NEOTH and the operator's Obsidian wiki. It should be copied into the configured Obsidian vault and ingested into NEOTH memory in a controlled way, not treated as an arbitrary folder dump.

## Why this exists

NEOTH already has Obsidian and wiki primitives: archive sync, wiki-build, vault reader/writer, self-map output, and graphify-backed self knowledge. The missing piece is a first-class preload source for curated operator knowledge.

The preload should give NEOTH useful context before the operator has accumulated enough live memory:

- operator profile and ground-truth anchors
- NEOTH architecture and intended mental model
- local AI, self-hosting, inference, and quantization notes
- security and privacy operating defaults
- offline security preparedness sources for no-internet incident response, hardening, and authorized reverse engineering
- software-engineering, Rust, distributed systems, and agent patterns
- curated wiki notes from upstream sources, with raw sources kept separate

## Trust policy

Use different trust levels. Do not flatten everything into verified facts.

- `operator-attested`: profile, identity, scope, explicit NEOTH architecture notes. These can become verified or high-priority groundtruth after operator review.
- `curated-reference`: wiki and domain knowledge. These should be searchable and citable, but not treated as personal/operator truth.
- `raw-source`: upstream READMEs under `sources/`. Keep them available in the vault, but do not inject full raw files into recall by default.
- `runtime-log`: logs. Do not import unless a specific diagnostic run asks for it.

## Ingestion contract

The importer should read `preload_manifest.yaml` and then:

1. Copy this directory into the operator Obsidian vault under `NEOTH-Preload/`.
2. Normalize copied note properties so each imported note has `source: neoth-preload`, `neoth_preload: true`, `neoth_scope`, `neoth_trust`, and `neoth_chunking`.
3. Ingest notes by Markdown heading chunks, except short operator-profile notes that can be imported as whole notes after review.
4. Exclude `.obsidian`, `.git`, `logs`, and NEOTH-generated directories such as `NEOTH-Facts`, `NEOTH-Synthesis`, `NEOTH-Self`, and `NEOTH-Wiki`.
5. Store a hash state file so repeated preloads update changed chunks without duplicating memory.
6. Preserve source links and file paths in metadata so answers can point back to Obsidian notes.

## Missing knowledge worth adding next

- Local hardware inventory: GPUs, VRAM, drivers, CUDA/toolchain constraints, storage layout.
- Homelab topology: Proxmox/LXC services, ports, reverse proxies, backups, and failure domains.
- Provider policy: which models are allowed for private, expensive, background, and safety-critical tasks.
- Evaluation goldset: canonical operator questions that NEOTH should answer from the preload.
- Incident runbooks: backup restore, WAL recovery, credential rotation, model/provider outage, vault corruption.
- Prompt-injection corpus: known bad snippets and expected NEOTH refusal/containment behavior.
- Source freshness ledger: per-note source URL, date checked, confidence, and kill criteria.
- Offline security mirror ledger: source tier, license state, mirror path, commit/tag, and ingest policy for dual-use and exploit-code corpora.

## External basis

- Obsidian Properties: <https://obsidian.md/help/properties>
- Obsidian Import: <https://obsidian.md/help/import>
- Obsidian Bases: <https://obsidian.md/help/bases>
