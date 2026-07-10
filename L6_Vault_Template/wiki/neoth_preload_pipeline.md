---
tags: [neoth, preload, obsidian, wiki, rag, memory]
aliases: ["NEOTH Vault Preload Pipeline", "Obsidian Preload Wiring"]
source: neoth-preload
status: seed
neoth_preload: true
neoth_scope: l6-wiki
neoth_trust: curated-reference
neoth_chunking: markdown-heading
created: 2026-07-06
---

# NEOTH Vault Preload Pipeline

## Target behavior

NEOTH should treat `L6_Vault_Template` as a first-class seed corpus:

1. `neoth init` asks whether to preload a curated vault template.
2. The wizard defaults to this template when it exists locally.
3. `neoth serve` can keep the preload synced into the configured Obsidian vault.
4. NEOTH memory receives scoped, hash-stable chunks from the copied notes.
5. Obsidian gets human-readable notes and, later, `.base` views over the same properties.

## Why manifest-first

Obsidian stores useful structured metadata as YAML properties at the top of Markdown files. Bases also operate over local Markdown files and their properties. A manifest keeps NEOTH honest about what to import, what to copy only, and what trust level a note carries.

Without a manifest, the current folder shape is ambiguous:

- `wiki/` notes are curated summaries and should be indexed.
- top-level domain folders are compact operator-ready notes and should be indexed.
- `sources/` contains raw upstream material and should usually be copied but not injected wholesale.
- `logs/` should not be imported by default.

## Minimal NEOTH implementation shape

- Add `freedom.yaml::knowledge_preload_dirs[]` or `obsidian_preload_template_dir`.
- Add a CLI surface: `neoth obsidian preload <vault> --template <dir> [--dry-run] [--ingest]`.
- Reuse existing atomic vault writes from Obsidian sync.
- Extend wiki/source discovery beyond direct `PLAN/*.md` files:
  - recursive Markdown walk
  - hidden/generated dir skip list
  - YAML property extraction
  - manifest section policy
- Ingest body chunks, not only pointer statements, under a scope such as `neoth-preload:<section>`.
- Track imported chunk hashes in `~/.neoth/obsidian_preload_state.json`.
- Keep raw `sources/` files out of recall unless the manifest marks them promoted.
- Keep offline security payload/exploit mirrors out of normal recall unless the source registry marks them as reviewed summaries or restricted index.

## Acceptance tests

- Dry-run over `L6_Vault_Template` reports the expected sections and excludes `logs/`.
- Sync writes `NEOTH-Preload/...` files into a temp vault and preserves relative paths.
- Re-running without changes writes zero changed chunks.
- Modifying one note updates only that note's chunks.
- Raw `sources/free_for_dev_readme.md` is copied but not ingested by default.
- Operator-profile notes require review or an explicit trust override before verified fact promotion.
- Generated `NEOTH-Facts` and `NEOTH-Synthesis` are never re-imported through the preload path.
- Offline security registry entries route OWASP/MITRE content to normal curated recall while PayloadsAllTheThings, Exploit-DB, and Metasploit route to restricted index or mirror-only storage.

## Source notes

- Obsidian Properties: <https://obsidian.md/help/properties>
- Obsidian Import: <https://obsidian.md/help/import>
- Obsidian Bases: <https://obsidian.md/help/bases>
