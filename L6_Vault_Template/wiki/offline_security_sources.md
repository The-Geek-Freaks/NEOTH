---
tags: [neoth, offline-prep, cybersecurity, source-catalog, obsidian, wiki]
aliases: ["Offline Security Source Catalog", "Prepper Security Wiki Sources"]
source: neoth-preload
status: seed
neoth_preload: true
neoth_scope: l6-wiki
neoth_trust: curated-reference
neoth_chunking: markdown-heading
neoth_safety_tier: defensive-summary
neoth_offline_priority: high
created: 2026-07-06
---

# Offline Security Source Catalog

This note turns the operator-provided source list into an Obsidian/NEOTH import plan. It is intentionally not a raw payload dump. The goal is offline utility without contaminating normal memory with weaponized snippets.

Machine-readable registry: `sources/offline_security_sources.yaml`.

## Category: hacker handbooks and pentest knowledge

| Source | Format | NEOTH offline role | Policy |
| --- | --- | --- | --- |
| HackTricks | GitHub Markdown/mdBook | Broad lookup for web, cloud, AD, Linux, Windows, CTF, and research notes | Mirror; ingest curated summaries only. |
| PayloadsAllTheThings | GitHub Markdown | Payload/bypass catalog for authorized validation labs | Restricted index; no normal recall. |
| OWASP WSTG | GitHub Markdown / site | Clean web-app and web-service testing methodology | Ingest as defensive test guide. |
| OWASP Cheat Sheet Series | GitHub Markdown / site | Defensive AppSec controls and implementation guidance | Ingest strongly; high RAG value. |

## Category: living-off-the-land and adversary taxonomy

| Source | Format | NEOTH offline role | Policy |
| --- | --- | --- | --- |
| GTFOBins | GitHub YAML/Markdown/API | Unix binary abuse awareness, hardening, triage | Mirror metadata; summarize detections and mitigations. |
| LOLBAS | GitHub YAML/site/API | Windows LOLBin awareness and ATT&CK mapping | Mirror metadata; map to detection/hardening notes. |
| MITRE ATT&CK | STIX/TAXII/JSON/site | Structured adversary graph | Import as graph/taxonomy and cite technique IDs. |

## Category: exploit databases and frameworks

| Source | Format | NEOTH offline role | Policy |
| --- | --- | --- | --- |
| Exploit-DB/SearchSploit | GitLab/database/local package | Offline vulnerability research and historical PoC lookup | Mirror or package locally; restrict raw exploit recall. |
| Metasploit Framework | GitHub Ruby modules/docs | Module metadata, exploit taxonomy, lab validation context | Mirror code; index module metadata only. |

## Category: hacker culture and historical archives

| Source | Format | NEOTH offline role | Policy |
| --- | --- | --- | --- |
| Phrack | HTML/TXT/PDF archive | Technical history, exploit-research lineage, hacker culture | Ingest issue/article index plus curated summaries. |
| 2600 | Magazine/back issues/index | Culture, phreaking/net history, surveillance critique | Copyright-sensitive; keep index and rights notes unless operator has copies. |
| textfiles.com | TXT archives | BBS-era underground texts and culture | Curate indexes; do not treat old technical claims as current truth. |

## Import order

1. Ingest OWASP Cheat Sheet Series, OWASP WSTG, and MITRE ATT&CK metadata first. These are the cleanest defensive/offline base.
2. Add GTFOBins and LOLBAS as structured metadata with defensive summaries, detection ideas, and ATT&CK mappings.
3. Mirror HackTricks for operator search, then promote only reviewed summaries into recall.
4. Put PayloadsAllTheThings, Exploit-DB, and Metasploit into a restricted index by default.
5. Add Phrack, 2600, and textfiles.com as culture/history indexes with copyright and freshness markings.

## Required NEOTH metadata

Every mirrored source should carry:

- `source_id`
- `source_url`
- `license`
- `license_review`
- `last_checked`
- `mirror_ref`
- `local_path`
- `source_tier`
- `ingest_policy`
- `offline_priority`

## Good offline questions NEOTH should answer from this corpus

- Which defensive checklist applies to this app or service?
- Which ATT&CK techniques match these observed behaviors?
- Which local binaries are risky under this misconfiguration?
- Which Windows LOLBins should defenders monitor on this host?
- Which source should the operator inspect offline for an authorized lab?
- Is this source safe for normal recall, restricted search, or mirror-only storage?

## Bad default behavior

- No autonomous exploit-chain planning from mirrored raw corpora.
- No automatic execution of tools described by these sources.
- No full-file ingestion of exploit modules, shellcode, payload lists, or bypass strings.
- No use of 2600/textfiles archive material as current operational truth without freshness review.
