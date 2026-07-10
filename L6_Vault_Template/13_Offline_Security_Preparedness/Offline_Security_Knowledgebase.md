---
tags: [neoth, offline-prep, cybersecurity, obsidian, wiki, preparedness]
aliases: ["Offline Security Knowledgebase", "Security Prep Sources", "No-Internet Security Corpus"]
source: neoth-preload
status: seed
neoth_preload: true
neoth_scope: offline-security-prep
neoth_trust: curated-reference
neoth_chunking: markdown-heading
neoth_safety_tier: defensive-summary
neoth_offline_priority: high
created: 2026-07-06
---

# Offline Security Knowledgebase

NEOTH should be useful when the internet is gone, filtered, or not trusted. This corpus is for defensive prep, incident response, authorized reverse engineering, hardening, and understanding hostile techniques without relying on live web access.

The source registry lives in `sources/offline_security_sources.yaml`. This note is the human-readable policy NEOTH should follow before ingesting or answering from that registry.

## Operating rule

Default to defensive summaries and structured metadata. Do not dump raw exploit code, payload lists, bypass snippets, or post-exploitation recipes into normal recall.

Use three surfaces:

- Obsidian mirror: broad local copy for the operator to inspect offline.
- NEOTH recall: curated summaries, checklists, schemas, taxonomy, defensive mappings, and source pointers.
- Restricted index: raw exploit/payload/code corpora that need explicit operator intent and isolated handling.

## Source tiers

| Tier | Use | Default NEOTH handling |
| --- | --- | --- |
| `safe-reference` | Defensive guidance, architecture, checklists, standards | Ingest summaries and selected full notes. |
| `defensive-test-guide` | Authorized testing methodology and verification steps | Ingest methodology summaries and control mappings. |
| `dual-use-payloads` | Payloads, bypass collections, living-off-the-land references | Copy/mirror and index metadata; restrict raw snippets. |
| `exploit-code` | PoCs, exploit modules, shellcode, weaponizable examples | Mirror only or restricted index; no normal recall by default. |
| `historical-archive` | Culture, history, old zines, BBS textfiles | Ingest curated summaries and indexes; license-review before bulk copy. |

## High-priority offline sources

| Source | Offline value | Tier | Default policy |
| --- | --- | --- | --- |
| OWASP WSTG | Clean web-app testing framework and methodology | `defensive-test-guide` | Ingest curated sections and checklist mappings. |
| OWASP Cheat Sheet Series | Defensive AppSec controls by topic | `safe-reference` | Ingest heavily; best RAG candidate in this group. |
| MITRE ATT&CK STIX | Structured adversary tactics, techniques, mitigations, detections | `safe-reference` | Import as graph/taxonomy, not prose blob. |
| GTFOBins | Unix binary misuse knowledge for hardening and triage | `dual-use-payloads` | Mirror YAML/API and summarize defensive detections. |
| LOLBAS | Windows living-off-the-land binary catalog | `dual-use-payloads` | Mirror YAML and map to ATT&CK/detection notes. |
| HackTricks | Broad pentest/CTF/cloud/AD/Linux/Windows knowledge | `dual-use-payloads` | Mirror for offline lookup; ingest only curated summaries. |
| PayloadsAllTheThings | Web payload/bypass collections | `dual-use-payloads` | Restricted index by default; useful for validation labs. |
| Exploit-DB/SearchSploit | Offline exploit lookup and vulnerability research | `exploit-code` | Mirror/search locally; no raw exploit recall by default. |
| Metasploit Framework | Module corpus and security research framework | `exploit-code` | Mirror code, index module metadata only. |
| Phrack | Hacker history, exploitation research, culture | `historical-archive` | Ingest index and curated historical summaries. |
| 2600 | Hacker/phreaker/net-culture archive | `historical-archive` | Do not bulk copy without rights; keep index/purchase notes. |
| textfiles.com | BBS and underground text archives | `historical-archive` | Curate indexes; avoid treating old claims as current truth. |

## NEOTH answer policy

When answering from this corpus, NEOTH should:

1. Prefer defensive interpretation: hardening, detection, triage, containment, reverse-engineering explanation, and safe lab validation.
2. Cite the local note/source ID and the source tier.
3. Tell the operator when an answer would require restricted raw payload/exploit material.
4. Avoid presenting old archive content as current practice unless the source has a freshness marker.
5. Keep exploit-code corpora out of autonomous planning and tool execution.

## Offline mirror shape

Use a stable directory layout inside the Obsidian vault:

- `NEOTH-Preload/Offline-Security/Reference/`
- `NEOTH-Preload/Offline-Security/Dual-Use-Mirror/`
- `NEOTH-Preload/Offline-Security/Restricted-Exploit-Code/`
- `NEOTH-Preload/Offline-Security/Historical-Archive/`

The mirror should store upstream URL, license, checked date, commit hash or release tag, local path, source tier, and ingest policy for every source. Do not use "latest" as a reproducibility marker.

## Gaps to add next

- Malware-analysis references that are safe for static analysis and incident response.
- Reverse-engineering references for ELF, PE, Mach-O, DWARF/PDB, firmware, and packed binaries.
- Offline CVE/NVD/OSV mirror policy with size limits and update cadence.
- YARA/Sigma/Suricata rule-source policy, separated from exploit/payload corpora.
- Emergency runbooks: evidence preservation, isolated lab setup, credential rotation, backup restore, and air-gapped documentation export.

## Primary source links

- HackTricks: <https://github.com/HackTricks-wiki/hacktricks>
- PayloadsAllTheThings: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- OWASP WSTG: <https://github.com/OWASP/wstg>
- OWASP Cheat Sheet Series: <https://github.com/OWASP/CheatSheetSeries>
- GTFOBins: <https://github.com/GTFOBins/GTFOBins.github.io>
- LOLBAS: <https://github.com/LOLBAS-Project/LOLBAS>
- MITRE ATT&CK STIX: <https://github.com/mitre-attack/attack-stix-data>
- Exploit-DB/SearchSploit: <https://gitlab.com/exploit-database/exploitdb>
- Metasploit Framework: <https://github.com/rapid7/metasploit-framework>
- Phrack: <https://phrack.org/>
- 2600: <https://www.2600.com/Magazine/digital-back-issues>
- textfiles.com: <http://textfiles.com/>
