# B — Knowledge → Skills Adoption Report
**Agent B of 6 · 2026-07-31**

Repos: book-to-skill (virgiliojr94, MIT) · fabric (danielmiessler, MIT) · agent-skills (addyosmani, MIT) · system-design-101 (ByteByteGo, CC BY-NC-ND 4.0)

---

## (a) book-to-skill (virgiliojr94/book-to-skill · MIT · 13.9k★ · Python)

### 1. What it actually does

This is a **meta-skill executed by the agent, not a callable library**. `SKILL.md` is a 10-step instruction manual for Claude/Copilot/Amp. The Python package (`book_to_skill/`, `scripts/extract.py`) is a preprocessing tool only — it extracts raw text from PDF/EPUB/DOCX/PPTX/RTF/HTML into `$TMPDIR/book_skill_work/full_text.txt` + `metadata.json`. The LLM agent then reads that file and executes the distillation steps manually.

**Extraction backends (parsers/):**
- `pdf.py`: tries `pdftotext` (system) → `pypdf` → `pdfminer` → `docling` in that order; emits `extraction_method` tag in metadata
- `epub.py`: `ebooklib` → zipfile fallback; spine-order traversal, OEBPS-aware
- `docx.py`: `python-docx` → zipfile+XML fallback; tables included as tab-separated rows
- `calibre.py`: `ebook-convert` subprocess for MOBI/AZW — timeout 300s

**Distillation phases (executed by the agent, specified in SKILL.md):**

- **Step 0**: Out-of-scope check (code only, no book-like content → abort)
- **Step 1-2**: Validate inputs, run `scripts/extract.py`, read `metadata.json`
- **Step 2.5**: Pre-flight token cost estimate shown to user before proceeding
- **Step 2.6**: For books >50k tokens — REPL/line-range access: `grep -n "^Chapter" full_text.txt` to find byte offsets, then `sed -n 'START,ENDp'` to read each chapter individually. No attempt to load the whole file at once.
- **Step 3**: Read first 8,000 chars → detect title/author/chapter structure/ToC
- **Step 4**: Classify BOOK_TYPE (`text` vs `technical`) + DEPTH (`reference` vs `study`)
- **Step 5-9**: Per-chapter pass — for each chapter, agent reads section from `full_text.txt`, generates a structured chapter file:

```markdown
# Chapter N: <Full Title>
## Core Idea          ← 1-2 sentences, the single most important teaching
## Frameworks Introduced  ← exact author naming, "when to use", "how: steps or criteria"
## Key Concepts       ← term: precise definition
## Code Examples / Reference Tables  ← technical books only; exact syntax
## Worked Example     ← reproduced artifact (study depth only; "what makes study depth earned")
## Key Takeaways      ← 3-7 actionable insights
## Connects To        ← cross-refs to other chapters + external concepts
```

- **Supporting files**: `glossary.md` (term → def, chapter refs), `patterns.md` (techniques/algorithms, <2500 tokens), `cheatsheet.md` (comparison rules, decision tables)
- **SKILL.md (master index)**: chapter index table, topic index, core frameworks section, metadata (author, source, generated date, chapter count)

**Update/Fold-in Workflow**: on second run against same skill slug — reads existing chapter files, glossary, patterns; merges new content (dedup key = chapter heading similarity); glossary deduplication = alphabetical merge with appended "(Ch N)" references.

**Provenance**: each chapter file is named `chapters/chN-<slug>.md`; glossary entries cite "(Ch N)"; no page-number provenance (only chapter-level).

**Prompt injection defense**: 
- `sanitize.py` removes zero-width codepoints (U+200B, U+200C, U+200D, U+2060, U+FEFF) + Unicode Tag block (U+E0000–U+E007F) from extracted text before any LLM sees it
- `tools/scan_generated_skill.py`: post-generation scanner that flags 7 injection patterns in all generated files:
  - `prompt.ignore_previous` — "ignore all previous instructions"
  - `prompt.disregard_system` — "disregard the system"
  - `prompt.role_reassignment` — "you are now"
  - `prompt.fake_system_prefix` — line starting with `system:` or `developer:`
  - `prompt.system_tag` — `<system>` tags
  - `prompt.chat_template_tag` — `<|im_start|>` / `[INST]`
  - `prompt.tool_call_tag` — `tool_call` control token
  - Also checks for invisible codepoints and exfiltration keywords (`curl`, `wget`, `send`, `upload`)
  - Refuses symlinked supporting files (symlink traversal attack)
  - Hard cap: `MAX_SKILL_FILES = 1000`, `MAX_FILE_BYTES = 2MB` per file

**No self-critique pass.** No dedup at concept level within one book. No routing decision (memory vs. skill vs. wiki).

**How 500-page book is handled**: the REPL/line-range trick (`sed -n` on `full_text.txt`) means the agent reads one chapter at a time. Cost estimate is computed upfront from `metadata.json`'s `estimated_tokens` field. Operator confirms before proceeding.

### 2. Where it beats NEOTH

| Gap | Their code | NEOTH equivalent | Delta |
|-----|-----------|-----------------|-------|
| Multi-pass chapter-by-chapter distillation | `SKILL.md` Step 2.6 + Step 7 chapter template | `arxiv_skill_scan_cron.rs::extract_learnings` (abstract only, 1-3 bullet facts → groundtruth) | NEOTH's arxiv path produces flat facts, not structured hierarchical skill content |
| Pre-flight token cost estimate | `SKILL.md` Step 2.5, reads `metadata.json` | None | NEOTH has no pre-flight budget display before a long distillation |
| Chapter provenance in generated artifacts | `chapters/chN-<slug>.md`, glossary "(Ch N)" | None | NEOTH skills have no chapter/section provenance field |
| Zero-width / Tag-block sanitization | `sanitize.py::sanitize_extracted_text` | `security/ingress_sanitizer.rs::defang_prompt_delimiters` | Both exist; NEOTH's is Rust/production. **No gap here — NEOTH wins.** |
| Post-generation injection scan | `tools/scan_generated_skill.py` — 7 patterns, symlink check, file size cap, exfiltration keywords | No equivalent for generated skill files | Gap — NEOTH's ingress scanner operates on incoming content but not on generated skill artifacts |
| Update/Fold-in glossary merge | Step 5 alphabetical merge with chapter citation | None | NEOTH skills don't have a fold-in patch workflow |
| Routing: skill vs. wiki vs. memory | None (always produces a skill) | None | Neither has this; both need it |

### 3. Steal-list

**S1 — Post-generation skill artifact injection scanner** (M effort)
- What: Port `scan_generated_skill.py` 7-rule regex scanner as `skills/generated_scan.rs`
- Consumer: `skills/creator.rs::write_skill_yaml_audited` — run before returning to caller
- Integration: add a `scan_generated_artifact(path)` call in `write_skill_yaml_audited`, fail-closed with a `ScanWarning` result type (never panic, but surface warnings through the existing `report.warnings` path)
- Architecture fit: Rule 5 (consent/audit) — this is an egress safety check. Rule 6 (untrusted content) — generated content from a doc is untrusted. No WAL opcode needed (warnings go through existing report path)
- Effort: M — ~150 lines Rust, the regex rules are directly portable

**S2 — Chapter-template distillation prompt** (S effort — prompt text only)
- What: The exact chapter template (Core Idea → Frameworks Introduced → Key Concepts → Code Examples → Worked Example → Key Takeaways → Connects To) is the core IP. Port as a `const CHAPTER_DISTILL_PROMPT_TMPL` in the new `skills/doc_distill.rs`
- Consumer: `skills/doc_distill.rs::distill_chapter` (new fn)
- Integration: adapt from SKILL.md Step 7; replace {CHAPTER_TEXT} slot; output structured markdown
- Effort: S — pure prompt text, no code port

**S3 — REPL/line-range large-document access pattern** (S effort)
- What: For documents >50k tokens, don't load full text; detect chapter offsets (regex on headings), read ranges
- Consumer: `skills/doc_distill.rs` — after text extraction via `media/document.rs` or `media/pdf.rs`, if `text.len() > LARGE_DOC_THRESHOLD`, switch to range-based chapter iteration
- Integration: `media/pdf.rs` already has per-page bounds; for other formats, a `detect_chapter_offsets(text) → Vec<(usize, usize)>` function working on byte offsets of the extracted text string
- Effort: S — ~60 lines, regex on extracted text

**S4 — Pre-flight token cost display** (S effort)
- What: Before starting a long distillation, emit a progress item to `ProactiveQueue` / GUI with estimated token count × model price
- Consumer: `skills/doc_distill.rs` — after structure detection, before first chapter pass
- Integration: use existing `media/document.rs` `metadata.word_count` to estimate tokens; publish to `proactive::ProactiveQueue`; also surface in GUI via the existing proactive drain
- Effort: S — ~40 lines

### 4. Architecture-fit check

| Steal | Rules at risk | Assessment |
|-------|--------------|------------|
| S1 generated scan | Rule 6 ✓ (this IS the rule 6 mechanism), Rule 5 ✓ (warnings to audit trail) | Clean fit |
| S2 chapter prompt | Rule 6 — document text must pass through `defang_prompt_delimiters` FIRST, then into the {CHAPTER_TEXT} slot. Currently NEOTH's ingress_sanitizer.rs does this for incoming requests. Same function must wrap the extracted text before it enters this prompt. | Needs explicit call to ingress_sanitizer; not automatic |
| S3 range access | Rule 8 (cross-platform) — `sed -n` is POSIX. NEOTH must implement in Rust over the String, not shell out | Rust byte-range implementation required |
| S4 pre-flight | Rules 2+3 (GUI parity) — cost display must appear in GUI panel, not just CLI | Needs GUI panel slot in doc-ingest workflow |

### 5. Verdict

**ADOPT-NATIVE** (port prompts + algorithms to Rust)
- License: MIT, no attribution obligation beyond SPDX in Cargo.toml
- Steal S1 (generated scan) and S2 (chapter prompt) are the highest priority items — they are independently useful even before the full pipeline exists

---

## (b) fabric (danielmiessler/fabric · MIT · 43k★ · Go · 256 patterns)

### 1. What it actually does

A command-line pipe-and-filter tool for LLM operations. Architecture:

**Pattern system** (`data/patterns/`): 256 directories, each containing `system.md` (the system prompt) and optionally `user.md`. Patterns are loaded by `internal/plugins/db/fsdb/Db` which reads `~/.config/fabric/patterns/<name>/system.md`. No compiled-in patterns — all are file-system resident.

**Chatter** (`internal/core/chatter.go`): `Send(ctx, request, opts)` builds a session from the request, injects the selected pattern as the system prompt, and calls the vendor's `SendStream` or `Send`. Pattern piping = the output of one call is the input of the next (done at the CLI layer via shell pipes, not internally).

**Strategies** (`data/strategies/`): 9 JSON files — each a short `{"description": ..., "prompt": ...}` object. The prompt text is APPENDED to the user message before sending. e.g. `reflexion.json`: `"Answer concisely, critique your reasoning briefly, and provide a refined answer."` These are not chaining; they're reasoning-style injections.

**Pattern loader**: `fsdb.Db.GetPattern(name)` → reads `system.md`; patterns can also define `user.md` for structured user-turn content.

**Pattern count and categories**: 256 total. High-value for a personal AI daemon:

| Category | Patterns (count) |
|----------|-----------------|
| Extract | 20+ (extract_wisdom, extract_insights, extract_ideas, extract_patterns, extract_skills, extract_recommendations, extract_references, extract_article_wisdom, extract_book_ideas, …) |
| Analyze | 25+ (analyze_paper, analyze_claims, analyze_malware, analyze_threat_report, analyze_logs, analyze_incident, analyze_prose, analyze_tech_impact, …) |
| Create | 30+ (create_summary, create_flash_cards, create_quiz, create_academic_paper, create_conceptmap, create_golden_rules, …) |
| Summarize/Explain | 10+ (summarize, explain_code, explain_docs, explain_terms, …) |
| Security | 10+ (analyze_malware, analyze_threat_report, analyze_threat_report_cmds, create_cyber_summary, create_network_threat_landscape, …) |

**The 15 highest-value patterns for a personal AI daemon:**

1. `extract_wisdom` — SUMMARY → IDEAS (20-50, exact 16 words each) → INSIGHTS (10-20) → QUOTES (15-30 exact) → HABITS → FACTS → REFERENCES → ONE-SENTENCE TAKEAWAY → RECOMMENDATIONS. **Full verbatim prompt:**

```
You extract surprising, insightful, and interesting information from text content. You are interested in insights related to the purpose and meaning of life, human flourishing, the role of technology in the future of humanity, artificial intelligence and its affect on humans, memes, learning, reading, books, continuous improvement, and similar topics.

STEPS:
- Extract a summary in 25 words (SUMMARY)
- Extract 20-50 most surprising, insightful, and/or interesting ideas (IDEAS) — exactly 16 words each
- Extract 10-20 best insights, more refined and abstracted than IDEAS (INSIGHTS) — exactly 16 words each
- Extract 15-30 most practical personal habits mentioned (HABITS) — exactly 16 words each
- Extract 15-30 surprising facts about the world mentioned (FACTS) — exactly 16 words each
- Extract all mentions of writing, art, tools, projects (REFERENCES)
- Most potent takeaway in 15 words (ONE-SENTENCE TAKEAWAY)
- Extract 15-30 most surprising recommendations (RECOMMENDATIONS) — exactly 16 words each
```

2. `analyze_paper` — structured academic paper analysis
3. `create_summary` — structured summary extraction
4. `analyze_claims` — claim verification and evidence analysis
5. `create_flash_cards` — Q&A pairs from content (8-16 word Q, ≤32 word A)
6. `extract_patterns` — 20+ patterns from observations, ADVICE FOR BUILDERS section
7. `explain_code` — code explanation
8. `analyze_malware` / `analyze_threat_report` — security-focused analysis
9. `find_logical_fallacies` — reasoning quality check
10. `improve_writing` — prose quality
11. `label_and_rate` — quality scoring
12. `create_golden_rules` — extract rules from content
13. `extract_insights` — insights extraction
14. `create_conceptmap` — knowledge graph from content
15. `analyze_prose` — writing style analysis

### 2. Where it beats NEOTH

| Gap | Their code | NEOTH equivalent | Delta |
|-----|-----------|-----------------|-------|
| 256 curated distillation patterns | `data/patterns/*/system.md` | `skills/bundled.rs` has ~N bundled skills but no structured content-analysis patterns | NEOTH has no equivalent of extract_wisdom, analyze_paper, create_flash_cards |
| Strategy injection (CoT, reflexion, self-refine, ToT) | `data/strategies/*.json` as prompt suffixes | `council/` adversarial panel, `council/self_reflect.rs` | NEOTH's mechanism is more complex (multi-agent) but also more powerful; simple strategy injections are a lightweight option NEOTH lacks |
| Pattern piping model | Shell pipe composability | None — NEOTH has no chain-pattern feature | Gap for multi-step processing |

### 3. Steal-list

**F1 — extract_wisdom distillation format as a bundled NEOTH skill** (S effort)
- What: The extract_wisdom prompt (verbatim above) + adapt for NEOTH's bundled skill format
- Consumer: `skills/bundled.rs` — new bundled skill `extract-wisdom`; also used as the synthesis template in `skills/doc_distill.rs` synthesis pass
- Integration: add to bundled skills array as a system_prompt-only skill with `trigger_keywords: ["extract wisdom", "summarize insights", "distill"]`
- Effort: S — just the prompt text in bundled.rs

**F2 — 15 high-value patterns as bundled skills** (M effort)
- What: analyze_paper, create_flash_cards, extract_patterns, create_flash_cards, analyze_claims, find_logical_fallacies, label_and_rate, create_golden_rules, analyze_malware, analyze_threat_report into bundled.rs
- Consumer: `skills/bundled.rs`, surfaced through existing `skills/router.rs`
- Attribution: MIT, cite `github.com/danielmiessler/fabric` in skill metadata's `homepage` field
- Effort: M — each is ~30-80 lines of prompt text; need trigger_keywords mapping

**F3 — Strategy injection as a low-overhead self-critique option** (S effort)
- What: The 4 strategy prompts (CoT, reflexion, self-refine, ToT) as optional request suffixes in `skills/doc_distill.rs`
- Consumer: `skills/doc_distill.rs::distill_chapter` — append strategy text to the per-chapter distillation request before calling provider
- This is specifically useful for the doc→skill pipeline's self-critique pass (use `self-refine` strategy on the distillation output)
- Effort: S — 4 string constants, 1 enum, 1 match arm

### 4. Architecture-fit check

| Steal | Rules at risk | Assessment |
|-------|--------------|------------|
| F1 bundled skill | Rules 2+3 — GUI must expose skill; Rule 9 — bundled skills already have a consumer (router) | Clean. Already a NEOTH pattern (bundled.rs exists) |
| F2 15 patterns | Same as F1. License requires no obligation beyond attribution | Clean. Add `homepage: "https://github.com/danielmiessler/fabric"` |
| F3 strategy injection | None — these are prompt strings, not code. Rule 4 (model-agnostic) — the prompts work on any model | Clean |

### 5. Verdict

**GROUND-TRUTH** for the pattern library — port the 15 high-value prompts verbatim as bundled NEOTH skills. The Go CLI infrastructure is not needed. **ADOPT-NATIVE** for F3 strategy injection. License: MIT, attribute via `homepage` field in skill YAML.

---

## (c) agent-skills (addyosmani/agent-skills · MIT · 81k★)

### 1. What it actually does

A reference collection of 24 structured skill prompts for coding agents (Claude Code / Amp / Copilot CLI), plus eval infrastructure, hooks, and references.

**Skill format** (each in `skills/<slug>/README.md`): Not YAML. These are structured markdown files with sections: Overview, When to Use, Core Principles (with named sub-principles), Anti-patterns, Quick Reference. Not a `SkillManifest` — more like documentation that the agent reads. Each principle carries named sub-rules (e.g., "Hyrum's Law", "The One-Version Rule") with When/How structure.

**Skills** (24): api-and-interface-design, browser-testing-with-devtools, ci-cd-and-automation, code-review-and-quality, code-simplification, context-engineering, debugging-and-error-recovery, deprecation-and-migration, documentation-and-adrs, doubt-driven-development, frontend-ui-engineering, git-workflow-and-versioning, idea-refine, incremental-implementation, interview-me, observability-and-instrumentation, performance-optimization, planning-and-task-breakdown, security-and-hardening, shipping-and-launch, source-driven-development, spec-driven-development, test-driven-development, using-agent-skills

**Evals system** (`evals/`): 3-tier architecture per `evals/README.md`:
- **Tier 1 — Trigger accuracy**: per-skill eval case `evals/cases/<slug>.json` with `trigger.positive[]` and `trigger.negative[]` prompts; `negative[].owner` names the expected winner skill (pairwise routing assertion)
- **Tier 2 — Behavioral**: `evals[].kind = "execution"` — full agent run against fixture files in `evals/fixtures/`; graded against `expectations[]` (verifiable behavioral statements)
- **Tier 3 — Dialogue**: `kind = "dialogue"` — no fixture files needed; transcript is the artifact

Eval case schema:
```json
{
  "skill_name": "test-driven-development",
  "trigger": {
    "positive": [{"prompt": "...", "top_k": 3}],
    "negative": [{"prompt": "...", "owner": "other-skill"}]
  },
  "evals": [{
    "id": 1, "kind": "execution",
    "prompt": "...", "expected_output": "...",
    "files": ["fixtures/..."],
    "expectations": ["A failing test is shown before the fix", ...]
  }]
}
```

**Hooks** (`hooks/`):
- `session-start.sh` (SessionStart hook): injects `using-agent-skills/SKILL.md` content into every new session as an IMPORTANT priority message — the agent reads the skill catalog on startup
- `simplify-ignore.sh` (PreToolUse Read + PostToolUse Edit/Write + Stop): protects blocks marked `<!-- SIMPLIFY-IGNORE -->` from simplification; replaces them with `BLOCK_<sha>` placeholders before agent reads, restores after agent writes
- `sdd-cache-post.sh` (PostToolUse WebFetch): caches response body with ETag/Last-Modified in `.claude/sdd-cache/`; prevents re-fetching unchanged docs

**References** (`references/`): 7 checklist files — accessibility, definition-of-done, observability, orchestration-patterns, performance, security, testing-patterns

**Agents** (4): code-reviewer, security-auditor, test-engineer, web-performance-auditor (agent definition .md files with specialized focus)

### 2. Where it beats NEOTH

| Gap | Their code | NEOTH equivalent | Delta |
|-----|-----------|-----------------|-------|
| Trigger accuracy eval (negative routing) | `evals/cases/*.json` trigger.negative with `owner` | `skills/test_harness.rs` | NEOTH tests skill execution but has no pairwise negative routing test — two skills that collide semantically go undetected |
| Session-start skill catalog injection | `hooks/session-start.sh` → IMPORTANT message with meta-skill content | No equivalent | Every NEOTH session starts blind to the active skill catalog |
| Simplify-ignore placeholder hook | `hooks/simplify-ignore.sh` | None | Blocks that should survive editing are unprotected |
| sdd-cache WebFetch hook | `hooks/sdd-cache-*.sh` | `tools/web_doc_cache.rs` | NEOTH has a document cache internally; no hook-level ETag revalidation for external web fetches |

### 3. Steal-list

**A1 — Pairwise negative routing test in test_harness.rs** (M effort)
- What: Extend `skills/test_harness.rs` with a `trigger_accuracy_test(skill_id, positive_prompts, negative_prompts_with_owner)` function that runs the router on each prompt and asserts positive wins + negative owner outranks tested skill
- Consumer: existing skill test suite; `cargo test -p neoth --test skill_routing` gate
- Integration: `skills/test_harness.rs` + `skills/router.rs` (router already exists, just needs test harness to call it with negative cases)
- Effort: M — ~100 lines new test infrastructure in test_harness.rs

**A2 — Session-start active skill catalog injection** (S effort)
- What: A `SessionStart` hook or daemon startup path that emits the active skill list (IDs + descriptions) as a context injection so the model knows what skills are available
- Consumer: `src/hooks/` SessionStart handler; injects into the initial system prompt via existing context injection mechanism (`memory/context_inject.rs`)
- Integration: daemon boot → enumerate enabled skills from `skills/registry.rs` → format as IMPORTANT system message via `memory/context_inject.rs`
- Effort: S — ~50 lines; the registry enumeration already exists, only the injection path is new

**A3 — Skill reference checklist files bundled as reference skills** (S effort)
- What: Port 7 reference checklists (security, observability, testing, performance, accessibility, definition-of-done, orchestration-patterns) as bundled NEOTH skills with `visibility: reference`
- Consumer: `skills/bundled.rs`; trigger: keyword-matched when user asks "what's the security checklist" etc.
- Effort: S — pure content, each ~1 page

### 4. Architecture-fit check

| Steal | Rules at risk | Assessment |
|-------|--------------|------------|
| A1 pairwise routing test | Rule 9 (real consumer) — the test harness is not end-user code; consumer is CI gate | Test-only code, no runtime risk |
| A2 session-start injection | Rules 2+3 (GUI parity) — GUI session start must also show active skills; Rule 5 (no audit trail needed for read-only metadata display) | Add to GUI startup panel; benign content (own skill metadata) |
| A3 bundled checklists | Rule 9 — consumer is keyword router in existing bundled skill lookup | Clean |

### 5. Verdict

**ADOPT-NATIVE** for A1 and A2 (port the eval schema + session-start mechanism into Rust). **GROUND-TRUTH** for A3 (port the 7 checklist files as content). License: MIT.

---

## (d) system-design-101 (ByteByteGo · 86k★)

### 1. What it actually does

A curated knowledge corpus — ByteByteGo newsletter content as structured markdown. Source-only; no runnable code.

**Structure:**
- `data/categories/` — 15 category files: ai-machine-learning, api-web-development, caching-performance, cloud-distributed-systems, computer-fundamentals, database-and-storage, devops-cicd, devtools-productivity, how-it-works, payment-and-fintech, real-world-case-studies, security, software-architecture, software-development, technical-interviews
- `data/guides/` — 60+ individual guide markdown files (e.g., "100x-postgres-scaling-at-figma.md", "18-key-design-patterns-every-developer-should-know.md", "11-steps-to-go-from-junior-to-senior-developer.md")
- `package.json` / `pnpm-lock.yaml` — website build tooling (irrelevant for adoption)

Content quality: high-density visual explanations of system design concepts. Typical entry: 2-4 paragraphs of precise definition + "when to use" + trade-offs. The categories are link collections to external newsletter posts; the guides are short standalone articles.

### 2. LICENSE — HARD BLOCK

The license is **CC BY-NC-ND 4.0** (`LICENSE.md`):
- **NC (NonCommercial)**: cannot use for commercial purposes
- **ND (NoDerivatives)**: cannot distribute adapted/modified versions

This creates TWO fatal barriers for NEOTH:
1. Any bundling of this content in NEOTH's binary = "distribution of adapted material" (reformatted as skills/prompts = adaptation) = **ND violation**
2. If NEOTH is ever sold or used commercially = **NC violation**

Cannot be used as: bundled skills, bundled wiki content, training data for internal models, or any compiled-in knowledge base.

**Can** only be used as: a reference link a user opens in a browser themselves. No scraping at runtime on behalf of the user (that would be redistribution of a derived work).

### 3. Steal-list

None. Hard SKIP on licensing grounds.

### 4. Architecture-fit check

N/A — license blocks all adoption paths.

### 5. Verdict

**SKIP**. License: CC BY-NC-ND 4.0 — violates ND on any bundling/adaptation, NC on any commercial use. The content quality is high but irrelevant given the license. If Alex wants this content in NEOTH's vault, he must license it separately from ByteByteGo or generate equivalent content from scratch.

---

## PROPOSED: doc→skill pipeline (operator ask)

### Design Brief

The operator's ask: "NEOTH soll PDFs oder Dateien aus Obsidian lesen können und die automatisch mit self-reflect in Skills verwandeln — pro-aktiv."

Existing infrastructure that survives: `media/pdf.rs` + `media/document.rs` (extraction) → `security/ingress_sanitizer.rs` (defang) → `proactive/action_staging.rs` (consent gate) → `skills/creator.rs` (install) → WAL. The arxiv_skill_scan_cron.rs is the EXACT structural precedent — text → provider → facts → groundtruth. The new pipeline generalizes this from arXiv abstracts to arbitrary documents.

### Pipeline Stages

```
[Source] ──► [Extract] ──► [Sanitize] ──► [Distill] ──► [Route] ──► [Self-critique] ──► [Stage] ──► [Install]
                                              ↓
                                        [Cost gate]
```

**Stage 1 — Source Trigger** (where the trigger lives)

Three entry points:
- **A. Manual**: `/skill-from-doc <path>` slash command → `src/slash/` handler calls pipeline directly
- **B. Watcher**: `daemon/doc_ingest_cron.rs` (new file, follows `arxiv_skill_scan_cron.rs` structure) — watches `freedom.yaml::doc_ingest_watch_paths[]` for new/modified files; debounce 30s; disabled by default
- **C. Obsidian vault**: the same watcher covers `~/.neoth/vault/` or configured vault root; any new `.md` or `.pdf` added to vault triggers pipeline with consent prompt first

**Stage 2 — Extraction** (REUSE existing)

`media/pdf.rs::PdfExtractor::extract(asset)` for PDFs (2000-page cap, 64MB input cap, 8MB text cap, isolated worker process — already hardened)
`media/document.rs::DocumentExtractor::extract(asset)` for DOCX/EPUB/PPTX/RTF
Output: `Extraction { text: String, metadata: serde_json::Value }`

No new code here. Wire: `doc_distill.rs` takes an `Extraction` as input.

**Stage 3 — Ingress Sanitization** (REUSE Rule 6)

Call `security::ingress_sanitizer::defang_prompt_delimiters(&extraction.text)` and `security::content_scanner::scan(&extraction.text)` before any LLM call. The document text is tagged `UntrustedContextClass::DocumentContent` (new variant, parallel to `ModelOutput`). This is the same pattern teacher.rs uses for local model output.

**Stage 4 — Budget Gate** (NEW — steal from book-to-skill S4)

```rust
// In skills/doc_distill.rs
fn estimate_tokens(text: &str) -> usize { text.split_whitespace().count() * 4 / 3 }

pub async fn preflight_estimate(extraction: &Extraction) -> DocDistillEstimate {
    DocDistillEstimate {
        token_count: estimate_tokens(&extraction.text),
        estimated_chapters: detect_chapter_count(&extraction.text),
        // emitted to ProactiveQueue / GUI before proceeding
    }
}
```

For CLI: print estimate and `Proceed? [y/N]`. For daemon watcher: publish as ProactiveItem (priority=50, TTL=24h) asking operator to approve the distillation budget. Only proceeds on approval.

**Stage 5 — Distillation** (NEW — `skills/doc_distill.rs`)

This is the new module. ~400 lines. Follows `arxiv_skill_scan_cron.rs::extract_learnings` structure but is more sophisticated:

```rust
pub struct DistilledDoc {
    pub summary: String,              // 25-word summary
    pub frameworks: Vec<Framework>,   // named frameworks with when/how
    pub principles: Vec<String>,      // actionable rules
    pub anti_patterns: Vec<String>,   // what to avoid
    pub takeaways: Vec<String>,       // top 7 insights (steal: extract_wisdom format)
    pub chapter_sections: Vec<ChapterSection>,  // per-chapter summaries
    pub provenance: DocProvenance,    // source path, hash, extraction timestamp
}

pub struct DocProvenance {
    pub source_path: PathBuf,
    pub content_hash: String,   // sha256 of extracted text — dedup key
    pub chapters_detected: usize,
    pub extracted_at: u64,      // unix ns
}
```

Two-pass distillation:
- **Pass 1 — Structure detection**: read first 8K chars → detect chapter structure → `Vec<(chapter_title, byte_start, byte_end)>`. Uses chapter heading regex (Arabic + Roman numerals, same pattern as `book_to_skill.utils._chapter_number`).
- **Pass 2 — Per-chunk extraction**: for each chapter (or 4K-token chunk if no chapters detected), call provider with the chapter distillation prompt (steal S2 from book-to-skill). For large docs (>50k tokens), use byte-range slice of `extraction.text[start..end]` per chapter (steal S3).

**Distillation prompt** (steal S2 + F1, adapted for NEOTH):

```
You are a knowledge distillation assistant. Given a section of text, extract structured knowledge suitable for a reusable skill.

Respond with ONLY valid JSON:
{
  "summary": "<25 words: what this section teaches>",
  "frameworks": [{"name": "<exact author naming>", "when_to_use": "<specific situation>", "how": "<steps or criteria>"}],
  "principles": ["<actionable rule, 16 words max>"],
  "anti_patterns": ["<what to avoid: why>"],
  "takeaways": ["<actionable insight, 16 words max>"],
  "computer_executable_procedures": [{"title": "<imperative phrase>", "steps": ["<step>"]}],
  "confidence": <0.0-1.0>
}

Rules:
- "frameworks" should use the EXACT name the author uses, not a paraphrase
- "computer_executable_procedures" only if steps can run without human judgment
- "confidence" >= 0.7 = this section contains substantive teachable knowledge

SECTION TEXT:
{CHAPTER_TEXT}
```

**Stage 6 — Route Decision** (NEW — in `skills/doc_distill.rs`)

```rust
pub enum DistillRoute {
    NewSkill(SkillManifest),              // new skill proposal
    PatchExistingSkill(SkillId, Patch),   // patch to existing skill's system_prompt
    MemoryFacts(Vec<String>),             // to groundtruth (low computer-executable content)
    WikiEntry(String),                    // to wiki/writer.rs (reference material)
}

pub fn route(distilled: &DistilledDoc, registry: &SkillRegistry, embeddings: &EmbeddingIndex) -> DistillRoute {
    // 1. Check dedup: sha256 of source_path + content_hash already in provenance store? → skip
    // 2. If computer_executable_procedures exist with confidence >= 0.7 → consider skill
    //    a. Compute embedding similarity of doc summary against existing skill descriptions
    //    b. similarity > 0.85 → PatchExistingSkill
    //    c. 0.60-0.85 → stage as NewSkill with "possible overlap" note
    //    d. < 0.60 → NewSkill
    // 3. If no computer_executable_procedures → MemoryFacts (to groundtruth scope="doc-learning")
    //    OR WikiEntry if it's reference material (detected by: mostly definitions, no procedures)
}
```

Dedup key: `content_hash` from `DocProvenance` — same doc processed twice = no-op.

Merge key for patching: semantic embedding cosine similarity against existing skill `description` + `system_prompt` (uses existing `memory/embeddings.rs`).

**Stage 7 — Self-Critique** (NEW — lightweight, not full council)

After routing to NewSkill or PatchExistingSkill, run a single self-critique call using the reflexion strategy (steal F3):

```rust
let critique_prompt = format!(
    "Review this skill proposal for quality:\n\n{}\n\n\
     Critique: Is it accurate? Is it actionable? Is it novel vs. existing skills? \
     Provide a refined version or confirm as-is. Answer concisely, critique briefly, \
     then provide the refined skill or CONFIRM.\n\nRefined skill:",
    &draft_yaml
);
```

This is a single additional provider call, NOT a full council round. For budget control: skip if `doc_distill_self_critique_enabled: false` in freedom.yaml (default: true).

**Stage 8 — Consent Gate** (REUSE `proactive/action_staging.rs`)

Every proposal — whether NewSkill or PatchExistingSkill — goes through `action_staging::stage_proposal(ProposalKind::Skill, draft_yaml)`. This:
1. Writes the proposal to `~/.neoth/proposals/<id>.json`
2. Writes a human-readable markdown draft to Obsidian vault under `Proposals/<id>.md` with embedded YAML block
3. Pushes a `ProactiveItem` to `ProactiveQueue` (priority=50, channel=operator_default)
4. Only `adopt_approved_skill()` actually installs it — explicit operator approval required

**Stage 9 — Install + WAL** (REUSE existing)

`adopt_approved_skill()` → `skills/creator.rs::write_skill_yaml_audited()` → existing WAL.

New WAL opcodes in Extended-Subtype band (since base opcodes 255/255 exhausted):

```rust
// In src/wal/events.rs, ExtendedSubtype variants:
DocIngestStarted = 0x01,    // source path + content hash
DocDistillComplete = 0x02,  // chapter count + route decision
DocSkillProposed = 0x03,    // proposal ID
DocSkillApproved = 0x04,    // skill ID
DocSkillRejected = 0x05,    // proposal ID + reason
```

### Failure Mode Mitigations

**Prompt injection from untrusted PDF:**
- Stage 3 sanitization is mandatory — `defang_prompt_delimiters` + `content_scanner` on all extracted text BEFORE any LLM call
- Document text is bracketed in the prompt: `\n---DOCUMENT-START---\n{CHAPTER_TEXT}\n---DOCUMENT-END---\n` with XML-style fences stripped (steal from ingress_sanitizer pattern)
- Stage 8 scan: run `skills/generated_scan.rs` (steal S1) on the generated skill YAML before staging — 7 injection patterns
- If scan finds findings: downgrade to MemoryFacts route instead (never install a skill from poisoned content)

**900-page book blowing budget:**
- Stage 4 budget gate emits cost estimate and requires explicit approval
- Stage 5 processes one chapter at a time (byte-range slicing, steal S3); chapters processed sequentially (same as arxiv cron's `max_per_topic` cap)
- Hard cap: `MAX_CHAPTERS_PER_DOC = 50` (configurable in freedom.yaml); remaining chapters become MemoryFacts
- Provider call budget: `cost_authorization::AuthorizedProvider` wraps all calls (existing mechanism from arxiv_skill_scan); if budget exceeded → stop, return partial `DistilledDoc`

**Skill registry pollution (100 junk skills from one vault import):**
- Rate limit: `ProactiveQueue::daily_cap` (default 3/day) applies to doc-ingest proposals; an entire vault import gets queued at one per day max
- Minimum confidence: only route to NewSkill if `distillation.confidence >= 0.7` AND `computer_executable_procedures.len() >= 1`
- `MAX_PROPOSAL_ENTRIES = 4096` is the existing staging area cap
- Bulk import path: for a folder import, produce ONE skill per document maximum (no sub-chapter skills from a single doc)
- Operator veto: any rejection from the consent gate writes to `Rejected` status; same source document cannot be re-proposed within 7 days

### New vs. Patch vs. Memory vs. Wiki — Decision Matrix

| Condition | Route |
|-----------|-------|
| ≥1 computer_executable_procedures, confidence ≥ 0.7, similarity to existing skill > 0.85 | PatchExistingSkill |
| ≥1 computer_executable_procedures, confidence ≥ 0.7, similarity 0.60-0.85 | NewSkill (with "possible overlap: <existing_id>" note) |
| ≥1 computer_executable_procedures, confidence ≥ 0.7, similarity < 0.60 | NewSkill |
| No computer_executable_procedures OR confidence < 0.6, document is mostly procedures/guides | MemoryFacts → `groundtruth` scope="doc-learning" |
| No procedures, document is mostly definitions/reference | WikiEntry → `wiki/writer.rs` |
| Sanitization findings detected | Abort, log to WAL, never stage |

### Build Order — Staged Slices

**Slice 1 (ships independently, ~1 week): Manual slash command**
- New file: `skills/doc_distill.rs` — `distill_doc(Extraction) → DistilledDoc`, using chapters + distillation prompt (steal S2). Single-pass initially (no chapter detection yet).
- Wire to existing `media/pdf.rs` + `media/document.rs` via `Asset::from_path()`
- Call `ingress_sanitizer` on extracted text (Rule 6)
- Output: print `DistilledDoc` as markdown to CLI — no skill installation yet
- New slash command: `/skill-from-doc <path>` shows the extracted content to operator for manual review
- Consumer: Alex immediately, provides value as a "show me what this doc contains" feature

**Slice 2 (~1 week after Slice 1): Consent-gated skill staging**
- Add route decision logic (skill vs. memory, via confidence threshold only — no embeddings yet)
- Wire `action_staging::stage_proposal` for skill route
- Wire `groundtruth::insert` for memory route
- Add WAL opcodes (Extended-Subtype band)
- Add `skills/generated_scan.rs` injection scanner (steal S1)
- Add pre-flight cost estimate (steal S4) — emitted to ProactiveQueue

**Slice 3 (~1 week after Slice 2): Proactive watcher**
- New file: `daemon/doc_ingest_cron.rs` — file system watcher (using `notify` crate already in tree or add) for configured paths
- Freedom.yaml keys: `doc_ingest.enabled`, `doc_ingest.watch_paths[]`, `doc_ingest.max_per_day`
- Obsidian vault auto-watch when vault is configured
- Disabled by default (Rule 2)

**Slice 4 (v1.1 scope): Embedding-based dedup + patch existing skill**
- Add similarity check against existing skill embeddings before routing to NewSkill
- PatchExistingSkill route: append new procedures to existing skill's `system_prompt`
- Chapter-level provenance storage: store `DocProvenance` in SQLite alongside groundtruth

### Files That Change Per Slice

| Slice | New files | Modified files |
|-------|-----------|---------------|
| 1 | `skills/doc_distill.rs` | `slash/mod.rs` (new command), `media/mod.rs` (expose Asset::from_path) |
| 2 | `skills/generated_scan.rs` | `skills/doc_distill.rs` (route fn), `wal/events.rs` (new ExtendedSubtype variants), `daemon/audit_rpc/server.rs` (allowlist), `freedom.yaml` template |
| 3 | `daemon/doc_ingest_cron.rs` | `daemon/mod.rs` (spawn), `freedom.yaml` template |
| 4 | — | `skills/doc_distill.rs` (embedding route), `memory/embeddings.rs` (skill embedding index) |

---

## Summary Steal-List (Ranked)

| # | Item | Source | Target NEOTH file | Effort | Real consumer |
|---|------|---------|-------------------|--------|---------------|
| 1 | Post-generation injection scanner (7 patterns + symlink check) | book-to-skill/tools/scan_generated_skill.py | `skills/generated_scan.rs` (new) | M | `skills/creator.rs::write_skill_yaml_audited` |
| 2 | Chapter distillation prompt template (Core Idea → Frameworks → Worked Example → Takeaways) | book-to-skill/SKILL.md Step 7 | `skills/doc_distill.rs::CHAPTER_DISTILL_PROMPT_TMPL` | S | `skills/doc_distill.rs::distill_chapter` |
| 3 | extract_wisdom prompt (SUMMARY → IDEAS → INSIGHTS → QUOTES → HABITS → FACTS → RECOMMENDATIONS, 16 words each) | fabric/data/patterns/extract_wisdom/system.md | `skills/bundled.rs` + `skills/doc_distill.rs` synthesis pass | S | `skills/router.rs` + doc distillation synthesis |
| 4 | REPL/line-range large-doc access (byte-range chapter reading) | book-to-skill/SKILL.md Step 2.6 | `skills/doc_distill.rs::detect_chapter_offsets` | S | `doc_distill.rs::distill_doc` when text.len() > 50K tokens |
| 5 | 14 fabric patterns as bundled skills (analyze_paper, create_flash_cards, extract_patterns, analyze_claims, find_logical_fallacies, label_and_rate, create_golden_rules, analyze_malware, analyze_threat_report, explain_code, create_summary, extract_insights, create_conceptmap, analyze_prose) | fabric/data/patterns/*/system.md | `skills/bundled.rs` | M | `skills/router.rs` |
| 6 | Pairwise negative routing test | agent-skills/evals/README.md + evals/cases/*.json | `skills/test_harness.rs` | M | CI gate, cargo test |
| 7 | Self-refine / reflexion strategy as single self-critique call | fabric/data/strategies/reflexion.json + self-refine.json | `skills/doc_distill.rs::self_critique_prompt` | S | `doc_distill.rs` Stage 7 |
| 8 | Pre-flight token cost estimate display | book-to-skill/SKILL.md Step 2.5 | `skills/doc_distill.rs::preflight_estimate` | S | ProactiveQueue + GUI |
| 9 | Session-start active skill catalog injection | agent-skills/hooks/session-start.sh | `daemon/startup.rs` or `hooks/` SessionStart handler | S | Daemon startup, every session |
| 10 | 7 reference checklist skills | agent-skills/references/*.md | `skills/bundled.rs` | S | `skills/router.rs` |

**First-slice recommendation: Ship Steal #2 + #4 + partial #1 together as `/skill-from-doc`** — this gives the operator the complete extraction-and-display path with injection safety, immediately usable, before any consent/staging infrastructure. Steal #3 (extract_wisdom bundled skill) is a one-liner alongside this. Total first-slice: one new file (`skills/doc_distill.rs`, ~200 lines), one new slash command, three stolen prompt constants.

---

## Items that contradict the brief's baseline

1. **book-to-skill is NOT a library** — it's a skill (SKILL.md) executed by the agent. There is no callable Python API for distillation. The value is the prompts and the text-extraction preprocessing scripts. Do not port the Python orchestration; port only the prompt templates and the injection-scanner logic.

2. **fabric `extract_skills` pattern is NOT useful for our purpose** — it extracts job-description skill terms into a table (hard/soft skill classification from HR listings). Ignore it. The valuable patterns are `extract_wisdom`, `analyze_paper`, `create_flash_cards`, `extract_patterns`.

3. **No book-to-skill self-critique exists to steal** — the project has no self-critique or self-refine pass. NEOTH's proposed Stage 7 (reflexion strategy) is NEOTH-native, not from book-to-skill.

4. **system-design-101 is a hard block** — CC BY-NC-ND 4.0 is incompatible with bundling or modification. Do not use, even as a reference for bundled content.

5. **WAL opcode exhaustion applies** — any new WAL events from Slices 2+ MUST use ExtendedSubtype band per the existing constraint in `wal/events.rs`. The report's Stage 9 accounts for this.
