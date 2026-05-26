PL-04a — Adversarial OCR corpus for the paperless ingest gate.

Each fixture is a single JSON file. The runner
`SRC/neothd/tests/prompt_injection_corpus_paperless_ocr.rs`
feeds `input_text` to `security::paperless_ingest::ingest_ocr_text`
and asserts the documented `expected_outcome`.

## Fixture schema

| field            | type   | required | description                                    |
|------------------|--------|----------|------------------------------------------------|
| id               | string | yes      | stable identifier, used in failure messages    |
| category         | string | yes      | groups fixtures (english_direct, role_escape…) |
| description      | string | yes      | one-line context                               |
| input_text       | string | yes      | raw OCR string fed to ingest_ocr_text          |
| expected_outcome | enum   | yes      | see below                                      |
| expected_marker  | string | no       | substring required in Quarantined.findings     |
| source           | string | yes      | provenance — manual_curation, owasp_llm_top10… |

## `expected_outcome` values

- **quarantine** — `ingest_ocr_text` MUST return `Err(IngestError::Quarantined)`.
  If `expected_marker` is set, one finding MUST contain that substring.
  These are the PL-04 regression guards.

- **allow_clean** — must return `Ok(payload)` with no
  `Finding::PromptInjectionMarker` entry. False-positive guards — benign OCR
  text that resembles attack markers (receipt mentioning "ignore", contract
  with "Assistant Director", etc.).

- **known_gap_quarantine_after_pl04** — currently `Ok(_)` because the
  sanitizer's marker list doesn't cover this attack class. The runner
  asserts the CURRENT behavior (Ok) so a PL-04 fix that flips it to Err
  trips this test — that's the signal to promote the fixture to
  `expected_outcome: quarantine`. This pile IS the PL-04 punch list.

## Adding a fixture

Drop a JSON file in this directory. No code change needed — the runner
discovers files by extension.
