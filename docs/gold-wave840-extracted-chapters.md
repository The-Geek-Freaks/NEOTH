# Large document chapters

The document review commands support chapter selection over extracted PDF,
Office and book text. The existing extractors first process the admitted
binary document; chapter offsets refer to their UTF-8 text output. They never
refer to byte positions inside a PDF or an Office archive.

For extracted text larger than 200 KiB, `neoth skills --from-doc PATH` and
`/skill-from-doc` return a chapter-selection-required result. Use:

```text
neoth skills --list-doc-chapters PATH
neoth skills --from-doc-chapter PATH --chapter-index INDEX
```

The second command reviews the selected range through the existing untrusted
document sanitizer. Each range fits that sanitizer's 64 KiB input limit.
The commands remain provider-free and do not stage, install or activate a
skill. The provider-backed `--distill-doc` operation still requires a document
that fits its full-review path; selected chapter review does not imply a new
provider invocation or staging capability.

For raw `.txt`, `.md` and `.markdown` sources, these commands retain the
bounded streaming reader and retained source handle. Binary documents use the
existing owned-byte admission and extractors. Small extracted documents retain
the full-review behavior and its existing sanitizer limits.

Chapter receipts carry the original document's kind, byte count and SHA-256,
the extracted text's byte count and SHA-256, and the selected byte range.
Structured receipts exclude raw extracted text. A command reads a fresh
document snapshot; the receipt identifies that snapshot and does not authorize
a later effect. An extractor-reported truncation is refused before chapter
selection, so an early chapter cannot conceal an omitted document tail.

Executable validation runs on GitHub under the workstation's BSOD hold.
The original ADOPT31-B3 row stays open until the actual extraction, connected
review, selection and truncation cases have been admitted from hosted results.
