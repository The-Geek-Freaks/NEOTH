# W177: Explicitly accepted local training datasets

W177 implements ADOPT31-D1 through fourteen source files. A strict autocommit
agent-turn insertion produces an internal receipt bound to the owning database,
session and row. Direct CLI and daemon terminal producers retain that receipt
through writer drain or flush before minting an opaque feedback target. Missing,
foreign or failed receipts and incognito responses remain unavailable for
feedback while normal chat completion is preserved.

Accepted is an explicit CLI and Main/Buddy action. Revision-CAS, verified GUI
readback, both negative labels, Remove and stale/foreign-target fences remain.
Legacy unbound records stay readable but cannot become training-eligible.

The additive `neoth export training-set` exports OpenAI or ShareGPT JSONL from
exact Accepted agent rows and their immediately preceding same-session operator
rows. It applies canonical redaction, excludes and counts ineligible candidates,
and permits teacher replacement only for one unambiguous selected original.
Usage contributes bounded provenance aggregates. Dataset and manifest publication
uses create-new operations, refuses conflicting/incomplete existing pairs, and
recognizes an identical complete pair. It does not claim two-file atomicity.
Generic export help, communication-profile output and DSAR rejection remain.
See [operator usage](training-set-export.md).

Fourteen new universal regression identities cover receipt validation, labels,
read-only candidate retrieval, exact pairing, both formats, exclusions, teacher
ambiguity, publication and real daemon-GUI production. The latter runs the actual
mock-provider chat path, post-reply transcript insertion and writer flush, then
Accepted/export, both negative replacements, Remove and an incognito turn.
Existing CLI-finalizer tests retain their assertions. The existing Main/Buddy
callback covers Accepted -> NeedsCorrection -> NotHelpful -> Remove at revisions
1 through 4; its name and the reducer test name are preserved. The public bridge
fixture continues to construct and exhaustively match only response/session/
revision and now also checks its Debug representation for private receipt fields.

The four existing W164 CLI fixture registrations are corrected from `cli::chat::tests`
to their actual `cli::chat::wave35_adapter_lifecycle_tests` module. This is an
identity correction, not four additional tests. Historical W164 evidence is
retained unchanged.

Independent reviews are retained under `work/gold-20260906/wave177-next-batch`:

- Review01: `0BDE1169378482BD565BA7DE4F925C5E09111D00FEF89E5356AFF082BAF20ADE`.
- Final Review02: `6620F305AF269D2A878A16A896BDF97ECD6CE34BDADFFE3F6127F9756FC4E091`.
- Producer acceptance receipt02: `225B8D14A6D112533A09817CDDD90DA6B95412D48EA289C1E10EF24A0B6EAADA`.
- Backend receipt02: `A4ED7F65470F46D64F33E4F9CD93E7BACA28806B3F5658836C280E2D221603C6`.

This is source approval. Exact-head Hosted formatting, compilation, generated
CLI reference, strict Clippy, native tests and GUI acceptance remain required.
No local executable validation ran and ADOPT31-D1 remains open.

Integration correction03 uses Debug for the fixed rejection enum, normalizes
the two remaining CRLF lines, and keeps owned dataset text alive while the
daemon test borrows its lines. Review03 confirms the error/line-ending delta
(SHA-256 242729A376DED2F35D77B407A28AA1896315ABB27F37A079F5A029AF26977D36);
Root reviewed the two test-only lifetime repairs. Prior reviews remain intact.
