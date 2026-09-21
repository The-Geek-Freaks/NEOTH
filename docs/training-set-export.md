# Local training-set export

The training-set exporter creates a redacted JSONL dataset and a companion
manifest on the operator's machine. It does not start training or call a model
provider. This W177 implementation is awaiting Hosted acceptance.

An example is eligible only after the operator explicitly selects **Accept for
local training** for a completed response in Main Chat or Buddy. The terminal's
feedback capability is privately bound to that exact stored agent response.
Incognito responses and responses without a committed transcript receipt cannot
receive an eligible capability. Existing unbound feedback records remain
ineligible even if they came from the same session.

The CLI exposes the same explicit choice:

```powershell
neoth feedback response set --response <RESPONSE_ID> --session <SESSION_ID> --revision <CURRENT_REVISION> --signal accepted
```

Use the opaque response and session values supplied with that completed reply,
and the current revision. Feedback changes retain the existing revision check.
Replacing Accepted with Needs correction or Not helpful excludes the response;
Remove leaves it unlabelled and also excludes it from subsequent exports.

Choose an explicit output file and format:

```powershell
neoth export training-set --out .\training-openai.jsonl --format openai
neoth export training-set --out .\training-sharegpt.jsonl --format sharegpt
```

Each record contains only a user message and an assistant message. The exporter
requires the operator row immediately preceding the bound agent row to belong
to the same session. It does not infer pairs from nearby timestamps, usage
events, or session-wide searches. Missing, negative, unlabelled, unbound and
ambiguous candidates are excluded and counted in the manifest. Feedback's
existing bounded projection limits which current response capabilities are
available; this is not an export of every historical conversation.

An existing teacher correction can replace the assistant text only when its
original-answer hash identifies one eligible original answer unambiguously.
Malformed or ambiguous corrections exclude that candidate. Every exported
message passes through NEOTH's canonical redaction before JSON serialization.
Usage data contributes separate provenance counts and never manufactures a
conversation pair.

The sibling manifest binds the dataset bytes with SHA-256 and records exported,
corrected and excluded counts. Publication refuses to overwrite an existing
different or incomplete pair. An identical complete pair returns unchanged.
The manifest is published before the dataset; the two files are not represented
as one atomic filesystem operation.

The existing generic `neoth export` command and its private-DSAR rejection
behavior remain available. Generated CLI help is updated from the Hosted binary
after compilation; source implementation alone is not runtime acceptance.
