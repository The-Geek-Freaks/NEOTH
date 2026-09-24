# Document proposals and explicit approval

An accepted document distillation can now propose one operator-selected
destination. Generation produces a pending proposal. Applying it requires a
separate `neoth proactive accept <proposal-id>` command.

```text
neoth skills --distill-doc guide.md --min-reflexion-score 80 --stage-route skill --stage-target review-guide
neoth skills --distill-doc guide.md --min-reflexion-score 80 --stage-route memory --stage-target project-notes
neoth skills --distill-doc guide.md --min-reflexion-score 80 --stage-route wiki --stage-target C:\Notes --stage-subdir NEOTH
neoth proactive show <proposal-id>
neoth proactive accept <proposal-id>
neoth proactive reject <proposal-id>
```

`--stage-target` means a Skill id, a Memory scope, or an existing absolute vault
directory, according to the chosen route. The provider cannot supply or change
this target. The optional Wiki subdirectory defaults to `NEOTH` and must be one
directory name. The ordinary `--distill-doc` command without staging flags keeps
its existing review-only result. Provider-free document and chapter review also
keep their existing behavior. Large-document provider execution still requires
the separately tracked chapter integration; this batch does not add a watcher.

Before either provider call, the command displays the token/cost estimate for
the actual staged request and the bounded review request. It then uses the
existing consent and cost-authorizing provider. One candidate call is followed
by one scored review, with no automatic retry. Malformed, refused, truncated,
unsafe, low-scoring, or rejected candidates create no proposal.

The pending `Document` proposal stores a strict canonical draft that binds the
source digest, sanitized input digest, candidate digest, route, exact target,
score, and threshold. Existing proposal locking and immutable payload checks
protect the approval record. Its notification contains only the proposal id and
review instructions. The draft is available through `proactive show`; the
distillation's machine-readable acknowledgement contains metadata, not candidate
text. Repeated staging preserves an existing terminal verdict.

After approval:

- **Skill:** the strict provider envelope must contain a valid scanned manifest
  for the selected id. The existing installer installs it with `enabled: false`.
  Activation remains a separate operation. An edited installed target is kept.
- **Memory:** bounded claims enter the existing `BulkText` source class. Schema
  v46 adds an applied-once ledger in the same SQLite savepoint as the fact
  effects. Replaying the same source/claim/scope cannot increase confidence or
  confirmation count. A different document may corroborate once. Hard deletion
  leaves a null-linked ledger tombstone, so privacy purges remain possible and
  replays cannot recreate the deleted fact.
- **Wiki:** a user-knowledge note is created under
  `<vault>/<subdir>/Documents/<proposal-id-sha256>.md`. Every path component is
  admitted without following links. Publication is exclusive and never replaces
  an existing note. Exact existing bytes reconcile a prior successful effect;
  different or oversized bytes refuse and preserve the operator's file. This
  route does not write NEOTH's self-wiki or Paperless notes.

Approval is recorded before the effect. A failed application therefore leaves
an approved proposal with an explicit error. A separate metadata-only Extended
WAL event follows a successful effect (`DocumentSkillApplied`,
`DocumentMemoryApplied`, or `DocumentNoteApplied`). If audit delivery fails,
re-accepting the unchanged proposal reconciles the effect before retrying audit;
the WAL is not the Memory replay ledger.

For vault notes, an actual publication or validation failure remains a recovery
state. Windows' lack of parent-directory sync support is reported separately as
`namespace_durability=unsupported` after exact live file verification; it does
not claim power-loss durability.

## Verification boundary

Source review found and corrected the OMI purge foreign-key conflict and the
Windows directory-sync distinction before publication. New fixtures cover the
producer, CLI staging, approval consumers, atomic claim replay and rollback,
actual OMI deletion, vault reconciliation, and registered audit boundaries.
Executable validation runs only on GitHub under the workstation's BSOD hold.
B7 remains open until the required hosted behavior results are admitted.
