# Council agreement V1

V1 adds a conservative agreement gate to production Council debates. Each
hemisphere declares one factual statement, one recommendation and one risk
assessment in a bounded final protocol block. These are model declarations,
not an independent semantic analysis or proof that an answer is correct.

The static protocol instruction sits outside the untrusted question envelope
and before optional ground-truth context; recursion forwards that framed
prompt once. The operator-facing answer excludes protocol material. A reply
containing only an envelope cannot count as a usable answer. Each statement
is limited to 512 UTF-8 bytes. An absent, malformed, duplicate, non-final or
oversized block yields missing evidence. An explicit `NONE` means a dimension
does not apply; it never earns an agreement point.

| Dimension | Weight |
| --- | ---: |
| `factual_claims` | 0.50 |
| `recommendations` | 0.30 |
| `risk_assessment` | 0.20 |

Comparison normalizes only case and whitespace. Numbers, punctuation,
negation and word order remain significant; paraphrases count as different.
Every pair of usable hemispheres scores either one for identical statements
or zero for different statements. The dimension score is the pairwise mean.
The aggregate uses the weights above, renormalized over applicable dimensions.

Missing evidence has no numeric score and prevents V1 consensus. All-`NONE`
dimensions have no numeric score; mixing `NONE` and a statement disagrees.
Consensus requires the existing whole-answer quorum/dissent rule and exact
textual identity in every applicable dimension, with at least one scored
dimension. Partial scores describe disagreement and cannot authorize consensus.

The V1 contract requires parsing before refusal classification, dissent,
early quorum, factual checking and winner selection, including nested
production debates. Factual checking uses the normal answer plus only the
declared factual statement. Recommendations and risk statements are excluded
from that factual input. Nested debates share the original budget.

Durable `COUNCIL_AGREEMENT_EVALUATED` audit data contains only the prompt hash,
protocol version, identity flag, scores, dimension states and role/reason
metadata. It contains no declared statements. The shared CLI/channel dispatch
respects incognito mode. Legacy direct library entry points retain their
historical behavior and report `not_evaluated`.

Implementation acceptance and runtime evidence are tracked separately in the
Gold roadmap. This contract alone is not evidence that P1-06 has passed.
