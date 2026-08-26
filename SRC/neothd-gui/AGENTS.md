# GUI working contract

Before reviewing or changing any `.slint` file in this subtree, read all of:

1. [`../../design-system/PRODUCT.md`](../../design-system/PRODUCT.md)
2. [`../../design-system/DESIGN.md`](../../design-system/DESIGN.md)
3. [`ui/COMPONENT_API.md`](ui/COMPONENT_API.md)

Treat `ui/theme.slint` as the production visual-token authority. Use
`Theme.*` from views rather than introducing visual literals. For GUI changes,
record the applicable evidence from
[`../../design-system/lint_rules.md`](../../design-system/lint_rules.md) and
[`../../design-system/AUDIT_CHECKLIST.md`](../../design-system/AUDIT_CHECKLIST.md).

Do not claim a complete GUI review from the token lint alone: screenshot,
accessibility, runtime behavior, and exact-head remote gates remain separate
evidence boundaries.
