# W246 Recall-chip citations

W246 adds an optional, passive, content-free `citation` to each ready Recall
chip. A citation is a typed identity projected only from the already validated
`RecallSourceRef` retained with the final same-query recall hit. It is never
derived from row position, rendered recall text, an ordinal, a second lookup,
or an identifier reconstructed from a warm sentinel.

The closed wire vocabulary is:

```text
event { event_id: positive i64, event_type: u8 }
warm_snapshot {
  consolidated_id: positive i64,
  warm_kind: retained | summary,
  original_event_id: positive i64 | null
}
ground_truth { fact_id: positive i64 }
```

`event` is valid only on available hot, warm, or cold rows. `ground_truth` is
valid only on an available canonical row. `warm_snapshot` is valid only on an
available warm row. A retained snapshot may have a nullable original event ID;
a summary has `original_event_id: null` and uses its positive
`consolidated_id`, never the internal negative event sentinel. Unknown tiers,
missing, untrusted, revoked, malformed, or mismatched identities omit the
citation.

The authenticated CLI raw control record retains
`neoth_stream: "recall_chip_batch"` and `protocol_version: 3`. The sealed GUI
stream retains `schema_version: 1`. No compatibility version is claimed for a
mixed deployed pair: W246 decoders accept an omitted `citation` from a legacy
row, but legacy `deny_unknown_fields` decoders reject a W246 row that includes
the new field. Deploy paired producers and consumers together whenever cited
rows can be emitted.

The citation is display metadata only. It authorizes neither database access
nor source navigation, and carries no recall text, prompt, session ID, request
token, provider identity, or storage path.

## Static target tests

The following focused tests cover the source projection and both transports;
they are intentionally not executed during the BSOD hold.

- `memory::recall_presentation::tests::exact_positive_event_and_ground_truth_bindings_project_typed_citations`
- `memory::recall_presentation::tests::warm_summary_uses_a_snapshot_identity_not_the_negative_event_sentinel`
- `memory::recall_presentation::tests::retained_snapshot_rejects_a_forged_positive_event_binding`
- `daemon::gui_chat_protocol::tests::recall_chip_citation_requires_exact_available_tier_and_positive_binding`
- `daemon::gui_chat_bridge::tests::recall_chip_bridge_event_preserves_the_reduced_daemon_batch`
- `cli::chat::tests::w163_recall_chip_wire_is_private_bounded_and_has_exact_schema`

## GUI projection and review boundary

The raw authenticated and issued-daemon reducers require matching available
source state, tier and positive citation IDs. Missing, revoked and untrusted
rows cannot carry citations. Legacy omitted citations remain decodable. Both
Main and Buddy retain only the accepted current-response snapshot after the
successful terminal; cancellation, replacement and detach clear it. Labels
remain passive and use the existing accessible text surfaces, without adding
Slint controls, navigation or new visual tokens.

New GUI case:
`chat_recall_chips::tests::citations_are_closed_available_source_labels_with_positive_matching_ids`.
Existing raw W163 and daemon W167 Main/Buddy runtime cases now assert exact
citation labels and terminal/clear behavior. The existing public bridge
integration fixture also carries a real typed summary citation.

Applicable design evidence: PRODUCT/DESIGN truth and source-state principles,
lint_rules text-review and source-review boundaries, and AUDIT_CHECKLIST labels
and state rows were reviewed in source. No Slint/token changes were needed;
rendered contrast, target screen-reader output, scaling and Hosted runtime
remain unverified by this static review. P2-27 remains open.

Independent W219 static review passed for all eight source files. Required
Hosted selection is Group418 (five additional core identities; prior25W231
recall identities retained) and GUI124 (98 universal +26 Linux). New source
has not yet executed. Prior Group413 success on1a6a19d7 cannot validate W246.