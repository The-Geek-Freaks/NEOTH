# Slack route identity repair and hosted acceptance

W684 preserves the persisted physical channel when a proactive queue entry
contains an account ID. Previously that shape unconditionally selected Telegram,
even when the stored channel was Slack. Unsupported account-only Slack entries
now settle as Slack configuration errors before Telegram authority or transport.
Mutable default routing cannot reinterpret that stored channel. A real dispatcher
tick regression checks the drained queue and durable Slack/error history. W693
corrects its fixture to Full autonomy with no Telegram configuration: both the
old and corrected paths remain free of provider sends, while the fixture reaches
the configuration error instead of Standard-mode trust-ledger suppression.

Legacy Slack planning also refuses delivery when either the public or credential
account map is active. The regression supplies damaged legacy credentials and a
destination alongside public-only, secret-only and complete account maps. None
may fall back to a legacy workspace. These two findings came from the prepared
Claude Desktop collaboration and were confirmed in source by Codex; an independent
static review approved the repairs. Named proactive Slack sending is still a
separate unfinished slice, including workspace identity across token rotation.

The two tests are selected by `wave684SlackAuthorityRepairAcceptance`. The portable
native inventory is now 1330 and the grouped hosted selection is 1060. Their
execution remains pending; no local compiler, formatter or test was run.

W685 admits Windows run35964379685 at796d34ed: 50 selected, executed and passed,
zero failures or missing terminals. Root verified the artifact ZIP digest,
58 internal hashes, 11 source bindings, two build inputs and every exact test
identity and terminal summary. Paperless dispatcher cases38-40 and retained
DELETE-binding namespace cases49-50 all pass. This proves those Windows fixture
behaviors; a real managed Docker installation remains a separate criterion.
See `verification/gold-wave685-windows50-terminals.json`.

W686 admits Core/CLI run35964376655 at796d34ed: slim-core production Clippy,
core test-target type-check, public CLI build and reference export all succeeded.
The source-bound generated CLI reference was imported byte-exact with SHA256
58079e3ee0c6acff052fdb7706a8a36591cd9acc9ddfa75496af769e48145108.
It includes add-slack and the updated account lifecycle help. See
`verification/gold-wave686-core-cli-reference.json`.

W683 separately confirmed four schema-2 routing terminals from Group1025 whose
`channels/routing.rs` blob still carries unchanged. Their success does not satisfy
an entire remaining P1-16 or Plan001 acceptance bullet. Road counts remain
1324 total /1046 checked /276 open /2 partial; WS-LF38 done /80 open.
