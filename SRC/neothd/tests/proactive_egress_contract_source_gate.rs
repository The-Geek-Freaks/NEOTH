//! Source-level tripwires for the proactive egress GOLD transaction.
//!
//! Executable tests in `proactive_egress` cover crash phases and filesystem
//! behavior. These guards pin the production topology so a later refactor
//! cannot silently revive raw drains, bypass the sole transport seam, or detach
//! CLI/GUI history from the same typed projection.

const EGRESS: &str = include_str!("../src/daemon/proactive_egress.rs");
const DISPATCHER: &str = include_str!("../src/daemon/proactive_dispatcher.rs");
const PROACTIVE: &str = include_str!("../src/proactive/mod.rs");
const CRON: &str = include_str!("../src/cron/state.rs");
const ATOMIC_WRITE: &str = include_str!("../src/util/atomic_write.rs");
const WIN_NATIVE: &str = include_str!("../src/wal/win_native.rs");
const EVENTS: &str = include_str!("../src/wal/events.rs");
const WAL_SCAN: &str = include_str!("../src/wal/scan.rs");
const WAL_WRITER: &str = include_str!("../src/wal/writer.rs");
const GUI_STREAM: &str = include_str!("../src/cli/gui_stream.rs");
const CLI_PROACTIVE: &str = include_str!("../src/cli/proactive.rs");
const GUI_MAIN: &str = include_str!("../../neothd-gui/src/main.rs");
const GUI_SLINT: &str = include_str!("../../neothd-gui/ui/settings.slint");
const SERVE: &str = include_str!("../src/cli/serve.rs");
const SERVE_TASKS: &str = include_str!("../src/cli/serve_tasks.rs");
const SKILL_STORE: &str = include_str!("../src/skills/store.rs");

fn matching_rust_brace(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = open;
    let mut depth = 0usize;
    let mut block_comment_depth = 0usize;
    let mut line_comment = false;
    let mut quoted = false;
    let mut character = false;
    let mut raw_hashes = None;
    while index < bytes.len() {
        if line_comment {
            line_comment = bytes[index] != b'\n';
            index += 1;
            continue;
        }
        if block_comment_depth > 0 {
            if bytes.get(index..index + 2) == Some(b"/*") {
                block_comment_depth += 1;
                index += 2;
            } else if bytes.get(index..index + 2) == Some(b"*/") {
                block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(hashes) = raw_hashes {
            if bytes[index] == b'"'
                && bytes
                    .get(index + 1..index + 1 + hashes)
                    .is_some_and(|tail| tail.iter().all(|byte| *byte == b'#'))
            {
                raw_hashes = None;
                index += 1 + hashes;
            } else {
                index += 1;
            }
            continue;
        }
        if quoted || character {
            if bytes[index] == b'\\' {
                index = (index + 2).min(bytes.len());
                continue;
            }
            if (quoted && bytes[index] == b'"') || (character && bytes[index] == b'\'') {
                quoted = false;
                character = false;
            }
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"//") {
            line_comment = true;
            index += 2;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            block_comment_depth = 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'r' {
            let mut probe = index + 1;
            while bytes.get(probe) == Some(&b'#') {
                probe += 1;
            }
            if bytes.get(probe) == Some(&b'"') {
                raw_hashes = Some(probe - index - 1);
                index = probe + 1;
                continue;
            }
        }
        if bytes[index] == b'"' {
            quoted = true;
            index += 1;
            continue;
        }
        if bytes[index] == b'\''
            && bytes
                .get(index + 1..(index + 8).min(bytes.len()))
                .is_some_and(|tail| tail.contains(&b'\''))
        {
            character = true;
            index += 1;
            continue;
        }
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Preserve byte offsets and newlines while erasing comments and every Rust
/// string/character literal. The seam gate scans identifiers in the result, so
/// source examples and comments cannot create false calls or hide real ones.
fn rust_code_only(source: &str) -> String {
    fn erase(bytes: &mut [u8], start: usize, end: usize) {
        for byte in &mut bytes[start..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }

    let source_bytes = source.as_bytes();
    let mut masked = source_bytes.to_vec();
    let mut index = 0usize;
    while index < source_bytes.len() {
        if source_bytes.get(index..index + 2) == Some(b"//") {
            let end = source_bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(source_bytes.len(), |relative| index + relative);
            erase(&mut masked, index, end);
            index = end;
            continue;
        }
        if source_bytes.get(index..index + 2) == Some(b"/*") {
            let start = index;
            let mut depth = 1usize;
            index += 2;
            while index < source_bytes.len() && depth > 0 {
                if source_bytes.get(index..index + 2) == Some(b"/*") {
                    depth += 1;
                    index += 2;
                } else if source_bytes.get(index..index + 2) == Some(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            erase(&mut masked, start, index);
            continue;
        }
        if source_bytes[index] == b'r' {
            let mut quote = index + 1;
            while source_bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if source_bytes.get(quote) == Some(&b'"') {
                let hashes = quote - index - 1;
                let start = index;
                index = quote + 1;
                while index < source_bytes.len() {
                    if source_bytes[index] == b'"'
                        && source_bytes
                            .get(index + 1..index + 1 + hashes)
                            .is_some_and(|tail| tail.iter().all(|byte| *byte == b'#'))
                    {
                        index += 1 + hashes;
                        break;
                    }
                    index += 1;
                }
                erase(&mut masked, start, index);
                continue;
            }
        }
        if source_bytes[index] == b'"' {
            let start = index;
            index += 1;
            while index < source_bytes.len() {
                if source_bytes[index] == b'\\' {
                    index = (index + 2).min(source_bytes.len());
                } else if source_bytes[index] == b'"' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            erase(&mut masked, start, index);
            continue;
        }
        if source_bytes[index] == b'\'' {
            let start = index;
            let mut end = index + 1;
            if source_bytes.get(end) == Some(&b'\\') {
                end += 2;
                if source_bytes.get(end.saturating_sub(1)) == Some(&b'u')
                    && source_bytes.get(end) == Some(&b'{')
                {
                    end = source_bytes[end..]
                        .iter()
                        .position(|byte| *byte == b'}')
                        .map_or(end, |relative| end + relative + 1);
                } else if source_bytes.get(end.saturating_sub(1)) == Some(&b'x') {
                    end = (end + 2).min(source_bytes.len());
                }
            } else if end < source_bytes.len() {
                let width = source[end..].chars().next().map_or(1, char::len_utf8);
                end = (end + width).min(source_bytes.len());
            }
            if source_bytes.get(end) == Some(&b'\'') {
                end += 1;
                erase(&mut masked, start, end);
                index = end;
                continue;
            }
        }
        index += 1;
    }
    String::from_utf8(masked).expect("ASCII masking preserves valid UTF-8")
}

fn without_cfg_test_modules(source: &str) -> String {
    let code = rust_code_only(source);
    let mut excluded = Vec::new();
    let mut search = 0usize;
    while let Some(relative) = code[search..].find("#[cfg") {
        let attribute_start = search + relative;
        let Some(attribute_end_relative) = code[attribute_start..].find(']') else {
            break;
        };
        let attribute_end = attribute_start + attribute_end_relative;
        let compact_attribute = code[attribute_start..=attribute_end]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        // Only this exact predicate is absent from every production build.
        // `not(test)` and mixed `any(test, feature = ...)` modules still have
        // production configurations and must remain visible to the seam scan.
        if compact_attribute != "#[cfg(test)]" {
            search = attribute_end + 1;
            continue;
        }
        let Some(open_relative) = code[attribute_end + 1..].find('{') else {
            break;
        };
        let open = attribute_end + 1 + open_relative;
        let header = &code[attribute_end + 1..open];
        let is_module = header
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| token == "mod");
        if !is_module || header.contains(';') {
            search = attribute_end + 1;
            continue;
        }
        let end = matching_rust_brace(source, open).expect("balanced cfg(test) module");
        excluded.push(attribute_start..end + 1);
        search = end + 1;
    }

    let mut production = source.as_bytes().to_vec();
    for range in excluded {
        for byte in &mut production[range] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(production).expect("replacing source bytes with ASCII preserves UTF-8")
}

fn production_send_proactive_references(source: &str) -> Vec<usize> {
    let production = without_cfg_test_modules(source);
    let code = rust_code_only(&production);
    let bytes = code.as_bytes();
    let mut references = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !(bytes[index].is_ascii_alphabetic() || bytes[index] == b'_') {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        if &bytes[start..index] != b"send_proactive" {
            continue;
        }
        let mut before = start;
        while before > 0 && bytes[before - 1].is_ascii_whitespace() {
            before -= 1;
        }
        let previous_end = before;
        while before > 0 && (bytes[before - 1].is_ascii_alphanumeric() || bytes[before - 1] == b'_')
        {
            before -= 1;
        }
        if &bytes[before..previous_end] != b"fn" {
            references.push(start);
        }
    }
    references
}

fn rust_sources_below(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        .map(|entry| entry.expect("read Rust source directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_sources_below(&path, out);
        } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
            out.push(path);
        }
    }
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("start marker");
    let tail = &source[start..];
    let end = tail.find(end).expect("end marker");
    &tail[..end]
}

#[test]
fn cfg_test_module_filter_preserves_production_after_nested_test_syntax() {
    let fixture = r##"
fn before() { channel.send_proactive("before", "body"); }
#[cfg(test)]
mod tests {
    const BRACES: &str = r#"{ not structure }"#;
    fn nested() { channel.send_proactive("test", BRACES); }
}
fn after() { channel.send_proactive("after", "body"); }
#[cfg(not(test))]
mod non_test {
    fn production() { channel.send_proactive("not-test", "body"); }
}
#[cfg(any(test, feature = "x"))]
mod mixed {
    fn feature_production() { channel.send_proactive("mixed", "body"); }
    }
"##;
    let production = without_cfg_test_modules(fixture);
    assert_eq!(production_send_proactive_references(fixture).len(), 4);
    assert!(production.contains("fn before"));
    assert!(production.contains("fn after"));
    assert!(production.contains("fn production"));
    assert!(production.contains("fn feature_production"));
    assert!(!production.contains("fn nested"));
}

#[test]
fn send_seam_scanner_sees_ufcs_spacing_and_references_but_not_source_examples() {
    let fixture = r##"
trait Channel { fn send_proactive(&self, recipient: &str, body: &str); }
fn implementation(channel: &dyn Channel) {
    channel.send_proactive /* spacing bypass */ ("one", "body");
    Channel::send_proactive(channel, "two", "body");
    let deferred = Channel::send_proactive;
    let _example = ".send_proactive(";
    // channel.send_proactive("comment", "body");
    /* Channel::send_proactive(channel, "comment", "body"); */
    let _ = deferred;
}
"##;
    assert_eq!(production_send_proactive_references(fixture).len(), 3);
}

#[test]
fn exactly_one_production_proactive_transport_seam_exists() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    rust_sources_below(&root, &mut sources);
    let mut seams = Vec::new();
    for path in sources {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for offset in production_send_proactive_references(&source) {
            let line = source[..offset]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            let relative = path
                .strip_prefix(&root)
                .expect("source below crate src")
                .to_string_lossy()
                .replace('\\', "/");
            seams.push(format!("{relative}:{line}"));
        }
    }
    assert_eq!(
        seams.len(),
        1,
        "expected one production proactive transport seam, found {seams:?}"
    );
    assert!(
        seams[0].starts_with("daemon/proactive_egress.rs:"),
        "sole proactive transport seam moved outside the durable egress boundary: {seams:?}"
    );
    assert!(EGRESS.contains("pub(crate) async fn execute_claimed_once("));
    for fossil in [
        "fn run_proactive_drain_tick(",
        "fn write_inflight_claim(",
        "fn evict_inflight_claimed(",
    ] {
        assert!(
            !DISPATCHER.contains(fossil),
            "legacy egress fossil returned: {fossil}"
        );
    }
}

#[test]
fn durable_admission_precedes_owned_deadline_bounded_transport_and_terminalization() {
    let execute = between(
        EGRESS,
        "pub(crate) async fn execute_claimed_once(",
        "/// Settle a configured-but-unavailable route",
    );
    let admission = [
        "persist_prepared_claim(&delivery_lock, home, &claim)",
        "append_intent(&delivery_lock, writer, &claim)",
        "persist_armed_claim(&delivery_lock, &claim_file, &claim)",
        "append_armed(&delivery_lock, writer, &claim)",
    ];
    let admission_positions: Vec<_> = admission
        .iter()
        .map(|needle| {
            execute
                .find(needle)
                .unwrap_or_else(|| panic!("missing stage: {needle}"))
        })
        .collect();
    assert!(
        admission_positions.windows(2).all(|pair| pair[0] < pair[1]),
        "Prepared, Intent and Armed durability must precede transport admission"
    );

    let start = execute
        .find("let mut transport = OwnedTransportAttempt::start(")
        .expect("owned transport admission");
    assert!(
        admission_positions.last().copied().unwrap() < start,
        "no provider task may be created before the Armed WAL acknowledgement"
    );
    let terminal = execute
        .find("let result = terminal_result(&claim, outcome, receipt, error, completed_at_unix);")
        .expect("terminal result construction");
    let terminalization = &execute[terminal..];
    let terminal_lock = terminalization
        .find("let delivery_lock = acquire_delivery_lock(home)")
        .expect("terminal lock reacquisition");
    let terminal_append = terminalization
        .find("append_result(&delivery_lock, writer, &result)")
        .expect("terminal result WAL append");
    let terminal_release = terminal_append
        + terminalization[terminal_append..]
            .find("transport.release_after_terminal_result();")
            .expect("terminal transport ownership release");
    let terminal_projection = terminalization
        .find("apply_projections_blocking(")
        .expect("terminal projection");
    assert!(
        terminal_lock < terminal_append
            && terminal_append < terminal_release
            && terminal_release < terminal_projection,
        "terminalization must re-lock, acknowledge Result, release transport ownership, then project"
    );
    assert!(
        start < terminal,
        "a transport attempt must resolve before terminal WAL evidence is built"
    );
    let expired_pre_spawn = execute
        .find("if tokio::time::Instant::now() >= transport_deadline {")
        .expect("strict pre-spawn deadline guard");
    assert!(
        expired_pre_spawn < start
            && execute.contains("proactive attempt deadline expired before transport start"),
        "transport admission must reject its deadline at equality before task creation"
    );
    assert!(
        execute
            .contains("let transport_deadline = original_monotonic_deadline.min(wall_deadline);"),
        "live transport must be bounded by both monotonic and durable-wall deadlines"
    );
    assert!(
        execute.contains("let completed_at_unix = chrono::Utc::now().timestamp();"),
        "terminal evidence must use completion time rather than the stale tick time"
    );
    assert!(EGRESS.contains("atomic_write_private_child_create_new("));
    assert!(EGRESS.contains("bind_written_claim(claim_root, name, &prepared)"));
}

#[test]
fn owned_transport_cancellation_is_abort_then_reap_and_recovery_is_fail_closed() {
    let owned = between(
        EGRESS,
        "impl OwnedTransportAttempt {",
        "impl Drop for OwnedTransportAttempt",
    );
    for required in [
        "channel: Arc<dyn Channel>",
        "runtime.spawn(async move",
        "channel.send_proactive(&recipient, &body).await",
        "tokio::time::timeout_at(deadline, handle).await",
        "handle.abort();",
        "let _ = (&mut handle).await;",
    ] {
        assert!(
            owned.contains(required),
            "owned transport lifecycle lost {required}"
        );
    }
    let timeout_abort = owned.find("handle.abort();").expect("timeout abort");
    let timeout_reap = owned[timeout_abort..]
        .find("let _ = (&mut handle).await;")
        .expect("timeout reaping acknowledgement");
    assert!(
        timeout_reap > 0,
        "a deadline must await its abort before emitting terminal evidence"
    );

    let drop_impl = between(
        EGRESS,
        "impl Drop for OwnedTransportAttempt",
        "async fn reap_cancelled_transport_attempts()",
    );
    let cancelled_handle = between(
        EGRESS,
        "struct CancelledTransportHandle {",
        "/// Outer-future cancellation cannot await",
    );
    assert!(
        cancelled_handle.contains("handle: TransportJoinHandle,")
            && cancelled_handle.contains("registration: TransportIntentRegistration,"),
        "a cancelled transport must retain both its local intent registration and JoinHandle"
    );
    assert!(
        EGRESS.contains("Mutex<Vec<CancelledTransportHandle>>"),
        "the cancellation supervisor must queue intent-bound handles"
    );
    let drop_abort = drop_impl.find("handle.abort();").expect("drop abort");
    let queued = &drop_impl[drop_abort..];
    let queue_entry = queued
        .find("queue.push(CancelledTransportHandle {")
        .expect("cancelled handle reaper queue");
    assert!(
        queued[queue_entry..].contains("handle,")
            && queued[queue_entry..].contains("registration,"),
        "dropping a live delivery must transfer its registration with the aborted handle"
    );

    let reaper = between(EGRESS, "impl CancelledTransportReapGuard {", "#[cfg(test)]");
    let joined = reaper
        .find("let _ = (&mut entry.handle).await;")
        .expect("cancelled handle join");
    let registration_release = reaper
        .find("drop(entry.registration);")
        .expect("reaped registration release");
    assert!(
        joined < registration_release,
        "only a joined cancelled task may release its transferred local registration"
    );

    let recovery = between(
        EGRESS,
        "async fn recover_pending_claims_locked(",
        "/// Reconcile every durable claim",
    );
    let reap = recovery
        .find("reap_cancelled_transport_attempts()\n        .await")
        .expect("cancelled transport reaping");
    let scan = recovery
        .find("let scan_lock = delivery_lock")
        .expect("durable recovery scan");
    assert!(
        reap < scan,
        "recovery must reap cancelled adapter work before inspecting durable claims"
    );
    assert!(
        recovery.contains("if claim.version == CLAIM_VERSION")
            && recovery.contains("is_some_and(|deadline| now_unix < deadline)")
            && recovery.contains("continue;"),
        "only an unexpired v2 Armed claim may remain in-flight during recovery"
    );
    assert!(
        !recovery.contains("now_unix <= deadline"),
        "deadline equality must not leave a v2 Armed attempt in-flight"
    );
    assert!(
        recovery.contains("ProactiveEgressOutcome::CrashUnknown"),
        "legacy or expired Armed uncertainty must settle fail-closed"
    );
}

#[test]
fn armed_claim_lease_and_registration_cover_admission_transport_and_terminalization() {
    let execute = between(
        EGRESS,
        "pub(crate) async fn execute_claimed_once(",
        "/// Settle a configured-but-unavailable route",
    );
    let provider_start = execute
        .find("let mut transport = OwnedTransportAttempt::start(")
        .expect("owned provider start");
    let admission = &execute[..provider_start];
    let admission_lock = admission
        .find("let delivery_lock = acquire_delivery_lock(home)")
        .expect("admission DeliveryLock");
    let persist_armed = admission
        .find("persist_armed_claim(&delivery_lock, &claim_file, &claim)")
        .expect("Armed claim persistence");
    let lease = admission
        .find("let armed_claim_lease = match ArmedClaimLease::try_acquire(&claim_file, &claim)")
        .expect("exact Armed claim lease acquisition");
    let registration = admission
        .find("let registration = TransportIntentRegistration::acquire(&claim.intent_id);")
        .expect("local intent registration");
    let armed_ack = admission
        .find("append_armed(&delivery_lock, writer, &claim)")
        .expect("Armed WAL acknowledgement");
    assert!(
        admission_lock < persist_armed
            && persist_armed < lease
            && lease < registration
            && registration < armed_ack,
        "the final Armed inode lease and local registration must be acquired under DeliveryLock before Armed ACK"
    );
    assert!(
        admission.contains("ArmedClaimLeaseProbe::Busy =>")
            && admission.contains("exact claim lease is already busy"),
        "a busy exact Armed lease must fail closed before any provider task starts"
    );
    let post_admission = &execute[provider_start..];
    assert!(
        post_admission.starts_with(
            "let mut transport = OwnedTransportAttempt::start(\n        registration,"
        ) && post_admission.contains("        armed_claim_lease,\n    );"),
        "only the post-unlock owned attempt may receive admission's registration and Armed lease"
    );

    let owned = between(
        EGRESS,
        "impl OwnedTransportAttempt {",
        "impl Drop for OwnedTransportAttempt",
    );
    let task_lease_clone = owned
        .find("let task_lease = Arc::clone(&armed_claim_lease);")
        .expect("provider lease Arc clone");
    let provider_send = owned
        .find("let result = channel.send_proactive(&recipient, &body).await;")
        .expect("sole provider send");
    let task_lease_drop = owned[provider_send..]
        .find("drop(task_lease);")
        .expect("provider lease Arc release");
    assert!(
        task_lease_clone < provider_send && task_lease_drop > 0,
        "the spawned provider task must retain an Armed lease Arc through send_proactive await"
    );

    let dedup = between(
        EGRESS,
        "async fn has_unexpired_inflight_dedup(",
        "fn deadline_after(",
    );
    assert!(
        dedup.contains("ArmedClaimLeaseProbe::Busy => return Ok(true)"),
        "dedup must defer while another process owns the exact Armed lease"
    );
    let recovery = between(
        EGRESS,
        "async fn recover_pending_claims_locked(",
        "/// Reconcile every durable claim",
    );
    assert!(
        recovery.contains("ArmedClaimLeaseProbe::Busy => continue"),
        "recovery must defer rather than synthesize a terminal result for a busy Armed lease"
    );
    let terminal = execute
        .find("let result = terminal_result(&claim, outcome, receipt, error, completed_at_unix);")
        .expect("terminal result construction");
    let terminalization = &execute[terminal..];
    let result_ack = terminalization
        .find("append_result(&delivery_lock, writer, &result)")
        .expect("Result WAL acknowledgement");
    let owner_release = result_ack
        + terminalization[result_ack..]
            .find("transport.release_after_terminal_result();")
            .expect("owner lease release");
    let projections = terminalization
        .find("apply_projections_blocking(")
        .expect("terminal projections");
    assert!(
        result_ack < owner_release && owner_release < projections,
        "owner Armed lease must survive Result ACK and be released before projection/removal"
    );
    let owner_release_impl = between(
        EGRESS,
        "fn release_after_terminal_result(&mut self)",
        "fn validate_claim_lease(&self, claim: &ProactiveEgressClaim)",
    );
    assert!(
        owner_release_impl.contains("drop(self.armed_claim_lease.take());")
            && owner_release_impl.contains("drop(self.registration.take());"),
        "the owner hand-off must release both OS lease and local registration together"
    );
    let projection_impl = between(
        EGRESS,
        "fn apply_projections(",
        "async fn apply_projections_blocking(",
    );
    assert!(
        projection_impl.contains("claim_file\n        .remove()"),
        "terminal projections retain the claim-removal authority after lease hand-off"
    );
}

#[test]
fn wal_intent_armed_and_result_bind_the_exact_effect_without_raw_secrets() {
    for subtype in [
        "ExtendedSubtype::ChannelEgressIntent",
        "ExtendedSubtype::ChannelEgressArmed",
        "ExtendedSubtype::ChannelEgressResult",
    ] {
        assert!(
            EGRESS.contains(subtype),
            "missing proactive subtype: {subtype}"
        );
        assert!(
            EVENTS.contains(subtype),
            "subtype missing from event registry: {subtype}"
        );
    }
    for domain in [
        "proactive-egress-binding-v1",
        "proactive-egress-recipient-v1",
        "proactive-egress-message-v1",
        "proactive-egress-dedup-v1",
        "proactive-egress-receipt-v1",
        "proactive-egress-error-v1",
    ] {
        assert!(
            EGRESS.contains(domain),
            "missing domain separation: {domain}"
        );
    }
    let intent = between(
        EGRESS,
        "struct ProactiveIntentFrame",
        "struct ProactiveArmedFrame",
    );
    assert!(!intent.contains("item:"));
    assert!(!intent.contains("body:"));
    assert!(!intent.contains("recipient:"));
    let armed = between(
        EGRESS,
        "struct ProactiveArmedFrame",
        "struct ProactiveResultFrame",
    );
    assert!(armed.contains("prepared_binding_sha256"));
    assert!(armed.contains("armed_binding_sha256"));
    let result = between(
        EGRESS,
        "struct ProactiveResultFrame",
        "struct ProactiveDeliveryRecord",
    );
    assert!(result.contains("receipt_sha256"));
    assert!(result.contains("error_sha256"));
    assert!(!result.contains("receipt: String"));
    assert!(!result.contains("error: String"));
}

#[test]
fn recovery_authenticates_only_active_claim_semantics_before_projection() {
    assert!(EGRESS.contains("for_each_frame_in_home_segment_chain("));
    assert!(EGRESS.contains("supported_home_scan_limits()"));
    assert!(EGRESS.contains("active_intent_ids"));
    assert!(EGRESS.contains("if claims.is_empty()"));
    assert!(
        EGRESS.contains("scan_authenticated_wal(&scan_home, &scan_segment, &active_intent_ids)")
    );
    for outcome in [
        "Delivered",
        "TransportError",
        "AuthError",
        "RateLimited",
        "AdapterConfigurationError",
        "SidecarOnly",
        "PolicySuppressed",
        "CrashUnknown",
        "NotAttempted",
    ] {
        assert!(
            EGRESS.contains(outcome),
            "missing terminal outcome: {outcome}"
        );
    }
    for conflict in [
        "duplicate proactive intent frame",
        "duplicate proactive Armed frame",
        "duplicate proactive result frame",
        "Armed proactive claim has no authenticated intent",
    ] {
        assert!(
            EGRESS.contains(conflict),
            "missing recovery conflict: {conflict}"
        );
    }
}

#[test]
fn executable_recovery_and_filesystem_matrix_is_present() {
    for case in [
        "recovery_discards_prepared_claim_without_intent_and_keeps_queue",
        "recovery_marks_intent_without_armed_not_attempted_and_keeps_queue",
        "recovery_defers_unexpired_armed_attempt_and_keeps_queue",
        "authenticated_armed_proof_rejects_a_claim_phase_rollback",
        "recovery_replays_terminal_result_without_duplicate_projection_or_budget",
        "concurrent_delivery_attempts_call_transport_once",
        "replacement_generation_survives_a_blocked_old_send",
        "cancellation_during_wal_ack_keeps_lock_until_recovery_is_safe",
        "terminal_result_marker_is_authenticated_before_ack",
        "sidecar_only_and_policy_suppressed_use_typed_terminal_chain",
        "self_consistent_forged_modern_projection_is_rejected_by_wal_binding",
        "legacy_claim_is_pessimistically_armed_and_settled_crash_unknown",
        "broad_modern_history_is_rejected_repeatedly_without_permission_blessing",
        "private_modern_projection_without_authenticated_wal_is_rejected",
        "verified_projection_enforces_exact_phase_matrix_and_chain_base",
        "rotated_history_replay_is_visible_and_does_not_duplicate_projection",
        "sidecar_and_claim_symlinks_are_rejected_without_following_them",
        "torn_legacy_sidecar_tail_is_preserved_and_blocks_new_projection",
        "orphan_claim_stage_is_removed_without_becoming_authority",
        "claim_root_and_leaf_authority_survive_namespace_replacement_attempts",
    ] {
        assert!(
            EGRESS.contains(case),
            "missing executable egress case: {case}"
        );
    }
    assert!(
        DISPATCHER.contains(
            "invalid_adapter_configuration_settles_only_that_item_and_does_not_starve_tick"
        )
    );
    assert!(
        DISPATCHER.contains(
            "invalid_persisted_front_item_is_quarantined_without_starving_valid_successor"
        )
    );
    assert!(DISPATCHER.contains("empty_or_blank_target_resolves_to_the_local_operator_inbox"));
}

#[test]
fn recovery_precedes_disabled_invalid_quiet_idle_and_routing_gates() {
    let loop_body = between(
        DISPATCHER,
        "pub fn spawn_proactive_drain_loop(",
        "#[cfg(test)]",
    );
    assert!(
        loop_body.find("recover_pending_claims(").unwrap()
            < loop_body
                .find("load_runtime_config_pair_from_path_or_default")
                .unwrap()
    );
    let tick = between(
        DISPATCHER,
        "pub async fn run_proactive_delivery_tick(",
        "/// Spawn the daemon-side drain loop.",
    );
    let recover = tick.find("recover_pending_claims(").unwrap();
    for gate in [
        "proactive.enabled",
        "quiet_hours_utc",
        "idle_only",
        "ChannelRouting::load_from",
    ] {
        assert!(
            recover < tick.find(gate).unwrap(),
            "recovery must precede {gate}"
        );
    }
}

#[test]
fn private_state_is_nofollow_bounded_atomic_and_cross_process_locked() {
    for source in [EGRESS, PROACTIVE, CRON] {
        assert!(source.contains("O_NOFOLLOW"));
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    }
    for bound in [
        "MAX_CLAIMS",
        "MAX_TOTAL_CLAIM_BYTES",
        "MAX_SIDECAR_BYTES",
        "MAX_ROTATED_SIDECARS",
    ] {
        assert!(EGRESS.contains(bound), "missing filesystem bound: {bound}");
    }
    assert!(EGRESS.contains("make_open_file_private(&file, &display_path)"));
    assert!(EGRESS.contains("open_bound_directory_from_trusted_anchor("));
    let compact_egress = EGRESS.split_whitespace().collect::<String>();
    assert!(compact_egress.contains("forentryinroot.dir.entries()"));
    assert!(EGRESS.contains("open_bound_regular_file("));
    assert!(EGRESS.contains("bind_regular_file_for_removal("));
    assert!(EGRESS.contains("claim_file\n        .remove()"));
    assert!(SKILL_STORE.contains("pub(crate) fn remove_bound_file("));
    assert!(PROACTIVE.contains("PROACTIVE_QUEUE_LOCK_FILE"));
    assert!(PROACTIVE.contains("lock_file_blocking("));
    assert!(PROACTIVE.contains("atomic_write_private(path, &bytes)"));
    assert!(ATOMIC_WRITE.contains("sync_parent_directory_required"));
    assert!(ATOMIC_WRITE.contains("durable_remove_file"));
    let compact_win_native = WIN_NATIVE.split_whitespace().collect::<String>();
    assert!(compact_win_native.contains(
        "letcreate_flags=FILE_ATTRIBUTE_NORMAL|ifshare_mode==0{FILE_FLAG_WRITE_THROUGH}else{0};"
    ));
    assert!(compact_win_native.contains("CREATE_NEW,create_flags"));
}

#[test]
fn claim_namespace_never_falls_back_to_ambient_paths_after_binding() {
    let claim_store = between(EGRESS, "fn open_claim_directory(", "fn intent_frame(");
    for forbidden in [
        "std::fs::read_dir(",
        "std::fs::symlink_metadata(",
        "std::fs::rename(",
        "durable_remove_file(",
        "atomic_write_private(",
    ] {
        assert!(
            !claim_store.contains(forbidden),
            "bound claim store regained ambient operation: {forbidden}"
        );
    }
    let persistence = between(
        EGRESS,
        "async fn persist_prepared_claim(",
        "async fn queue_generation_matches(",
    );
    for required in [
        "atomic_write_private_child_create_new(",
        "atomic_write_private_child(",
        "bind_written_claim(",
    ] {
        assert!(
            persistence.contains(required),
            "bound claim persistence lost {required}"
        );
    }
    assert!(EGRESS.contains("verify_private_directory_handle_dacl(&root.dir)"));
}

#[test]
fn producer_load_and_claim_boundaries_share_one_exact_item_validator() {
    for required in [
        "MAX_PROACTIVE_DEDUP_KEY_BYTES: usize = 4_096",
        "MAX_PROACTIVE_CHANNEL_BYTES: usize = 64",
        "MAX_PROACTIVE_SOURCE_BYTES: usize = 4_096",
        "MAX_PROACTIVE_BODY_BYTES: usize = 1024 * 1024",
        "MAX_PROACTIVE_ITEM_ENCODED_BYTES: usize = 1152 * 1024",
        "pub(crate) fn validate(&self)",
        "quarantined_items: Vec<QuarantinedProactiveItem>",
        "normalization_dirty: bool",
    ] {
        assert!(
            PROACTIVE.contains(required),
            "proactive item authority lost {required}"
        );
    }
    let enqueue = between(
        PROACTIVE,
        "pub fn enqueue(&mut self, item: ProactiveItem)",
        "pub fn enqueue_at(",
    );
    assert!(enqueue.contains("item.validate()"));
    let normalization = between(
        PROACTIVE,
        "fn normalize_item_generations(&mut self)",
        "fn validate_invariants(&self)",
    );
    assert!(normalization.contains("item.validate()"));
    let save = between(
        PROACTIVE,
        "pub fn save_to(&self, path: &Path)",
        "pub fn load_from(",
    );
    assert!(save.contains("bytes.len() as u64 <= MAX_QUEUE_BYTES"));
    let claim_validation = between(EGRESS, "fn validate_claim(", "fn open_claim_directory(");
    assert!(claim_validation.contains("claim\n        .item\n        .validate()"));
    assert!(EGRESS.contains("MIN_CLAIM_ENVELOPE_HEADROOM_BYTES"));
    assert!(EGRESS.contains("MIN_HISTORY_RECORD_ENVELOPE_HEADROOM_BYTES"));
    let history_append = between(EGRESS, "fn append_delivery_record_once(", "fn cron_status(");
    assert!(history_append.contains("record.len() <= MAX_HISTORY_RECORD_BYTES"));
}

#[test]
fn projections_queue_generation_and_rotation_replay_are_idempotent() {
    for required in [
        "proactive_delivery.lock",
        "append_delivery_record_once",
        "archived_delivery_record_matches",
        "update_announce_result_once",
        "settle_egress_once",
        "durably remove settled proactive claim",
    ] {
        assert!(
            EGRESS.contains(required),
            "missing projection contract: {required}"
        );
    }
    assert!(PROACTIVE.contains("settled_egress_intents: BTreeSet<String>"));
    assert!(PROACTIVE.contains("clear_settled_egress_intents"));
    assert!(PROACTIVE.contains("entry_generation"));
    assert!(!PROACTIVE.contains("settled_egress_floor"));
}

#[test]
fn adapter_configuration_is_item_local_but_durability_stays_global() {
    assert!(DISPATCHER.contains("enum LiveRouteError"));
    assert!(DISPATCHER.contains("AdapterConfiguration(String)"));
    assert!(DISPATCHER.contains("Durability(String)"));
    assert!(DISPATCHER.contains("record_adapter_configuration_error_once("));
    assert!(DISPATCHER.contains("Err(LiveRouteError::Durability(error)) => return Err(error)"));
    assert!(EGRESS.contains("pub(crate) async fn record_adapter_configuration_error_once("));
}

#[test]
fn every_live_route_uses_the_choke_point_and_keet_binds_raw_capability() {
    let route = between(
        DISPATCHER,
        "async fn deliver_live_route(",
        "fn canonical_target_channel(",
    );
    let route_code = rust_code_only(route);
    let route = route_code.as_str();
    let live_route_arms = [
        "DeliveryRoute::Telegram",
        "DeliveryRoute::Slack",
        "DeliveryRoute::Discord",
        "DeliveryRoute::WhatsApp",
        "DeliveryRoute::WhatsAppBaileys",
        "DeliveryRoute::Keet",
        "DeliveryRoute::Signal",
        "DeliveryRoute::Line",
        "DeliveryRoute::Mattermost",
        "DeliveryRoute::IMessage",
        "DeliveryRoute::Matrix",
        "DeliveryRoute::GoogleChat",
    ];
    for variant in live_route_arms {
        assert!(
            route.contains(variant),
            "unwired proactive route: {variant}"
        );
    }
    for pair in live_route_arms.windows(2) {
        let arm = between(route, pair[0], pair[1]);
        assert!(
            arm.contains("execute!("),
            "live proactive route bypasses durable choke point: {}",
            pair[0]
        );
    }
    let google_chat_start = route
        .find("DeliveryRoute::GoogleChat")
        .expect("Google Chat live-route arm");
    let google_chat_open = route[google_chat_start..]
        .find("=> {")
        .map(|relative| google_chat_start + relative + "=> ".len())
        .expect("Google Chat live-route arm body");
    let google_chat_end = matching_rust_brace(route, google_chat_open)
        .expect("complete Google Chat live-route arm body");
    let google_chat_arm = &route[google_chat_start..=google_chat_end];
    assert!(
        google_chat_arm.contains("execute!("),
        "live proactive route bypasses durable choke point: DeliveryRoute::GoogleChat"
    );
    assert_eq!(
        route.matches("execute!(").count(),
        live_route_arms.len(),
        "each declared live route must have exactly one durable choke-point call"
    );
    let route_compact = route
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    let production_dispatcher = without_cfg_test_modules(DISPATCHER);
    let dispatcher_code = rust_code_only(&production_dispatcher);
    let dispatcher_compact = dispatcher_code
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    let execute_macro = between(&route_compact, "macro_rules!execute", "matchroute{");
    assert_eq!(route_compact.matches("macro_rules!execute").count(), 1);
    assert_eq!(
        dispatcher_compact.matches("execute_claimed_once").count(),
        1,
        "production dispatcher must name the durable egress seam only inside execute!"
    );
    assert!(execute_macro.contains("execute_claimed_once("));
    let keet_arm = between(route, "DeliveryRoute::Keet", "DeliveryRoute::Signal");
    let keet_compact = keet_arm
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    assert!(keet_compact.contains("lettopic_capability=topic.expose();"));
    let keet_constructor = between(
        &keet_compact,
        "crate::channels::keet::KeetChannel::new(",
        ").map_err(",
    );
    assert!(keet_constructor.contains("topic_capability,"));
    assert_eq!(keet_compact.matches("topic_capability").count(), 3);
    assert!(keet_compact.ends_with("execute!(topic_capability,channel)}"));
    assert!(!keet_arm.contains("topic_alias"));
}

#[test]
fn cli_gui_and_buddy_share_the_typed_private_history() {
    assert!(CLI_PROACTIVE.contains("read_delivery_history(home)"));
    assert!(CLI_PROACTIVE.contains("record.verification_label()"));
    assert!(GUI_STREAM.contains("tokio::task::spawn_blocking(move ||"));
    assert!(GUI_STREAM.contains("read_delivery_history(home)?"));
    assert!(GUI_STREAM.contains("format!(\"proactive:{}\", record.intent_id())"));
    assert!(GUI_STREAM.contains("EVENT_TYPE_PROACTIVE_SENT => None"));
    assert!(GUI_MAIN.contains("proactive_egress::read_delivery_history(home)"));
    assert!(GUI_MAIN.contains("merge_channel_activity_rows"));
    assert!(GUI_SLINT.contains("outcome: string"));
    assert!(GUI_SLINT.contains("verification: string"));
    assert!(GUI_SLINT.contains("\"legacy_unverified\""));
    assert!(GUI_SLINT.contains("wal_verified | legacy_unverified"));
    assert!(GUI_MAIN.contains("\"wal_verified\""));
    assert!(!GUI_MAIN.contains("private_projection"));
    assert!(!GUI_SLINT.contains("private_projection"));
}

#[test]
fn modern_history_is_bound_to_marker_authenticated_wal_evidence() {
    let record = between(
        EGRESS,
        "pub struct ProactiveDeliveryRecord",
        "impl ProactiveDeliveryRecord",
    );
    for field in [
        "wal_chain_base: String",
        "recipient_sha256: String",
        "intent_frame_sha256: String",
        "armed_frame_sha256: Option<String>",
        "result_frame_sha256: String",
    ] {
        assert!(
            record.contains(field),
            "missing authenticated record field: {field}"
        );
    }
    let append_result = between(EGRESS, "async fn append_result(", "fn terminal_result(");
    assert!(append_result.contains("append_authenticated_while_lock_survives_cancellation"));
    let history = between(
        EGRESS,
        "pub fn read_delivery_history(",
        "fn rotate_sidecar(",
    );
    assert!(history.contains("scan_authenticated_projection_wal"));
    assert!(history.contains("verify_delivery_record_against_wal"));
    assert!(EGRESS.contains("for_each_authenticated_frame_in_existing_home_segment_chain"));
    assert!(EGRESS.contains("\"wal_verified\""));
    assert!(!EGRESS.contains("\"private_projection\""));
    assert!(WAL_WRITER.contains("pub(crate) async fn append_authenticated("));
    assert!(WAL_WRITER.contains("state_c.should_emit() || req.force_authentication_marker"));
    assert!(WAL_SCAN.contains("authenticated_through: usize"));
    assert!(WAL_SCAN.contains("authenticated_prefix_only"));
    assert!(
        WAL_SCAN.contains("authenticated_prefix_scan_hides_live_tail_and_accepts_rotation_archive")
    );
}

#[test]
fn canonical_wal_chain_path_and_authenticated_commit_are_threaded_from_serve() {
    assert!(SERVE.contains("&segment_chain_base_path,"));
    assert!(SERVE_TASKS.contains("wal_segment_path: &std::path::Path"));
    assert!(SERVE_TASKS.contains("wal_segment_path.to_path_buf()"));
    assert!(DISPATCHER.contains("wal_segment_path: PathBuf"));

    let result_append = between(EGRESS, "async fn append_result(", "fn terminal_result(");
    assert!(result_append.contains("HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)"));
    assert!(result_append.contains("append_authenticated_while_lock_survives_cancellation("));
    let authenticated_append = between(
        EGRESS,
        "async fn append_authenticated_while_lock_survives_cancellation(",
        "async fn append_intent(",
    );
    assert!(authenticated_append.contains("writer.append_authenticated(header, payload).await"));

    let authenticated_request = between(
        WAL_WRITER,
        "pub(crate) async fn append_authenticated(",
        "async fn append_with_marker_policy(",
    );
    assert!(
        authenticated_request
            .contains("self.append_with_marker_policy(header, payload, true).await")
    );
    let request = between(
        WAL_WRITER,
        "pub struct WriteRequest {",
        "/// Deterministic one-shot pause",
    );
    assert!(request.contains("force_authentication_marker: bool"));
    let enqueue = between(
        WAL_WRITER,
        "async fn append_with_marker_policy(",
        "/// Blocking counterpart to",
    );
    assert!(enqueue.contains("WriteRequest {"));
    assert!(enqueue.contains("force_authentication_marker,"));

    let immediate_policy = between(
        EVENTS,
        "pub fn needs_immediate_sync(event_type: u8) -> bool {",
        "/// Operator-facing event-type name table",
    );
    assert!(immediate_policy.contains("!matches!("));
    assert!(
        !immediate_policy.contains("EVENT_TYPE_EXTENDED"),
        "proactive EXTENDED frames must remain immediate-sync by default"
    );

    let writer_commit = between(
        WAL_WRITER,
        "let immediate = crate::wal::events::needs_immediate_sync(req.header.event_type);",
        "// Pick #40: shutdown drain",
    );
    let ordered = [
        "let immediate = crate::wal::events::needs_immediate_sync(req.header.event_type);",
        "write_and_sync(state.active_file_mut()?, &frame).await",
        "state_c.should_emit() || req.force_authentication_marker",
        "emit_compaction_marker(&mut state, state_c, key).await",
        "req.ack.send(Ok(written_at))",
    ];
    let positions: Vec<_> = ordered
        .iter()
        .map(|needle| {
            writer_commit
                .find(needle)
                .unwrap_or_else(|| panic!("missing authenticated commit stage: {needle}"))
        })
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));

    let marker_commit = between(
        WAL_WRITER,
        "async fn emit_compaction_marker(",
        "async fn closed_segment_binding(",
    );
    assert!(
        marker_commit.contains("write_and_sync(state.active_file_mut()?, &marker_frame).await?")
    );
}
