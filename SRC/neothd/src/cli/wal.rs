//! `neoth wal` — read-only WAL segment inspector. Phase 33c follow-up.
//!
//! Two subcommands:
//!   `stats <segment>` — count frames per event-type, total bytes, header
//!                       validity. Pairs with `neoth events` (registry) for
//!                       "what's actually in this segment".
//!   `show <segment>`  — pretty-print every frame: offset, code, payload-len,
//!                       importance, ts_ns, hash. `--limit N` for quick peeks.
//!
//! Pure read-only over `wal/*.wal` files. No DB access. No daemon
//! required — operator can run this against a backup tarball's segments
//! before restoring.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wal::compaction::{self, MarkerPayload};
use crate::wal::compress::decompress_frames;
use crate::wal::events::{
    EVENT_TYPE_COMPACTION_MARKER, event_code_from_filter, event_name_from_code,
};
use crate::wal::frame::decode_frame;
use crate::wal::proof_bundle::{
    PROOF_SCHEMA_VERSION, ProofBundle, ProofEnvelope, ProofFrame, ProofMarker,
};
use crate::wal::segment_header::{SEGMENT_HEADER_LEN, parse_segment_header};

#[derive(Args, Debug, Clone)]
pub struct WalArgs {
    #[command(subcommand)]
    pub action: WalAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum WalAction {
    /// Count frames per event type + report header validity + total bytes.
    Stats {
        /// Path to the segment file (`~/.neoth/wal/NNNNNN.wal`).
        segment: PathBuf,
    },
    /// Pretty-print frames, newest first. With no `<segment>`, scans
    /// EVERY `~/.neoth/wal/*.wal` segment so an operator can audit the
    /// whole chain without naming a file. `--type` filters to one event
    /// type — this is how an operator proves a guarantee, e.g.
    /// `neoth wal show --type plugin_cap_denied` (every denied plugin
    /// hostcall) or `--type provider_fallback_attempted` (every 429
    /// failover).
    Show {
        /// Segment file. Omit to scan ALL `~/.neoth/wal/*.wal`.
        segment: Option<PathBuf>,
        /// Filter to ONE event type. Accepts a name (`plugin_cap_denied`),
        /// hex (`0xC7` / `c7`), or decimal. See `neoth events` for names.
        #[arg(long = "type", value_name = "TYPE")]
        event_type: Option<String>,
        /// Show at most this many (the most recent). `--last` is an alias.
        #[arg(long, visible_alias = "last", default_value_t = 50)]
        limit: usize,
        /// Skip this many of the most-recent frames before showing.
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// KF-03 — export a tamper-evidence `.neoth-proof` bundle covering every
    /// frame in a time window, plus the HMAC compaction marker(s) sealing
    /// those bytes. A third party re-checks integrity offline (`neoth wal
    /// verify-proof`). `--sign` uses the operator's auto-managed ed25519 proof
    /// key (generated on first use; no minisign tool / keygen / password).
    Export {
        /// Window: a duration back from now (`24h`, `7d`, `30m`, `3600`) or a
        /// UTC RFC3339 range (`2026-05-01T00:00:00Z..2026-05-02T00:00:00Z`).
        #[arg(long, value_name = "WINDOW")]
        window: String,
        /// Output path. Default: `~/.neoth/exports/neoth-<unix>.neoth-proof`.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        /// Re-verify each included compaction marker's HMAC against the local
        /// key at export time (sets `chain_verified`). Off by default so an
        /// operator without the key can still export the metadata bundle.
        #[arg(long, default_value_t = false)]
        verify_chain: bool,
        /// WAL directory override (tests / inspecting a backup).
        #[arg(long, value_name = "DIR")]
        wal_dir: Option<PathBuf>,
        /// KF-03 — ed25519-sign the bundle with the operator's auto-managed
        /// signing key (`~/.neoth/wal/signing.key`, generated on first use, no
        /// prompt). Embeds the signature + public key so a third party can run
        /// `neoth wal verify-proof`. Off by default (an unsigned metadata
        /// bundle still carries the SHA-256 self-integrity digest).
        #[arg(long, default_value_t = false)]
        sign: bool,
    },
    /// KF-03 — verify a `.neoth-proof` bundle: re-check the SHA-256
    /// self-integrity digest, then (if signed) the ed25519 signature. Prints a
    /// plain-language verdict + exits non-zero on tamper / bad signature.
    /// Pass `--pubkey <base64>` (the operator's out-of-band-shared key) for
    /// TRUE attribution; without it the signature is only self-consistency-
    /// checked against the key embedded in the file.
    VerifyProof {
        /// Path to the `.neoth-proof` file.
        #[arg(long, value_name = "PATH")]
        proof: PathBuf,
        /// Operator's expected signing public key (base64), pinned out-of-band.
        #[arg(long, value_name = "BASE64")]
        pubkey: Option<String>,
    },
    /// PROOF-KEY-01 — inspect the operator's proof signing key (the ed25519
    /// key `wal export --sign` uses, `~/.neoth/wal/signing.key`). READ-ONLY —
    /// never generates the key (use `wal export --sign` to create it on first
    /// use). `rotate` is a follow-on.
    ProofKey {
        #[command(subcommand)]
        action: ProofKeyAction,
    },
}

/// PROOF-KEY-01 sub-actions.
#[derive(Subcommand, Debug, Clone)]
pub enum ProofKeyAction {
    /// Print the proof signing key's public key + on-disk path (or report that
    /// no key exists yet).
    Show,
    /// Print ONLY the base64 public key (pipe it to an auditor so they can
    /// `wal verify-proof --pubkey <key>`). Exits non-zero if no key exists yet.
    ExportPub,
    /// PROOF-KEY-01 — sign an arbitrary message with the operator's proof key
    /// (auto-creates the key on first use, same as `wal export --sign`). Prints
    /// the base64 detached ed25519 signature + the public key.
    Sign {
        /// The message to sign.
        #[arg(value_name = "MESSAGE")]
        message: String,
    },
    /// PROOF-KEY-01 — verify a base64 signature over MESSAGE. Defaults to THIS
    /// operator's proof key when `--pubkey` is omitted; exits non-zero on
    /// mismatch.
    Verify {
        /// The signed message.
        #[arg(value_name = "MESSAGE")]
        message: String,
        /// The base64 detached signature (from `proof-key sign`).
        #[arg(value_name = "BASE64_SIG")]
        signature: String,
        /// The signer's base64 public key. Defaults to this operator's proof key.
        #[arg(long, value_name = "BASE64")]
        pubkey: Option<String>,
    },
}

pub async fn run_wal(args: WalArgs) -> Result<()> {
    match args.action {
        WalAction::Stats { segment } => stats(&segment, args.output),
        WalAction::Show {
            segment,
            event_type,
            limit,
            skip,
        } => {
            let home = FreedomConfig::default_neoth_home();
            show(
                segment.as_deref(),
                event_type.as_deref(),
                limit,
                skip,
                &home,
                args.output,
            )
        }
        WalAction::Export {
            window,
            out,
            verify_chain,
            wal_dir,
            sign,
        } => {
            let wal_dir = wal_dir.unwrap_or_else(FreedomConfig::default_wal_dir);
            run_wal_export(
                &window,
                out.as_deref(),
                &wal_dir,
                verify_chain,
                sign,
                args.output,
            )
        }
        WalAction::VerifyProof { proof, pubkey } => {
            run_verify_proof(&proof, pubkey.as_deref(), args.output)
        }
        WalAction::ProofKey { action } => run_proof_key(action, args.output),
    }
}

/// PROOF-KEY-01 — the proof signing key's public key (base64), or `None` when
/// no key has been created yet. READ-ONLY: does not generate the key (unlike
/// `wal export --sign`), so `proof-key show` on a fresh install reports "not
/// created" instead of silently minting one.
fn proof_key_pubkey(key_path: &Path) -> Result<Option<String>> {
    if !key_path.exists() {
        return Ok(None);
    }
    // The key file exists, so `load_or_init_signing_key` reads it (no
    // generation path is taken).
    let key = crate::wal::signing::load_or_init_signing_key(key_path)
        .context("read the proof signing key")?;
    Ok(Some(crate::wal::signing::pubkey_b64(&key)))
}

/// PROOF-KEY-01 (PROG-17) — sign `message` with the operator's proof key
/// (auto-created on first use), returning `(base64_signature, base64_pubkey)`.
/// Pure helper so the CLI handler is unit-testable against a temp key path.
fn proof_sign(key_path: &Path, message: &str) -> Result<(String, String)> {
    let key = crate::wal::signing::load_or_init_signing_key(key_path)
        .context("load or create the proof signing key")?;
    Ok((
        crate::wal::signing::sign_b64(&key, message.as_bytes()),
        crate::wal::signing::pubkey_b64(&key),
    ))
}

/// PROOF-KEY-01 (PROG-17) — verify a base64 `signature` over `message`.
/// `claimed_pubkey` defaults to THIS operator's proof key (read-only; never
/// mints one). `Ok(())` iff valid, descriptive `Err` otherwise.
fn proof_verify(
    key_path: &Path,
    message: &str,
    signature: &str,
    claimed_pubkey: Option<&str>,
) -> Result<()> {
    let pk = match claimed_pubkey {
        Some(p) => p.to_string(),
        None => proof_key_pubkey(key_path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no proof signing key yet + no --pubkey given — nothing to verify against"
            )
        })?,
    };
    crate::wal::signing::verify_b64(&pk, signature, message.as_bytes())
}

fn run_proof_key(action: ProofKeyAction, output: OutputFormat) -> Result<()> {
    let path = crate::wal::signing::default_signing_key_path();
    let pubkey = proof_key_pubkey(&path)?;
    match action {
        ProofKeyAction::Show => match (&pubkey, output) {
            (_, OutputFormat::Json | OutputFormat::Jsonl) => println!(
                "{}",
                serde_json::json!({
                    "path": path.display().to_string(),
                    "exists": pubkey.is_some(),
                    "algorithm": crate::wal::signing::SIG_ALGORITHM,
                    "public_key": pubkey,
                })
            ),
            (Some(pk), OutputFormat::Table) => {
                println!("proof signing key ({})", crate::wal::signing::SIG_ALGORITHM);
                println!("  path:       {}", path.display());
                println!("  public_key: {pk}");
                println!(
                    "  share the public key with auditors; they verify with \
                     `neoth wal verify-proof --proof <file> --pubkey <key>`"
                );
            }
            (None, OutputFormat::Table) => {
                println!(
                    "no proof signing key yet at {} — run `neoth wal export --sign` once to \
                     create it (auto-generated, no prompt).",
                    path.display(),
                );
            }
        },
        ProofKeyAction::ExportPub => match pubkey {
            Some(pk) => println!("{pk}"),
            None => {
                eprintln!(
                    "no proof signing key yet — run `neoth wal export --sign` once to create it."
                );
                // GOLD-COR-01 / A-03: QuietExit instead of process::exit so the
                // stack unwinds (Drop-time flushes run) before the code lands.
                return Err(crate::QuietExit(1).into());
            }
        },
        ProofKeyAction::Sign { message } => {
            let (sig, pk) = proof_sign(&path, &message)?;
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({
                        "message": message,
                        "signature": sig,
                        "public_key": pk,
                        "algorithm": crate::wal::signing::SIG_ALGORITHM,
                    })
                ),
                OutputFormat::Table => {
                    println!("signature:  {sig}");
                    println!("public_key: {pk}");
                    println!("  verify: neoth wal proof-key verify \"{message}\" {sig}");
                }
            }
        }
        ProofKeyAction::Verify {
            message,
            signature,
            pubkey: claimed,
        } => match proof_verify(&path, &message, &signature, claimed.as_deref()) {
            Ok(()) => match output {
                OutputFormat::Json | OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::json!({ "verified": true, "message": message })
                ),
                OutputFormat::Table => println!("✓ verified — signature matches the public key"),
            },
            Err(e) => {
                match output {
                    OutputFormat::Json | OutputFormat::Jsonl => println!(
                        "{}",
                        serde_json::json!({ "verified": false, "error": e.to_string() })
                    ),
                    OutputFormat::Table => eprintln!("✗ NOT verified — {e}"),
                }
                return Err(crate::QuietExit(1).into());
            }
        },
    }
    Ok(())
}

/// Full result of a stats walk over one segment.
#[derive(Debug, Clone)]
pub struct SegmentStats {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub segment_seq: Option<u64>,
    pub header_ok: bool,
    pub header_error: Option<String>,
    pub frame_count: usize,
    pub bad_frames: usize,
    pub per_event: BTreeMap<u8, usize>,
}

pub fn collect_stats(segment: &std::path::Path) -> Result<SegmentStats> {
    let bytes = std::fs::read(segment).with_context(|| format!("read {}", segment.display()))?;
    let size = bytes.len() as u64;
    let mut stats = SegmentStats {
        path: segment.to_path_buf(),
        size_bytes: size,
        segment_seq: None,
        header_ok: false,
        header_error: None,
        frame_count: 0,
        bad_frames: 0,
        per_event: BTreeMap::new(),
    };
    if bytes.len() < SEGMENT_HEADER_LEN {
        stats.header_error = Some(format!(
            "shorter than SegmentHeader ({} < {})",
            bytes.len(),
            SEGMENT_HEADER_LEN,
        ));
        return Ok(stats);
    }
    // GOLD-ARCH-03: parse v1/v2 headers and decompress a v2/zstd body so a
    // compressed segment's frames are COUNTED rather than silently skipped
    // (the old v1-only `SegmentHeader::from_le_bytes` + hardcoded-offset walk
    // reported a valid compressed segment as header-BAD with zero frames).
    // Mirrors the `show` / `collect_proof` scanners in this file.
    let hdr = match parse_segment_header(&bytes) {
        Ok(h) => h,
        Err(e) => {
            stats.header_error = Some(format!("{e}"));
            return Ok(stats);
        }
    };
    stats.header_ok = true;
    stats.segment_seq = Some(hdr.segment_seq());
    let header_len = hdr.header_len();
    let body = bytes.get(header_len..).unwrap_or(&[]);
    let decompressed;
    let frames: &[u8] = if hdr.is_compressed() {
        match decompress_frames(body) {
            Ok(d) => {
                decompressed = d;
                &decompressed
            }
            Err(e) => {
                // A flagged-compressed body that won't inflate is corrupt —
                // surface it rather than report a misleading zero-frame count.
                stats.header_error = Some(format!("decompress segment body: {e}"));
                return Ok(stats);
            }
        }
    } else {
        body
    };

    let mut cursor = 0usize;
    while cursor < frames.len() {
        match decode_frame(&frames[cursor..]) {
            Ok(dec) => {
                stats.frame_count += 1;
                *stats.per_event.entry(dec.header.event_type).or_insert(0) += 1;
                let total = dec.header.total_len as usize;
                if total == 0 {
                    stats.bad_frames += 1;
                    break;
                }
                cursor = cursor.saturating_add(total);
            }
            Err(_) => {
                stats.bad_frames += 1;
                break;
            }
        }
    }
    Ok(stats)
}

fn stats(segment: &std::path::Path, output: OutputFormat) -> Result<()> {
    let s = collect_stats(segment)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = s
                .per_event
                .iter()
                .map(|(code, n)| {
                    serde_json::json!({
                        "code": format!("0x{code:02X}"),
                        "count": n,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "path": s.path.display().to_string(),
                    "size_bytes": s.size_bytes,
                    "segment_seq": s.segment_seq,
                    "header_ok": s.header_ok,
                    "header_error": s.header_error,
                    "frame_count": s.frame_count,
                    "bad_frames": s.bad_frames,
                    "per_event": rows,
                })
            );
        }
        OutputFormat::Table => {
            println!("# segment: {}", s.path.display());
            println!("#   size:      {} bytes", s.size_bytes);
            match (s.header_ok, s.segment_seq, &s.header_error) {
                (true, Some(seq), _) => println!("#   header:    ok (segment_seq={seq})"),
                (false, _, Some(e)) => println!("#   header:    BAD — {e}"),
                _ => println!("#   header:    BAD — unknown error"),
            }
            println!("#   frames:    {}", s.frame_count);
            if s.bad_frames > 0 {
                println!("#   bad frame: STOP — torn frame at end (op safe; daemon will recover)");
            }
            println!();
            if s.per_event.is_empty() {
                println!("  (no frames)");
            } else {
                println!("  {:<6}  {:<6}  per-event count", "code", "count");
                for (code, n) in &s.per_event {
                    println!("  0x{code:02X}    {n:<6}");
                }
            }
        }
    }
    Ok(())
}

/// One decoded frame the show pass surfaces.
struct ShownFrame {
    event_type: u8,
    event_subtype: u8,
    payload_len: u32,
    importance: f32,
    ts_ns: u64,
    event_id: u64,
    payload_hash: u64,
}

fn show(
    segment: Option<&Path>,
    type_filter: Option<&str>,
    limit: usize,
    skip: usize,
    home: &Path,
    output: OutputFormat,
) -> Result<()> {
    // Resolve the --type filter to a concrete code (fail loudly on an
    // unknown token rather than silently filtering to nothing).
    let want: Option<u8> = match type_filter {
        Some(t) => Some(event_code_from_filter(t).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown --type `{t}` — use an event name (e.g. plugin_cap_denied), \
                 a hex code (0xC7), or a decimal. `neoth events` lists the registry."
            )
        })?),
        None => None,
    };

    // Segments: an explicit path is read strictly (a bad header is an
    // error — the operator named that file); a whole-chain scan is
    // tolerant (a torn segment is skipped, like the ledger/council walkers).
    let (segments, strict) = match segment {
        Some(p) => (vec![p.to_path_buf()], true),
        None => (sorted_segments(&home.join("wal")), false),
    };

    let mut frames: Vec<ShownFrame> = Vec::new();
    let mut walked = 0usize;
    for seg in &segments {
        match read_segment_frames(seg, want, &mut frames, &mut walked) {
            Ok(()) => {}
            Err(e) if strict => return Err(e),
            Err(e) => {
                tracing::warn!(error = %e, segment = %seg.display(), "skipped unreadable segment")
            }
        }
    }

    // Newest-first: the chain is appended chronologically, so the tail is
    // the most recent. Apply `skip` from the newest end, then take `limit`.
    frames.reverse();
    let view: Vec<&ShownFrame> = frames.iter().skip(skip).take(limit).collect();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<serde_json::Value> = view
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "event_type": format!("0x{:02X}", f.event_type),
                        "event_name": event_name_from_code(f.event_type),
                        "event_subtype": f.event_subtype,
                        "payload_len": f.payload_len,
                        "importance": f.importance,
                        "ts_ns": f.ts_ns,
                        "event_id": f.event_id,
                        "payload_hash": format!("{:016x}", f.payload_hash),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "type_filter": type_filter,
                    "segments_scanned": segments.len(),
                    "frames_matched": frames.len(),
                    "frames_shown": view.len(),
                    "frames": rows,
                })
            );
        }
        OutputFormat::Table => {
            for f in &view {
                let name = event_name_from_code(f.event_type).unwrap_or("?");
                println!(
                    "  0x{code:02X} {name:<26}  id={id:<8}  ts_ns={ts}  payload={plen}  imp={imp:.2}  hash={h:016x}",
                    code = f.event_type,
                    name = name,
                    id = f.event_id,
                    ts = f.ts_ns,
                    plen = f.payload_len,
                    imp = f.importance,
                    h = f.payload_hash,
                );
            }
            let filt = type_filter
                .map(|t| format!(" (type={t})"))
                .unwrap_or_default();
            println!(
                "# {} of {} matching frame(s){filt}, newest first — scanned {} segment(s)",
                view.len(),
                frames.len(),
                segments.len(),
            );
        }
    }
    Ok(())
}

/// Sorted `*.wal` paths under `wal_dir` (zero-padded names sort
/// chronologically). Empty when the dir is missing or has none.
fn sorted_segments(wal_dir: &Path) -> Vec<PathBuf> {
    let mut segs: Vec<PathBuf> = match std::fs::read_dir(wal_dir) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
            .collect(),
        Err(_) => Vec::new(),
    };
    segs.sort();
    segs
}

/// Robust v1/v2 read of one segment: parse the header, decompress a v2
/// zstd body, then walk frames, pushing those matching `want` (or all
/// when `None`). Mirrors the ledger/council/refusal walkers.
fn read_segment_frames(
    path: &Path,
    want: Option<u8>,
    out: &mut Vec<ShownFrame>,
    walked: &mut usize,
) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let hdr = parse_segment_header(&bytes)
        .map_err(|e| anyhow::anyhow!("parse segment header {}: {e}", path.display()))?;
    let header_len = hdr.header_len();
    if bytes.len() <= header_len {
        return Ok(());
    }
    let body = &bytes[header_len..];
    let decompressed;
    let frames: &[u8] = if hdr.is_compressed() {
        decompressed = decompress_frames(body)
            .map_err(|e| anyhow::anyhow!("decompress {}: {e}", path.display()))?;
        &decompressed
    } else {
        body
    };

    let mut cursor = 0usize;
    while cursor < frames.len() {
        let dec = match decode_frame(&frames[cursor..]) {
            Ok(d) => d,
            Err(_) => break, // torn tail — stop this segment cleanly
        };
        *walked += 1;
        if want.is_none_or(|w| dec.header.event_type == w) {
            out.push(ShownFrame {
                event_type: dec.header.event_type,
                event_subtype: dec.header.event_subtype,
                payload_len: dec.header.payload_len,
                importance: dec.header.importance.raw(),
                ts_ns: dec.header.hlc.physical_ns(),
                event_id: dec.header.event_id.0,
                payload_hash: dec.header.payload_hash,
            });
        }
        let total = dec.header.total_len as usize;
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    Ok(())
}

// ── KF-03 tamper-evidence export ─────────────────────────────────────────

/// Parse a `--window` spec into `(start_ns, end_ns)` unix nanoseconds.
/// Two forms: a duration back from now (`24h` / `7d` / `30m` / bare seconds
/// via [`crate::cli::privacy::parse_duration`]) or a UTC RFC3339 range
/// `<from>..<to>`. The range is half-open `[start, end)`.
fn parse_window(spec: &str, now_ns: u64) -> Result<(u64, u64)> {
    if let Some((lo, hi)) = spec.split_once("..") {
        let from = chrono::DateTime::parse_from_rfc3339(lo.trim())
            .with_context(|| format!("parse window start `{lo}` as RFC3339"))?;
        let to = chrono::DateTime::parse_from_rfc3339(hi.trim())
            .with_context(|| format!("parse window end `{hi}` as RFC3339"))?;
        let s = from.timestamp_nanos_opt().unwrap_or(0).max(0) as u64;
        let e = to.timestamp_nanos_opt().unwrap_or(0).max(0) as u64;
        if e <= s {
            anyhow::bail!("window end must be after start (`{lo}` .. `{hi}`)");
        }
        Ok((s, e))
    } else {
        let secs = crate::cli::privacy::parse_duration(spec)
            .with_context(|| format!("parse window duration `{spec}`"))?;
        let span_ns = secs.saturating_mul(1_000_000_000);
        Ok((now_ns.saturating_sub(span_ns), now_ns))
    }
}

/// A collected compaction marker plus the on-disk segment path it lives in
/// (needed to re-run `verify_marker` against the original bytes).
type CollectedMarker = (PathBuf, MarkerPayload);

/// Walk every segment, collecting frames in `[start_ns, end_ns)` plus all
/// compaction markers encountered (markers seal byte ranges — a verifier
/// uses them to re-check tamper evidence). Returns `(frames, markers)` where
/// each marker carries its full on-disk segment path for later verification.
fn collect_proof(
    wal_dir: &Path,
    start_ns: u64,
    end_ns: u64,
) -> Result<(Vec<ProofFrame>, Vec<CollectedMarker>)> {
    let mut frames: Vec<ProofFrame> = Vec::new();
    let mut markers: Vec<CollectedMarker> = Vec::new();

    for seg_path in sorted_segments(wal_dir) {
        let seg_name = seg_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?.wal")
            .to_string();
        let bytes =
            std::fs::read(&seg_path).with_context(|| format!("read {}", seg_path.display()))?;
        let hdr = match parse_segment_header(&bytes) {
            Ok(h) => h,
            Err(_) => continue, // skip an unreadable header rather than abort the export
        };
        let header_len = hdr.header_len();
        if bytes.len() <= header_len {
            continue;
        }
        let body = &bytes[header_len..];
        let decompressed;
        let stream: &[u8] = if hdr.is_compressed() {
            decompressed = match decompress_frames(body) {
                Ok(d) => d,
                Err(_) => continue,
            };
            &decompressed
        } else {
            body
        };

        let mut cursor = 0usize;
        while cursor < stream.len() {
            let dec = match decode_frame(&stream[cursor..]) {
                Ok(d) => d,
                Err(_) => break, // torn tail — stop this segment cleanly
            };
            let et = dec.header.event_type;
            let ts = dec.header.hlc.physical_ns();
            if et == EVENT_TYPE_COMPACTION_MARKER {
                // Markers anchor the HMAC chain; include every one we see so a
                // verifier can re-check whatever range covers the window.
                if let Ok(m) = serde_json::from_slice::<MarkerPayload>(dec.payload) {
                    markers.push((seg_path.clone(), m));
                }
            } else if ts >= start_ns && ts < end_ns {
                frames.push(ProofFrame {
                    segment: seg_name.clone(),
                    offset: cursor as u64,
                    event_type: et,
                    event_id: dec.header.event_id.0,
                    ts_ns: ts,
                    payload_hash: dec.header.payload_hash,
                    payload_len: dec.header.payload_len,
                    importance: dec.header.importance.raw(),
                });
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
    }
    Ok((frames, markers))
}

fn run_wal_export(
    window: &str,
    out: Option<&Path>,
    wal_dir: &Path,
    verify_chain: bool,
    sign: bool,
    output: OutputFormat,
) -> Result<()> {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let now_unix = (now_ns / 1_000_000_000) as i64;
    let (start_ns, end_ns) = parse_window(window, now_ns)?;

    let (frames, raw_markers) = collect_proof(wal_dir, start_ns, end_ns)?;

    // Optionally re-verify each marker's HMAC against the local key NOW so the
    // bundle records a verified-at-export verdict. Without the key (or with the
    // flag off) the verifier checks it themselves — `verified_at_export: None`.
    let key = if verify_chain {
        compaction::load_or_init_key(&compaction::default_key_path()).ok()
    } else {
        None
    };
    let mut all_verified = !raw_markers.is_empty();
    let markers: Vec<ProofMarker> = raw_markers
        .iter()
        .map(|(seg, m)| {
            let verified = key
                .as_ref()
                .map(|k| compaction::verify_marker(seg, k, m).is_ok());
            if verified != Some(true) {
                all_verified = false;
            }
            ProofMarker {
                segment: seg
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?.wal")
                    .to_string(),
                from_offset: m.from_offset,
                to_offset: m.to_offset,
                frame_count: m.frame_count,
                hmac_hex: m.hmac_hex.clone(),
                verified_at_export: verified,
            }
        })
        .collect();

    let frame_count = frames.len();
    let marker_count = markers.len();
    let bundle = ProofBundle {
        schema_version: PROOF_SCHEMA_VERSION,
        neoth_version: env!("CARGO_PKG_VERSION").to_string(),
        window_start_ts_ns: start_ns,
        window_end_ts_ns: end_ns,
        generated_unix: now_unix,
        frames,
        markers,
        chain_verified: all_verified,
    };
    let mut envelope = ProofEnvelope::seal(bundle);

    // KF-03: optionally ed25519-sign the bundle with the operator's
    // auto-managed signing key (generated on first use — DAU-safe, no prompt,
    // no install). Embeds the signature + public key into the envelope.
    let signed_pubkey: Option<String> = if sign {
        let key = crate::wal::signing::load_or_init_signing_key(
            &crate::wal::signing::default_signing_key_path(),
        )
        .context("load or generate the operator signing key")?;
        envelope.sign(&key);
        Some(crate::wal::signing::pubkey_b64(&key))
    } else {
        None
    };

    // Default output: ~/.neoth/exports/neoth-<unix>.neoth-proof (predictable
    // dir so the doctor freshness check can find it).
    let out_path: PathBuf = match out {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = FreedomConfig::default_neoth_home().join("exports");
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("create export dir {}", dir.display()))?;
            dir.join(format!("neoth-{now_unix}.neoth-proof"))
        }
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create export dir {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(&envelope).context("serialise proof envelope")?;
    // Atomic tmp + rename so a crash mid-write can't leave a truncated proof.
    let tmp = out_path.with_extension("neoth-proof.tmp");
    std::fs::write(&tmp, body.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &out_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), out_path.display()))?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "out": out_path.display().to_string(),
                    "frames": frame_count,
                    "markers": marker_count,
                    "chain_verified": envelope.bundle.chain_verified,
                    "digest_sha256": envelope.digest_sha256,
                    "window_start_ts_ns": start_ns,
                    "window_end_ts_ns": end_ns,
                    "signed": signed_pubkey.is_some(),
                    "signer_pubkey": signed_pubkey,
                })
            );
        }
        OutputFormat::Table => {
            println!("# Tamper-evidence proof written");
            println!("  out:            {}", out_path.display());
            println!("  frames:         {frame_count}");
            println!(
                "  markers:        {marker_count} (chain_verified={})",
                envelope.bundle.chain_verified
            );
            println!("  digest_sha256:  {}", envelope.digest_sha256);
            match &signed_pubkey {
                Some(pk) => {
                    println!("  signed:         yes (ed25519)");
                    println!("  signer_pubkey:  {pk}");
                    println!(
                        "  share that public key with auditors; they verify with \
                         `neoth wal verify-proof --proof <file> --pubkey <key>`"
                    );
                }
                None => println!(
                    "  signed:         no (--sign to ed25519-sign with your operator key)"
                ),
            }
            if marker_count == 0 {
                println!(
                    "  note: window is not yet sealed by a compaction marker — \
                     per-frame payload_hash still anchors integrity; \
                     re-export later once a marker covers it for full chain proof."
                );
            }
            if !envelope.bundle.chain_verified && verify_chain && marker_count > 0 {
                println!(
                    "  WARNING: at least one marker FAILED HMAC re-verification — \
                     the WAL window may have been tampered with."
                );
            }
        }
    }
    Ok(())
}

/// First 16 chars of a base64 public key + an ellipsis, for human-readable
/// output (the full key is in the JSON / the file).
fn short_pubkey(pk: &str) -> String {
    let t = pk.trim();
    if t.len() > 16 {
        format!("{}…", &t[..16])
    } else {
        t.to_string()
    }
}

/// KF-03 — verify a `.neoth-proof` bundle. Checks the SHA-256 self-integrity
/// digest FIRST (catches frame-list tampering), then the ed25519 signature if
/// present. Prints ONE plain-language verdict line a non-technical operator
/// can act on, and exits non-zero on tamper / bad signature so it gates a
/// script. `--pubkey` (the operator's out-of-band-pinned key) upgrades a
/// self-consistency check into true attribution.
fn run_verify_proof(
    proof: &Path,
    expected_pubkey: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    use crate::wal::proof_bundle::{ProofEnvelope, SignatureCheck};

    let body = std::fs::read_to_string(proof)
        .with_context(|| format!("read proof bundle {}", proof.display()))?;
    let envelope: ProofEnvelope = serde_json::from_str(&body)
        .with_context(|| format!("parse proof bundle {}", proof.display()))?;

    let digest_ok = envelope.digest_matches();
    let (ok, verdict): (bool, String) = if !digest_ok {
        (
            false,
            "TAMPERED — SHA-256 digest mismatch: the bundle's frame list was altered after export."
                .to_string(),
        )
    } else {
        match envelope.check_signature(expected_pubkey) {
            SignatureCheck::Unsigned => (
                true,
                "OK (UNSIGNED) — digest intact; the bundle was not signed, so its origin is not attested."
                    .to_string(),
            ),
            SignatureCheck::SelfConsistent { signer_pubkey } => (
                true,
                format!(
                    "OK (SELF-CONSISTENT) — digest intact + signature valid against the embedded key \
                     {}. NOTE: this proves the bundle was not altered after signing, NOT who signed it \
                     — for true attribution re-run with --pubkey <the operator's out-of-band key>.",
                    short_pubkey(&signer_pubkey),
                ),
            ),
            SignatureCheck::VerifiedAgainstExpected => (
                true,
                "VERIFIED — digest intact + signature valid against the operator's pinned public key. Authentic."
                    .to_string(),
            ),
            SignatureCheck::Invalid { reason } => (false, format!("BAD SIGNATURE — {reason}")),
        }
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "proof": proof.display().to_string(),
                    "ok": ok,
                    "digest_ok": digest_ok,
                    "verdict": verdict,
                    "signed": envelope.signature.is_some(),
                    "signer_pubkey": envelope.signer_pubkey,
                    "sig_algorithm": envelope.sig_algorithm,
                })
            );
        }
        OutputFormat::Table => println!("{verdict}"),
    }

    if !ok {
        // GOLD-COR-01 / A-03: verify-failure status via QuietExit so the WAL
        // reader + any open handles Drop-flush before the exit code is applied.
        return Err(crate::QuietExit(1).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::HeaderBuilder;
    use crate::wal::events::EVENT_TYPE_RAW_TEXT;
    use crate::wal::frame::encode_frame;
    use crate::wal::header::EventHeaderV2;
    use crate::wal::segment_header::SegmentHeader;
    use tempfile::tempdir;

    #[test]
    fn proof_sign_then_verify_round_trips_and_rejects_tampering() {
        // PROG-17: sign a message with a fresh proof key, verify with its pubkey
        // (explicit + operator-default), and prove tampering / wrong-sig fail.
        let dir = tempdir().unwrap();
        let kp = dir.path().join("signing.key");
        let (sig, pk) = proof_sign(&kp, "attest this bundle").unwrap();
        // Explicit pubkey verifies.
        assert!(proof_verify(&kp, "attest this bundle", &sig, Some(&pk)).is_ok());
        // Operator-default (None → reads the same on-disk key) verifies.
        assert!(proof_verify(&kp, "attest this bundle", &sig, None).is_ok());
        // A tampered message fails.
        assert!(proof_verify(&kp, "attest THAT bundle", &sig, Some(&pk)).is_err());
        // A garbage signature fails (not a 64-byte ed25519 sig).
        assert!(proof_verify(&kp, "attest this bundle", "AAAA", Some(&pk)).is_err());
        // Verify against an empty key dir with no --pubkey errors loudly.
        let empty = tempdir().unwrap();
        assert!(
            proof_verify(&empty.path().join("none.key"), "x", &sig, None).is_err(),
            "no key + no --pubkey must error, not silently pass"
        );
    }

    fn write_segment(dir: &std::path::Path, seq: u64, frames: usize) -> PathBuf {
        let path = dir.join(format!("{:06}.wal", seq));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut bytes: Vec<u8> = Vec::new();
        let sh = SegmentHeader::new(0, seq, 0, now, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        for i in 0..frames {
            let payload = format!("frame {i}").into_bytes();
            let header: EventHeaderV2 = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, &payload).build();
            let frame = encode_frame(&header, &payload);
            bytes.extend_from_slice(&frame);
        }
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    // ── KF-03 export tests ────────────────────────────────────────────────

    /// Write a segment with `raw` RAW_TEXT frames plus one COMPACTION_MARKER.
    fn write_segment_with_marker(dir: &std::path::Path, seq: u64, raw: usize) -> PathBuf {
        let path = dir.join(format!("{:06}.wal", seq));
        let mut bytes: Vec<u8> = Vec::new();
        let sh = SegmentHeader::new(0, seq, 0, 0, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        for i in 0..raw {
            let payload = format!("frame {i}").into_bytes();
            let header: EventHeaderV2 = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, &payload).build();
            bytes.extend_from_slice(&encode_frame(&header, &payload));
        }
        let marker = MarkerPayload {
            from_offset: 0,
            to_offset: 64,
            frame_count: raw as u32,
            hmac_hex: "deadbeef".into(),
        };
        let mpayload = serde_json::to_vec(&marker).unwrap();
        let mheader: EventHeaderV2 =
            HeaderBuilder::new(EVENT_TYPE_COMPACTION_MARKER, &mpayload).build();
        bytes.extend_from_slice(&encode_frame(&mheader, &mpayload));
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    #[test]
    fn parse_window_duration_forms() {
        let now = 1_000_000_000_000_000u64; // 1e6 s in ns — bigger than any span here
        let (s, e) = parse_window("100", now).unwrap(); // 100 bare seconds
        assert_eq!(e, now);
        assert_eq!(s, now - 100 * 1_000_000_000);
        let (s2, _) = parse_window("1h", now).unwrap();
        assert_eq!(now - s2, 3600 * 1_000_000_000);
    }

    #[test]
    fn parse_window_rfc3339_range() {
        let (s, e) = parse_window("2026-05-01T00:00:00Z..2026-05-02T00:00:00Z", 0).unwrap();
        assert_eq!(e - s, 86_400 * 1_000_000_000, "exactly one day apart");
        assert!(s > 0);
    }

    #[test]
    fn parse_window_rejects_garbage_and_inverted_range() {
        assert!(parse_window("notawindow", 0).is_err());
        assert!(
            parse_window("2026-05-02T00:00:00Z..2026-05-01T00:00:00Z", 0).is_err(),
            "end before start must error"
        );
    }

    #[test]
    fn collect_proof_picks_window_frames_and_markers() {
        // GOLD-COR-35: hold the shared test lock so a concurrent `wal::builder`
        // HLC-saturation test can't poison this test's `build()` stamps to
        // u64::MAX (which the `ts < u64::MAX` window-filter would then drop).
        let _env = crate::test_env::lock();
        let dir = tempdir().unwrap();
        write_segment_with_marker(dir.path(), 1, 3);
        // Wide-open window catches everything regardless of the now-stamped HLC.
        let (frames, markers) = collect_proof(dir.path(), 0, u64::MAX).unwrap();
        assert_eq!(frames.len(), 3, "3 RAW_TEXT frames in window");
        assert_eq!(markers.len(), 1, "the COMPACTION_MARKER is collected");
        assert_eq!(markers[0].1.frame_count, 3);
        // Frames carry their segment + a payload_hash anchor.
        assert_eq!(frames[0].segment, "000001.wal");
    }

    #[test]
    fn collect_proof_excludes_out_of_window_frames() {
        let dir = tempdir().unwrap();
        write_segment(dir.path(), 1, 4);
        // A window entirely in the past (ns 1..2) excludes the now-stamped frames.
        let (frames, _) = collect_proof(dir.path(), 1, 2).unwrap();
        assert!(frames.is_empty(), "no frames fall in a long-past window");
    }

    #[test]
    fn export_round_trip_writes_verifiable_envelope() {
        // GOLD-COR-35: shared test lock — see collect_proof test above.
        let _env = crate::test_env::lock();
        let waldir = tempdir().unwrap();
        write_segment_with_marker(waldir.path(), 1, 5);
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("proof.neoth-proof");
        run_wal_export("100d", Some(&out), waldir.path(), false, false, OutputFormat::Json).unwrap();

        let body = std::fs::read_to_string(&out).unwrap();
        let env: ProofEnvelope = serde_json::from_str(&body).unwrap();
        assert!(env.digest_matches(), "written envelope must self-verify");
        assert_eq!(env.bundle.frames.len(), 5);
        assert_eq!(env.bundle.markers.len(), 1);
        assert!(env.signature.is_none(), "unsigned slice");
        // verify_chain=false ⇒ marker not re-checked ⇒ chain_verified false.
        assert!(!env.bundle.chain_verified);
        assert_eq!(env.bundle.markers[0].verified_at_export, None);
    }

    #[test]
    fn export_tamper_in_envelope_is_detectable() {
        // GOLD-COR-35: shared test lock — see collect_proof test above.
        let _env = crate::test_env::lock();
        let waldir = tempdir().unwrap();
        write_segment_with_marker(waldir.path(), 1, 3);
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("p.neoth-proof");
        run_wal_export("100d", Some(&out), waldir.path(), false, false, OutputFormat::Json).unwrap();
        let mut env: ProofEnvelope =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        // Flip a frame's hash after export: the envelope digest must reject it.
        env.bundle.frames[0].payload_hash ^= 0xFFFF_FFFF;
        assert!(
            !env.digest_matches(),
            "post-export frame tampering must break the digest"
        );
    }

    #[test]
    fn verify_proof_accepts_a_signed_bundle() {
        // Export unsigned, then sign in-test with an EPHEMERAL key (so the test
        // never touches the operator's real ~/.neoth signing key), rewrite the
        // file, and confirm `verify-proof` accepts it on both the pinned-key
        // (VerifiedAgainstExpected) and embedded-key (SelfConsistent) paths.
        let waldir = tempdir().unwrap();
        write_segment_with_marker(waldir.path(), 1, 3);
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("p.neoth-proof");
        run_wal_export("100d", Some(&out), waldir.path(), false, false, OutputFormat::Json)
            .unwrap();
        let mut env: ProofEnvelope =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        env.sign(&key);
        std::fs::write(&out, serde_json::to_string_pretty(&env).unwrap()).unwrap();
        let pubkey = crate::wal::signing::pubkey_b64(&key);
        // Both OK paths return Ok(()) (no process::exit); the tamper/bad paths
        // are covered hermetically by proof_bundle::check_signature tests.
        run_verify_proof(&out, Some(&pubkey), OutputFormat::Json)
            .expect("pinned-key verify of a valid signed proof must succeed");
        run_verify_proof(&out, None, OutputFormat::Json)
            .expect("self-consistent verify of a valid signed proof must succeed");
    }

    #[test]
    fn verify_proof_bad_signature_returns_quiet_exit_not_process_exit() {
        // GOLD-COR-01 / A-03: a failed verify must surface as a recoverable
        // `Err(QuietExit(1))` that unwinds the stack — NOT `std::process::exit`,
        // which would skip Drop-time WAL flushes (and could never be exercised
        // from a test, because it would kill the test runner). Sign with key A,
        // then pin key B → BAD SIGNATURE → ok=false.
        let waldir = tempdir().unwrap();
        write_segment_with_marker(waldir.path(), 1, 3);
        let outdir = tempdir().unwrap();
        let out = outdir.path().join("p.neoth-proof");
        run_wal_export("100d", Some(&out), waldir.path(), false, false, OutputFormat::Json)
            .unwrap();
        let mut env: ProofEnvelope =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let key_a = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        env.sign(&key_a);
        std::fs::write(&out, serde_json::to_string_pretty(&env).unwrap()).unwrap();
        // Pin a DIFFERENT key — the signature can't verify against it.
        let key_b = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let wrong_pubkey = crate::wal::signing::pubkey_b64(&key_b);

        let err = run_verify_proof(&out, Some(&wrong_pubkey), OutputFormat::Json)
            .expect_err("verify against the wrong pinned key must fail");
        let quiet = err
            .downcast_ref::<crate::QuietExit>()
            .expect("a verify failure must carry QuietExit, not a generic error");
        assert_eq!(quiet.0, 1, "verify failure exits with status 1");
    }

    #[test]
    fn proof_key_pubkey_reports_absent_then_present() {
        // PROOF-KEY-01: `show`/`export-pub` are READ-ONLY — absent key → None
        // (never generates), present key → its pubkey.
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.key");
        assert!(
            proof_key_pubkey(&key_path).unwrap().is_none(),
            "no key yet → None (must not generate)"
        );
        let key = crate::wal::signing::load_or_init_signing_key(&key_path).unwrap();
        let reported = proof_key_pubkey(&key_path)
            .unwrap()
            .expect("key now exists → Some");
        assert_eq!(reported, crate::wal::signing::pubkey_b64(&key));
    }

    #[test]
    fn stats_counts_frames_per_event_type() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 5);
        let s = collect_stats(&seg).unwrap();
        assert!(s.header_ok);
        assert_eq!(s.segment_seq, Some(1));
        assert_eq!(s.frame_count, 5);
        assert_eq!(s.bad_frames, 0);
        assert_eq!(*s.per_event.get(&EVENT_TYPE_RAW_TEXT).unwrap(), 5);
    }

    #[test]
    fn stats_handles_empty_segment_after_header() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 7, 0);
        let s = collect_stats(&seg).unwrap();
        assert!(s.header_ok);
        assert_eq!(s.frame_count, 0);
        assert!(s.per_event.is_empty());
    }

    #[test]
    fn stats_short_file_reports_bad_header() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        std::fs::write(&seg, b"too short").unwrap();
        let s = collect_stats(&seg).unwrap();
        assert!(!s.header_ok);
        assert!(s.header_error.is_some());
        assert_eq!(s.frame_count, 0);
    }

    #[test]
    fn stats_counts_frames_in_a_v2_compressed_segment() {
        // GOLD-ARCH-03 regression: a sealed v2/zstd segment must have its
        // frames COUNTED, not silently skipped. The pre-fix v1-only header
        // parse + hardcoded-offset walk reported header-BAD / zero frames.
        use crate::wal::compress::compress_frames;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000009.wal");
        let mut raw_frames: Vec<u8> = Vec::new();
        for i in 0..4 {
            let payload = format!("frame {i}").into_bytes();
            let header: EventHeaderV2 = HeaderBuilder::new(EVENT_TYPE_RAW_TEXT, &payload).build();
            raw_frames.extend_from_slice(&encode_frame(&header, &payload));
        }
        let blob = compress_frames(&raw_frames).unwrap();
        let mut bytes = SegmentHeaderV2::new(0, 9, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED)
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(&blob);
        std::fs::write(&seg, &bytes).unwrap();

        let s = collect_stats(&seg).unwrap();
        assert!(s.header_ok, "v2 header must parse");
        assert_eq!(s.segment_seq, Some(9));
        assert_eq!(s.frame_count, 4, "all 4 compressed frames counted");
        assert_eq!(s.bad_frames, 0);
        assert_eq!(*s.per_event.get(&EVENT_TYPE_RAW_TEXT).unwrap(), 4);
    }

    #[test]
    fn stats_truncated_tail_stops_cleanly() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 3);
        // Truncate to 80% of length — last frame becomes torn.
        let body = std::fs::read(&seg).unwrap();
        let cut = (body.len() as f64 * 0.8) as usize;
        std::fs::write(&seg, &body[..cut]).unwrap();
        let s = collect_stats(&seg).unwrap();
        // Some frames before the torn one must have decoded.
        assert!(s.frame_count < 3);
        assert_eq!(s.bad_frames, 1, "exactly one bad-frame stop");
    }

    #[tokio::test]
    async fn show_respects_limit_and_skip() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 10);
        // limit 3 + skip 2 should not error and should walk through.
        let args = WalArgs {
            action: WalAction::Show {
                segment: Some(seg),
                event_type: None,
                limit: 3,
                skip: 2,
            },
            output: OutputFormat::Table,
        };
        run_wal(args).await.unwrap();
    }

    #[tokio::test]
    async fn stats_command_runs_against_real_segment() {
        let dir = tempdir().unwrap();
        let seg = write_segment(dir.path(), 1, 2);
        let args = WalArgs {
            action: WalAction::Stats { segment: seg },
            output: OutputFormat::Table,
        };
        run_wal(args).await.unwrap();
    }

    #[tokio::test]
    async fn show_errors_when_file_missing_header() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.wal");
        std::fs::write(&path, b"nope").unwrap();
        let args = WalArgs {
            action: WalAction::Show {
                segment: Some(path),
                event_type: None,
                limit: 1,
                skip: 0,
            },
            output: OutputFormat::Table,
        };
        let r = run_wal(args).await;
        assert!(r.is_err());
    }

    /// Build a segment with a few RAW_TEXT frames plus one of a different
    /// type so the `--type` filter has something to discriminate.
    fn write_mixed_segment(dir: &std::path::Path, seq: u64) -> PathBuf {
        use crate::wal::events::EVENT_TYPE_BOOT;
        let path = dir.join(format!("{:06}.wal", seq));
        let now = 1_700_000_000_000_000_000u64;
        let mut bytes: Vec<u8> = Vec::new();
        let sh = SegmentHeader::new(0, seq, 0, now, [0u8; 16]);
        bytes.extend_from_slice(&sh.to_le_bytes());
        for code in [
            EVENT_TYPE_RAW_TEXT,
            EVENT_TYPE_RAW_TEXT,
            EVENT_TYPE_BOOT,
            EVENT_TYPE_RAW_TEXT,
        ] {
            let payload = b"x".to_vec();
            let header: EventHeaderV2 = HeaderBuilder::new(code, &payload).build();
            bytes.extend_from_slice(&encode_frame(&header, &payload));
        }
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    #[test]
    fn read_segment_frames_filters_by_type() {
        use crate::wal::events::EVENT_TYPE_BOOT;
        let dir = tempdir().unwrap();
        let seg = write_mixed_segment(dir.path(), 1);
        // No filter → all 4 frames.
        let mut all = Vec::new();
        let mut walked = 0;
        read_segment_frames(&seg, None, &mut all, &mut walked).unwrap();
        assert_eq!(all.len(), 4);
        // Filter to BOOT → exactly the 1 boot frame.
        let mut boots = Vec::new();
        let mut w2 = 0;
        read_segment_frames(&seg, Some(EVENT_TYPE_BOOT), &mut boots, &mut w2).unwrap();
        assert_eq!(boots.len(), 1);
        assert_eq!(boots[0].event_type, EVENT_TYPE_BOOT);
        assert_eq!(w2, 4, "walked count counts every frame, not just matches");
    }

    #[tokio::test]
    async fn show_scans_all_segments_when_no_path_given() {
        // Point home at a temp dir with two segments; `segment: None`
        // must scan both via the wal/ subdir.
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        write_segment(&wal, 1, 3);
        write_segment(&wal, 2, 2);
        // Direct call (run_wal uses the real home; here we exercise the
        // multi-segment core against an explicit home).
        show(None, None, 50, 0, home.path(), OutputFormat::Table).unwrap();
        // Unknown --type must error, not silently show nothing.
        let err = show(
            None,
            Some("not_a_type"),
            50,
            0,
            home.path(),
            OutputFormat::Table,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown --type"), "got: {err}");
    }

    #[test]
    fn sorted_segments_missing_dir_is_empty() {
        let dir = tempdir().unwrap();
        assert!(sorted_segments(&dir.path().join("nope")).is_empty());
    }
}
