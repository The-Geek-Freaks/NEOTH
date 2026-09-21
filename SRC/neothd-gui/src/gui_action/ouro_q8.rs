//! Typed GUI boundary for `neothd --output json ouro verify-q8`.
//!
//! The GUI controller consumes only these typed outcomes and keeps a second
//! verification unavailable when terminal process exit was not observed.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde::de::Deserializer;

const MAX_CAPTURE_BYTES: usize = 16 * 1024;
const MAX_FIELD_CHARS: usize = 512;
const MAX_DETAIL_CHARS: usize = 400;
const MAX_OBSERVATION: Duration = Duration::from_secs(130);
const MAX_TOTAL_UT_STEPS: usize = 8;

/// A verified Q8 receipt or a CLI-confirmed failed verification. The latter
/// is a typed CLI state, not a transport/parser error and never carries a
/// success identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OuroQ8VerifyOutcome {
    Verified(OuroQ8Verified),
    Failed {
        configured_quant_mode: String,
        detail: String,
    },
}

/// A transport, wire, or GUI-observation failure. `process_exit_observed` is
/// deliberately separate from the text: callers must keep a second action
/// unavailable until they have observed terminal process state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OuroQ8VerifyError {
    pub(crate) process_exit_observed: bool,
    pub(crate) detail: String,
}

impl OuroQ8VerifyError {
    fn observed(detail: impl Into<String>) -> Self {
        Self {
            process_exit_observed: true,
            detail: detail.into(),
        }
    }

    fn unobserved(detail: impl Into<String>) -> Self {
        Self {
            process_exit_observed: false,
            detail: detail.into(),
        }
    }
}

type VerifyResult<T> = std::result::Result<T, OuroQ8VerifyError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OuroQ8Verified {
    pub(crate) configured_quant_mode: String,
    pub(crate) receipt: String,
    pub(crate) resolved_device: String,
    pub(crate) loop_steps: usize,
    pub(crate) forward_digest: String,
    pub(crate) alternate_forward_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OuroQ8VerifyWire {
    configured_quant_mode: String,
    tested_quant_mode: String,
    result: OuroQ8VerifyResultWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OuroQ8VerifyResultWire {
    verified: bool,
    quant_mode: String,
    repo: String,
    cache_dir: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    receipt: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    resolved_device: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    loop_steps: Option<usize>,
    forward_checked: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    forward_digest: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    alternate_forward_digest: Option<String>,
    context_sensitive: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    detail: Option<String>,
}

/// Makes a nullable JSON key mandatory. `Option<T>` alone accepts an omitted
/// key as `None`, which would weaken the CLI's exact wire shape.
fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Run the cache-only verifier with bounded pipe capture and observation.
///
/// A GUI observation timeout asks the observed CLI process to stop, then only
/// reports a terminal exit if `try_wait` actually observed one. No device-load
/// cancellation acknowledgement exists, so the resulting error makes none.
pub(crate) fn run_ouro_q8_verify(
    command: &mut Command,
    action: &str,
) -> VerifyResult<OuroQ8VerifyOutcome> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            OuroQ8VerifyError::observed(format!("could not start {action}: {error}"))
        })?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            return Err(OuroQ8VerifyError::unobserved(format!(
                "could not capture {action} stdout; no terminal process exit was observed"
            )));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let _ = child.kill();
            return Err(OuroQ8VerifyError::unobserved(format!(
                "could not capture {action} stderr; no terminal process exit was observed"
            )));
        }
    };
    let stdout_reader = spawn_capture(stdout);
    let stderr_reader = spawn_capture(stderr);

    let deadline = Instant::now() + MAX_OBSERVATION;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let observed = matches!(child.try_wait(), Ok(Some(_)));
                return Err(timeout_error(action, observed));
            }
            Err(error) => {
                let _ = child.kill();
                let observed = matches!(child.try_wait(), Ok(Some(_)));
                return Err(if observed {
                    OuroQ8VerifyError::observed(format!("could not observe {action}: {error}"))
                } else {
                    OuroQ8VerifyError::unobserved(format!(
                        "could not observe {action}; no terminal process exit was observed and no device-load cancellation acknowledgement was received: {error}"
                    ))
                });
            }
        }
    };

    let stdout = receive_capture(stdout_reader, deadline, action, "stdout")?;
    let stderr = receive_capture(stderr_reader, deadline, action, "stderr")?;
    if stdout.truncated {
        return Err(OuroQ8VerifyError::observed(format!(
            "{action} returned an oversized acknowledgement; state was not assumed"
        )));
    }
    decode_ouro_q8_verify(&stdout.bytes, &stderr.bytes, status.success(), action)
        .map_err(OuroQ8VerifyError::observed)
}

#[derive(Debug)]
struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<Capture> {
    let mut bytes = Vec::with_capacity(MAX_CAPTURE_BYTES);
    let mut buffer = [0_u8; 4096];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(bytes.len());
        let kept = remaining.min(read);
        bytes.extend_from_slice(&buffer[..kept]);
        truncated |= kept != read;
    }
    Ok(Capture { bytes, truncated })
}

fn spawn_capture(reader: impl Read + Send + 'static) -> Receiver<std::io::Result<Capture>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(read_bounded(reader));
    });
    receiver
}

fn receive_capture(
    receiver: Receiver<std::io::Result<Capture>>,
    deadline: Instant,
    action: &str,
    stream: &str,
) -> VerifyResult<Capture> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    receiver.recv_timeout(remaining).map_err(|error| match error {
        mpsc::RecvTimeoutError::Timeout => OuroQ8VerifyError::observed(format!(
            "{action} process exited, but {stream} did not close before the observation deadline; a descendant may retain the pipe"
        )),
        mpsc::RecvTimeoutError::Disconnected => OuroQ8VerifyError::observed(format!(
            "{action} {stream} reader ended without a capture"
        )),
    })?
    .map_err(|error| OuroQ8VerifyError::observed(format!(
        "could not read {action} {stream}: {error}"
    )))
}

fn timeout_error(action: &str, process_exit_observed: bool) -> OuroQ8VerifyError {
    if process_exit_observed {
        OuroQ8VerifyError::observed(format!(
            "{action} observation timed out after a terminal CLI exit was observed; no device-load cancellation acknowledgement was received"
        ))
    } else {
        OuroQ8VerifyError::unobserved(format!(
            "{action} observation timed out; no terminal CLI exit was observed and no device-load cancellation acknowledgement was received"
        ))
    }
}

fn decode_ouro_q8_verify(
    stdout: &[u8],
    stderr: &[u8],
    process_succeeded: bool,
    action: &str,
) -> Result<OuroQ8VerifyOutcome, String> {
    if stdout.iter().all(u8::is_ascii_whitespace) {
        return Err(if process_succeeded {
            format!("{action} returned no acknowledgement; state was not assumed")
        } else {
            format!(
                "{action} failed without a typed receipt: {}",
                bounded_diagnostic(stderr)
            )
        });
    }
    let wire: OuroQ8VerifyWire = serde_json::from_slice(stdout)
        .map_err(|error| format!("{action} returned an invalid acknowledgement: {error}"))?;
    classify_wire(wire, process_succeeded)
}

fn classify_wire(
    wire: OuroQ8VerifyWire,
    process_succeeded: bool,
) -> Result<OuroQ8VerifyOutcome, String> {
    if !matches!(wire.configured_quant_mode.as_str(), "none" | "q8") {
        return Err("Ouro Q8 acknowledgement has an unknown configured quantization mode".into());
    }
    if wire.tested_quant_mode != "q8" || wire.result.quant_mode != "q8" {
        return Err("Ouro Q8 acknowledgement is not bound to the exact q8 test mode".into());
    }
    require_plain_text(&wire.result.repo, "repository")?;
    require_plain_text(&wire.result.cache_dir, "cache directory")?;

    match (process_succeeded, wire.result.verified) {
        (true, true) => classify_verified(wire),
        (false, false) => classify_failed(wire),
        (true, false) => Err(
            "Ouro Q8 verification reported failure with a successful process exit; state was not assumed"
                .into(),
        ),
        (false, true) => Err(
            "Ouro Q8 verification reported success with a non-zero process exit; state was not assumed"
                .into(),
        ),
    }
}

fn classify_verified(wire: OuroQ8VerifyWire) -> Result<OuroQ8VerifyOutcome, String> {
    let result = wire.result;
    if !result.forward_checked || !result.context_sensitive || result.detail.is_some() {
        return Err("Ouro Q8 success acknowledgement is missing required forward claims".into());
    }
    let receipt = required_field(result.receipt, "receipt")?;
    if !super::is_canonical_sha256(&receipt) {
        return Err("Ouro Q8 receipt must be canonical lowercase SHA-256".into());
    }
    let resolved_device = required_field(result.resolved_device, "resolved device")?;
    require_plain_text(&resolved_device, "resolved device")?;
    let loop_steps = result
        .loop_steps
        .ok_or_else(|| "Ouro Q8 success acknowledgement lacks loop steps".to_string())?;
    if !(1..=MAX_TOTAL_UT_STEPS).contains(&loop_steps) {
        return Err("Ouro Q8 loop steps are outside the accepted 1..=8 range".into());
    }
    let forward_digest = required_field(result.forward_digest, "forward digest")?;
    let alternate_forward_digest =
        required_field(result.alternate_forward_digest, "alternate forward digest")?;
    if !super::is_canonical_sha256(&forward_digest)
        || !super::is_canonical_sha256(&alternate_forward_digest)
        || forward_digest == alternate_forward_digest
    {
        return Err("Ouro Q8 forward digests are invalid or context-insensitive".into());
    }
    Ok(OuroQ8VerifyOutcome::Verified(OuroQ8Verified {
        configured_quant_mode: wire.configured_quant_mode,
        receipt,
        resolved_device,
        loop_steps,
        forward_digest,
        alternate_forward_digest,
    }))
}

fn classify_failed(wire: OuroQ8VerifyWire) -> Result<OuroQ8VerifyOutcome, String> {
    let result = wire.result;
    if result.forward_checked
        || result.context_sensitive
        || result.receipt.is_some()
        || result.resolved_device.is_some()
        || result.loop_steps.is_some()
        || result.forward_digest.is_some()
        || result.alternate_forward_digest.is_some()
    {
        return Err("Ouro Q8 failed acknowledgement carries success-only state".into());
    }
    let detail = result
        .detail
        .ok_or_else(|| "Ouro Q8 failed acknowledgement lacks diagnostic detail".to_string())?;
    let detail = normalized_detail(&detail).ok_or_else(|| {
        "Ouro Q8 failed acknowledgement has unusable diagnostic detail".to_string()
    })?;
    Ok(OuroQ8VerifyOutcome::Failed {
        configured_quant_mode: wire.configured_quant_mode,
        detail,
    })
}

fn required_field(value: Option<String>, label: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("Ouro Q8 success acknowledgement lacks {label}"))
}

fn require_plain_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_FIELD_CHARS
        || value.chars().any(char::is_control)
    {
        Err(format!("Ouro Q8 {label} is empty or malformed"))
    } else {
        Ok(())
    }
}

fn normalized_detail(value: &str) -> Option<String> {
    let detail = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    let detail = detail.trim();
    (!detail.is_empty()).then(|| detail.chars().take(MAX_DETAIL_CHARS).collect())
}

fn bounded_diagnostic(stderr: &[u8]) -> String {
    super::operator_diagnostic(stderr)
        .unwrap_or_else(|| "NEOTH reported an error — run neoth doctor for details.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn body(configured: &str, verified: bool, fields: &str) -> String {
        format!(
            r#"{{"configured_quant_mode":"{configured}","tested_quant_mode":"q8","result":{{"verified":{verified},"quant_mode":"q8","repo":"ByteDance/Ouro-1.4B-Thinking","cache_dir":"ouro-cache",{fields}}}}}"#
        )
    }

    fn success_fields() -> String {
        format!(
            r#""receipt":"{SHA_A}","resolved_device":"Cpu","loop_steps":4,"forward_checked":true,"forward_digest":"{SHA_A}","alternate_forward_digest":"{SHA_B}","context_sensitive":true,"detail":null"#
        )
    }

    const FAILURE_FIELDS: &str = "\"receipt\":null,\"resolved_device\":null,\"loop_steps\":null,\"forward_checked\":false,\"forward_digest\":null,\"alternate_forward_digest\":null,\"context_sensitive\":false,\"detail\":\"published cache was unavailable\"";

    #[test]
    fn accepts_verified_q8_even_when_configured_none() {
        let result = decode_ouro_q8_verify(
            body("none", true, &success_fields()).as_bytes(),
            b"",
            true,
            "Ouro Q8 verify",
        )
        .unwrap();
        assert!(matches!(result, OuroQ8VerifyOutcome::Verified(ref ok) if ok.loop_steps == 4));
    }

    #[test]
    fn accepts_typed_nonzero_failure_without_success_identity() {
        let result = decode_ouro_q8_verify(
            body("q8", false, FAILURE_FIELDS).as_bytes(),
            b"Error: cache missing",
            false,
            "Ouro Q8 verify",
        )
        .unwrap();
        assert!(
            matches!(result, OuroQ8VerifyOutcome::Failed { ref detail, .. } if detail == "published cache was unavailable")
        );
    }

    #[test]
    fn rejects_crossed_exit_and_verification_claims() {
        assert!(
            decode_ouro_q8_verify(
                body("q8", false, FAILURE_FIELDS).as_bytes(),
                b"",
                true,
                "q8"
            )
            .is_err()
        );
        assert!(
            decode_ouro_q8_verify(
                body("q8", true, &success_fields()).as_bytes(),
                b"",
                false,
                "q8"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_nullable_key_and_unknown_fields() {
        for key in [
            "receipt",
            "resolved_device",
            "loop_steps",
            "forward_digest",
            "alternate_forward_digest",
            "detail",
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&body("q8", true, &success_fields())).unwrap();
            value["result"].as_object_mut().unwrap().remove(key);
            let missing = serde_json::to_vec(&value).unwrap();
            assert!(
                decode_ouro_q8_verify(&missing, b"", true, "q8").is_err(),
                "missing nullable key `{key}` must fail exact decoding"
            );
        }
        let extra = body(
            "q8",
            true,
            &format!("{},\"unexpected\":true", success_fields()),
        );
        assert!(decode_ouro_q8_verify(extra.as_bytes(), b"", true, "q8").is_err());
    }

    #[test]
    fn rejects_duplicate_wire_keys() {
        let duplicate = body(
            "q8",
            true,
            &format!("{},\"receipt\":\"{SHA_B}\"", success_fields()),
        );
        assert!(decode_ouro_q8_verify(duplicate.as_bytes(), b"", true, "q8").is_err());
    }

    #[test]
    fn rejects_wrong_loop_mode_and_context_claims() {
        let wrong_loop = body(
            "q8",
            true,
            &success_fields().replace("\"loop_steps\":4", "\"loop_steps\":0"),
        );
        assert!(decode_ouro_q8_verify(wrong_loop.as_bytes(), b"", true, "q8").is_err());
        let wrong_mode = body("q8", true, &success_fields()).replace(
            "\"tested_quant_mode\":\"q8\"",
            "\"tested_quant_mode\":\"none\"",
        );
        assert!(decode_ouro_q8_verify(wrong_mode.as_bytes(), b"", true, "q8").is_err());
        let same_digest = body("q8", true, &success_fields().replace(SHA_B, SHA_A));
        assert!(decode_ouro_q8_verify(same_digest.as_bytes(), b"", true, "q8").is_err());
        let no_forward = body(
            "q8",
            true,
            &success_fields().replace("\"forward_checked\":true", "\"forward_checked\":false"),
        );
        assert!(decode_ouro_q8_verify(no_forward.as_bytes(), b"", true, "q8").is_err());
        let no_context = body(
            "q8",
            true,
            &success_fields().replace("\"context_sensitive\":true", "\"context_sensitive\":false"),
        );
        assert!(decode_ouro_q8_verify(no_context.as_bytes(), b"", true, "q8").is_err());
    }

    #[test]
    fn rejects_success_data_on_typed_failure_and_normalizes_detail() {
        let contaminated = body(
            "q8",
            false,
            &FAILURE_FIELDS.replace("\"receipt\":null", &format!("\"receipt\":\"{SHA_A}\"")),
        );
        assert!(decode_ouro_q8_verify(contaminated.as_bytes(), b"", false, "q8").is_err());
        assert_eq!(
            normalized_detail("  cache\n unavailable  ").as_deref(),
            Some("cache  unavailable")
        );
    }

    #[test]
    fn capture_receive_returns_while_the_reader_is_still_held() {
        struct HeldReader {
            started: mpsc::SyncSender<()>,
            release: mpsc::Receiver<()>,
            finished: mpsc::SyncSender<()>,
        }
        impl Read for HeldReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
                self.finished.send(()).unwrap();
                Ok(0)
            }
        }

        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let receiver = spawn_capture(HeldReader {
            started: started_tx,
            release: release_rx,
            finished: finished_tx,
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let result = receive_capture(
            receiver,
            Instant::now() + Duration::from_millis(20),
            "q8",
            "stdout",
        );
        // The production receiver returned before this reader was released.
        // Release before assertions so a failing result does not leave it held.
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let err = result.unwrap_err();
        assert!(err.process_exit_observed);
        assert!(
            err.detail
                .contains("did not close before the observation deadline")
        );

        let capture =
            read_bounded(std::io::Cursor::new(vec![b'x'; MAX_CAPTURE_BYTES + 100])).unwrap();
        assert!(capture.truncated);
        assert_eq!(capture.bytes.len(), MAX_CAPTURE_BYTES);
    }
}
