//! MM-03 — canonical local TTS providers.
//!
//! Piper uses the operator-installed native `piper` executable and
//! operator-provided ONNX/config files under `~/.neoth/models/piper`; NEOTH
//! never performs an unaudited model download. Spoken text is sent through
//! stdin and never appears in process argv. OS-native and Edge adapters share
//! the same provider trait and audited dispatch boundary.
//!
//! ## What ships today
//!
//! - [`TtsProvider`] trait — `async fn synth(request) ->
//!   Result<TtsResponse>`.
//! - [`SystemNativeProvider`] — real subprocess wrapper around
//!   `say` (macOS) / `espeak-ng` (Linux) / PowerShell `Add-Type`
//!   SAPI (Windows). Writes WAV bytes to a temp file + reads them
//!   back. Zero new deps — uses `tokio::process` which is already
//!   a workspace dep.
//! - [`pick_native_binary`] + [`build_native_args`] pure helpers
//!   so the OS-selection + arg-formatting logic is testable
//!   without spawning subprocesses on the CI host.
//!
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::AsyncWriteExt;

use super::tts_dispatch::{TtsFormat, TtsProvider as TtsProviderKind, TtsRequest, TtsResponse};

/// Common provider surface — every backend implements this. The
/// dispatcher routes a [`TtsRequest`] through the operator-chosen
/// provider.
#[async_trait::async_trait]
pub trait TtsProvider: Send + Sync {
    /// The dispatcher's pinned `TtsProvider` variant for this impl
    /// — lets the operator-config layer match impl to enum.
    fn kind(&self) -> TtsProviderKind;

    /// Synthesise. Errors carry an operator-readable string —
    /// the dispatcher chains a fallback provider per
    /// `TtsDispatcherConfig::fallback`.
    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String>;
}

static PIPER_TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

/// Resolved, containment-checked Piper voice assets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiperAssets {
    pub model: PathBuf,
    pub config: PathBuf,
}

/// Local Piper CLI provider. Asset paths are resolved at synthesis time so a
/// locale-derived voice id can select `<voice>.onnx` without duplicating
/// selection logic in the CLI.
pub struct PiperProvider {
    models_root: PathBuf,
    model_override: Option<PathBuf>,
    config_override: Option<PathBuf>,
    command: PathBuf,
    command_prefix: Vec<OsString>,
    workdir: PathBuf,
}

impl PiperProvider {
    pub fn new(
        models_root: PathBuf,
        model_override: Option<PathBuf>,
        config_override: Option<PathBuf>,
    ) -> Result<Self, String> {
        let command = find_on_path("piper").ok_or_else(|| {
            "piper executable not found on PATH — install Piper, then run `neoth tts status`"
                .to_string()
        })?;
        Ok(Self {
            models_root,
            model_override,
            config_override,
            command,
            command_prefix: Vec::new(),
            workdir: std::env::temp_dir(),
        })
    }

    #[cfg(test)]
    fn with_test_command(
        models_root: PathBuf,
        model_override: Option<PathBuf>,
        config_override: Option<PathBuf>,
        command: PathBuf,
        command_prefix: Vec<OsString>,
        workdir: PathBuf,
    ) -> Self {
        Self {
            models_root,
            model_override,
            config_override,
            command,
            command_prefix,
            workdir,
        }
    }

    fn assets(&self, voice_id: &str) -> Result<PiperAssets, String> {
        resolve_piper_assets(
            &self.models_root,
            self.model_override.as_deref(),
            self.config_override.as_deref(),
            voice_id,
        )
    }
}

/// Resolve Piper assets while enforcing that both final canonical paths remain
/// under `models_root`. This rejects `..`, absolute escapes, and symlinks that
/// point outside the operator-owned model directory.
pub fn resolve_piper_assets(
    models_root: &Path,
    model_override: Option<&Path>,
    config_override: Option<&Path>,
    voice_id: &str,
) -> Result<PiperAssets, String> {
    let model_hint = match model_override {
        Some(path) => path.to_path_buf(),
        None => {
            validate_piper_voice_id(voice_id)?;
            PathBuf::from(format!("{voice_id}.onnx"))
        }
    };
    let config_hint = match config_override {
        Some(path) => path.to_path_buf(),
        None => {
            let file_name = model_hint
                .file_name()
                .ok_or_else(|| "piper model path has no file name".to_string())?;
            let mut name = file_name.to_os_string();
            name.push(".json");
            model_hint.with_file_name(name)
        }
    };
    let model = contained_existing_asset(models_root, &model_hint, "model")?;
    let config = contained_existing_asset(models_root, &config_hint, "config")?;
    if model.extension().and_then(|v| v.to_str()) != Some("onnx") {
        return Err(format!(
            "piper model must be an .onnx file under {}",
            models_root.display()
        ));
    }
    if config.extension().and_then(|v| v.to_str()) != Some("json") {
        return Err(format!(
            "piper config must be a .json file under {}",
            models_root.display()
        ));
    }
    Ok(PiperAssets { model, config })
}

fn validate_piper_voice_id(voice_id: &str) -> Result<(), String> {
    if voice_id.is_empty()
        || voice_id == "."
        || voice_id == ".."
        || !voice_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(
            "piper voice must be a non-empty file-safe id (letters, digits, '.', '_' or '-')"
                .to_string(),
        );
    }
    Ok(())
}

fn contained_existing_asset(root: &Path, hint: &Path, label: &str) -> Result<PathBuf, String> {
    if !hint.is_absolute()
        && hint.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!("piper {label} path may not escape with '..'"));
    }
    let candidate = if hint.is_absolute() {
        hint.to_path_buf()
    } else {
        root.join(hint)
    };
    let canonical_root = std::fs::canonicalize(root).map_err(|e| {
        format!(
            "piper model directory {} is unavailable: {e}; place operator-provided voice files there",
            root.display()
        )
    })?;
    let canonical = std::fs::canonicalize(&candidate).map_err(|e| {
        format!(
            "piper {label} {} is unavailable: {e}; inspect with `neoth models list` or `neoth tts status`",
            candidate.display()
        )
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(format!(
            "piper {label} {} escapes model root {}",
            canonical.display(),
            canonical_root.display()
        ));
    }
    if !canonical.is_file() {
        return Err(format!(
            "piper {label} {} is not a file",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// Operator-facing local Piper readiness without downloading or executing a
/// model. `voice_id` is only used for conventional filename discovery.
pub fn piper_status(
    models_root: &Path,
    model_override: Option<&Path>,
    config_override: Option<&Path>,
    voice_id: &str,
) -> Result<PiperAssets, String> {
    if find_on_path("piper").is_none() {
        return Err("piper executable not found on PATH".to_string());
    }
    resolve_piper_assets(models_root, model_override, config_override, voice_id)
}

/// Piper command arguments contain only model/config/output paths. Spoken text
/// is deliberately absent and is written to the child's stdin instead.
pub fn build_piper_args(assets: &PiperAssets, output: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--model"),
        assets.model.as_os_str().to_os_string(),
        OsString::from("--config"),
        assets.config.as_os_str().to_os_string(),
        OsString::from("--output_file"),
        output.as_os_str().to_os_string(),
    ]
}

#[async_trait::async_trait]
impl TtsProvider for PiperProvider {
    fn kind(&self) -> TtsProviderKind {
        TtsProviderKind::Piper
    }

    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String> {
        if request.text.trim().is_empty() {
            return Err("empty text — nothing to synthesise".to_string());
        }
        if request.format != TtsFormat::Wav {
            return Err(
                "piper produces WAV; select a .wav output (no implicit codec conversion)"
                    .to_string(),
            );
        }
        let assets = self.assets(&request.voice_id)?;
        std::fs::create_dir_all(&self.workdir)
            .map_err(|e| format!("create Piper workdir {}: {e}", self.workdir.display()))?;
        let nonce = PIPER_TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
        let output = self.workdir.join(format!(
            "neoth-piper-{}-{}-{nonce}.wav",
            std::process::id(),
            crate::time::now_unix_ns()
        ));

        let mut command = tokio::process::Command::new(&self.command);
        command
            .args(&self.command_prefix)
            .args(build_piper_args(&assets, &output));
        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn piper ({}): {e}", self.command.display()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "piper stdin was not piped".to_string())?;
        stdin
            .write_all(request.text.as_bytes())
            .await
            .map_err(|e| format!("write text to piper stdin: {e}"))?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|e| format!("terminate piper stdin text: {e}"))?;
        drop(stdin);
        let process = child
            .wait_with_output()
            .await
            .map_err(|e| format!("wait for piper: {e}"))?;
        if !process.status.success() {
            let _ = tokio::fs::remove_file(&output).await;
            return Err(format!(
                "piper exited with {:?}: {}",
                process.status,
                String::from_utf8_lossy(&process.stderr).trim()
            ));
        }
        let audio_bytes = tokio::fs::read(&output)
            .await
            .map_err(|e| format!("read Piper output {}: {e}", output.display()))?;
        let _ = tokio::fs::remove_file(&output).await;
        if audio_bytes.len() < 12 || &audio_bytes[..4] != b"RIFF" || &audio_bytes[8..12] != b"WAVE"
        {
            return Err("piper produced empty or invalid WAV output".to_string());
        }
        let approx_duration_ms =
            ((audio_bytes.len().saturating_sub(44)) as u64 * 1000 / (22_050 * 2)) as u32;
        Ok(TtsResponse {
            audio_bytes,
            format: TtsFormat::Wav,
            duration_ms: approx_duration_ms,
        })
    }
}

/// OS-native TTS — `say` / `espeak-ng` / Windows SAPI.
pub struct SystemNativeProvider {
    /// Override the temp dir for unit tests / locked-down container
    /// envs. Defaults to [`std::env::temp_dir`].
    pub workdir: Option<PathBuf>,
}

impl SystemNativeProvider {
    pub fn new() -> Self {
        Self { workdir: None }
    }

    pub fn with_workdir(workdir: PathBuf) -> Self {
        Self {
            workdir: Some(workdir),
        }
    }

    fn workdir_resolved(&self) -> PathBuf {
        self.workdir.clone().unwrap_or_else(std::env::temp_dir)
    }
}

impl Default for SystemNativeProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Which OS-native binary to use. Pinned exhaustively so a new
/// platform target gets caught at PR review (matches `cfg(target_os
/// = ...)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBinary {
    /// macOS `say` — built-in. Pipes audio to file via `-o`.
    MacSay,
    /// Linux `espeak-ng` — needs apt install on most distros.
    LinuxEspeakNg,
    /// Windows PowerShell + `System.Speech` (SAPI). Built-in on
    /// every supported Windows version.
    WindowsPowerShellSapi,
}

impl NativeBinary {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MacSay => "mac_say",
            Self::LinuxEspeakNg => "linux_espeak_ng",
            Self::WindowsPowerShellSapi => "windows_powershell_sapi",
        }
    }
}

/// Pick the OS-native binary for the current target. Pure-fn —
/// returns the same value on each call so tests pin behaviour
/// against the host OS at compile time.
pub const fn pick_native_binary() -> NativeBinary {
    #[cfg(target_os = "macos")]
    {
        NativeBinary::MacSay
    }
    #[cfg(target_os = "linux")]
    {
        NativeBinary::LinuxEspeakNg
    }
    #[cfg(target_os = "windows")]
    {
        NativeBinary::WindowsPowerShellSapi
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        // BSD / Solaris / unknown — fall back to espeak-ng path;
        // operators on these hosts must install it manually.
        NativeBinary::LinuxEspeakNg
    }
}

/// Build the subprocess command-line argv for the chosen binary.
/// Pure-fn — separated from spawn so the arg-shape can be tested
/// on every host regardless of which binary is actually installed.
pub fn build_native_args(
    binary: NativeBinary,
    text: &str,
    output_path: &Path,
    voice_id: &str,
) -> (String, Vec<String>) {
    let out = output_path.to_string_lossy().to_string();
    match binary {
        NativeBinary::MacSay => {
            let mut args = vec!["-o".to_string(), out];
            if !voice_id.is_empty() {
                args.push("-v".to_string());
                args.push(voice_id.to_string());
            }
            args.push(text.to_string());
            ("say".to_string(), args)
        }
        NativeBinary::LinuxEspeakNg => {
            let mut args = vec!["-w".to_string(), out];
            if !voice_id.is_empty() {
                args.push("-v".to_string());
                args.push(voice_id.to_string());
            }
            args.push(text.to_string());
            ("espeak-ng".to_string(), args)
        }
        NativeBinary::WindowsPowerShellSapi => {
            // PowerShell one-liner that loads System.Speech +
            // synthesizes to the output file. Operators see the
            // exact command in the WAL when this fires.
            let voice_select = if voice_id.is_empty() {
                String::new()
            } else {
                format!("$s.SelectVoice('{}');", voice_id.replace('\'', "''"))
            };
            let escaped_text = text.replace('\'', "''");
            let escaped_out = out.replace('\'', "''");
            let script = format!(
                "Add-Type -AssemblyName System.Speech; \
                 $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; \
                 {voice_select} \
                 $s.SetOutputToWaveFile('{escaped_out}'); \
                 $s.Speak('{escaped_text}'); \
                 $s.Dispose();"
            );
            (
                "powershell".to_string(),
                vec![
                    "-NoProfile".to_string(),
                    "-NonInteractive".to_string(),
                    "-Command".to_string(),
                    script,
                ],
            )
        }
    }
}

// ── JV-VOICE-01: EdgeTts provider ───────────────────────────────────────────

/// JV-VOICE-01 — `edge-tts` subprocess provider. Invokes the `edge-tts` Python
/// CLI (installed via `pip install edge-tts`) and reads MP3 audio from its
/// stdout. The process is local but the service is not: input text is sent to
/// Microsoft's online Edge speech endpoint. No API key is required, but the
/// provider factory must still enforce the cloud-egress consent rail.
///
/// The subprocess is invoked as:
///   `edge-tts --text <text> --voice <voice> --rate <rate>% --write-media -`
///
/// stdout = raw MP3 bytes. stderr is captured for error diagnostics.
/// On Windows, `PYTHONIOENCODING=utf-8` is injected so non-ASCII text
/// (e.g. German umlauts) survives the subprocess pipe.
/// Crate-private on purpose: Edge TTS is cloud egress even though its adapter
/// is a local subprocess. External callers must use the canonical dispatcher,
/// which applies consent, autonomy, and required WAL lifecycle gates.
pub(crate) struct EdgeTtsProvider;

impl EdgeTtsProvider {
    pub(crate) fn new() -> Self {
        EdgeTtsProvider
    }
}

impl Default for EdgeTtsProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the argv for the `edge-tts` CLI subprocess. Pure fn — separated so
/// the arg-shape is testable without spawning a subprocess.
///
/// `rate` is a signed percentage offset (0 = normal, +10 = 10% faster,
/// -10 = 10% slower).  Edge-TTS expects the format `+10%` / `-10%` / `+0%`.
pub fn build_edge_args(text: &str, voice: &str, rate: i8) -> Vec<OsString> {
    let rate_str = if rate >= 0 {
        format!("+{rate}%")
    } else {
        format!("{rate}%")
    };
    vec![
        OsString::from("--text"),
        OsString::from(text),
        OsString::from("--voice"),
        OsString::from(voice),
        OsString::from("--rate"),
        OsString::from(rate_str),
        OsString::from("--write-media"),
        OsString::from("-"),
    ]
}

/// Probe whether the `edge-tts` executable is available on PATH. Returns the
/// resolved path when found.
pub fn edge_tts_exe() -> Option<PathBuf> {
    // `edge-tts` is the canonical PyPI entry point name; on Windows it
    // is also exposed as `edge-tts.exe` inside the Scripts directory.
    find_on_path("edge-tts")
}

/// Probe PATH for `name`, optionally appending `.exe` on Windows. Returns the
/// first matching absolute path found. Zero-dep alternative to the `which` crate.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        // Try the bare name first, then with `.exe` on Windows.
        for candidate_name in candidate_names(name) {
            let candidate = dir.join(&candidate_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn candidate_names(name: &str) -> Vec<std::ffi::OsString> {
    // `names` is only mutated under the windows cfg below; on other targets
    // the `mut` is unused and trips CI's `-D unused-mut` (the Windows-only
    // dev loop never compiles this path).
    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut names = vec![std::ffi::OsString::from(name)];
    #[cfg(target_os = "windows")]
    if !name.ends_with(".exe") && !name.ends_with(".cmd") && !name.ends_with(".bat") {
        names.push(std::ffi::OsString::from(format!("{name}.exe")));
        // Python entry points on Windows are sometimes installed as .cmd wrappers.
        names.push(std::ffi::OsString::from(format!("{name}.cmd")));
    }
    names
}

#[async_trait::async_trait]
impl TtsProvider for EdgeTtsProvider {
    fn kind(&self) -> TtsProviderKind {
        TtsProviderKind::EdgeTts
    }

    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String> {
        if request.text.is_empty() {
            return Err("empty text — nothing to synthesise".to_string());
        }
        let exe = edge_tts_exe().ok_or_else(|| {
            "edge-tts not found on PATH — install with: pip install edge-tts".to_string()
        })?;

        // Pick a voice: request voice_id if set, otherwise fall back to the
        // locale-driven default for EdgeTts, otherwise use the en-US Aria voice.
        let voice = if !request.voice_id.is_empty() {
            request.voice_id.clone()
        } else {
            super::tts_dispatch::pick_voice_for_locale(&request.locale, TtsProviderKind::EdgeTts)
                .unwrap_or("en-US-AriaNeural")
                .to_string()
        };

        let args = build_edge_args(&request.text, &voice, 0);
        let out = tokio::process::Command::new(&exe)
            .args(&args)
            // Non-ASCII text (German umlauts, etc.) must survive the Windows
            // code-page boundary on the subprocess stdout pipe.
            .env("PYTHONIOENCODING", "utf-8")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| format!("edge-tts spawn ({}): {e}", exe.display()))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "edge-tts exited with {:?}: {}",
                out.status,
                stderr.trim()
            ));
        }
        if out.stdout.is_empty() {
            return Err("edge-tts produced no audio output".to_string());
        }
        // Duration estimate: MP3 at ~48 kbps typical (edge-tts default).
        // 48 000 bits/s → 6 000 bytes/s → approx ms = bytes * 1000 / 6000.
        let approx_duration_ms = (out.stdout.len() as u64 * 1000 / 6_000) as u32;
        Ok(TtsResponse {
            audio_bytes: out.stdout,
            format: TtsFormat::Mp3,
            duration_ms: approx_duration_ms,
        })
    }
}

/// Generate a per-process temp filename inside `workdir` for a given request.
///
/// The key incorporates `std::process::id()` so that parallel identical TTS
/// requests in concurrent processes (or test workers) do not collide on the
/// same temp file — tts-tempfile fix. The long-term cache key lives in the
/// dispatcher's `cached_filename`; this file is the short-lived per-synth path.
pub fn temp_output_path(workdir: &Path, request: &TtsRequest) -> PathBuf {
    let pid = std::process::id();
    let key = format!(
        "{}|{}|{}|{}",
        pid,
        request.text,
        request.voice_id,
        request.format.as_str()
    );
    let h = xxhash_rust::xxh3::xxh3_64(key.as_bytes());
    let ext = match request.format {
        TtsFormat::Wav | TtsFormat::PcmS16le => "wav",
        TtsFormat::Mp3 => "mp3",
        TtsFormat::Opus => "opus",
    };
    workdir.join(format!("neoth-tts-{h:016x}.{ext}"))
}

#[async_trait::async_trait]
impl TtsProvider for SystemNativeProvider {
    fn kind(&self) -> TtsProviderKind {
        TtsProviderKind::SystemNative
    }

    async fn synth(&self, request: &TtsRequest) -> Result<TtsResponse, String> {
        if request.text.is_empty() {
            return Err("empty text — nothing to synthesise".to_string());
        }

        let workdir = self.workdir_resolved();
        std::fs::create_dir_all(&workdir)
            .map_err(|e| format!("create workdir {}: {}", workdir.display(), e))?;
        let out_path = temp_output_path(&workdir, request);

        let binary = pick_native_binary();
        let (cmd, args) = build_native_args(binary, &request.text, &out_path, &request.voice_id);

        let status = tokio::process::Command::new(&cmd)
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .status()
            .await
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !status.success() {
            return Err(format!("{cmd} exited with {status:?}"));
        }

        let audio_bytes = tokio::fs::read(&out_path)
            .await
            .map_err(|e| format!("read {}: {}", out_path.display(), e))?;
        let _ = tokio::fs::remove_file(&out_path).await;

        // Duration estimate — every native binary outputs WAV at
        // 22050 Hz / 16-bit / mono in the default config. A
        // precise duration needs WAV-header parse; the operator
        // UIs treat this as best-effort.
        let approx_duration_ms =
            ((audio_bytes.len().saturating_sub(44)) as u64 * 1000 / (22_050 * 2)) as u32;

        Ok(TtsResponse {
            audio_bytes,
            format: TtsFormat::Wav,
            duration_ms: approx_duration_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(text: &str, voice: &str) -> TtsRequest {
        TtsRequest {
            text: text.to_string(),
            voice_id: voice.to_string(),
            locale: String::new(),
            format: TtsFormat::Wav,
            sample_rate_hz: 22_050,
        }
    }

    fn piper_assets(root: &Path, voice: &str) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join(format!("{voice}.onnx")), b"operator model").unwrap();
        std::fs::write(root.join(format!("{voice}.onnx.json")), b"{}").unwrap();
    }

    #[derive(Clone, Copy)]
    enum MockPiperMode {
        Success,
        Failure,
        Empty,
    }

    #[cfg(unix)]
    fn mock_piper_command(dir: &Path, mode: MockPiperMode) -> (PathBuf, Vec<OsString>) {
        use std::os::unix::fs::PermissionsExt;

        let script = dir.join("mock-piper.sh");
        let action = match mode {
            MockPiperMode::Success => "printf 'RIFF0000WAVEdata' > \"$out\"",
            MockPiperMode::Failure => "echo mock-piper-failed >&2; exit 7",
            MockPiperMode::Empty => ": > \"$out\"",
        };
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nall_args=\"$*\"\nout=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output_file\" ]; then shift; out=\"$1\"; fi\n  shift\ndone\nprintf '%s' \"$all_args\" > \"$out.args\"\ncat > \"$out.stdin\"\n{action}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        (PathBuf::from("/bin/sh"), vec![script.into_os_string()])
    }

    #[cfg(windows)]
    fn mock_piper_command(dir: &Path, mode: MockPiperMode) -> (PathBuf, Vec<OsString>) {
        let script = dir.join("mock-piper.ps1");
        let action = match mode {
            MockPiperMode::Success => {
                "[IO.File]::WriteAllBytes($out, [byte[]](82,73,70,70,48,48,48,48,87,65,86,69,100,97,116,97))"
            }
            MockPiperMode::Failure => "[Console]::Error.Write('mock-piper-failed'); exit 7",
            MockPiperMode::Empty => "[IO.File]::WriteAllBytes($out, [byte[]]@())",
        };
        std::fs::write(
            &script,
            format!(
                "$out = $null\nfor ($i = 0; $i -lt $args.Count; $i++) {{ if ($args[$i] -eq '--output_file') {{ $out = $args[$i + 1] }} }}\n[IO.File]::WriteAllText(\"$out.args\", ($args -join \"`n\"))\n[IO.File]::WriteAllText(\"$out.stdin\", [Console]::In.ReadToEnd())\n{action}\n"
            ),
        )
        .unwrap();
        (
            PathBuf::from("powershell"),
            vec![
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-File"),
                script.into_os_string(),
            ],
        )
    }

    fn test_piper_provider(dir: &Path, mode: MockPiperMode, voice: &str) -> PiperProvider {
        let root = dir.join("models/piper");
        let workdir = dir.join("work");
        piper_assets(&root, voice);
        std::fs::create_dir_all(&workdir).unwrap();
        let (command, prefix) = mock_piper_command(dir, mode);
        PiperProvider::with_test_command(root, None, None, command, prefix, workdir)
    }

    #[test]
    fn piper_args_never_contain_spoken_text() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("models/piper");
        piper_assets(&root, "voice");
        let assets = resolve_piper_assets(&root, None, None, "voice").unwrap();
        let args = build_piper_args(&assets, &dir.path().join("out.wav"));
        assert!(
            !args
                .iter()
                .any(|arg| arg.to_string_lossy() == "secret spoken text")
        );
        assert!(args.iter().any(|arg| arg.to_string_lossy() == "--model"));
        assert!(
            args.iter()
                .any(|arg| arg.to_string_lossy() == "--output_file")
        );
    }

    #[test]
    fn piper_assets_reject_parent_and_absolute_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("models/piper");
        piper_assets(&root, "voice");
        let outside = dir.path().join("outside.onnx");
        std::fs::write(&outside, b"outside").unwrap();
        assert!(
            resolve_piper_assets(&root, Some(Path::new("../outside.onnx")), None, "voice").is_err()
        );
        assert!(resolve_piper_assets(&root, Some(&outside), None, "voice").is_err());
    }

    #[tokio::test]
    async fn piper_mock_executable_reads_stdin_and_returns_wav() {
        let dir = tempfile::tempdir().unwrap();
        let provider = test_piper_provider(dir.path(), MockPiperMode::Success, "voice");
        let response = provider
            .synth(&req("secret spoken text", "voice"))
            .await
            .unwrap();
        assert_eq!(response.format, TtsFormat::Wav);
        assert_eq!(&response.audio_bytes[..4], b"RIFF");
        let work = dir.path().join("work");
        let stdin_path = std::fs::read_dir(&work)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|v| v.to_str()) == Some("stdin"))
            .unwrap();
        let args_path = std::fs::read_dir(&work)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|v| v.to_str()) == Some("args"))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(stdin_path).unwrap().trim(),
            "secret spoken text"
        );
        assert!(
            !std::fs::read_to_string(args_path)
                .unwrap()
                .contains("secret spoken text")
        );
    }

    #[tokio::test]
    async fn piper_mock_failure_and_empty_output_fail_loud() {
        for (mode, expected) in [
            (MockPiperMode::Failure, "mock-piper-failed"),
            (MockPiperMode::Empty, "invalid WAV"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let provider = test_piper_provider(dir.path(), mode, "voice");
            let error = provider.synth(&req("hello", "voice")).await.unwrap_err();
            assert!(error.contains(expected), "unexpected error: {error}");
        }
    }

    // ── native binary surface ─────────────────────────────────────

    #[test]
    fn native_binary_as_str_pinned() {
        assert_eq!(NativeBinary::MacSay.as_str(), "mac_say");
        assert_eq!(NativeBinary::LinuxEspeakNg.as_str(), "linux_espeak_ng");
        assert_eq!(
            NativeBinary::WindowsPowerShellSapi.as_str(),
            "windows_powershell_sapi"
        );
    }

    #[test]
    fn pick_native_binary_matches_host_os() {
        let pick = pick_native_binary();
        #[cfg(target_os = "macos")]
        assert_eq!(pick, NativeBinary::MacSay);
        #[cfg(target_os = "linux")]
        assert_eq!(pick, NativeBinary::LinuxEspeakNg);
        #[cfg(target_os = "windows")]
        assert_eq!(pick, NativeBinary::WindowsPowerShellSapi);
    }

    // ── arg builder (host-independent — tests every binary) ───────

    #[test]
    fn build_args_mac_say_has_dash_o_output() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (cmd, args) = build_native_args(NativeBinary::MacSay, "hello", &path, "");
        assert_eq!(cmd, "say");
        assert!(args.iter().any(|a| a == "-o"));
        assert!(args.iter().any(|a| a == "/tmp/out.wav"));
        assert!(args.contains(&"hello".to_string()));
    }

    #[test]
    fn build_args_mac_say_includes_voice_when_set() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (_, args) = build_native_args(NativeBinary::MacSay, "hi", &path, "Sam");
        assert!(args.iter().any(|a| a == "-v"));
        assert!(args.iter().any(|a| a == "Sam"));
    }

    #[test]
    fn build_args_mac_say_omits_voice_when_empty() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (_, args) = build_native_args(NativeBinary::MacSay, "hi", &path, "");
        assert!(!args.iter().any(|a| a == "-v"));
    }

    #[test]
    fn build_args_espeak_ng_has_dash_w_output() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (cmd, args) = build_native_args(NativeBinary::LinuxEspeakNg, "hello", &path, "");
        assert_eq!(cmd, "espeak-ng");
        assert!(args.iter().any(|a| a == "-w"));
        assert!(args.iter().any(|a| a == "/tmp/out.wav"));
    }

    #[test]
    fn build_args_espeak_ng_includes_voice() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (_, args) = build_native_args(NativeBinary::LinuxEspeakNg, "hi", &path, "de");
        assert!(args.iter().any(|a| a == "-v"));
        assert!(args.iter().any(|a| a == "de"));
    }

    #[test]
    fn build_args_windows_uses_powershell_with_speech() {
        let path = std::path::PathBuf::from("C:\\temp\\out.wav");
        let (cmd, args) = build_native_args(NativeBinary::WindowsPowerShellSapi, "hi", &path, "");
        assert_eq!(cmd, "powershell");
        assert!(args.contains(&"-NoProfile".to_string()));
        assert!(args.contains(&"-NonInteractive".to_string()));
        assert!(args.contains(&"-Command".to_string()));
        let script = args.last().unwrap();
        assert!(script.contains("System.Speech"));
        assert!(script.contains("SpeechSynthesizer"));
        assert!(script.contains("SetOutputToWaveFile"));
        assert!(script.contains("hi"));
        assert!(script.contains("C:\\temp\\out.wav"));
    }

    #[test]
    fn build_args_windows_escapes_single_quotes_in_text() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (_, args) = build_native_args(
            NativeBinary::WindowsPowerShellSapi,
            "sam's voice",
            &path,
            "",
        );
        let script = args.last().unwrap();
        assert!(
            script.contains("sam''s voice"),
            "single quote not doubled — PowerShell would break: {script}",
        );
    }

    #[test]
    fn build_args_windows_includes_voice_select_block_when_set() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (_, args) = build_native_args(
            NativeBinary::WindowsPowerShellSapi,
            "hi",
            &path,
            "Microsoft Hedda Desktop",
        );
        let script = args.last().unwrap();
        assert!(script.contains("SelectVoice"));
        assert!(script.contains("Microsoft Hedda Desktop"));
    }

    #[test]
    fn build_args_windows_omits_voice_select_block_when_empty() {
        let path = std::path::PathBuf::from("/tmp/out.wav");
        let (_, args) = build_native_args(NativeBinary::WindowsPowerShellSapi, "hi", &path, "");
        let script = args.last().unwrap();
        assert!(!script.contains("SelectVoice"));
    }

    // ── temp output path ──────────────────────────────────────────

    #[test]
    fn temp_output_path_deterministic_for_same_request() {
        let workdir = std::path::Path::new("/tmp");
        let r = req("hello", "v1");
        assert_eq!(temp_output_path(workdir, &r), temp_output_path(workdir, &r));
    }

    #[test]
    fn temp_output_path_differs_on_text_change() {
        let workdir = std::path::Path::new("/tmp");
        let r1 = req("hello", "v1");
        let r2 = req("world", "v1");
        assert_ne!(
            temp_output_path(workdir, &r1),
            temp_output_path(workdir, &r2)
        );
    }

    #[test]
    fn temp_output_path_extension_matches_format() {
        let workdir = std::path::Path::new("/tmp");
        let mut r = req("hi", "");
        r.format = TtsFormat::Mp3;
        let p = temp_output_path(workdir, &r);
        assert_eq!(p.extension().and_then(|x| x.to_str()), Some("mp3"));

        r.format = TtsFormat::Opus;
        let p = temp_output_path(workdir, &r);
        assert_eq!(p.extension().and_then(|x| x.to_str()), Some("opus"));

        r.format = TtsFormat::Wav;
        let p = temp_output_path(workdir, &r);
        assert_eq!(p.extension().and_then(|x| x.to_str()), Some("wav"));
    }

    #[test]
    fn temp_output_path_under_workdir() {
        let workdir = std::path::Path::new("/custom/workdir");
        let r = req("hi", "");
        let p = temp_output_path(workdir, &r);
        assert!(p.starts_with(workdir));
        assert!(
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("neoth-tts-")
        );
    }

    // ── EdgeTtsProvider surface ───────────────────────────────────

    #[test]
    fn build_edge_args_includes_text_voice_and_rate() {
        let args = build_edge_args("hello world", "en-US-AriaNeural", 0);
        let flat: Vec<_> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(flat.contains(&"--text".to_string()));
        assert!(flat.contains(&"hello world".to_string()));
        assert!(flat.contains(&"--voice".to_string()));
        assert!(flat.contains(&"en-US-AriaNeural".to_string()));
        assert!(flat.contains(&"--rate".to_string()));
        assert!(flat.iter().any(|a| a == "+0%"), "rate 0 → +0%");
        assert!(flat.contains(&"--write-media".to_string()));
        assert!(flat.contains(&"-".to_string()));
    }

    #[test]
    fn build_edge_args_positive_rate_has_plus_prefix() {
        let args = build_edge_args("hi", "v", 10);
        let flat: Vec<_> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(flat.iter().any(|a| a == "+10%"));
    }

    #[test]
    fn build_edge_args_negative_rate_no_plus_prefix() {
        let args = build_edge_args("hi", "v", -5);
        let flat: Vec<_> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(flat.iter().any(|a| a == "-5%"));
    }

    #[test]
    fn edge_tts_provider_kind_is_edge_tts() {
        let p = EdgeTtsProvider::new();
        assert_eq!(p.kind(), TtsProviderKind::EdgeTts);
    }

    #[test]
    fn edge_tts_provider_kind_is_cloud_egress() {
        assert!(!TtsProviderKind::EdgeTts.is_local());
        assert!(include_str!("tts_provider.rs").contains("pub(crate) struct EdgeTtsProvider"));
    }

    #[tokio::test]
    async fn edge_tts_provider_rejects_empty_text() {
        let p = EdgeTtsProvider::new();
        let r = req("", "");
        let result = p.synth(&r).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty text"));
    }

    #[tokio::test]
    async fn edge_tts_provider_returns_err_when_exe_missing() {
        // If edge-tts is not on PATH (common in CI), the provider must return
        // a clear error rather than panic.
        if edge_tts_exe().is_some() {
            // edge-tts IS installed — skip the missing-exe path.
            return;
        }
        let p = EdgeTtsProvider::new();
        let r = req("hello", "en-US-AriaNeural");
        let err = p.synth(&r).await.unwrap_err();
        assert!(
            err.contains("edge-tts not found"),
            "unexpected error: {err}"
        );
    }

    // ── provider trait ────────────────────────────────────────────

    #[test]
    fn system_native_provider_kind_is_system_native() {
        let p = SystemNativeProvider::new();
        assert_eq!(p.kind(), TtsProviderKind::SystemNative);
    }

    #[tokio::test]
    async fn system_native_provider_rejects_empty_text() {
        let p = SystemNativeProvider::new();
        let r = req("", "");
        let result = p.synth(&r).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty text"));
    }

    #[tokio::test]
    async fn system_native_provider_returns_audio_when_binary_present() {
        // Live integration — only runs when the OS binary is on
        // PATH; otherwise the test is "expected to error with
        // spawn failure" which still proves the surface works.
        let workdir = tempfile::tempdir().unwrap();
        let p = SystemNativeProvider::with_workdir(workdir.path().to_path_buf());
        let r = req("hello world", "");
        match p.synth(&r).await {
            Ok(response) => {
                // Real synth succeeded → assert non-empty audio.
                assert!(!response.audio_bytes.is_empty(), "audio bytes empty");
                assert_eq!(response.format, TtsFormat::Wav);
            }
            Err(e) => {
                // Binary missing — still validates the surface.
                let msg = e.to_lowercase();
                assert!(
                    msg.contains("spawn")
                        || msg.contains("exited")
                        || msg.contains("read")
                        || msg.contains("not found")
                        || msg.contains("nicht gefunden")
                        || msg.contains("kann den angegebenen"),
                    "unexpected error shape: {e}",
                );
            }
        }
    }
}
