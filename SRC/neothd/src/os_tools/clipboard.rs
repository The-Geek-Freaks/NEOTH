//! PC-01 (clipboard slice) — the OS clipboard BACKEND: a thin, panic-free
//! wrapper over [`arboard`].
//!
//! This module is the ONLY place `arboard` is touched; it is compiled solely
//! under `#[cfg(feature = "os-clipboard")]` (gated at the `mod` declaration in
//! [`super`]). It does NO policy work — every gate (kill-switch, autonomy,
//! size-cap, pastejacking newline guard, audit) lives in
//! [`super::gate::read_os_clipboard`] / [`super::gate::write_os_clipboard`].
//!
//! Panic-free by construction: every `arboard` call propagates with `?`, never
//! `unwrap`/`expect`. A failure (most commonly a headless host with no display
//! backend) returns [`arboard::Error`], which the gate maps to
//! `OsGateError::ClipboardUnavailable` and audits as `0xBD OS_CLIPBOARD_DENIED`.
//!
//! A fresh `Clipboard` handle is opened per call: `arboard::Clipboard` is not
//! designed to be held across `.await` points (its platform handles are not
//! `Send`), and the gate's async boundary sits around these synchronous calls.

/// Read the current OS clipboard text. `Ok("")` is a legitimate result (an empty
/// clipboard); the gate's size-cap + audit treat it like any other value.
pub fn read_clipboard_text() -> Result<String, arboard::Error> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.get_text()
}

/// Replace the OS clipboard text with `content`. The caller (the gate) has
/// already enforced the size cap + newline/pastejacking guard + autonomy +
/// kill-switches BEFORE this runs — this function performs no validation.
pub fn write_clipboard_text(content: &str) -> Result<(), arboard::Error> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(content)
}
