//! GOLD-PROG-10 (OP-03) — LSP diagnostic type shared by `lsp::client` and
//! any downstream consumer (e.g. `cli::edit`, `coding::dispatcher`).
//!
//! Mirrors `coding::cargo_check::CargoDiagnostic` structurally so callers
//! that already handle cargo-check output can handle LSP output with
//! minimal adapter code.

use std::fmt;

/// A single diagnostic emitted by an LSP server for one source location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LspDiagnostic {
    /// Path to the file the diagnostic refers to (may be relative).
    pub file: String,
    /// 0-based line number.
    pub line: u32,
    /// 0-based character/column offset.
    pub col: u32,
    /// Human-readable severity string: `"error"`, `"warning"`, `"information"`,
    /// `"hint"`, or a raw numeric string when the server emits an unknown code.
    pub severity: String,
    /// The diagnostic message text.
    pub message: String,
}

impl fmt::Display for LspDiagnostic {
    /// Compact `file:line:col: severity: message` format — identical in
    /// structure to rustc / cargo diagnostics so tools can parse both.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}: {}",
            self.file, self.line, self.col, self.severity, self.message
        )
    }
}

/// Convert a JSON-RPC `DiagnosticSeverity` integer to a human-readable string.
/// The LSP spec defines: 1=Error, 2=Warning, 3=Information, 4=Hint.
pub fn severity_name(code: i64) -> &'static str {
    match code {
        1 => "error",
        2 => "warning",
        3 => "information",
        4 => "hint",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format_matches_compiler_style() {
        let d = LspDiagnostic {
            file: "src/main.rs".into(),
            line: 10,
            col: 4,
            severity: "error".into(),
            message: "unused variable".into(),
        };
        assert_eq!(d.to_string(), "src/main.rs:10:4: error: unused variable");
    }

    #[test]
    fn severity_name_covers_all_lsp_codes() {
        assert_eq!(severity_name(1), "error");
        assert_eq!(severity_name(2), "warning");
        assert_eq!(severity_name(3), "information");
        assert_eq!(severity_name(4), "hint");
        assert_eq!(severity_name(99), "unknown");
    }
}
