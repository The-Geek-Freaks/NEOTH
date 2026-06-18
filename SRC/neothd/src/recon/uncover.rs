//! `projectdiscovery/uncover` shim — discover exposed hosts via search engines.
//!
//! Passive: queries third-party engine APIs (Shodan / Censys / FOFA / …), which
//! the operator configures with their own API keys via `uncover`'s own config /
//! env (NEOTH never handles the keys). We build a validated argv, run the binary,
//! and parse its JSONL output (struct mirrored from `sources/result.go`).

use anyhow::{Context, Result};

pub const BINARY: &str = "uncover";
pub const INSTALL_HINT: &str =
    "go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest";

/// Search engines `uncover` supports (validated against operator input so a
/// typo / injected value never reaches the binary). Mirrors `-engine` help.
pub const KNOWN_ENGINES: &[&str] = &[
    "shodan",
    "shodan-idb",
    "fofa",
    "censys",
    "quake",
    "hunter",
    "zoomeye",
    "netlas",
    "criminalip",
    "publicwww",
    "hunterhow",
    "google",
    "odin",
];

/// One discovered host (mirrors uncover's `sources.Result`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UncoverResult {
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: u32,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub url: String,
}

/// Build a validated argv: `-q <query> -e <engines> -l <limit> -json -silent`.
/// Errors on an empty query, an unknown engine, or a flag-injection attempt.
pub fn build_args(query: &str, engines: &[String], limit: u32) -> Result<Vec<String>> {
    super::validate_arg("query", query)?;
    if engines.is_empty() {
        anyhow::bail!(
            "recon uncover: at least one -engine required ({:?})",
            KNOWN_ENGINES
        );
    }
    for e in engines {
        if !KNOWN_ENGINES.contains(&e.as_str()) {
            anyhow::bail!(
                "recon uncover: unknown engine {e:?} (known: {:?})",
                KNOWN_ENGINES
            );
        }
    }
    let limit = limit.clamp(1, 10_000);
    Ok(vec![
        "-q".into(),
        query.to_string(),
        "-e".into(),
        engines.join(","),
        "-l".into(),
        limit.to_string(),
        "-json".into(),
        "-silent".into(),
    ])
}

/// Parse uncover's JSONL stdout — one host per line, malformed lines skipped.
pub fn parse_jsonl(stdout: &str) -> Vec<UncoverResult> {
    stdout
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() {
                return None;
            }
            serde_json::from_str::<UncoverResult>(l).ok()
        })
        .collect()
}

/// Run uncover and return parsed results. Errors if the binary isn't installed.
/// The (potentially slow) subprocess runs off the async runtime.
pub async fn run(query: &str, engines: &[String], limit: u32) -> Result<Vec<UncoverResult>> {
    let bin = super::locate(BINARY)
        .ok_or_else(|| anyhow::anyhow!("`{BINARY}` not installed — `{INSTALL_HINT}`"))?;
    let args = build_args(query, engines, limit)?;
    let out =
        tokio::task::spawn_blocking(move || std::process::Command::new(bin).args(&args).output())
            .await
            .context("join uncover task")?
            .context("run uncover")?;
    // uncover prints engine/auth errors to stderr; surface them but still parse
    // whatever stdout produced (partial results across engines are normal).
    if !out.stderr.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr);
        for line in err.lines().filter(|l| !l.trim().is_empty()).take(8) {
            tracing::warn!(uncover_stderr = %line);
        }
    }
    Ok(parse_jsonl(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_validates_engine_and_query() {
        let a = build_args("title:\"GitLab\"", &["shodan".into(), "fofa".into()], 50).unwrap();
        assert!(a.contains(&"-json".to_string()));
        assert!(a.contains(&"shodan,fofa".to_string()));
        assert!(a.windows(2).any(|w| w[0] == "-l" && w[1] == "50"));
        // unknown engine rejected
        assert!(build_args("q", &["bingbong".into()], 10).is_err());
        // flag-injection query rejected
        assert!(build_args("-rm -rf", &["shodan".into()], 10).is_err());
        // no engine rejected
        assert!(build_args("q", &[], 10).is_err());
        // limit clamped
        let a = build_args("q", &["shodan".into()], 0).unwrap();
        assert!(a.windows(2).any(|w| w[0] == "-l" && w[1] == "1"));
    }

    #[test]
    fn parse_jsonl_skips_garbage() {
        let s = "{\"ip\":\"1.2.3.4\",\"port\":443,\"host\":\"a.com\",\"source\":\"shodan\"}\n\
                 not json\n\
                 {\"ip\":\"5.6.7.8\",\"port\":80,\"source\":\"fofa\"}\n";
        let r = parse_jsonl(s);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].ip, "1.2.3.4");
        assert_eq!(r[0].port, 443);
        assert_eq!(r[0].host, "a.com");
        assert_eq!(r[1].source, "fofa");
    }
}
