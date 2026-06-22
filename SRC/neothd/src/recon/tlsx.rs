//! `projectdiscovery/tlsx` shim — TLS/cert intelligence grabber.
//!
//! Active: connects to each `host:port` and extracts the certificate (SAN, CN,
//! issuer, JARM, cipher, validity window). We build a validated argv, run the
//! binary, and parse its JSONL output (fields mirrored from tlsx's documented
//! JSON shape).

use anyhow::{Context, Result};

pub const BINARY: &str = "tlsx";
pub const INSTALL_HINT: &str = "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest";

/// One TLS probe result (subset of tlsx's JSON output).
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TlsxResult {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub probe_status: bool,
    #[serde(default)]
    pub tls_version: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
    #[serde(default)]
    pub subject_cn: String,
    #[serde(default)]
    pub subject_dn: String,
    #[serde(default)]
    pub subject_an: Vec<String>,
    #[serde(default)]
    pub issuer_cn: String,
    #[serde(default)]
    pub self_signed: bool,
    #[serde(default)]
    pub expired: bool,
    /// GR-fix: the argv requests `-jarm` (the JARM TLS fingerprint), but the field
    /// was missing here so serde silently dropped it from every probe result.
    #[serde(default)]
    pub jarm: String,
}

/// Build a validated argv: `-u <hosts> [-p <ports>] -json -san -cn -cipher
/// -jarm -silent`. Errors on an empty host list or a flag-injection attempt.
pub fn build_args(hosts: &[String], ports: &[String]) -> Result<Vec<String>> {
    if hosts.is_empty() {
        anyhow::bail!("recon tlsx: at least one -host required");
    }
    for h in hosts {
        super::validate_arg("host", h)?;
        // Hosts are joined with ',' into one -u value; an embedded comma in a
        // single host would smuggle EXTRA scan targets past validation. Multiple
        // hosts must come as separate Vec elements, never one comma-joined value.
        if h.contains(',') {
            anyhow::bail!(
                "recon tlsx: host {h:?} must not contain ',' (pass multiple hosts as separate values)"
            );
        }
    }
    for p in ports {
        super::validate_arg("port", p)?;
        if p.parse::<u16>().is_err() {
            anyhow::bail!("recon tlsx: port {p:?} is not a valid 0–65535 number");
        }
    }
    let mut args = vec!["-u".to_string(), hosts.join(",")];
    if !ports.is_empty() {
        args.push("-p".into());
        args.push(ports.join(","));
    }
    args.extend(
        [
            "-json", "-san", "-cn", "-cipher", "-jarm", "-ex", "-ss", "-silent",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    Ok(args)
}

/// Parse tlsx's JSONL stdout — one probe per line, malformed lines skipped.
pub fn parse_jsonl(stdout: &str) -> Vec<TlsxResult> {
    stdout
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() {
                return None;
            }
            serde_json::from_str::<TlsxResult>(l).ok()
        })
        .collect()
}

/// Run tlsx against the given hosts/ports and return parsed results. Errors if
/// the binary isn't installed. Subprocess runs off the async runtime.
pub async fn run(hosts: &[String], ports: &[String]) -> Result<Vec<TlsxResult>> {
    let bin = super::locate(BINARY)
        .ok_or_else(|| anyhow::anyhow!("`{BINARY}` not installed — `{INSTALL_HINT}`"))?;
    let args = build_args(hosts, ports)?;
    let out =
        tokio::task::spawn_blocking(move || std::process::Command::new(bin).args(&args).output())
            .await
            .context("join tlsx task")?
            .context("run tlsx")?;
    if !out.stderr.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr);
        for line in err.lines().filter(|l| !l.trim().is_empty()).take(8) {
            tracing::warn!(tlsx_stderr = %line);
        }
    }
    Ok(parse_jsonl(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_validates_hosts_and_ports() {
        let a = build_args(&["example.com".into()], &["443".into(), "8443".into()]).unwrap();
        assert!(a.contains(&"-json".to_string()));
        assert!(a.windows(2).any(|w| w[0] == "-u" && w[1] == "example.com"));
        assert!(a.windows(2).any(|w| w[0] == "-p" && w[1] == "443,8443"));
        // empty host rejected
        assert!(build_args(&[], &[]).is_err());
        // flag-injection host rejected
        assert!(build_args(&["-config /etc/x".into()], &[]).is_err());
        // comma-injection host rejected (would smuggle extra scan targets)
        assert!(build_args(&["a.com,evil.com".into()], &[]).is_err());
        // non-numeric port rejected
        assert!(build_args(&["a.com".into()], &["https".into()]).is_err());
    }

    #[test]
    fn parse_jsonl_reads_cert_fields() {
        let s = "{\"host\":\"example.com\",\"ip\":\"93.184.216.34\",\"port\":\"443\",\
                 \"probe_status\":true,\"tls_version\":\"tls13\",\"cipher\":\"TLS_AES_256_GCM_SHA384\",\
                 \"subject_cn\":\"www.example.org\",\"subject_an\":[\"example.com\",\"example.net\"],\
                 \"not_after\":\"2023-03-14T23:59:59Z\"}\nbad line\n";
        let r = parse_jsonl(s);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].host, "example.com");
        assert!(r[0].probe_status);
        assert_eq!(r[0].tls_version, "tls13");
        assert_eq!(r[0].subject_cn, "www.example.org");
        assert_eq!(r[0].subject_an.len(), 2);
    }
}
