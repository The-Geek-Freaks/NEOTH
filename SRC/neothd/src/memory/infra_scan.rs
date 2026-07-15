//! Infrastructure scanner — Phase 28c R-24 GT-7.
//!
//! Discovers hosts on the operator's local network and turns each into an
//! `idx_groundtruth` row tagged `host:<hostname-or-ip>` with the relevant
//! `Source::ArpScan` / `Source::NmapScan`. Two paths:
//!
//!   1. **ARP table sweep** — parses `arp -a` (Windows/macOS) / `ip neigh`
//!      (Linux preferred, with `arp -a` fallback). Zero privilege, zero
//!      network packets — just reads the local kernel's neighbour cache.
//!      Always opt-in via `neoth groundtruth import-infra --arp`.
//!
//!   2. **nmap ping-sweep** — runs `nmap -sn <subnet>`. Requires nmap on
//!      PATH. Always opt-in via `--nmap`. Generates network traffic so the
//!      autonomy/policy layer above must consent before this runs.
//!
//! ## Privacy gates (from memo `neoth_gt_onboarding_pins.md`)
//!
//! - MAC address collection is **opt-in only** via `--include-mac`. Default
//!   strips MACs from the parsed rows before they reach ground-truth.
//! - Guest devices (those with no resolvable hostname) are aggregated into
//!   a single `"N guest devices detected"` summary row unless MACs are
//!   opted-in.
//! - Results are NEVER uploaded anywhere — this module returns a `Vec<Host>`
//!   to the caller, who decides what to persist.
//!
//! The caller is responsible for autonomy gating before calling
//! [`run_arp_scan`] / [`run_nmap_scan`].

use std::collections::HashMap;

use anyhow::{Context, Result};
use tokio::process::Command;

/// One discovered host. `mac` is `None` when scanning without `--include-mac`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub source: ScanSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanSource {
    Arp,
    Nmap,
}

impl ScanSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanSource::Arp => "arp",
            ScanSource::Nmap => "nmap",
        }
    }
}

/// Options shared between the scanners.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanOptions {
    /// If false, MAC addresses are stripped from the output before return.
    pub include_mac: bool,
    /// If true, hosts with no resolvable hostname are aggregated into a
    /// summary row instead of one row per address.
    pub aggregate_guests: bool,
}

// ── ARP path ────────────────────────────────────────────────────────────────

/// Run the platform-appropriate ARP-table read. Pure subprocess invocation
/// — no raw network traffic generated.
pub async fn run_arp_scan(opts: ScanOptions) -> Result<Vec<Host>> {
    let raw = arp_raw_output().await.context("arp subprocess")?;
    Ok(filter_hosts(parse_arp_output(&raw), opts))
}

#[cfg(target_os = "linux")]
async fn arp_raw_output() -> Result<String> {
    // Prefer `ip neigh` (modern Linux); fall back to `arp -a` if missing.
    match Command::new("ip").args(["neigh", "show"]).output().await {
        Ok(out) if out.status.success() => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        _ => fallback_arp_a().await,
    }
}

#[cfg(not(target_os = "linux"))]
async fn arp_raw_output() -> Result<String> {
    fallback_arp_a().await
}

async fn fallback_arp_a() -> Result<String> {
    let out = Command::new("arp").arg("-a").output().await?;
    if !out.status.success() {
        anyhow::bail!(
            "arp -a exited with status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse `arp -a` / `ip neigh` output into `Host` rows.
///
/// The format varies wildly between platforms; we recognise the common
/// shape `<ip>   <mac>  <iface-or-status>` and tolerate extra columns.
pub fn parse_arp_output(text: &str) -> Vec<Host> {
    let mut hosts = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Interface:") {
            continue;
        }
        // Strip the windows `arp -a` parenthesised IP form: `(192.168.1.1) at`.
        let candidate = trimmed
            .trim_start_matches('?')
            .trim_start_matches([' ', '(']);
        let mut tokens = candidate.split_whitespace();
        let Some(first) = tokens.next() else {
            continue;
        };
        // First token must look like an IPv4 dotted-quad. Reject ipv6 (no
        // colons), reject mac-shaped tokens, reject headers.
        if !looks_like_ipv4(first) {
            continue;
        }
        let ip = first
            .trim_matches(|c: char| c == '(' || c == ')')
            .to_string();
        // The next plausible MAC-shaped token, anywhere on the line.
        let mac = tokens.find(|t| looks_like_mac(t)).map(|t| t.to_string());
        hosts.push(Host {
            ip,
            hostname: None,
            mac,
            source: ScanSource::Arp,
        });
    }
    hosts
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_mac(s: &str) -> bool {
    // 6 hex pairs separated by `:` or `-`. Length 17 either way.
    if s.len() != 17 {
        return false;
    }
    let sep = if s.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

// ── nmap path ───────────────────────────────────────────────────────────────

/// Run `nmap -sn <subnet>`. Fails fast if nmap is not on PATH so the caller
/// can surface a helpful message rather than a cryptic "command not found".
pub async fn run_nmap_scan(subnet: &str, opts: ScanOptions) -> Result<Vec<Host>> {
    if !nmap_on_path().await {
        anyhow::bail!(
            "nmap not found on PATH. Install it or skip --nmap (arp-only mode still works)."
        );
    }
    let out = Command::new("nmap")
        .args(["-sn", subnet])
        .output()
        .await
        .with_context(|| format!("nmap -sn {subnet} subprocess"))?;
    if !out.status.success() {
        anyhow::bail!(
            "nmap -sn {subnet} exited with status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(filter_hosts(parse_nmap_output(&text), opts))
}

async fn nmap_on_path() -> bool {
    let probe = Command::new("nmap").arg("--version").output().await;
    matches!(probe, Ok(out) if out.status.success())
}

/// Parse nmap `-sn` output. Looks for `Nmap scan report for <name>` lines
/// followed by `Host is up` and pulls the hostname / IP.
pub fn parse_nmap_output(text: &str) -> Vec<Host> {
    let mut hosts = Vec::new();
    let mut current: Option<(String, Option<String>)> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Nmap scan report for ") {
            // `name (ip)` or just `ip`.
            let (hostname, ip) = match rest.rsplit_once(' ') {
                Some((name, ip_paren)) => (
                    Some(name.trim().to_string()),
                    ip_paren
                        .trim_matches(|c: char| c == '(' || c == ')')
                        .to_string(),
                ),
                None => (None, rest.trim().to_string()),
            };
            if !looks_like_ipv4(&ip) {
                // Hostname-only line (no ip in parens): treat hostname as ip.
                current = Some((ip, None));
            } else {
                current = Some((ip, hostname));
            }
        } else if trimmed.starts_with("Host is up")
            && let Some((ip, hostname)) = current.take()
        {
            hosts.push(Host {
                ip,
                hostname,
                mac: None,
                source: ScanSource::Nmap,
            });
        }
    }
    hosts
}

// ── shared filtering ────────────────────────────────────────────────────────

fn filter_hosts(mut hosts: Vec<Host>, opts: ScanOptions) -> Vec<Host> {
    if !opts.include_mac {
        for h in &mut hosts {
            h.mac = None;
        }
    }
    if !opts.aggregate_guests {
        return hosts;
    }
    let (named, anonymous): (Vec<Host>, Vec<Host>) =
        hosts.into_iter().partition(|h| h.hostname.is_some());
    let mut out = named;
    if !anonymous.is_empty() {
        // Aggregate by /24 subnet so a homelab with 3 anonymous devices
        // becomes "3 guest devices detected on 192.168.178.0/24", not
        // three separate rows.
        let mut by_subnet: HashMap<String, usize> = HashMap::new();
        for h in &anonymous {
            let subnet =
                h.ip.rsplit_once('.')
                    .map(|(p, _)| p)
                    .unwrap_or("?")
                    .to_string();
            *by_subnet.entry(subnet).or_insert(0) += 1;
        }
        for (subnet, n) in by_subnet {
            out.push(Host {
                ip: format!("{subnet}.0/24"),
                hostname: Some(format!(
                    "{n} guest device{} detected",
                    if n == 1 { "" } else { "s" }
                )),
                mac: None,
                source: anonymous[0].source,
            });
        }
    }
    out
}

/// Build the ground-truth statement string for a host row.
pub fn statement_for_host(h: &Host) -> String {
    match (&h.hostname, &h.mac) {
        (Some(name), Some(mac)) => format!(
            "{name} ({}) at MAC {mac} (source: {})",
            h.ip,
            h.source.as_str()
        ),
        (Some(name), None) => format!("{name} at {} (source: {})", h.ip, h.source.as_str()),
        (None, Some(mac)) => format!(
            "host at {} (MAC {mac}, source: {})",
            h.ip,
            h.source.as_str()
        ),
        (None, None) => format!("host at {} (source: {})", h.ip, h.source.as_str()),
    }
}

/// Build the scope tag for a host row.
pub fn scope_for_host(h: &Host) -> String {
    match &h.hostname {
        Some(name) => format!("host:{name}"),
        None => format!("host:{}", h.ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_recogniser_accepts_dotted_quad_only() {
        assert!(looks_like_ipv4("192.168.1.1"));
        assert!(looks_like_ipv4("10.0.0.255"));
        assert!(!looks_like_ipv4("192.168.1"));
        assert!(!looks_like_ipv4("not.an.ip.addr"));
        assert!(!looks_like_ipv4("256.0.0.1"));
        assert!(!looks_like_ipv4("fe80::1"));
    }

    #[test]
    fn mac_recogniser_accepts_colon_and_dash() {
        assert!(looks_like_mac("aa:bb:cc:dd:ee:ff"));
        assert!(looks_like_mac("AA-BB-CC-DD-EE-FF"));
        assert!(!looks_like_mac("aa:bb:cc:dd:ee"));
        assert!(!looks_like_mac("not-a-mac-address"));
    }

    #[test]
    fn parse_windows_arp_output() {
        let sample = "\
Interface: 192.168.178.20 --- 0x4
  Internet Address      Physical Address      Type
  192.168.178.1         00-11-22-33-44-55     dynamic
  192.168.178.117       aa-bb-cc-dd-ee-ff     dynamic
  192.168.178.255       ff-ff-ff-ff-ff-ff     static
";
        let hosts = parse_arp_output(sample);
        let ips: Vec<&String> = hosts.iter().map(|h| &h.ip).collect();
        assert!(ips.iter().any(|i| *i == "192.168.178.1"));
        assert!(ips.iter().any(|i| *i == "192.168.178.117"));
        // MACs are extracted; filtering happens later.
        assert!(
            hosts
                .iter()
                .any(|h| h.mac.as_deref() == Some("aa-bb-cc-dd-ee-ff"))
        );
    }

    #[test]
    fn parse_linux_ip_neigh_output() {
        let sample = "\
192.168.1.1 dev wlan0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.42 dev wlan0 lladdr aa:bb:cc:dd:ee:ff STALE
";
        let hosts = parse_arp_output(sample);
        assert_eq!(hosts.len(), 2);
        assert!(hosts.iter().any(|h| h.ip == "192.168.1.42"));
    }

    #[test]
    fn parse_nmap_sn_output() {
        let sample = "\
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for server.local (192.168.178.50)
Host is up (0.00021s latency).
Nmap scan report for 192.168.178.117
Host is up (0.00045s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 2.42s
";
        let hosts = parse_nmap_output(sample);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].hostname.as_deref(), Some("server.local"));
        assert_eq!(hosts[0].ip, "192.168.178.50");
        assert_eq!(hosts[1].ip, "192.168.178.117");
        assert!(hosts[1].hostname.is_none());
    }

    #[test]
    fn filter_strips_mac_when_not_opted_in() {
        let hosts = vec![Host {
            ip: "10.0.0.1".into(),
            hostname: None,
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            source: ScanSource::Arp,
        }];
        let filtered = filter_hosts(
            hosts,
            ScanOptions {
                include_mac: false,
                aggregate_guests: false,
            },
        );
        assert!(filtered[0].mac.is_none());
    }

    #[test]
    fn filter_aggregates_anonymous_hosts_per_subnet() {
        let hosts = vec![
            Host {
                ip: "192.168.1.10".into(),
                hostname: None,
                mac: None,
                source: ScanSource::Arp,
            },
            Host {
                ip: "192.168.1.11".into(),
                hostname: None,
                mac: None,
                source: ScanSource::Arp,
            },
            Host {
                ip: "192.168.1.12".into(),
                hostname: Some("named-device".into()),
                mac: None,
                source: ScanSource::Arp,
            },
        ];
        let filtered = filter_hosts(
            hosts,
            ScanOptions {
                include_mac: false,
                aggregate_guests: true,
            },
        );
        // 1 named device + 1 aggregate row.
        assert_eq!(filtered.len(), 2);
        assert!(
            filtered
                .iter()
                .any(|h| h.hostname.as_deref() == Some("named-device"))
        );
        assert!(
            filtered
                .iter()
                .any(|h| h.hostname.as_deref() == Some("2 guest devices detected"))
        );
    }

    #[test]
    fn statement_for_host_formats_known_fields() {
        let h = Host {
            ip: "192.168.178.50".into(),
            hostname: Some("server.local".into()),
            mac: None,
            source: ScanSource::Nmap,
        };
        let s = statement_for_host(&h);
        assert!(s.contains("server.local"));
        assert!(s.contains("192.168.178.50"));
        assert!(s.contains("nmap"));
    }

    #[test]
    fn scope_for_host_prefers_hostname_then_ip() {
        let named = Host {
            ip: "10.0.0.1".into(),
            hostname: Some("server.local".into()),
            mac: None,
            source: ScanSource::Arp,
        };
        assert_eq!(scope_for_host(&named), "host:server.local");
        let anon = Host {
            ip: "10.0.0.42".into(),
            hostname: None,
            mac: None,
            source: ScanSource::Arp,
        };
        assert_eq!(scope_for_host(&anon), "host:10.0.0.42");
    }
}
