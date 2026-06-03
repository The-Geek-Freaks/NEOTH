//! EM-01b — live IMAP inbound fetch (feature `imap_fetch`).
//!
//! Connects to an IMAP server over TLS (rustls, `imaps://` port 993 — Gmail
//! rejects anything else), authenticates with an app-password or an XOAUTH2
//! access token, `SELECT INBOX`, `UID SEARCH UNSEEN`, and `UID FETCH
//! BODY.PEEK[]` for the newest `limit` unseen messages. Each raw RFC822 is
//! parsed by [`parse_rfc822`] into an [`InboundEmail`] which the caller runs
//! through [`super::inbound::triage_inbound`].
//!
//! `BODY.PEEK[]` (not `BODY[]`) is deliberate: peeking does NOT set the
//! `\Seen` flag, so a fetch is non-destructive — the operator's own read
//! state on their phone/desktop is never clobbered by NEOTH polling.
//!
//! The TLS + IMAP socket is the thin, network-only shell (not unit-testable
//! without a live server); the RFC822 parser is pure and IS tested here.

use std::sync::Arc;

use anyhow::{Context, Result};
use futures::StreamExt;
use mailparse::{MailHeaderMap, ParsedMail};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::gmail::{AuthMethod, ImapConnectionConfig, build_xoauth2_sasl};
use super::inbound::{InboundEmail, extract_from_domain};

/// Cap on how many unseen messages a single fetch pulls — a runaway inbox
/// must not OOM the daemon. The caller's `--limit` is additionally clamped
/// to this.
pub const MAX_FETCH_LIMIT: usize = 200;

/// XOAUTH2 SASL authenticator for `async-imap`. `process` returns the RAW
/// SASL string (`user=…\x01auth=Bearer …\x01\x01`); async-imap base64-encodes
/// it before sending, matching Google's spec.
struct Xoauth2 {
    sasl: String,
}

impl async_imap::Authenticator for &Xoauth2 {
    type Response = String;
    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        self.sasl.clone()
    }
}

/// Build a rustls client config trusting the Mozilla CA bundle (webpki-roots)
/// — the same root set the rest of NEOTH's rustls egress uses.
fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Connect, authenticate, and fetch up to `limit` newest UNSEEN messages
/// from INBOX. Non-destructive (`BODY.PEEK[]`). The TLS/socket path is the
/// untested shell; failures surface the IMAP/TLS error context only —
/// never the password / access token.
pub async fn fetch_unseen(cfg: &ImapConnectionConfig, limit: usize) -> Result<Vec<InboundEmail>> {
    let limit = limit.min(MAX_FETCH_LIMIT);
    if limit == 0 {
        return Ok(Vec::new());
    }
    if !cfg.use_tls {
        anyhow::bail!("imap_fetch refuses a non-TLS connection (STARTTLS/143 not supported)");
    }

    let connector = TlsConnector::from(tls_config());
    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .await
        .with_context(|| format!("connect {}:{}", cfg.host, cfg.port))?;
    let server_name = ServerName::try_from(cfg.host.clone())
        .with_context(|| format!("invalid IMAP host for TLS SNI: {}", cfg.host))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("IMAP TLS handshake failed")?;

    let client = async_imap::Client::new(tls);
    // Credentials never appear in an error: map the (Error, Client) tuple to
    // the error half only, with a generic context.
    let mut session = match &cfg.auth {
        AuthMethod::PasswordPlain { password } => client
            .login(&cfg.username, password)
            .await
            .map_err(|(e, _)| e)
            .context("IMAP password login rejected")?,
        AuthMethod::OAuth2Xoauth2 { access_token } => {
            let auth = Xoauth2 {
                sasl: build_xoauth2_sasl(&cfg.username, access_token),
            };
            client
                .authenticate("XOAUTH2", &auth)
                .await
                .map_err(|(e, _)| e)
                .context("IMAP XOAUTH2 authentication rejected")?
        }
    };

    session.select("INBOX").await.context("SELECT INBOX failed")?;

    let uids = session
        .uid_search("UNSEEN")
        .await
        .context("UID SEARCH UNSEEN failed")?;
    // Newest-first: highest UIDs are the most recent arrivals.
    let mut uid_vec: Vec<u32> = uids.into_iter().collect();
    uid_vec.sort_unstable_by(|a, b| b.cmp(a));
    uid_vec.truncate(limit);

    let mut out = Vec::with_capacity(uid_vec.len());
    for uid in uid_vec {
        let mut stream = session
            .uid_fetch(uid.to_string(), "BODY.PEEK[]")
            .await
            .with_context(|| format!("UID FETCH {uid} failed"))?;
        while let Some(item) = stream.next().await {
            let fetch = item.context("IMAP fetch stream error")?;
            if let Some(body) = fetch.body() {
                if let Some(email) = parse_rfc822(uid, body) {
                    out.push(email);
                }
            }
        }
        drop(stream);
    }

    // Best-effort logout; a failure here doesn't invalidate what we fetched.
    let _ = session.logout().await;
    Ok(out)
}

/// Parse a raw RFC822 message into an [`InboundEmail`]. Pure. Pulls the
/// `From`/`Subject` headers, the first `text/plain` body (falling back to the
/// top-level body), and every attachment filename. Returns `None` only when
/// the bytes don't parse as a mail at all.
pub fn parse_rfc822(uid: u32, raw: &[u8]) -> Option<InboundEmail> {
    let parsed = mailparse::parse_mail(raw).ok()?;
    let from = parsed
        .headers
        .get_first_value("From")
        .unwrap_or_default();
    let subject = parsed
        .headers
        .get_first_value("Subject")
        .unwrap_or_default();
    let from_domain = extract_from_domain(&from);

    let mut body = String::new();
    let mut attachment_filenames = Vec::new();
    collect_parts(&parsed, &mut body, &mut attachment_filenames);

    // If no text/plain part was found, fall back to the top-level body.
    if body.trim().is_empty() {
        if let Ok(top) = parsed.get_body() {
            body = top;
        }
    }

    Some(InboundEmail {
        uid: uid.to_string(),
        from,
        from_domain,
        subject,
        body,
        attachment_filenames,
    })
}

/// Walk a (possibly multipart) message, accumulating the first non-empty
/// `text/plain` body and every part that carries a filename (attachment).
fn collect_parts(part: &ParsedMail, body: &mut String, attachments: &mut Vec<String>) {
    let ctype = part.ctype.mimetype.to_ascii_lowercase();

    // Attachment? A `Content-Disposition: attachment` or any part with a
    // filename param counts.
    if let Some(name) = part_filename(part) {
        attachments.push(name);
    }

    if part.subparts.is_empty() {
        if ctype == "text/plain" && body.trim().is_empty() {
            if let Ok(text) = part.get_body() {
                *body = text;
            }
        }
    } else {
        for sub in &part.subparts {
            collect_parts(sub, body, attachments);
        }
    }
}

/// Extract a `filename` from a part's `Content-Disposition` or, failing that,
/// the `name` from its `Content-Type`. `None` for inline/body parts.
fn part_filename(part: &ParsedMail) -> Option<String> {
    if let Some(disp) = part.headers.get_first_value("Content-Disposition") {
        if let Some(name) = param_value(&disp, "filename") {
            return Some(name);
        }
    }
    if let Some(ct) = part.headers.get_first_value("Content-Type") {
        if let Some(name) = param_value(&ct, "name") {
            return Some(name);
        }
    }
    None
}

/// Pull `<key>="value"` (or `<key>=value`) from a header parameter list.
/// Tiny, dependency-free — good enough for the filename/name params we read.
fn param_value(header: &str, key: &str) -> Option<String> {
    for seg in header.split(';') {
        let seg = seg.trim();
        // A param-less segment (e.g. the leading `attachment`) has no `=`;
        // skip it rather than aborting the whole scan.
        let Some((k, v)) = seg.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(key) {
            let v = v.trim().trim_matches('"').trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_email_extracts_headers_and_body() {
        let raw = b"From: Acme <noreply@acme.com>\r\n\
                    Subject: Hello\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    This is the body.\r\n";
        let e = parse_rfc822(7, raw).expect("parses");
        assert_eq!(e.uid, "7");
        assert_eq!(e.from, "Acme <noreply@acme.com>");
        assert_eq!(e.from_domain.as_deref(), Some("acme.com"));
        assert_eq!(e.subject, "Hello");
        assert!(e.body.contains("This is the body."));
        assert!(e.attachment_filenames.is_empty());
    }

    #[test]
    fn parse_multipart_finds_text_and_attachment() {
        let raw = b"From: a@b.com\r\n\
                    Subject: With attach\r\n\
                    Content-Type: multipart/mixed; boundary=BOUND\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    body text here\r\n\
                    --BOUND\r\n\
                    Content-Type: application/octet-stream; name=\"evil.exe\"\r\n\
                    Content-Disposition: attachment; filename=\"evil.exe\"\r\n\
                    \r\n\
                    AAAA\r\n\
                    --BOUND--\r\n";
        let e = parse_rfc822(9, raw).expect("parses");
        assert!(e.body.contains("body text here"));
        assert!(
            e.attachment_filenames.iter().any(|f| f == "evil.exe"),
            "got {:?}",
            e.attachment_filenames
        );
    }

    #[test]
    fn parse_garbage_is_some_with_empty_fields_not_panic() {
        // mailparse is lenient; the contract is "never panic". Even bare
        // bytes parse to a mail with empty headers.
        let e = parse_rfc822(1, b"not really an email");
        assert!(e.is_some());
    }

    #[test]
    fn param_value_handles_quoted_and_unquoted() {
        assert_eq!(
            param_value("attachment; filename=\"a b.pdf\"", "filename").as_deref(),
            Some("a b.pdf")
        );
        assert_eq!(
            param_value("inline; filename=plain.txt", "filename").as_deref(),
            Some("plain.txt")
        );
        assert_eq!(param_value("attachment", "filename"), None);
    }

    #[test]
    fn fetch_limit_zero_is_empty_without_connecting() {
        // limit 0 must short-circuit before any socket work.
        let cfg = ImapConnectionConfig::gmail(
            "x@gmail.com",
            AuthMethod::PasswordPlain {
                password: "p".to_string(),
            },
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = rt.block_on(fetch_unseen(&cfg, 0)).unwrap();
        assert!(r.is_empty());
    }
}
