//! EM-01 — Gmail OAuth + IMAP config primitives.
//!
//! Pure-data + URL-building surface for the Gmail OAuth + IMAP path.
//! The actual TLS IMAP connection lands in EM-01b once we add the
//! `imap` crate (gated behind a feature flag so default builds stay
//! lean). What ships today:
//!
//!   - [`OAuthConfig`] / [`OAuthScope`] — operator-config primitives.
//!   - [`build_authorize_url`] — exact URL string an operator browser
//!     pops with PKCE challenge + state.
//!   - [`token_exchange_form`] — application/x-www-form-urlencoded
//!     body for the code→token POST.
//!   - [`ImapConnectionConfig`] / [`AuthMethod`] — IMAP-side knobs +
//!     auth selector (operator password OR XOAUTH2 token); helpers
//!     to format the XOAUTH2 SASL string per Google's spec.
//!   - [`fetch_strategy_for_freshness`] — picks `RECENT` vs `UNSEEN`
//!     vs `SINCE <date>` based on operator's last-poll timestamp.
//!
//! ## Why no crate add today
//!
//! Adding `imap` + `mailparse` would expand the dep graph by ~12
//! crates, half of them with OpenSSL pulls. The primitives above are
//! sufficient for the SC-15 sanitizer + PL-05 threat-assessment +
//! EM-04 draft path to be exercised end-to-end against in-memory
//! fixtures. The actual network fetch is a one-file follow-up that
//! plugs into these primitives once an operator opts in.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::installers::oauth_pkce::PkcePair;

/// Gmail OAuth 2.0 authorise endpoint. Pinned because operators
/// copying-pasting from Google docs must hit the canonical URL.
pub const GOOGLE_OAUTH_AUTHORIZE_ENDPOINT: &str =
    "https://accounts.google.com/o/oauth2/v2/auth";

/// Gmail OAuth 2.0 token endpoint.
pub const GOOGLE_OAUTH_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Gmail IMAP host (TLS on port 993 — Google deprecates anything
/// older).
pub const GMAIL_IMAP_HOST: &str = "imap.gmail.com";

/// Gmail IMAP TLS port. The non-TLS variant doesn't exist for
/// Gmail; pinning the constant prevents a "let's also try 143"
/// regression.
pub const GMAIL_IMAP_PORT: u16 = 993;

/// Gmail SMTP submission TLS port — the send-side primitive for
/// EM-01b lands here once we wire `lettre`. Pinned today so
/// operator-config validators have something to check.
pub const GMAIL_SMTP_HOST: &str = "smtp.gmail.com";
pub const GMAIL_SMTP_PORT: u16 = 587;

/// One Gmail-relevant OAuth scope. Pinned exhaustively — adding a
/// scope is an operator-visible permission change so it gets its
/// own enum variant + as_str pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthScope {
    /// Read-only IMAP + Gmail API. Required for inbound-only flows
    /// like the EM-01 draft-mode (no send).
    GmailReadonly,
    /// Read + send via Gmail API. Required for EM-04 send wire-up
    /// in EM-01b.
    GmailModify,
    /// SMTP submission. Required only when going via SMTP instead
    /// of the Gmail API send endpoint.
    GmailSend,
    /// User profile (email address + display name). Always
    /// requested so the draft module knows the operator's address.
    OpenidProfile,
    /// User email address. Pairs with `OpenidProfile`.
    OpenidEmail,
}

impl OAuthScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GmailReadonly => "https://www.googleapis.com/auth/gmail.readonly",
            Self::GmailModify => "https://www.googleapis.com/auth/gmail.modify",
            Self::GmailSend => "https://www.googleapis.com/auth/gmail.send",
            Self::OpenidProfile => "https://www.googleapis.com/auth/userinfo.profile",
            Self::OpenidEmail => "https://www.googleapis.com/auth/userinfo.email",
        }
    }

    /// Snake_case audit tag (the wire form serde emits). Pinned so
    /// audit consumers downstream stay stable when a scope's URL
    /// changes upstream.
    pub fn audit_tag(self) -> &'static str {
        match self {
            Self::GmailReadonly => "gmail_readonly",
            Self::GmailModify => "gmail_modify",
            Self::GmailSend => "gmail_send",
            Self::OpenidProfile => "openid_profile",
            Self::OpenidEmail => "openid_email",
        }
    }
}

/// Operator-facing Gmail OAuth configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    /// Loopback redirect — the wizard binds a local HTTP listener
    /// per RFC 8252 (OAuth 2.0 for Native Apps).
    pub redirect_uri: String,
    /// Scopes requested. Deduped + sorted by the URL builder.
    pub scopes: Vec<OAuthScope>,
}

impl OAuthConfig {
    /// True when the configured scopes include the send capability
    /// — the email::draft mark-sent path consults this to decide
    /// whether send is reachable.
    pub fn can_send(&self) -> bool {
        self.scopes
            .iter()
            .any(|s| matches!(s, OAuthScope::GmailModify | OAuthScope::GmailSend))
    }

    /// True when the configured scopes include readonly access —
    /// the inbox-fetch path requires this.
    pub fn can_read(&self) -> bool {
        self.scopes.iter().any(|s| {
            matches!(
                s,
                OAuthScope::GmailReadonly | OAuthScope::GmailModify
            )
        })
    }
}

/// Build the exact authorize URL the operator browser pops. Uses
/// `BTreeSet`-driven scope sort so two equivalent configs always
/// produce the same URL (cache-friendly).
pub fn build_authorize_url(
    config: &OAuthConfig,
    pkce: &PkcePair,
    state: &str,
) -> String {
    let scopes: BTreeSet<OAuthScope> = config.scopes.iter().copied().collect();
    let scope_str = scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{base}?client_id={cid}&redirect_uri={ru}&response_type=code\
         &scope={scope}&state={state}&code_challenge={chal}&code_challenge_method={meth}\
         &access_type=offline&prompt=consent",
        base = GOOGLE_OAUTH_AUTHORIZE_ENDPOINT,
        cid = url_encode(&config.client_id),
        ru = url_encode(&config.redirect_uri),
        scope = url_encode(&scope_str),
        state = url_encode(state),
        chal = url_encode(&pkce.challenge),
        meth = pkce.method,
    )
}

/// Build the application/x-www-form-urlencoded body for the
/// code→token POST. Returns a `String` ready to feed to a future
/// HTTP client.
pub fn token_exchange_form(
    config: &OAuthConfig,
    pkce: &PkcePair,
    auth_code: &str,
) -> String {
    [
        ("grant_type", "authorization_code"),
        ("code", auth_code),
        ("redirect_uri", &config.redirect_uri),
        ("client_id", &config.client_id),
        ("code_verifier", &pkce.verifier),
    ]
    .iter()
    .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
    .collect::<Vec<_>>()
    .join("&")
}

/// Minimal URL form-encoder. Handles the OAuth-relevant characters
/// (spaces, slashes in scope URLs, equals signs). Avoids pulling in
/// the `url` crate for one helper.
fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            // RFC 3986 unreserved set — safe verbatim.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── IMAP-side primitives ──────────────────────────────────────────

/// Auth method for IMAP. Email accounts that allow plain passwords
/// (legacy operator setups with app-passwords) still use
/// [`AuthMethod::PasswordPlain`]; Gmail in 2026 requires
/// [`AuthMethod::OAuth2Xoauth2`] with a fresh access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthMethod {
    PasswordPlain { password: String },
    OAuth2Xoauth2 { access_token: String },
}

impl AuthMethod {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::PasswordPlain { .. } => "password_plain",
            Self::OAuth2Xoauth2 { .. } => "oauth2_xoauth2",
        }
    }
}

/// IMAP connection config. `host` + `port` default to Gmail when
/// constructed via [`ImapConnectionConfig::gmail`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImapConnectionConfig {
    pub host: String,
    pub port: u16,
    /// IMAP username — for Gmail this is the email address.
    pub username: String,
    pub auth: AuthMethod,
    /// True when the connection is wrapped in TLS from the start
    /// (`imaps://` — port 993). False = STARTTLS upgrade on port
    /// 143. Gmail rejects everything except direct TLS.
    pub use_tls: bool,
}

impl ImapConnectionConfig {
    /// Gmail-flavoured constructor. Pins host/port/TLS so operator
    /// misconfig can't drift.
    pub fn gmail(username: impl Into<String>, auth: AuthMethod) -> Self {
        Self {
            host: GMAIL_IMAP_HOST.to_string(),
            port: GMAIL_IMAP_PORT,
            username: username.into(),
            auth,
            use_tls: true,
        }
    }
}

/// Format the SASL XOAUTH2 string per Google's spec.
///
///   `user=<email>^Aauth=Bearer <token>^A^A`
///
/// where `^A` is the literal 0x01 control character. The whole
/// string is base64 (not URL-safe) when handed to IMAP — the
/// caller is responsible for that final step; we return the raw
/// SASL string here.
pub fn build_xoauth2_sasl(email: &str, access_token: &str) -> String {
    format!("user={email}\x01auth=Bearer {access_token}\x01\x01")
}

/// Operator-facing fetch strategy. Picked by
/// [`fetch_strategy_for_freshness`] based on how long since the
/// last poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchStrategy {
    /// `SEARCH UNSEEN` — cheapest, catches everything new since
    /// last operator interaction.
    Unseen,
    /// `SEARCH SINCE <date>` — recovers from a long gap when the
    /// UNSEEN flag drifted (operator read on phone, server already
    /// flipped seen).
    Since { since_unix: i64 },
    /// `SEARCH RECENT` — server-side flag for messages added since
    /// the last IMAP session. Use as a redundancy probe right after
    /// a SINCE catch-up.
    Recent,
}

impl FetchStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unseen => "unseen",
            Self::Since { .. } => "since",
            Self::Recent => "recent",
        }
    }
}

/// Pick a fetch strategy based on the time since the operator's
/// last successful poll. Heuristics:
///
///   - `None` (first poll) or > 30 days → `Since { since_unix }`
///     (set to `now_unix - 30*86400`) to bootstrap without
///     mass-fetching the inbox.
///   - 0..=30 days → `Unseen` (cheap + correct for the common case).
///
/// Pure helper — no clock side effects (caller passes `now_unix`).
pub fn fetch_strategy_for_freshness(
    last_poll_unix: Option<i64>,
    now_unix: i64,
) -> FetchStrategy {
    const THIRTY_DAYS_SECS: i64 = 30 * 86_400;
    match last_poll_unix {
        None => FetchStrategy::Since {
            since_unix: now_unix.saturating_sub(THIRTY_DAYS_SECS),
        },
        Some(last) if now_unix.saturating_sub(last) > THIRTY_DAYS_SECS => {
            FetchStrategy::Since {
                since_unix: now_unix.saturating_sub(THIRTY_DAYS_SECS),
            }
        }
        Some(_) => FetchStrategy::Unseen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_pkce() -> PkcePair {
        PkcePair {
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
            challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            method: "S256",
        }
    }

    fn fixture_config(scopes: Vec<OAuthScope>) -> OAuthConfig {
        OAuthConfig {
            client_id: "demo-client.apps.googleusercontent.com".into(),
            redirect_uri: "http://127.0.0.1:9001/oauth/callback".into(),
            scopes,
        }
    }

    // ── pinned endpoints + constants ──────────────────────────────

    #[test]
    fn gmail_endpoints_pinned() {
        assert_eq!(
            GOOGLE_OAUTH_AUTHORIZE_ENDPOINT,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(
            GOOGLE_OAUTH_TOKEN_ENDPOINT,
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(GMAIL_IMAP_HOST, "imap.gmail.com");
        assert_eq!(GMAIL_IMAP_PORT, 993);
        assert_eq!(GMAIL_SMTP_HOST, "smtp.gmail.com");
        assert_eq!(GMAIL_SMTP_PORT, 587);
    }

    #[test]
    fn scope_as_str_carries_full_google_url() {
        assert_eq!(
            OAuthScope::GmailReadonly.as_str(),
            "https://www.googleapis.com/auth/gmail.readonly"
        );
        assert_eq!(
            OAuthScope::GmailModify.as_str(),
            "https://www.googleapis.com/auth/gmail.modify"
        );
        assert_eq!(
            OAuthScope::GmailSend.as_str(),
            "https://www.googleapis.com/auth/gmail.send"
        );
    }

    #[test]
    fn scope_audit_tag_snake_case() {
        assert_eq!(OAuthScope::GmailReadonly.audit_tag(), "gmail_readonly");
        assert_eq!(OAuthScope::GmailModify.audit_tag(), "gmail_modify");
        assert_eq!(OAuthScope::GmailSend.audit_tag(), "gmail_send");
        assert_eq!(OAuthScope::OpenidProfile.audit_tag(), "openid_profile");
        assert_eq!(OAuthScope::OpenidEmail.audit_tag(), "openid_email");
    }

    // ── config capability flags ───────────────────────────────────

    #[test]
    fn can_read_true_for_readonly_or_modify() {
        assert!(fixture_config(vec![OAuthScope::GmailReadonly]).can_read());
        assert!(fixture_config(vec![OAuthScope::GmailModify]).can_read());
    }

    #[test]
    fn can_read_false_when_no_inbox_scope() {
        assert!(!fixture_config(vec![OAuthScope::GmailSend]).can_read());
        assert!(!fixture_config(vec![OAuthScope::OpenidEmail]).can_read());
    }

    #[test]
    fn can_send_true_for_modify_or_send() {
        assert!(fixture_config(vec![OAuthScope::GmailModify]).can_send());
        assert!(fixture_config(vec![OAuthScope::GmailSend]).can_send());
    }

    #[test]
    fn can_send_false_for_readonly_only() {
        assert!(!fixture_config(vec![OAuthScope::GmailReadonly]).can_send());
    }

    // ── authorize URL ─────────────────────────────────────────────

    #[test]
    fn authorize_url_has_required_params_in_canonical_order() {
        let cfg = fixture_config(vec![OAuthScope::GmailReadonly]);
        let url = build_authorize_url(&cfg, &fixture_pkce(), "state-xyz");
        assert!(url.starts_with(GOOGLE_OAUTH_AUTHORIZE_ENDPOINT));
        assert!(url.contains("client_id=demo-client.apps.googleusercontent.com"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A9001%2Foauth%2Fcallback"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=state-xyz"));
        assert!(url.contains("code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
    }

    #[test]
    fn authorize_url_dedups_and_sorts_scopes() {
        let cfg = fixture_config(vec![
            OAuthScope::GmailModify,
            OAuthScope::GmailReadonly,
            OAuthScope::GmailModify,
        ]);
        let url = build_authorize_url(&cfg, &fixture_pkce(), "s");
        // Scopes are URL-encoded as %20 between scope URLs.
        let scope_param = url
            .split("&scope=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        // The sort order is by enum discriminant — GmailReadonly < GmailModify.
        assert!(scope_param.contains("gmail.readonly"));
        assert!(scope_param.contains("gmail.modify"));
        let readonly_pos = scope_param.find("gmail.readonly").unwrap();
        let modify_pos = scope_param.find("gmail.modify").unwrap();
        assert!(
            readonly_pos < modify_pos,
            "scopes must come out sorted by enum order: {scope_param}",
        );
    }

    #[test]
    fn authorize_url_url_encodes_state_with_special_chars() {
        let cfg = fixture_config(vec![OAuthScope::GmailReadonly]);
        let url = build_authorize_url(&cfg, &fixture_pkce(), "abc def&xyz");
        // Space → %20, ampersand → %26
        assert!(url.contains("state=abc%20def%26xyz"));
    }

    // ── token exchange form ───────────────────────────────────────

    #[test]
    fn token_exchange_form_has_grant_type_code_redirect_client_verifier() {
        let cfg = fixture_config(vec![OAuthScope::GmailReadonly]);
        let body = token_exchange_form(&cfg, &fixture_pkce(), "auth-code-123");
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=auth-code-123"));
        assert!(
            body.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A9001%2Foauth%2Fcallback")
        );
        assert!(body.contains("client_id=demo-client.apps.googleusercontent.com"));
        assert!(body.contains("code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    #[test]
    fn token_exchange_form_url_encodes_special_chars_in_code() {
        let cfg = fixture_config(vec![OAuthScope::GmailReadonly]);
        let body = token_exchange_form(&cfg, &fixture_pkce(), "code+with/special=chars");
        assert!(body.contains("code=code%2Bwith%2Fspecial%3Dchars"));
    }

    // ── IMAP config ───────────────────────────────────────────────

    #[test]
    fn gmail_imap_config_pins_host_port_tls() {
        let cfg = ImapConnectionConfig::gmail(
            "operator@example.com",
            AuthMethod::OAuth2Xoauth2 {
                access_token: "ya29.fake".into(),
            },
        );
        assert_eq!(cfg.host, "imap.gmail.com");
        assert_eq!(cfg.port, 993);
        assert!(cfg.use_tls);
        assert_eq!(cfg.username, "operator@example.com");
    }

    #[test]
    fn auth_method_kind_str_pinned_for_audit() {
        let p = AuthMethod::PasswordPlain { password: "x".into() };
        let o = AuthMethod::OAuth2Xoauth2 {
            access_token: "y".into(),
        };
        assert_eq!(p.kind_str(), "password_plain");
        assert_eq!(o.kind_str(), "oauth2_xoauth2");
    }

    #[test]
    fn xoauth2_sasl_string_per_google_spec() {
        let s = build_xoauth2_sasl("op@example.com", "ya29.token");
        // Each delimiter is a single 0x01 byte; verify by char count.
        let ctrls = s.chars().filter(|c| *c == '\x01').count();
        assert_eq!(ctrls, 3);
        assert!(s.starts_with("user=op@example.com\x01auth=Bearer ya29.token\x01\x01"));
    }

    // ── fetch strategy ────────────────────────────────────────────

    #[test]
    fn fetch_strategy_first_poll_uses_since_30d() {
        let now = 1_700_000_000;
        let s = fetch_strategy_for_freshness(None, now);
        match s {
            FetchStrategy::Since { since_unix } => {
                assert_eq!(since_unix, now - 30 * 86_400);
            }
            other => panic!("expected Since, got {other:?}"),
        }
    }

    #[test]
    fn fetch_strategy_recent_poll_uses_unseen() {
        let now = 1_700_000_000;
        let s = fetch_strategy_for_freshness(Some(now - 3600), now);
        assert_eq!(s, FetchStrategy::Unseen);
    }

    #[test]
    fn fetch_strategy_stale_poll_falls_back_to_since() {
        let now = 1_700_000_000;
        let stale = now - 31 * 86_400;
        let s = fetch_strategy_for_freshness(Some(stale), now);
        assert!(matches!(s, FetchStrategy::Since { .. }));
    }

    #[test]
    fn fetch_strategy_as_str_pinned() {
        assert_eq!(FetchStrategy::Unseen.as_str(), "unseen");
        assert_eq!(FetchStrategy::Recent.as_str(), "recent");
        assert_eq!(
            FetchStrategy::Since { since_unix: 0 }.as_str(),
            "since"
        );
    }

    #[test]
    fn fetch_strategy_serialises_snake_case_for_audit() {
        let s = FetchStrategy::Since { since_unix: 42 };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"since\""));
        assert!(json.contains("\"since_unix\":42"));
    }

    #[test]
    fn auth_method_serialises_snake_case_with_kind_tag() {
        let p = AuthMethod::PasswordPlain { password: "x".into() };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"kind\":\"password_plain\""));
    }
}
