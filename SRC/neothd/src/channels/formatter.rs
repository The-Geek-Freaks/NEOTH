//! Per-channel Markdown formatter (F-1..F-4).
//!
//! Each messenger speaks its own dialect of Markdown:
//!   - **Telegram**: MarkdownV2 — strict escape rules, every `_`, `*`,
//!     `[`, `]`, `(`, `)`, `~`, `` ` ``, `>`, `#`, `+`, `-`, `=`, `|`,
//!     `{`, `}`, `.`, `!` outside a formatting region must be escaped
//!     with a backslash. 4096-byte body limit per message.
//!   - **Slack**: mrkdwn — asterisks-for-bold (`*text*`), underscores
//!     for italic (`_text_`), tildes for strike (`~text~`), backticks
//!     for code. NO link syntax — Slack auto-linkifies URLs but also
//!     supports `<URL|label>`. 40000 char limit, but `chat.postMessage`
//!     splits at 4000 to render reliably.
//!   - **WhatsApp**: subset — `*bold*` / `_italic_` / `~strike~` /
//!     `` ` ``code`` ` `` / triple-backtick block. No link syntax, no
//!     headers. 4096-byte text body limit (per the Cloud API).
//!   - **Discord**: CommonMark-ish — `**bold**`, `*italic*`, fenced
//!     code with lang tag for syntax highlighting, blockquotes `> `,
//!     inline links `[label](url)`. 2000-char body cap. Tolerant of
//!     unbalanced markdown (unlike Telegram MarkdownV2).
//!
//! Input: [`CanonicalReply`] — the LLM's response normalised into a
//! channel-agnostic shape (text + extracted code blocks + length
//! hint). Output: `Vec<String>` — each element fits the channel's
//! single-message limit. Operators don't see a 4097-char Telegram
//! reply silently dropped; the formatter splits + numbers continuation
//! markers so the operator can read the full thread.
//!
//! Why a trait: future Markdown dialects (Discord, Matrix, MS Teams)
//! plug in without touching every callsite. Channel adapters call
//! `formatter::for_channel(kind).format(&reply)` once per outbound
//! send.

use super::ChannelKind;

/// Channel-agnostic shape the LLM dispatch hands to the formatter.
/// Operators read this directly via `neoth wal show` so the shape
/// stays stable across formatter dialects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalReply {
    /// The reply body as the LLM produced it (may include embedded
    /// fences, lists, links — the formatter does the per-channel
    /// dialect conversion). Already passed through the persona /
    /// truncation pipeline upstream.
    pub text: String,
    /// Pre-extracted code blocks the formatter renders with channel-
    /// appropriate fences. Empty when the LLM didn't return code.
    pub code_blocks: Vec<CodeBlock>,
    /// Channel-style hint the formatter uses to decide split / fence
    /// behaviour. `None` lets the formatter pick its default.
    pub length_hint: Option<LengthHint>,
}

/// A code block extracted from the LLM response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlock {
    /// Optional language tag (`rust`, `python`, ...). Empty string
    /// when the fence had no tag.
    pub lang: String,
    /// Raw source — the formatter inserts the channel's fence syntax;
    /// the body itself is never escaped.
    pub body: String,
}

/// Operator-readable hint about how aggressive the splitter should be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthHint {
    /// "Short reply — one chat bubble." Formatter avoids hard splits
    /// when the body fits, even if it touches the limit.
    Short,
    /// "Long reply, prefer paragraph boundaries." Formatter prefers
    /// double-newline splits over mid-sentence cuts.
    Long,
}

/// What every channel formatter exposes. Stable trait so future
/// dialects (Discord, Matrix) drop in without churning callers.
pub trait Formatter {
    /// Channel this formatter renders for. Used to pick + verify the
    /// right impl at the dispatch site.
    fn channel(&self) -> ChannelKind;

    /// Hard single-message body cap in characters. Telegram / WhatsApp
    /// = 4096; Slack chat.postMessage = 4000 (under the 40k absolute
    /// because Slack renders the first 4k inline + collapses the rest).
    fn max_chars_per_message(&self) -> usize;

    /// Render the canonical reply into one or more channel-native
    /// strings, each ≤ `max_chars_per_message`. Continuation messages
    /// (when split) get a `[N/M]` suffix on the first line.
    fn format(&self, reply: &CanonicalReply) -> Vec<String>;
}

/// Build the right formatter for a supported channel. Keet deliberately
/// returns `None`: no supported public Keet chat transport exists.
pub fn for_channel(kind: ChannelKind) -> Option<Box<dyn Formatter>> {
    match kind {
        ChannelKind::Telegram => Some(Box::new(TelegramFormatter)),
        ChannelKind::Slack => Some(Box::new(SlackFormatter)),
        ChannelKind::WhatsAppBusiness | ChannelKind::WhatsAppBaileys => {
            Some(Box::new(WhatsAppFormatter))
        }
        ChannelKind::Discord => Some(Box::new(DiscordFormatter)),
        ChannelKind::Keet => None,
        ChannelKind::Signal => Some(Box::new(SignalFormatter)),
        ChannelKind::Matrix => Some(Box::new(MatrixFormatter)),
        ChannelKind::Line => Some(Box::new(LineFormatter)),
        ChannelKind::Irc => Some(Box::new(IrcFormatter)),
        ChannelKind::Mattermost => Some(Box::new(MattermostFormatter)),
        ChannelKind::Twitch => Some(Box::new(TwitchFormatter)),
        ChannelKind::Nostr => Some(Box::new(NostrFormatter)),
        // iMessage renders plain text — same treatment as Signal.
        ChannelKind::IMessageBlueBubbles => Some(Box::new(SignalFormatter)),
        // Google Chat renders plain text with a 4096-char message cap —
        // same shape as Matrix, so it reuses that formatter.
        ChannelKind::GoogleChat => Some(Box::new(MatrixFormatter)),
    }
}

// ── Telegram MarkdownV2 ──────────────────────────────────────────────

/// Telegram MarkdownV2 formatter.
///
/// Honours Telegram's "escape every metacharacter outside a formatting
/// region" rule. v0.1 strategy: escape AGGRESSIVELY (every special
/// character gets a backslash) and render code blocks via triple
/// backtick fences with the operator-supplied lang tag. Inline `*` /
/// `_` from the LLM response are escaped — the LLM's bold/italic
/// intent is lost on Telegram in exchange for predictable parse
/// success. A richer mode (preserve LLM-emitted markdown) is a
/// follow-up once we wire the LLM to opt into MarkdownV2 explicitly.
pub struct TelegramFormatter;

/// Per Telegram Bot API docs: sendMessage body cap = 4096 chars.
const TELEGRAM_MAX_CHARS: usize = 4096;

/// Headroom for the `[N/M]` continuation marker the splitter prepends.
const SPLIT_HEADROOM: usize = 16;

impl Formatter for TelegramFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Telegram
    }
    fn max_chars_per_message(&self) -> usize {
        TELEGRAM_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&escape_markdown_v2(&reply.text));
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            // The lang tag itself doesn't need escaping inside the
            // opening fence — Telegram parses up to the newline as
            // the language. Body stays literal.
            rendered.push_str(&cb.lang);
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            TELEGRAM_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

/// Escape every MarkdownV2 metacharacter so the rendered string parses
/// as plain text. Telegram is strict: an unescaped `_` mid-word fails
/// the WHOLE message, not just the offending segment.
fn escape_markdown_v2(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for c in input.chars() {
        match c {
            '_' | '*' | '[' | ']' | '(' | ')' | '~' | '`' | '>' | '#' | '+' | '-' | '=' | '|'
            | '{' | '}' | '.' | '!' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

// ── Slack mrkdwn ─────────────────────────────────────────────────────

/// Slack mrkdwn formatter.
///
/// Slack's flavour is mostly tolerant — unescaped `*` outside a word
/// renders as literal `*` rather than failing the message. So this
/// formatter is permissive: pass `text` through verbatim and only
/// rewrite code blocks into Slack-style triple-backticks.
pub struct SlackFormatter;

/// `chat.postMessage` accepts up to ~40k chars but renders only the
/// first 4k inline; rest collapses behind a "Show more" affordance.
/// We split at the inline cap so operators see the whole reply
/// without clicking through.
const SLACK_MAX_CHARS: usize = 4000;

impl Formatter for SlackFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Slack
    }
    fn max_chars_per_message(&self) -> usize {
        SLACK_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            // Slack ignores the language hint after the fence (no
            // syntax highlighting), but emitting it stays consistent
            // with the canonical body shape for operators who copy.
            if !cb.lang.is_empty() {
                rendered.push_str(&cb.lang);
            }
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            SLACK_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── WhatsApp Cloud ───────────────────────────────────────────────────

/// WhatsApp Business / Cloud API formatter.
///
/// WhatsApp's `messages` endpoint accepts only the small Markdown
/// subset documented at developers.facebook.com/docs/whatsapp/cloud-api
/// — bold (`*text*`), italic (`_text_`), strike (`~text~`), monospace
/// (`` `text` ``), block monospace (triple backtick). Links and
/// headers don't render; we leave them as-is so the operator at least
/// sees the URL string.
pub struct WhatsAppFormatter;

/// 4096-byte text body cap per the Cloud API. We use the chars limit
/// (UTF-8 multi-byte chars rare in practice; operator messages are
/// mostly ASCII).
const WHATSAPP_MAX_CHARS: usize = 4096;

impl Formatter for WhatsAppFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::WhatsAppBusiness
    }
    fn max_chars_per_message(&self) -> usize {
        WHATSAPP_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```\n");
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            WHATSAPP_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── Discord ──────────────────────────────────────────────────────────

/// Discord channel message formatter (Session 14 Pick #27).
///
/// Discord renders a permissive CommonMark dialect: `**bold**`,
/// `*italic*`, fenced code blocks with a language tag for syntax
/// highlighting, blockquotes via `> `, and embedded links via
/// `[label](url)`. Apart from the operator's literal text we don't
/// escape anything — Discord interprets unbalanced markdown
/// gracefully (an unmatched `*` renders as a literal asterisk),
/// unlike Telegram's MarkdownV2 which fails the whole message.
///
/// Hard cap: 2000 characters per message. The shared
/// [`split_into_messages`] splitter takes care of multi-message
/// chunking with paragraph-preferred boundaries.
pub struct DiscordFormatter;

/// Discord's hard `content` cap on `POST /channels/{id}/messages`.
/// Mirrors `channels::discord::DISCORD_MAX_CONTENT_CHARS` — the
/// Phase-1 adapter chunker pre-dates this formatter and can be
/// migrated as a follow-up.
const DISCORD_MAX_CHARS: usize = 2000;

impl Formatter for DiscordFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Discord
    }
    fn max_chars_per_message(&self) -> usize {
        DISCORD_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            // Discord respects the lang tag for syntax highlighting.
            rendered.push_str(&cb.lang);
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            DISCORD_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── Signal (plaintext) ───────────────────────────────────────────────

/// GOLD-FEAT-10 — Signal formatter. signal-cli `send` takes a plaintext
/// `message` (no markdown dialect to honour): append code blocks as literal triple-backtick
/// fences (readable + copy-paste-clean) and split at the 2000-char UX
/// floor (Signal has no hard protocol cap, but mobile render degrades
/// above ~2k).
pub struct SignalFormatter;

const SIGNAL_MAX_CHARS: usize = 2_000;

impl Formatter for SignalFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Signal
    }
    fn max_chars_per_message(&self) -> usize {
        SIGNAL_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            if !cb.lang.is_empty() {
                rendered.push_str(&cb.lang);
            }
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            SIGNAL_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── Matrix (plaintext body) ──────────────────────────────────────────

/// GOLD-FEAT-10 — Matrix formatter. v1 sends the plaintext `body` of an
/// `m.room.message` (rich `formatted_body`/HTML is a follow-up), so this
/// mirrors the Signal plaintext renderer. 4096-char split — Matrix has
/// no fixed event cap but homeservers reject oversized events.
pub struct MatrixFormatter;

const MATRIX_MAX_CHARS: usize = 4096;

impl Formatter for MatrixFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Matrix
    }
    fn max_chars_per_message(&self) -> usize {
        MATRIX_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            if !cb.lang.is_empty() {
                rendered.push_str(&cb.lang);
            }
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            MATRIX_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── LINE (plaintext) ─────────────────────────────────────────────────

/// GOLD-FEAT-10 — LINE formatter. A LINE text message is a plain UTF-8 string
/// (no markdown dialect to honour), so this mirrors the Signal/Matrix plaintext
/// renderer: append code blocks as literal triple-backtick fences (readable +
/// copy-paste-clean) and split at the LINE 5000-char-per-text-message API cap.
pub struct LineFormatter;

/// LINE rejects a text message body longer than 5000 chars (matches
/// `line_api::LINE_MAX_TEXT_CHARS`).
const LINE_MAX_CHARS: usize = 5_000;

impl Formatter for LineFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Line
    }
    fn max_chars_per_message(&self) -> usize {
        LINE_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            if !cb.lang.is_empty() {
                rendered.push_str(&cb.lang);
            }
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            LINE_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

/// GOLD-FEAT-10 — IRC plain-text formatter. IRC is line-oriented with a 512-byte
/// line cap, so the payload splits at 400 chars (matches
/// `irc_api::IRC_MAX_TEXT_CHARS`); the `irc` adapter additionally splits on
/// newlines (one PRIVMSG per line) at send time.
pub struct IrcFormatter;

const IRC_MAX_CHARS: usize = 400;

impl Formatter for IrcFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Irc
    }
    fn max_chars_per_message(&self) -> usize {
        IRC_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            if !cb.lang.is_empty() {
                rendered.push_str(&cb.lang);
            }
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(&rendered, IRC_MAX_CHARS - SPLIT_HEADROOM, reply.length_hint)
    }
}

// ── Nostr (plain text) ───────────────────────────────────────────────

/// GOLD-FEAT-10 — Nostr plain-text formatter. Nostr event content is free-form
/// text (no universal markdown renderer across clients), so this passes the
/// canonical text through verbatim and appends code blocks as literal
/// triple-backtick fences. Splits at 8000 chars (matches
/// `nostr_api::NOSTR_MAX_TEXT_CHARS`) to stay under typical relay event-size
/// limits.
pub struct NostrFormatter;

const NOSTR_MAX_CHARS: usize = 8_000;

impl Formatter for NostrFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Nostr
    }
    fn max_chars_per_message(&self) -> usize {
        NOSTR_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            if !cb.lang.is_empty() {
                rendered.push_str(&cb.lang);
            }
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            NOSTR_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── Mattermost (GitHub-flavored Markdown) ────────────────────────────

/// Mattermost formatter. Mattermost renders full GitHub-flavored Markdown, so —
/// like Slack — this formatter is permissive: pass the canonical text through
/// verbatim and append code blocks as triple-backtick fences (with the language
/// hint, which Mattermost DOES use for syntax highlighting).
pub struct MattermostFormatter;

/// Mattermost's default `MaxPostSize` is 16383 chars; split a hair under it so
/// the `[N/M]` continuation marker + any server-side trimming stay safe.
const MATTERMOST_MAX_CHARS: usize = 16000;

impl Formatter for MattermostFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Mattermost
    }
    fn max_chars_per_message(&self) -> usize {
        MATTERMOST_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push_str("\n```");
            if !cb.lang.is_empty() {
                rendered.push_str(&cb.lang);
            }
            rendered.push('\n');
            rendered.push_str(&cb.body);
            if !cb.body.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```");
        }
        split_into_messages(
            &rendered,
            MATTERMOST_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── Twitch (plaintext IRC) ───────────────────────────────────────────

/// Twitch chat formatter. Twitch chat is IRC: plaintext, no markdown rendering.
/// Mirrors [`IrcFormatter`] but at Twitch's 500-char per-message cap (the send
/// path's `irc_lines` applies a further wire-safety split). Code blocks are kept
/// as literal text so the operator still sees the code.
pub struct TwitchFormatter;

/// Twitch's per-message limit is 500 characters.
const TWITCH_MAX_CHARS: usize = 500;

impl Formatter for TwitchFormatter {
    fn channel(&self) -> ChannelKind {
        ChannelKind::Twitch
    }
    fn max_chars_per_message(&self) -> usize {
        TWITCH_MAX_CHARS
    }
    fn format(&self, reply: &CanonicalReply) -> Vec<String> {
        let mut rendered = String::new();
        rendered.push_str(&reply.text);
        for cb in &reply.code_blocks {
            rendered.push('\n');
            rendered.push_str(&cb.body);
        }
        split_into_messages(
            &rendered,
            TWITCH_MAX_CHARS - SPLIT_HEADROOM,
            reply.length_hint,
        )
    }
}

// ── Splitter ─────────────────────────────────────────────────────────

/// Split `body` into `Vec<String>` chunks each ≤ `cap` chars, prepending
/// `[N/M]` markers when the body needs more than one message. Prefer
/// double-newline breaks (paragraph boundary), fall back to single
/// newline, then hard char cut.
fn split_into_messages(body: &str, cap: usize, hint: Option<LengthHint>) -> Vec<String> {
    let _ = hint; // Hint is informational today; reserved for future
    // "prefer-paragraph-vs-hard-cut" tuning. Honouring it now would
    // require re-scoring split candidates per hint variant; keeping
    // the splitter simple ships sooner without losing correctness.
    let (_, single_fits) = cap_byte_window(body, cap);
    if single_fits {
        return vec![body.to_string()];
    }
    let mut chunks = Vec::new();
    let mut remaining: &str = body;
    while !remaining.is_empty() {
        let (byte_cap, exhausted) = cap_byte_window(remaining, cap);
        if exhausted {
            chunks.push(remaining.to_string());
            break;
        }
        // Find the best split point ≤ cap, scanning back from the
        // limit for a paragraph (\n\n), then a newline, then a space.
        let candidate = &remaining[..byte_cap];
        let split = candidate
            .rfind("\n\n")
            .or_else(|| candidate.rfind('\n'))
            .or_else(|| candidate.rfind(' '))
            .unwrap_or(byte_cap);
        // Avoid producing an empty chunk if rfind returned 0.
        let split = if split == 0 { byte_cap } else { split };
        chunks.push(remaining[..split].trim_end().to_string());
        remaining = remaining[split..].trim_start();
    }
    let total = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| format!("[{}/{}] {}", i + 1, total, c))
        .collect()
}

/// Walk `s` until either `cap` chars have been consumed or the string ends.
///
/// Returns `(byte_end, exhausted)`:
///   - `exhausted = true`  → `s` has ≤ `cap` chars; `byte_end == s.len()`.
///   - `exhausted = false` → `byte_end` is the byte offset AFTER the `cap`-th
///     char (so `&s[..byte_end]` slices exactly `cap` chars).
///
/// Audit 2026-05-19 Perf #10: replaces back-to-back `s.chars().count()` calls
/// in [`split_into_messages`] that walked the full string per chunk, making
/// the splitter O(N²) on long replies. This helper short-circuits at `cap+1`
/// chars, so the whole splitter is O(N) — every char is visited once across
/// the chunk-emit loop. `s.is_char_boundary(byte_end)` holds by construction
/// because we only advance through `char_indices()`.
fn cap_byte_window(s: &str, cap: usize) -> (usize, bool) {
    let mut last_end = 0;
    for (count, (i, c)) in s.char_indices().enumerate() {
        if count >= cap {
            return (i, false);
        }
        last_end = i + c.len_utf8();
    }
    (last_end, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(text: &str) -> CanonicalReply {
        CanonicalReply {
            text: text.to_string(),
            code_blocks: vec![],
            length_hint: None,
        }
    }

    fn reply_with_code(text: &str, lang: &str, body: &str) -> CanonicalReply {
        CanonicalReply {
            text: text.to_string(),
            code_blocks: vec![CodeBlock {
                lang: lang.to_string(),
                body: body.to_string(),
            }],
            length_hint: None,
        }
    }

    // ── for_channel routing ──────────────────────────────────────────

    #[test]
    fn for_channel_routes_every_known_dialect() {
        // Supported transports have a formatter; the known-but-unavailable
        // Keet inventory row deliberately does not.
        assert!(for_channel(ChannelKind::Telegram).is_some());
        assert!(for_channel(ChannelKind::Slack).is_some());
        assert!(for_channel(ChannelKind::WhatsAppBusiness).is_some());
        assert!(for_channel(ChannelKind::WhatsAppBaileys).is_some());
        assert!(for_channel(ChannelKind::Discord).is_some());
        assert!(for_channel(ChannelKind::Keet).is_none());
    }

    #[test]
    fn formatter_reports_its_own_channel() {
        assert_eq!(TelegramFormatter.channel(), ChannelKind::Telegram);
        assert_eq!(SlackFormatter.channel(), ChannelKind::Slack);
        assert_eq!(WhatsAppFormatter.channel(), ChannelKind::WhatsAppBusiness);
        assert_eq!(DiscordFormatter.channel(), ChannelKind::Discord);
    }

    // ── Telegram MarkdownV2 golden output ────────────────────────────

    #[test]
    fn telegram_escapes_every_special_character() {
        let r = reply("Heading. _italic_ *bold* [link](url). a-b+c=d|e!");
        let out = TelegramFormatter.format(&r);
        assert_eq!(out.len(), 1);
        let s = &out[0];
        // Each special char must be backslash-escaped.
        for c in ['.', '_', '*', '[', ']', '(', ')', '-', '+', '=', '|', '!'] {
            let escaped = format!("\\{c}");
            assert!(
                s.contains(&escaped),
                "expected escaped `{}` in output: {s}",
                c
            );
        }
    }

    #[test]
    fn telegram_renders_code_block_with_language_tag() {
        let r = reply_with_code("Here is the snippet:", "rust", "fn main() {}");
        let out = TelegramFormatter.format(&r);
        let s = &out[0];
        assert!(s.contains("```rust\nfn main() {}\n```"));
    }

    // ── Slack mrkdwn golden output ───────────────────────────────────

    #[test]
    fn slack_passes_text_through_verbatim() {
        let r = reply("Look at *this* result _here_.");
        let out = SlackFormatter.format(&r);
        assert_eq!(out, vec!["Look at *this* result _here_.".to_string()]);
    }

    #[test]
    fn slack_renders_code_block_with_no_language_when_empty() {
        let r = reply_with_code("Code:", "", "let x = 1;");
        let out = SlackFormatter.format(&r);
        let s = &out[0];
        // No language tag, but body lands.
        assert!(s.contains("```\nlet x = 1;\n```"));
    }

    // ── WhatsApp dialect ─────────────────────────────────────────────

    #[test]
    fn whatsapp_passes_text_and_code_through_in_supported_dialect() {
        let r = reply_with_code("Status: *bold*", "rust", "x");
        let out = WhatsAppFormatter.format(&r);
        let s = &out[0];
        assert!(s.contains("Status: *bold*"));
        // WhatsApp's triple-backtick block accepts no language tag; we
        // emit just the fence + body.
        assert!(s.contains("```\nx\n```"));
    }

    // ── Splitter ─────────────────────────────────────────────────────

    #[test]
    fn split_short_body_yields_single_message() {
        let r = reply("short");
        assert_eq!(TelegramFormatter.format(&r).len(), 1);
    }

    #[test]
    fn split_long_body_yields_multiple_numbered_messages() {
        // Build a body that exceeds Slack's 4000 cap by ~2x to force
        // a 2-message split.
        let para = "x".repeat(2000);
        let body = format!("{para}\n\n{para}\n\n{para}");
        let r = reply(&body);
        let out = SlackFormatter.format(&r);
        assert!(out.len() >= 2, "expected ≥2 chunks, got {}", out.len());
        // First chunk carries the [1/N] marker.
        assert!(out[0].starts_with("[1/"));
        // Last chunk carries [N/N].
        let last = out.last().unwrap();
        let m = last.split_once('/').unwrap().0.trim_start_matches('[');
        let _: u32 = m.parse().expect("chunk index parses");
    }

    #[test]
    fn split_prefers_paragraph_boundary_over_hard_cut() {
        // Build two paragraphs that together exceed Slack's 4000-cap
        // (incl. SPLIT_HEADROOM). Each paragraph = 500 * 6 = 3000 chars,
        // so total ≈ 6002 chars forces a 2-chunk split.
        let para_a = "alpha ".repeat(500);
        let para_b = "beta ".repeat(500);
        let body = format!("{para_a}\n\n{para_b}");
        let out = SlackFormatter.format(&reply(&body));
        // If the splitter cut mid-word the first chunk would end with
        // an `alpha alp` truncation. With paragraph-preference the
        // first chunk ends at the paragraph break.
        assert!(out.len() >= 2, "expected ≥2 chunks, got {}", out.len());
        let first_body = out[0].strip_prefix("[1/").unwrap();
        assert!(
            !first_body.contains("alph\n") && !first_body.ends_with("alph"),
            "should not mid-word cut: {first_body:?}"
        );
    }

    // ── Length-hint smoke ────────────────────────────────────────────

    #[test]
    fn length_hint_does_not_break_short_body() {
        // Hint is informational — must not change output shape for a
        // body that fits in one message.
        let mut r = reply("ok");
        r.length_hint = Some(LengthHint::Long);
        assert_eq!(TelegramFormatter.format(&r), vec!["ok".to_string()]);
    }

    // ── Discord (Pick #27) ───────────────────────────────────────────

    #[test]
    fn discord_passes_text_through_verbatim() {
        // Discord renders unbalanced markdown gracefully — no escape.
        let r = reply("Hello **world**! _italic_ and `code`");
        let out = DiscordFormatter.format(&r);
        assert_eq!(out, vec!["Hello **world**! _italic_ and `code`"]);
    }

    #[test]
    fn discord_renders_code_block_with_language_for_highlighting() {
        let r = reply_with_code("Snippet:", "rust", "fn main() {}");
        let out = DiscordFormatter.format(&r);
        let s = &out[0];
        assert!(
            s.contains("```rust\nfn main() {}\n```"),
            "Discord must keep the lang tag for syntax highlighting; got: {s}",
        );
    }

    #[test]
    fn discord_chunks_long_message_into_2000_char_bites() {
        // 2500-char body forces a 2-chunk split. Each chunk must fit
        // under the documented hard cap.
        let body = "x".repeat(2500);
        let out = DiscordFormatter.format(&reply(&body));
        assert!(out.len() >= 2, "expected ≥2 chunks; got {}", out.len());
        for c in &out {
            assert!(
                c.chars().count() <= DISCORD_MAX_CHARS,
                "chunk over Discord cap: {} > {}",
                c.chars().count(),
                DISCORD_MAX_CHARS,
            );
        }
    }

    #[test]
    fn discord_short_message_yields_single_chunk() {
        assert_eq!(DiscordFormatter.format(&reply("short")).len(), 1);
    }

    #[test]
    fn discord_does_not_escape_telegram_specials() {
        // Cross-channel sanity: chars Telegram MarkdownV2 would escape
        // pass straight through Discord. Catches accidental copy-paste
        // of the escape table between formatters.
        let r = reply("auth_middleware in src/auth/middleware.rs");
        let out = DiscordFormatter.format(&r);
        assert_eq!(out[0], "auth_middleware in src/auth/middleware.rs");
        assert!(!out[0].contains("\\_"), "Discord must not backslash-escape");
    }

    #[test]
    fn discord_max_chars_per_message_matches_const() {
        assert_eq!(DiscordFormatter.max_chars_per_message(), DISCORD_MAX_CHARS);
    }

    // ── cap_byte_window helper (Audit 2026-05-19 Perf #10) ───────────

    #[test]
    fn cap_byte_window_exhausts_when_under_cap() {
        let (end, exhausted) = cap_byte_window("hi", 100);
        assert!(exhausted);
        assert_eq!(end, 2);
    }

    #[test]
    fn cap_byte_window_returns_byte_after_cap_char_for_ascii() {
        let (end, exhausted) = cap_byte_window("abcdefghij", 3);
        assert!(!exhausted);
        assert_eq!(end, 3, "first 3 ASCII chars = 3 bytes");
    }

    #[test]
    fn cap_byte_window_counts_chars_not_bytes_for_multibyte() {
        // Each "ä" is 2 bytes in UTF-8 — 3 chars = 6 bytes.
        let s = "äöüxx";
        let (end, exhausted) = cap_byte_window(s, 3);
        assert!(!exhausted);
        assert_eq!(end, 6);
        assert!(s.is_char_boundary(end));
    }

    #[test]
    fn cap_byte_window_handles_zero_cap() {
        let (end, exhausted) = cap_byte_window("abc", 0);
        assert!(!exhausted);
        assert_eq!(end, 0);
    }

    #[test]
    fn cap_byte_window_handles_empty_string() {
        let (end, exhausted) = cap_byte_window("", 5);
        assert!(exhausted);
        assert_eq!(end, 0);
    }

    #[test]
    fn split_runs_in_linear_time_on_large_input() {
        // Regression guard for the O(N²) path that called
        // `remaining.chars().count()` twice per chunk-emit. With cap=200
        // and N=50_000, the old splitter performed ~250 full-string
        // counts → ~12.5M char walks. This test simply asserts the
        // splitter completes well under 1s — wall-time isn't a strict
        // bound but catches regression where the splitter becomes
        // quadratic again.
        let n = 50_000;
        let body = "x".repeat(n);
        let cap = 200;
        let start = std::time::Instant::now();
        let out = split_into_messages(&body, cap, None);
        let elapsed = start.elapsed();
        assert!(out.len() >= n / cap);
        assert!(
            elapsed.as_millis() < 500,
            "splitter took {}ms — regressed to O(N²)?",
            elapsed.as_millis()
        );
    }
}
