//! Parse `/name args` prefix invocations.
//!
//! Only fires when the input starts with a single `/` followed by a name.
//! Leading whitespace before the `/` is tolerated. `//` is NOT a slash
//! command — that's an escape sequence for operators who want to start a
//! message with `/` (the parser strips the leading slash and returns the
//! rest as a normal message).

/// Result of running [`parse_invocation`] over an inbound message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invocation {
    /// A slash-command invocation. `name` is lowercased; `args` is the
    /// trimmed remainder of the line.
    Command { name: String, args: String },
    /// The operator escaped a leading slash with `//`. Caller treats this
    /// as a normal message — the unescaped form is in `text`.
    Escaped { text: String },
    /// Not a slash command — caller treats the original message as normal.
    NotACommand,
}

/// Inspect `input` for a slash-command prefix. Returns one of the three
/// variants — no side effects, no errors.
pub fn parse_invocation(input: &str) -> Invocation {
    let trimmed_start = input.trim_start();
    // Escape: `//` at the start means "literal slash" — strip one slash and
    // pass through as a normal message.
    if let Some(rest) = trimmed_start.strip_prefix("//") {
        return Invocation::Escaped {
            text: rest.to_string(),
        };
    }
    let Some(rest) = trimmed_start.strip_prefix('/') else {
        return Invocation::NotACommand;
    };
    // Command name is whitespace-terminated. Reject empty names.
    let (name, args) = match rest.split_once(char::is_whitespace) {
        Some((n, a)) => (n, a.trim()),
        None => (rest, ""),
    };
    if name.is_empty() {
        return Invocation::NotACommand;
    }
    // Command names must be `[a-z0-9_-]+` (case-folded). Anything outside
    // that set (e.g. `/path/to/file`) is treated as a normal message so we
    // don't hijack URLs.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Invocation::NotACommand;
    }
    Invocation::Command {
        name: name.to_ascii_lowercase(),
        args: args.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_command() {
        assert_eq!(
            parse_invocation("/help"),
            Invocation::Command {
                name: "help".into(),
                args: String::new(),
            },
        );
    }

    #[test]
    fn parses_command_with_args() {
        assert_eq!(
            parse_invocation("/recall my cool query"),
            Invocation::Command {
                name: "recall".into(),
                args: "my cool query".into(),
            },
        );
    }

    #[test]
    fn lowercases_command_name() {
        let Invocation::Command { name, .. } = parse_invocation("/STATUS") else {
            panic!("expected Command");
        };
        assert_eq!(name, "status");
    }

    #[test]
    fn double_slash_is_escape() {
        assert_eq!(
            parse_invocation("//actually a path"),
            Invocation::Escaped {
                text: "actually a path".into(),
            },
        );
    }

    #[test]
    fn non_command_passes_through() {
        assert_eq!(parse_invocation("hello there"), Invocation::NotACommand);
        assert_eq!(parse_invocation("  no slash"), Invocation::NotACommand);
    }

    #[test]
    fn empty_after_slash_is_not_a_command() {
        assert_eq!(parse_invocation("/"), Invocation::NotACommand);
        assert_eq!(parse_invocation("/ "), Invocation::NotACommand);
    }

    #[test]
    fn url_like_path_is_not_a_command() {
        // `/usr/local/bin` looks like a path — must not hijack.
        assert_eq!(parse_invocation("/usr/local/bin"), Invocation::NotACommand,);
    }

    #[test]
    fn leading_whitespace_tolerated() {
        let Invocation::Command { name, args } = parse_invocation("   /help me") else {
            panic!("expected Command");
        };
        assert_eq!(name, "help");
        assert_eq!(args, "me");
    }

    #[test]
    fn name_can_have_dashes_and_underscores() {
        let Invocation::Command { name, .. } = parse_invocation("/say-hi alex") else {
            panic!("expected Command");
        };
        assert_eq!(name, "say-hi");
        let Invocation::Command { name, .. } = parse_invocation("/my_command") else {
            panic!("expected Command");
        };
        assert_eq!(name, "my_command");
    }
}
