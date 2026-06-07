//! Slash commands — Phase 28 R-17.
//!
//! Channel-side prefix dispatch. When an inbound message starts with `/`,
//! the pipeline looks up the command name in the registry. Three sources
//! feed the registry, evaluated in order:
//!
//!   1. **Built-ins** — 21 commands compiled into the binary (`/help`,
//!      `/recall`, `/status`, `/jobs`, `/rollback`, `/critic`, `/wizard`,
//!      `/config`, `/provider`, `/connect`, `/disconnect`, `/skill`,
//!      `/plugin`, `/memory`, `/consent`, `/reload`, `/autonomy`, `/quit`,
//!      `/glossary`, `/privacy`, `/tour`) so a fresh install ships with a
//!      useful surface. See `slash::builtins::built_in_commands`.
//!   2. **Operator overrides** — `~/.neoth/commands/<name>.toml`. Takes
//!      precedence over a built-in of the same name so operators can rebind.
//!   3. **Operator-defined** — any additional `~/.neoth/commands/*.toml`.
//!
//! The TOML schema is intentionally tiny: a slash command is a named
//! prompt template plus optional metadata. No code execution, no shell:
//! the command body is fed back into the provider as a system prompt
//! prefix on the next turn.

pub mod action_dispatch;
pub mod builtins;
pub mod loader;
pub mod parser;
pub mod schema;

#[allow(unused_imports)] // ActionOutcome used by tests + future GUI callers
pub use action_dispatch::{ActionOutcome, dispatch_action};
pub use loader::load_all;
pub use parser::{Invocation, parse_invocation};
pub use schema::CommandSource;
