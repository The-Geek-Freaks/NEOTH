//! `neoth todo` — TD-01 (Todoist) + TD-02 (Google Tasks + CalDAV). Operator
//! CLI over the task adapters: `list` / `add <content>` / `close <id>`.
//!
//! Backend chosen by `--provider` (default `todoist`):
//!
//! - **`todoist`** — Todoist REST v2 (`tools::todoist`). Static API token,
//!   resolved: `--token` → `credentials.yaml::todoist_token` →
//!   `NEOTH_TODOIST_TOKEN`.
//! - **`google`** — Google Tasks (`tools::google_tasks`) via OAuth refresh.
//!   Needs `google_oauth_{client_id,client_secret,refresh_token}` in
//!   `credentials.yaml` (or the `NEOTH_GOOGLE_{CLIENT_ID,CLIENT_SECRET,
//!   REFRESH_TOKEN}` env overrides). The refresh token is exchanged for a
//!   short-lived access token on each run; access tokens are never stored.
//! - **`caldav`** — CalDAV VTODO (`tools::caldav`): `list` (WebDAV `REPORT`
//!   calendar-query) + `add`/`close` writes (TD-02). The write path is the
//!   gated one: idempotent create (`If-None-Match: *` → no duplicate on re-run),
//!   ETag-guarded complete (`If-Match` → never clobber a concurrent edit), an
//!   autonomy/consent confirm (`--yes` / TTY / Elevated+), `--dry-run`, and a
//!   `0xC8 TODO_WRITE` audit frame. Needs `caldav_{url,username,password}` in
//!   `credentials.yaml` (or `NEOTH_CALDAV_*` env).

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::secret::SecretString;
use crate::tools::{caldav, google_tasks, todoist};

#[derive(Args, Debug, Clone)]
pub struct TodoArgs {
    #[command(subcommand)]
    pub action: TodoAction,
    /// Task backend. `todoist` (static API token) or `google` (Google
    /// Tasks via OAuth refresh).
    #[arg(long, value_enum, default_value_t = TaskProvider::Todoist, global = true)]
    pub provider: TaskProvider,
    /// Todoist REST v2 API token (provider `todoist` only). Overrides
    /// `credentials.yaml::todoist_token` and `NEOTH_TODOIST_TOKEN`. Get it
    /// from Todoist → Settings → Integrations → Developer.
    #[arg(long, value_name = "TOKEN", global = true)]
    pub token: Option<String>,
    /// TD-02 (CalDAV write): show what WOULD be created/completed without
    /// sending the request or emitting the audit frame.
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// TD-02 (CalDAV write): skip the interactive confirmation for the network
    /// mutation (needed for scripts at Strict/Standard autonomy). The write is
    /// still WAL-audited.
    #[arg(long, global = true)]
    pub yes: bool,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum TaskProvider {
    Todoist,
    Google,
    /// TD-02 — CalDAV (Nextcloud Tasks, Radicale, Apple Reminders via iCloud
    /// CalDAV, …). `list` + `add`/`close` (gated network writes: idempotent
    /// create via `If-None-Match`, ETag-guarded complete via `If-Match`, an
    /// autonomy/consent confirm, and a `0xC8 TODO_WRITE` audit frame). Needs
    /// `caldav_{url,username,password}` in credentials.yaml (or `NEOTH_CALDAV_*`).
    Caldav,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TodoAction {
    /// List active (open) tasks.
    List,
    /// Create a task: `neoth todo add "buy milk"`.
    Add {
        /// Task content (the title shown in the backend).
        content: String,
    },
    /// Close (complete) a task by its backend id.
    Close {
        /// Task id (from `neoth todo list`).
        id: String,
    },
}

pub async fn run_todo(args: TodoArgs) -> Result<()> {
    match args.provider {
        TaskProvider::Todoist => run_todoist(&args).await,
        TaskProvider::Google => run_google(&args).await,
        TaskProvider::Caldav => run_caldav(&args).await,
    }
}

// ── Todoist (TD-01) ────────────────────────────────────────────────────

async fn run_todoist(args: &TodoArgs) -> Result<()> {
    let token = resolve_todoist_token(args.token.as_deref())?;
    match &args.action {
        TodoAction::List => {
            let tasks = todoist::list_tasks(&token).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&tasks)?);
                }
                OutputFormat::Table => {
                    if tasks.is_empty() {
                        println!("(no open tasks)");
                        return Ok(());
                    }
                    for t in &tasks {
                        let due = t
                            .due
                            .as_ref()
                            .and_then(|d| d.string.as_deref().or(d.date.as_deref()))
                            .map(|s| format!("  (due {s})"))
                            .unwrap_or_default();
                        println!("{}  {}{}", t.id, t.content, due);
                    }
                }
            }
        }
        TodoAction::Add { content } => {
            let task = todoist::create_task(&token, content).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&task)?);
                }
                OutputFormat::Table => {
                    println!("✓ created #{} — {}", task.id, task.content);
                }
            }
        }
        TodoAction::Close { id } => {
            todoist::close_task(&token, id).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "closed": id, "ok": true }));
                }
                OutputFormat::Table => println!("✓ closed #{id}"),
            }
        }
    }
    Ok(())
}

// ── Google Tasks (TD-02) ───────────────────────────────────────────────

async fn run_google(args: &TodoArgs) -> Result<()> {
    let creds = google_creds()?;
    // Exchange the long-lived refresh token for a short-lived access
    // token (once per invocation — never persisted).
    let access = google_tasks::refresh_access_token(
        &creds.client_id,
        &creds.client_secret,
        &creds.refresh_token,
    )
    .await?;
    match &args.action {
        TodoAction::List => {
            let tasks = google_tasks::list_tasks(&access).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&tasks)?);
                }
                OutputFormat::Table => {
                    if tasks.is_empty() {
                        println!("(no open tasks)");
                        return Ok(());
                    }
                    for t in &tasks {
                        let due = t
                            .due
                            .as_deref()
                            .map(|s| format!("  (due {s})"))
                            .unwrap_or_default();
                        println!("{}  {}{}", t.id, t.title, due);
                    }
                }
            }
        }
        TodoAction::Add { content } => {
            let task = google_tasks::create_task(&access, content).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&task)?);
                }
                OutputFormat::Table => {
                    println!("✓ created {} — {}", task.id, task.title);
                }
            }
        }
        TodoAction::Close { id } => {
            google_tasks::close_task(&access, id).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "closed": id, "ok": true }));
                }
                OutputFormat::Table => println!("✓ closed {id}"),
            }
        }
    }
    Ok(())
}

// ── CalDAV (TD-02) ─────────────────────────────────────────────────────

async fn run_caldav(args: &TodoArgs) -> Result<()> {
    let creds = caldav_creds()?;
    match &args.action {
        TodoAction::List => {
            let tasks =
                caldav::list_tasks(&creds.url, &creds.username, creds.password.expose()).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&tasks)?);
                }
                OutputFormat::Table => {
                    if tasks.is_empty() {
                        println!("(no open tasks)");
                        return Ok(());
                    }
                    for t in &tasks {
                        let due = t
                            .due
                            .as_deref()
                            .map(|s| format!("  (due {s})"))
                            .unwrap_or_default();
                        let id = if t.uid.is_empty() { "?" } else { t.uid.as_str() };
                        println!("{id}  {}{due}", t.summary);
                    }
                }
            }
            Ok(())
        }
        TodoAction::Add { content } => {
            gate_external_task_write(args, "caldav", "add")?;
            if args.dry_run {
                print_dry_run(args, "caldav", "add", content, &caldav::task_uid(content));
                return Ok(());
            }
            let (uid, outcome) =
                caldav::create_task(&creds.url, &creds.username, creds.password.expose(), content, None)
                    .await?;
            // Audit only an ACTUAL write (a no-dup AlreadyExists still happened
            // server-side as a no-op, but nothing changed — record both as the
            // write attempt's terminal state for the operator trail).
            emit_todo_write("caldav", "add", &uid, Some(content));
            match outcome {
                caldav::CreateOutcome::Created => render_write(args, &format!("✓ created \"{content}\" (uid {uid})")),
                caldav::CreateOutcome::AlreadyExists => {
                    render_write(args, &format!("• \"{content}\" already exists (uid {uid}) — no duplicate"))
                }
            }
            Ok(())
        }
        TodoAction::Close { id } => {
            caldav::validate_uid(id)?;
            gate_external_task_write(args, "caldav", "close")?;
            if args.dry_run {
                print_dry_run(args, "caldav", "close", id, id);
                return Ok(());
            }
            let outcome =
                caldav::close_task(&creds.url, &creds.username, creds.password.expose(), id).await?;
            match outcome {
                caldav::CloseOutcome::Completed => {
                    emit_todo_write("caldav", "close", id, None);
                    render_write(args, &format!("✓ completed {id}"));
                }
                caldav::CloseOutcome::NotFound => {
                    render_write(args, &format!("• no task at uid {id} (nothing to close)"))
                }
                caldav::CloseOutcome::Conflict => anyhow::bail!(
                    "conflict: the server copy of {id} changed since it was read \
                     (If-Match mismatch) — re-run `neoth todo --provider caldav list` then retry, \
                     so a concurrent edit isn't clobbered"
                ),
            }
            Ok(())
        }
    }
}

/// TD-02 — gate a CalDAV (external task) write through the autonomy/consent
/// layer. `Deny` bails; `Confirm` is satisfied by `--yes`, an interactive TTY
/// y/n prompt, or otherwise bails (no silent network write). `Allow` proceeds.
fn gate_external_task_write(args: &TodoArgs, provider: &str, action: &str) -> Result<()> {
    use crate::permissions::{Action, Decision, evaluate};
    let cfg = crate::config::FreedomConfig::load_from_default_path().unwrap_or_default();
    let act = Action::ExternalTaskWrite {
        provider: provider.into(),
        action: action.into(),
    };
    match evaluate(&act, cfg.autonomy) {
        Decision::Allow => Ok(()),
        Decision::Deny(r) => anyhow::bail!("denied: {r}"),
        Decision::Confirm(reason) => {
            if args.yes {
                return Ok(());
            }
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                use crate::permissions::confirm::{ConfirmOutcome, confirm_interactive};
                match confirm_interactive(&reason) {
                    ConfirmOutcome::Approved => Ok(()),
                    _ => anyhow::bail!("confirmation declined — task NOT written"),
                }
            } else {
                anyhow::bail!(
                    "{reason} — re-run with --yes (non-interactive) or from a terminal, \
                     or raise autonomy to Elevated"
                )
            }
        }
    }
}

/// Best-effort `0xC8 TODO_WRITE` audit. One-shot writer; skipped when a daemon
/// owns the WAL (avoids a segment race — mirrors `neoth dream now`). Metadata
/// only (provider + action + uid + summary), never credentials.
fn emit_todo_write(provider: &str, action: &str, uid: &str, summary: Option<&str>) {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    ) {
        tracing::info!("todo: daemon live — skipping one-shot TODO_WRITE audit to avoid a writer race");
        return;
    }
    let segment = crate::config::FreedomConfig::default_wal_dir().join("000001.wal");
    if let Some(p) = segment.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let (writer, _join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "todo: WAL writer spawn failed; TODO_WRITE not recorded");
            return;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = serde_json::to_vec(&serde_json::json!({
        "provider": provider,
        "action": action,
        "uid": uid,
        "summary": summary,
        "ts_unix": now,
    }))
    .unwrap_or_default();
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_TODO_WRITE, &payload).build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "todo: TODO_WRITE frame append failed (audit gap)");
    }
}

fn print_dry_run(args: &TodoArgs, provider: &str, action: &str, target: &str, uid: &str) {
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "dry_run": true,
                "provider": provider,
                "action": action,
                "target": target,
                "uid": uid,
            })
        ),
        OutputFormat::Table => {
            println!("[dry-run] would {action} on {provider}: \"{target}\" (uid {uid}) — nothing sent")
        }
    }
}

fn render_write(args: &TodoArgs, msg: &str) {
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::json!({ "result": msg }))
        }
        OutputFormat::Table => println!("{msg}"),
    }
}

/// CalDAV connection settings.
struct CaldavCreds {
    url: String,
    username: String,
    password: SecretString,
}

/// Resolve CalDAV creds: `credentials.yaml::caldav_{url,username,password}`
/// first, then `NEOTH_CALDAV_{URL,USERNAME,PASSWORD}`. Bails with the exact
/// missing field + how to set it.
fn caldav_creds() -> Result<CaldavCreds> {
    let creds = crate::config::credentials::Credentials::load_or_default(
        &crate::config::credentials::default_path(),
    )
    .context("load credentials.yaml")?;
    let url = creds
        .caldav_url
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("NEOTH_CALDAV_URL")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| missing_caldav("url", "NEOTH_CALDAV_URL"))?;
    let username = creds
        .caldav_username
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("NEOTH_CALDAV_USERNAME")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| missing_caldav("username", "NEOTH_CALDAV_USERNAME"))?;
    let password = creds
        .caldav_password
        .or_else(|| env_secret("NEOTH_CALDAV_PASSWORD"))
        .ok_or_else(|| missing_caldav("password", "NEOTH_CALDAV_PASSWORD"))?;
    Ok(CaldavCreds {
        url,
        username,
        password,
    })
}

fn missing_caldav(field: &str, env: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "no CalDAV {field} — add `caldav_{field}` to ~/.neoth/credentials.yaml or set {env}. \
         The url is your task-calendar collection (e.g. Nextcloud: \
         https://<host>/remote.php/dav/calendars/<user>/<tasklist>/); username + password are \
         your CalDAV / app-password Basic-auth credentials."
    )
}

/// Resolve the Todoist token: `--token` → `credentials.yaml::todoist_token`
/// → `NEOTH_TODOIST_TOKEN`, else a clear error.
fn resolve_todoist_token(arg: Option<&str>) -> Result<SecretString> {
    if let Some(t) = arg {
        if !t.is_empty() {
            return Ok(SecretString::from(t));
        }
    }
    // Propagate a corrupt-credentials parse error (load_or_default hard-errors
    // on bad YAML by contract) rather than `unwrap_or_default()`-swallowing it
    // into a misleading "no Todoist token" bail. Mirrors cli::slack.
    let creds = crate::config::credentials::Credentials::load_or_default(
        &crate::config::credentials::default_path(),
    )
    .context("load credentials.yaml")?;
    if let Some(tok) = creds.todoist_token {
        return Ok(tok);
    }
    if let Ok(env) = std::env::var("NEOTH_TODOIST_TOKEN") {
        if !env.is_empty() {
            return Ok(SecretString::from(env));
        }
    }
    anyhow::bail!(
        "no Todoist token — pass --token <TOKEN>, add `todoist_token` to \
         ~/.neoth/credentials.yaml, or set NEOTH_TODOIST_TOKEN. Get a token from \
         Todoist → Settings → Integrations → Developer."
    )
}

/// The three Google OAuth secrets `neoth todo --provider google` needs.
struct GoogleCreds {
    client_id: String,
    client_secret: SecretString,
    refresh_token: SecretString,
}

/// Resolve the Google OAuth credentials: `credentials.yaml::google_oauth_*`
/// first, then the `NEOTH_GOOGLE_{CLIENT_ID,CLIENT_SECRET,REFRESH_TOKEN}`
/// env overrides. Bails with the exact missing field + how to set it.
fn google_creds() -> Result<GoogleCreds> {
    let creds = crate::config::credentials::Credentials::load_or_default(
        &crate::config::credentials::default_path(),
    )
    .context("load credentials.yaml")?;

    let client_id = creds
        .google_oauth_client_id
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("NEOTH_GOOGLE_CLIENT_ID")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| missing_google("client_id", "NEOTH_GOOGLE_CLIENT_ID"))?;
    let client_secret = creds
        .google_oauth_client_secret
        .or_else(|| env_secret("NEOTH_GOOGLE_CLIENT_SECRET"))
        .ok_or_else(|| missing_google("client_secret", "NEOTH_GOOGLE_CLIENT_SECRET"))?;
    let refresh_token = creds
        .google_oauth_refresh_token
        .or_else(|| env_secret("NEOTH_GOOGLE_REFRESH_TOKEN"))
        .ok_or_else(|| missing_google("refresh_token", "NEOTH_GOOGLE_REFRESH_TOKEN"))?;

    Ok(GoogleCreds {
        client_id,
        client_secret,
        refresh_token,
    })
}

fn env_secret(var: &str) -> Option<SecretString> {
    std::env::var(var)
        .ok()
        .filter(|s| !s.is_empty())
        .map(SecretString::from)
}

fn missing_google(field: &str, env: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "no Google OAuth {field} — add `google_oauth_{field}` to \
         ~/.neoth/credentials.yaml or set {env}. One-time setup: create an \
         OAuth installed-app client in the Google Cloud console, grant the \
         scope `{scope}`, and complete consent once to mint a refresh token.",
        scope = google_tasks::GOOGLE_TASKS_SCOPE,
    )
}

impl TaskProvider {
    /// The clap default, exposed for the drift-guard test.
    #[cfg(test)]
    fn default_value() -> Self {
        TaskProvider::Todoist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_todoist_token_prefers_explicit_arg() {
        // The explicit --token wins before any creds-file / env lookup, so
        // this is hermetic regardless of the host's ~/.neoth or env.
        let t = resolve_todoist_token(Some("arg-token")).expect("arg token");
        assert_eq!(t.expose(), "arg-token");
    }

    #[test]
    fn task_provider_default_is_todoist() {
        assert_eq!(TaskProvider::default_value(), TaskProvider::Todoist);
    }

    #[test]
    fn missing_google_error_names_field_and_env_and_scope() {
        let e = missing_google("refresh_token", "NEOTH_GOOGLE_REFRESH_TOKEN").to_string();
        assert!(e.contains("google_oauth_refresh_token"));
        assert!(e.contains("NEOTH_GOOGLE_REFRESH_TOKEN"));
        assert!(e.contains("auth/tasks"), "scope shown: {e}");
    }
}
