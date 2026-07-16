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
use crate::tools::{caldav, google_tasks, microsoft_todo, todoist};

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
    /// TD-02 — Microsoft To Do (MS Graph) via OAuth refresh. Needs
    /// `ms_todo_{tenant_id,client_id,client_secret,refresh_token}` in
    /// credentials.yaml (or `NEOTH_MS_TODO_*`).
    Microsoft,
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
    // P0: every external task WRITE (add/close on ANY backend — todoist, google,
    // caldav, microsoft) routes through the SAME ExternalTaskWrite gate +
    // `--dry-run` + fail-closed audit path. Previously only CalDAV was gated.
    let provider = provider_name(args.provider);
    let action = match &args.action {
        TodoAction::List => None,
        TodoAction::Add { .. } => Some("add"),
        TodoAction::Close { .. } => Some("close"),
    };
    if let Some(action) = action {
        gate_external_task_write(args.yes, provider, action)?;
        if args.dry_run {
            let target = match &args.action {
                TodoAction::Add { content } => content.as_str(),
                TodoAction::Close { id } => id.as_str(),
                TodoAction::List => "",
            };
            // CalDAV mints a deterministic uid from the content (idempotent
            // create), so a dry-run can show the exact uid that WOULD be used;
            // the OAuth/REST backends generate ids server-side, so the target
            // stands in as the uid placeholder.
            let uid = if matches!(args.provider, TaskProvider::Caldav) {
                if let TodoAction::Add { content } = &args.action {
                    caldav::task_uid(content)
                } else {
                    target.to_string()
                }
            } else {
                target.to_string()
            };
            print_dry_run(&args, provider, action, target, &uid);
            return Ok(());
        }
    }
    match args.provider {
        TaskProvider::Todoist => run_todoist(&args).await,
        TaskProvider::Google => run_google(&args).await,
        TaskProvider::Caldav => run_caldav(&args).await,
        TaskProvider::Microsoft => run_microsoft(&args).await,
    }
}

fn provider_name(p: TaskProvider) -> &'static str {
    match p {
        TaskProvider::Todoist => "todoist",
        TaskProvider::Google => "google",
        TaskProvider::Caldav => "caldav",
        TaskProvider::Microsoft => "microsoft",
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
            emit_todo_write("todoist", "add", &task.id, Some(content)).await;
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
            emit_todo_write("todoist", "close", id, None).await;
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
            emit_todo_write("google", "add", &task.id, Some(content)).await;
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
            emit_todo_write("google", "close", id, None).await;
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
                        let id = if t.uid.is_empty() {
                            "?"
                        } else {
                            t.uid.as_str()
                        };
                        println!("{id}  {}{due}", t.summary);
                    }
                }
            }
            Ok(())
        }
        TodoAction::Add { content } => {
            // The ExternalTaskWrite gate + `--dry-run` already ran centrally in
            // `run_todo`; here we just do the idempotent network write + audit.
            let (uid, outcome) = caldav::create_task(
                &creds.url,
                &creds.username,
                creds.password.expose(),
                content,
                None,
            )
            .await?;
            // Audit only an ACTUAL write (a no-dup AlreadyExists still happened
            // server-side as a no-op, but nothing changed — record both as the
            // write attempt's terminal state for the operator trail).
            emit_todo_write("caldav", "add", &uid, Some(content)).await;
            match outcome {
                caldav::CreateOutcome::Created => {
                    render_write(args, &format!("✓ created \"{content}\" (uid {uid})"))
                }
                caldav::CreateOutcome::AlreadyExists => render_write(
                    args,
                    &format!("• \"{content}\" already exists (uid {uid}) — no duplicate"),
                ),
            }
            Ok(())
        }
        TodoAction::Close { id } => {
            // Validate the uid shape before any network call; the central gate +
            // `--dry-run` already ran in `run_todo`.
            caldav::validate_uid(id)?;
            let outcome =
                caldav::close_task(&creds.url, &creds.username, creds.password.expose(), id)
                    .await?;
            match outcome {
                caldav::CloseOutcome::Completed => {
                    emit_todo_write("caldav", "close", id, None).await;
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

/// P0 — gate an external task write (ANY backend) through the autonomy/consent
/// layer + a fail-closed audit pre-flight. `Deny` bails; `Confirm` is satisfied
/// by `--yes`, an interactive TTY y/n prompt, or otherwise bails (no silent
/// network write). `Allow` proceeds. Under `required_for_oneshot_permission_
/// events`, a live daemon with an unreachable audit-RPC listener REFUSES the
/// write (the `0xC8 TODO_WRITE` frame couldn't land).
pub(crate) fn gate_external_task_write(yes: bool, provider: &str, action: &str) -> Result<()> {
    use crate::permissions::{Action, Decision, evaluate};
    let cfg = crate::config::FreedomConfig::load_from_default_path_or_default()?;
    let home = crate::config::FreedomConfig::default_neoth_home();
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile()),
        Ok(Some(_))
    );
    crate::daemon::audit_rpc::enforce_required_audit(
        cfg.audit_rpc.required_for_oneshot_permission_events,
        daemon_live,
        &home,
    )
    .context("task write refused: required audit cannot be written")?;
    let act = Action::ExternalTaskWrite {
        provider: provider.into(),
        action: action.into(),
    };
    match evaluate(&act, &cfg.autonomy_policy()) {
        Decision::Allow => Ok(()),
        Decision::Deny(r) => anyhow::bail!("denied: {r}"),
        Decision::Confirm(reason) => {
            if yes {
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

/// `0xC8 TODO_WRITE` audit. Metadata only (provider + action + uid + summary),
/// never credentials. Delegates the daemon-forward-or-one-shot delivery to the
/// shared [`emit_oneshot_audit`].
pub(crate) async fn emit_todo_write(
    provider: &str,
    action: &str,
    uid: &str,
    summary: Option<&str>,
) {
    let now = crate::time::now_unix_secs();
    let payload = serde_json::to_vec(&serde_json::json!({
        "provider": provider,
        "action": action,
        "uid": uid,
        "summary": summary,
        "ts_unix": now,
    }))
    .unwrap_or_default();
    emit_oneshot_audit(
        crate::wal::events::EVENT_TYPE_TODO_WRITE,
        payload,
        "TODO_WRITE",
    )
    .await;
}

/// Shared one-shot external-write audit delivery. P0: when a daemon owns the WAL
/// FORWARD over the loopback audit-RPC channel (the `event_type` must be in the
/// audit-RPC allowlist) instead of skipping; otherwise open a one-shot writer.
/// Used by `neoth todo` (`0xC8`) + `neoth calendar` (`0xCA`/`0xCB`) so every
/// external-write audit takes the identical durable path. `label` only names the
/// frame in the warn/debug logs. The caller builds the metadata-only payload
/// (NEVER credentials).
pub(crate) async fn emit_oneshot_audit(event_type: u8, payload: Vec<u8>, label: &'static str) {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let _ = emit_oneshot_audit_at(&home, event_type, payload, label, false).await;
}

/// Instance-home-bound counterpart used by callers that already resolved the
/// authoritative home. Keeping PID detection, audit RPC and the local WAL on
/// this exact path prevents Custom-Home actions from being audited elsewhere.
///
/// `required=true` means actual delivery, not a reachability proxy: a live
/// daemon must ACK the fsynced append, while a one-shot owner must successfully
/// append through the home-bound writer. Optional posture keeps the historical
/// best-effort behavior but surfaces the gap in logs.
pub(crate) async fn emit_oneshot_audit_at(
    home: &std::path::Path,
    event_type: u8,
    payload: Vec<u8>,
    label: &'static str,
    required: bool,
) -> Result<()> {
    let delivery: Result<()> = async {
        let daemon_live = crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid"))
            .context("inspect daemon ownership before audit delivery")?
            .is_some();
        if daemon_live {
            crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload)
                .await
                .map_err(anyhow::Error::new)
                .with_context(|| format!("daemon did not durably ACK {label}"))?;
            return Ok(());
        }

        let segment = home.join("wal").join("000001.wal");
        if let Some(parent) = segment.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create audit WAL directory {}", parent.display()))?;
        }
        let (writer, join) = crate::wal::writer::spawn_for_home(segment, home.to_path_buf())
            .with_context(|| format!("spawn home-bound writer for {label}"))?;
        let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
        let append = writer
            .append(header, payload)
            .await
            .with_context(|| format!("durably append {label}"));
        drop(writer);
        let joined = join
            .await
            .with_context(|| format!("join home-bound writer after {label}"));
        append?;
        joined?;
        Ok(())
    }
    .await;

    match delivery {
        Ok(()) => Ok(()),
        Err(error) if required => Err(error).with_context(|| {
            format!(
                "required audit `{label}` was not durably recorded; refusing the protected mutation"
            )
        }),
        Err(error) => {
            tracing::warn!(%error, label, "optional audit was not recorded");
            Ok(())
        }
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
            println!(
                "[dry-run] would {action} on {provider}: \"{target}\" (uid {uid}) — nothing sent"
            )
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

/// CalDAV connection settings. Shared by `neoth todo --provider caldav` and
/// `neoth calendar` (EM-02b) — both resolve the same operator credentials.
pub(crate) struct CaldavCreds {
    pub url: String,
    pub username: String,
    pub password: SecretString,
}

/// Resolve CalDAV creds: `credentials.yaml::caldav_{url,username,password}`
/// first, then `NEOTH_CALDAV_{URL,USERNAME,PASSWORD}`. Bails with the exact
/// missing field + how to set it.
pub(crate) fn caldav_creds() -> Result<CaldavCreds> {
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
    if let Some(t) = arg
        && !t.is_empty()
    {
        return Ok(SecretString::from(t));
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
    if let Ok(env) = std::env::var("NEOTH_TODOIST_TOKEN")
        && !env.is_empty()
    {
        return Ok(SecretString::from(env));
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

// ── Microsoft To Do (TD-02) ────────────────────────────────────────────

async fn run_microsoft(args: &TodoArgs) -> Result<()> {
    let creds = microsoft_creds()?;
    let access = microsoft_todo::refresh_access_token(
        &creds.tenant_id,
        &creds.client_id,
        &creds.client_secret,
        &creds.refresh_token,
    )
    .await?;
    match &args.action {
        TodoAction::List => {
            let tasks = microsoft_todo::list_tasks(&access).await?;
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
                            .map(|d| format!("  (due {})", d.date_time))
                            .unwrap_or_default();
                        println!("{}  {}{}", t.id, t.title, due);
                    }
                }
            }
        }
        TodoAction::Add { content } => {
            let task = microsoft_todo::create_task(&access, content).await?;
            emit_todo_write("microsoft", "add", &task.id, Some(content)).await;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&task)?);
                }
                OutputFormat::Table => println!("✓ created {} — {}", task.id, task.title),
            }
        }
        TodoAction::Close { id } => {
            microsoft_todo::close_task(&access, id).await?;
            emit_todo_write("microsoft", "close", id, None).await;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "closed": id, "ok": true }))
                }
                OutputFormat::Table => println!("✓ closed {id}"),
            }
        }
    }
    Ok(())
}

struct MicrosoftCreds {
    tenant_id: String,
    client_id: String,
    client_secret: SecretString,
    refresh_token: SecretString,
}

/// Resolve MS To Do creds: `credentials.yaml::ms_todo_*` then the
/// `NEOTH_MS_TODO_*` env overrides. `tenant_id` defaults to `common` (personal
/// accounts); the rest bail with the exact missing field.
fn microsoft_creds() -> Result<MicrosoftCreds> {
    let creds = crate::config::credentials::Credentials::load_or_default(
        &crate::config::credentials::default_path(),
    )
    .context("load credentials.yaml")?;
    let tenant_id = creds
        .ms_todo_tenant_id
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("NEOTH_MS_TODO_TENANT_ID")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "common".to_string());
    let client_id = creds
        .ms_todo_client_id
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("NEOTH_MS_TODO_CLIENT_ID")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| missing_ms("client_id", "NEOTH_MS_TODO_CLIENT_ID"))?;
    let client_secret = creds
        .ms_todo_client_secret
        .or_else(|| env_secret("NEOTH_MS_TODO_CLIENT_SECRET"))
        .ok_or_else(|| missing_ms("client_secret", "NEOTH_MS_TODO_CLIENT_SECRET"))?;
    let refresh_token = creds
        .ms_todo_refresh_token
        .or_else(|| env_secret("NEOTH_MS_TODO_REFRESH_TOKEN"))
        .ok_or_else(|| missing_ms("refresh_token", "NEOTH_MS_TODO_REFRESH_TOKEN"))?;
    Ok(MicrosoftCreds {
        tenant_id,
        client_id,
        client_secret,
        refresh_token,
    })
}

fn missing_ms(field: &str, env: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "no Microsoft To Do {field} — add `ms_todo_{field}` to ~/.neoth/credentials.yaml or set {env}. \
         Register an Azure app (delegated `Tasks.ReadWrite` + `offline_access`), run the OAuth consent \
         flow to mint a refresh token; tenant defaults to `common` for personal accounts."
    )
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
