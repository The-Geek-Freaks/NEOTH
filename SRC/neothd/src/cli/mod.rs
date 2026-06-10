//! `neoth` CLI — top-level command dispatch.
//!
//! Normative reference: PLAN/SPEC_onboarding.md
//! Clap 4.5+ derive macros.
//!
//! Phase 1 (Day 3-4): `init` subcommand stubbed with 7-step wizard structure.
//! Phase 2+: `chat`, `profile`, `quota`, `provider`, `channel` subcommands.

use clap::{Parser, Subcommand, ValueEnum};

pub mod adr;
pub mod agents;
pub mod arxiv;
pub mod arxiv_ingest_task;
/// GOLD-ADOPT-26 — RSS / Atom / JSON-Feed poller cron.
pub mod rss_feed_task;
pub mod backup;
pub mod catalog;
pub mod channel;
pub mod chat;
pub mod cloud;
pub mod cloud_sync_task;
// GOLD-SEC-16: `neoth cluster` CLI surface gated with the `cluster` feature.
#[cfg(feature = "cluster")]
pub mod cluster;
pub mod code;
pub mod code_map;
pub mod completions;
pub mod connect;
pub mod consent;
pub mod cost;
pub mod council;
pub mod ctx;
pub mod docgen;
pub mod doctor;
pub mod dreaming_task;
pub mod events;
pub mod export;
pub mod fact_check;
pub mod risk_confirm;
pub mod fetch;
pub mod fs;
pub mod github;
pub mod glossary;
pub mod groundtruth;
pub mod groundtruth_wizard;
pub mod autonomy;
/// EM-02b — `neoth calendar` CalDAV calendar (VEVENT) list/add surface.
pub mod calendar;
pub mod checkpoint;
pub mod credential;
pub mod cron;
pub mod dream;
pub mod ecology;
pub mod email;
pub mod identity;
pub mod transfer;
pub mod gui;
pub mod n8n;
pub mod gui_stream;
pub mod hardware;
pub mod hemispheres;
pub mod hooks;
pub mod hysteria;
pub mod ingest;
pub mod init;
pub mod installer;
pub mod jobs;
pub mod feedback;
pub mod kanban;
pub mod keys;
pub mod lease;
pub mod mcp;
pub mod memory;
pub mod migrate;
pub mod mode;
pub mod monitor;
pub mod models;
pub mod obsidian;
pub mod obsidian_sync_task;
pub mod os;
pub mod ouro;
pub mod paperless;
pub mod permissions;
pub mod plugin;
pub mod preset;
pub mod privacy;
pub mod proactive;
pub mod profile;
pub mod providers;
pub mod quota;
pub mod goal;
pub mod recall;
pub mod recipe;
pub mod review;
pub mod recall_score;
pub mod recover;
pub mod refusal;
/// MAR-02 — `neoth release {keygen, sign, pubkey}` DAU-friendly release signing.
pub mod release;
pub mod reload;
pub mod rollback;
pub mod schema;
pub mod search;
/// Round-3 v0.4 SC-04 — `neoth security audit` operator-facing
/// security-posture aggregator. Runs HMAC key + WAL segment +
/// memory drift + credential sidecar checks in one pass.
pub mod security;
pub mod self_dev;
pub mod self_dev_outbox;
pub mod serve;
pub mod serve_pipeline;
pub mod skills;
pub mod slack;
pub mod slash;
pub mod status;
pub mod supervisor;
pub mod telemetry;
pub mod todo;
pub mod trust;
pub mod tour;
pub mod tts;
pub mod tweaks;
pub mod undo;
pub mod unlock_moment;
pub mod update;
pub mod updater;
pub mod usage;
pub mod verify;
pub mod wal;
pub mod webhook;
pub mod wizard_checkpoint;

/// Output format for any subcommand that produces structured data.
/// Established globally so streaming + format flags are consistent across
/// `neoth recall`, `neoth chat`, etc. See OPEN_DECISIONS.md D-005.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Human-readable table (default).
    #[default]
    Table,
    /// Pretty-printed JSON object on stdout.
    Json,
    /// Newline-delimited JSON, one record per line. Pipeable to jq.
    Jsonl,
}

/// Neoth — personal AI agent.
///
/// Run `neoth init` to configure on first use.
#[derive(Parser, Debug)]
#[command(
    name = "neoth",
    version,
    about = "neoth knows.",
    long_about = "Neoth is a Rust-based personal AI agent.\nRun `neoth init` to get started."
)]
pub struct Cli {
    /// Increase verbosity (use NEOTH_LOG=debug for full debug output)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output format. `--stream` implies `jsonl`.
    #[arg(long, global = true, default_value = "table")]
    pub output: OutputFormat,

    /// Stream results as they arrive instead of collecting first.
    /// Implies `--output jsonl`. The final line of a complete stream is the
    /// sentinel `{"neoth_stream":"done","count":N}` — consumers MUST check for
    /// it to detect truncated streams. Exit code is non-zero on any stream
    /// error.
    #[arg(long, global = true)]
    pub stream: bool,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Effective output format: `--stream` forces jsonl regardless of `--output`.
    pub fn effective_output(&self) -> OutputFormat {
        if self.stream {
            OutputFormat::Jsonl
        } else {
            self.output
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Interactive onboarding wizard. Sets up ~/.neoth/ config.
    ///
    /// Re-running when already initialized: shows per-section reconfigure menu.
    /// Use --force to re-run the full wizard unconditionally.
    Init(init::InitArgs),

    /// Run the daemon. Reads ~/.neoth/freedom.yaml, opens the WAL,
    /// awaits SIGTERM / Ctrl+C, drains cleanly on shutdown.
    Serve(serve::ServeArgs),

    /// One-shot LLM round trip. Loads freedom.yaml, sends prompt, prints reply.
    /// Both request and response are persisted as WAL events.
    Chat(chat::ChatArgs),

    /// GOLD-WIRE-11 — fact-check a claim. Decomposes the text into atomic
    /// propositions, classifies each (verifiable / plausible / opinion /
    /// suspect) with deterministic heuristics (no LLM call), and prints a
    /// `clean` / `needs_framing` / `needs_revision` verdict.
    /// `neoth fact-check "NEOTH was released in 2026."`
    #[command(name = "fact-check")]
    FactCheck(fact_check::FactCheckArgs),

    /// GOLD-ADOPT-23 — open a TTL-bounded risk-confirm window so the next
    /// risk-gate-blocked tool call proceeds. Sugar over the `operator`
    /// risk-override lease; auto-expires. `neoth risk-confirm --ttl 10m`
    /// (add `--egress` to also lift an egress block).
    #[command(name = "risk-confirm")]
    RiskConfirm(risk_confirm::RiskConfirmArgs),

    /// Search the SQLite recall views for matching text.
    /// Runs the indexer once before querying.
    Recall(recall::RecallArgs),

    /// ARCH-05/SPEC-08 — score the legacy-AI→NEOTH recall-parity gate over grader
    /// sheets: inter-rater kappa + kappa-adjusted weighted-harmonic parity +
    /// per-query CRITICAL divergences (emits `0x3E`). Exits non-zero on FAIL.
    /// `recall-score --grades a.jsonl --grades b.jsonl [--goldset g.jsonl]`.
    RecallScore(recall_score::RecallScoreArgs),

    /// Check or apply updates for NEOTH-managed CLIs (claude-cli, antigravity-cli, codex).
    ///
    /// `--check` (default) probes installed vs. latest versions and prints a report.
    /// `--apply` runs `npm install -g <pkg>@latest` for each component that needs it.
    /// `--list` prints the static list of components NEOTH knows.
    Update(update::UpdateArgs),

    /// MAR-02 — DAU-friendly release signing. `keygen` mints the project signing
    /// keypair in-process (no `minisign` tool); `sign` produces a `.minisig` the
    /// updater verifies; `pubkey` reprints the public key for CI.
    Release(release::ReleaseArgs),

    /// MV-01b #3 — install/remove the OS-native process supervisor
    /// (systemd user unit / launchd LaunchAgent / Windows Task) that
    /// keeps `neoth serve` running + auto-restarts it so self-update can
    /// activate a new binary. `neoth supervisor loop` is the built-in
    /// restart wrapper the Windows task targets. User-scoped, no
    /// root/admin.
    Supervisor(supervisor::SupervisorArgs),

    /// List + validate scheduled jobs defined in `~/.neoth/jobs.yaml`.
    ///
    /// `--list` (default) shows job id, name, enabled flag, next-fire UTC + cron expr.
    /// `--validate` parses + cron-validates without printing the table.
    Jobs(jobs::JobsArgs),

    /// V11 coding workflow — autonomous software-engineering entry point.
    ///
    /// `neoth code "Add dark mode toggle"` opens a kanban session,
    /// asks the Cerebellum hemisphere to decompose the prompt into
    /// atomic tasks, heuristically classifies each as Fast (Left) or
    /// Deep (Right), and prints the resulting task list. Pick #5b per
    /// `PLAN/SPEC_coding_workflow.md` — closes the v1.0 ship-blocker
    /// chain.
    Code(code::CodeArgs),

    /// V11 coding workflow — operator-facing kanban CLI.
    ///
    /// Subcommands: `list` / `show <session>` / `task <task>` /
    /// `move <task> <status>` / `assign <task> <hemisphere> [--worker NAME]` /
    /// `comment <task> "body" [--author NAME]` / `archive <session>` /
    /// `watch`. Maps the Hermes-adapted 5-column board (BACKLOG / TODO
    /// / IN_PROGRESS / REVIEW / DONE) onto NEOTH's `idx_kanban_*`
    /// tables. Pick #5a per `PLAN/SPEC_coding_workflow.md` build order.
    Kanban(kanban::KanbanArgs),

    /// View or set the operator autonomy level (`strict | standard | elevated
    /// | full | custom`) in freedom.yaml. `show` prints the current level + the
    /// operating mode; `set <level>` persists a raw level; `gated` / `full-auto`
    /// are the headline operating-mode switches.
    Autonomy(autonomy::AutonomyArgs),

    /// Shortcut for `neoth autonomy full-auto` (GOLD-FEAT-01): flip NEOTH into
    /// FULL-AUTO mode in one word — autonomy `full` + the entire skill library
    /// routed proactively. The irreducible security floor still holds
    /// (self-replace / patch-apply / dangerous targets stay gated; revoked &
    /// unsigned plugins stay blocked). Switch back with `neoth autonomy gated`.
    Sudomode,

    /// GOLD-ADOPT-16 — declarative parametrized recipe templates. `recipe run
    /// <file|deeplink> --param k=v` renders a typed-parameter prompt template +
    /// runs it through the chat pipeline; `list` / `validate` / `share` (base64
    /// `neoth://recipe/…` deeplink) round out the surface.
    Recipe(recipe::RecipeArgs),

    /// Compose dreams now (SPEC-12 / R-02): `dream now` runs one dreaming pass
    /// over the recent window on-demand — embed + cosine-cluster the window's
    /// episodes into themed Dream records under `~/.neoth/dreams/` — instead of
    /// waiting for the nightly cron. Emits `0xF4 DREAM_COMPOSED`.
    Dream(dream::DreamArgs),

    /// Recipient-encrypted, operator-signed memory bundles (A3-01):
    /// `transfer export --dest <x25519_pubkey_b64>` seals the last N days of
    /// hot-tier memory (ephemeral X25519 ECDH → AES-256-GCM, ed25519-signed,
    /// size-capped, `0xF5`-audited); `verify` / `inspect` / `import` handle a
    /// received bundle. Share your receiving key via `neoth identity pubkey`.
    Transfer(transfer::TransferArgs),

    /// Cross-channel identity (SPEC-11): `identity list` shows each resolved
    /// person (UUID v7) + their channel aliases; `identity merge <keep> <fold>`
    /// unifies two identities the resolver minted separately. Identities are
    /// produced automatically as channel messages arrive.
    Identity(identity::IdentityArgs),

    /// Manage `credentials.yaml`: `list` shows which credential keys are set
    /// (NAMES only, never values); `import --file <path>` merges a
    /// credentials.yaml-shaped file in (set fields overwrite; absent fields
    /// untouched). Never prints secret values.
    Credential(credential::CredentialArgs),

    /// Inspect the n8n integration (READ-ONLY): `status` reports the webhook
    /// base URL n8n POSTs to + whether the `n8n` binary is on PATH;
    /// `workflows` lists the NEOTH starter workflows bundled in the binary.
    N8n(n8n::N8nArgs),

    /// Fire a scheduled job NOW, out of band of the daemon scheduler:
    /// `cron run <id>` loads jobs.yaml, runs the job through the configured
    /// provider (real call + delivery), writing the same WAL frames the
    /// scheduler does. Refused while `neoth serve` owns the WAL.
    Cron(cron::CronArgs),

    /// Launch the NEOTH desktop GUI (`neothd-gui`). Thin launcher: resolves
    /// the separate GUI binary (next to `neoth`, else via PATH) and spawns it.
    /// `--locate` resolves + prints the path without launching. Prints the
    /// install command if the GUI binary isn't present.
    Gui(gui::GuiArgs),

    /// Persistent NDJSON request/response channel for `neothd-gui`
    /// (B — persistent-stdio-stream, Session 30). The GUI holds this
    /// process open and sends `{"id":N,"method":"board"}` lines on
    /// stdin, reading one JSON board snapshot per line on stdout —
    /// collapsing the previous 4-subprocess-per-2s-tick board refresh
    /// into one warm in-process query. READ-ONLY (board queries only);
    /// mutations stay on their gated subprocess paths. Not intended for
    /// direct operator use. See `cli/gui_stream.rs`.
    #[command(hide = true)]
    GuiStream(gui_stream::GuiStreamArgs),

    /// Inspect the assembled NEOTH.md operator context.
    ///
    /// `--show` (default) renders the full assembled context with attribution.
    /// `--paths` lists just the source files. `--size` shows per-block byte sizes.
    Memory(memory::MemoryArgs),

    /// Ctx-mode parity — persistent indexed knowledge with hybrid FTS5 search.
    ///
    /// Modes: `--search "q"`, `--index <path>`, `--index-stdin --label X`,
    /// `--stats`, `--doctor`, `--purge --label/--category/--all`.
    Ctx(ctx::CtxArgs),

    /// List installed skills + probe the router with a test message.
    ///
    /// `--list` (default) shows id / enabled / keyword count / description.
    /// `--test "msg"` runs the keyword router and prints the match.
    /// `--install <path>` copies a local skill dir into ~/.neoth/skills/ (QM-11).
    /// `--uninstall <id>` removes ~/.neoth/skills/<id>/ (QM-11).
    #[command(visible_alias = "skill")]
    Skills(skills::SkillsArgs),

    /// QM-3 mode-registry surface — list / show / match operator-facing
    /// view of every named mode the bundled + user-installed skills ship.
    ///
    /// Subcommands: `list`, `show <id>`, `match "<text>"`. Composes with
    /// QM-3 ModeRegistry foundation + QM-23 academic modes.
    Mode(mode::ModeArgs),

    /// NOOB-UX-2 glossary screen. `neoth glossary` prints the
    /// operator-readable cheat sheet for NEOTH-specific terms
    /// (plugin / channel / council / provider / WAL / autonomy /
    /// hemisphere / skill / mode / groundtruth / profile).
    ///
    /// `--term <name>` filters to a single term by case-insensitive
    /// substring match.
    Glossary(glossary::GlossaryArgs),

    /// L-08 privacy audit. `neoth privacy audit` reports — before
    /// you send a prompt — whether the next call hits a cloud
    /// provider, whether profile-learning is on, which channels are
    /// configured, and how WAL frames are sealed.
    ///
    /// Pure read-only; no network, no mutation.
    Privacy(privacy::PrivacyArgs),

    /// NOOB-UX-5 first-launch tour. `neoth tour` walks the operator
    /// through chat / memory / consent / privacy-audit / where-to-go.
    ///
    /// `--step <id>` jumps to a single stop (`chat` / `memory` /
    /// `consent` / `audit` / `next`).
    Tour(tour::TourArgs),

    /// Manage hard-stored ground-truth facts (Phase 28c R-24).
    ///
    /// Subcommands: `list [--scope global]`, `add <statement> [--scope global]`,
    /// `revoke <id>`. Facts are decay-immune; they always surface in recall
    /// before any episodic row.
    Groundtruth(groundtruth::GroundtruthArgs),

    /// Opt-in anonymous version-check telemetry (E-18 Workstream N).
    ///
    /// Subcommands: `status` (default) / `preview` / `on` / `off` /
    /// `send-now [--force]`. Default state is OFF. The opt-in payload
    /// is `{neoth_version, os, arch, anonymous_id (SHA-256 prefix)}` —
    /// nothing else. Endpoint pinned to `https://telemetry.neoth.dev/v1/ping`;
    /// operator override via `freedom.yaml::telemetry.endpoint`.
    Telemetry(telemetry::TelemetryArgs),

    /// Architecture Decision Records — list / extract. Phase 31 R-21.
    ///
    /// Subcommands: `list`, `extract <path>`.
    Adr(adr::AdrArgs),

    /// Write a tar.gz backup of `~/.neoth/` state. Phase 33c BS-2.
    Backup(backup::BackupArgs),

    /// Paperless OCR ingest + consult. Subcommands: `ingest`, `consult`.
    /// Operator surface for the SC-16/PL-02/PL-03 vertical slice.
    Paperless(paperless::PaperlessArgs),

    /// Proactive proposal management (OB-03). Subcommands: `list`,
    /// `accept`, `reject`, `show`, `sync-vault`. NEOTH NEVER edits
    /// operator CONFIG behind their back — for config/cron proposals
    /// `accept` only flips status + the operator copy-pastes the draft
    /// YAML into the live config + runs `neoth reload`. A `kind=Skill`
    /// proposal (KF-04 idle forge) is the exception: `accept` ADOPTS it,
    /// writing the manifest live to `~/.neoth/skills/<id>/` (additive +
    /// the skill system still gates loading).
    Proactive(proactive::ProactiveArgs),

    /// Webhook HTTP server. Subcommand: `serve`. Starts the
    /// `paperless::webhook_server` so n8n + future MCP plugins can
    /// drive the paperless slice via real HTTP requests. Required
    /// `--token` (or `NEOTH_TOKEN` env) for Bearer auth on every
    /// non-healthz route; refuses to start unauthenticated unless
    /// `--allow-no-auth` is explicitly passed.
    Webhook(webhook::WebhookArgs),

    /// U-01..U-04 updater status + check entry. Subcommands:
    /// `status`, `check`. Renders the most recent
    /// `UpdaterTaskResultPayload`s (the WAL 0x45 frames) as a
    /// readable table. The actual update pipeline (U-01 binary
    /// self-update, U-02 skills+plugins, U-03 CLI versions) wires
    /// in follow-up commits — today's surface is the status view.
    Updater(updater::UpdaterArgs),

    /// W-05b — package-manager fallback chain runner. `--dry-run`
    /// (default) prints the per-pkg-manager argv preview the
    /// wizard's step6h already shows. `--execute` actually invokes
    /// the chain (winget→choco / apt→dnf→pacman / brew) until one
    /// handle succeeds. Operator-explicit because the execute
    /// path runs sudo apt install / winget install on the host.
    Installer(installer::InstallerArgs),

    /// Pick #37 (Session 14, Agent #4 design-consensus): trigger the
    /// running `neoth serve` daemon to re-read `freedom.yaml` and
    /// atomically swap its live `Arc<FreedomConfig>` via `arc-swap`.
    /// Touches a sentinel file `~/.neoth/.reload-requested`; the
    /// daemon polls for it on every ingress tick. Immutable fields
    /// (`operator_id`, `provider_kind`, `telegram_user_id`) cause a
    /// `CONFIG_RELOAD_REJECTED` audit frame + the prior config stays
    /// live. Tunable fields (`council.*`, `code_map.*`,
    /// `claude_cli.tmux.*`, autonomy level, …) reload without a
    /// daemon restart.
    Reload(reload::ReloadArgs),

    /// Restore a previously-written backup into `~/.neoth/`.
    Restore(backup::RestoreArgs),

    /// Verify HMAC compaction markers across the WAL. Phase 33b SP-2.
    /// Reads every segment, recomputes the tag over each window, and
    /// reports any mismatches.
    Verify(verify::VerifyArgs),

    /// GR-03 — one read-only view of NEOTH's trust posture: the live
    /// autonomy level + what it gates, the HMAC-chained WAL ledger size
    /// (+ optional `--verify-chain` integrity check), and which recovery
    /// levers are armed right now. Ties together `verify`/`wal`/`autonomy`/
    /// `recover` without mutating anything.
    Trust(trust::TrustArgs),

    /// EM-01b — inbound email. `fetch` pulls newest UNSEEN inbox messages
    /// over IMAP (non-destructive `BODY.PEEK[]`) and triages each through
    /// the sanitizer→threat pipeline. Live socket needs the `imap_fetch`
    /// build feature; `--dry-run` works on every build.
    Email(email::EmailArgs),

    /// EM-02b — CalDAV calendar. `list` reports VEVENTs in the configured
    /// collection; `add` PUTs a new event (gated + audited like every external
    /// write). Uses the same `caldav_{url,username,password}` as `neoth todo`.
    Calendar(calendar::CalendarArgs),

    /// CH-13 / F4-01 — Ecology self-adaptation diagnostics. `correlation`
    /// reports providers that won many consecutive outer-council debates (a
    /// low-dissent fitness signal). Read-only + deterministic.
    Ecology(ecology::EcologyArgs),

    /// SC-02 — named checkpoints over the rollback snapshot primitive.
    /// `save <label>` tags the most recent pre-mutation snapshot; `list`
    /// shows them; `restore <label>` resolves the name + delegates to the
    /// rollback `apply` path.
    Checkpoint(checkpoint::CheckpointArgs),

    /// Round-3 v0.4 SC-04 — operator-facing security posture
    /// aggregator. `neoth security audit` runs every available
    /// security check (HMAC key + WAL segment health + memory drift
    /// + credential sidecar) and prints a pass/warn/fail checklist.
    /// Exit code 1 iff any check FAILed; warnings don't change exit.
    Security(security::SecurityArgs),

    /// Daemon-state snapshot — WAL bytes, tier counts, channels, autonomy.
    /// Phase 33c BS-1. Pure read, no IPC, no daemon required.
    Status(status::StatusArgs),

    /// Consolidated hardware probe — CPU + RAM + accelerator (CUDA / Metal
    /// / OpenVINO / CPU) + ffmpeg/CLI presence + cached model detection.
    /// Drives the onboarding wizard's "this is what your machine can do"
    /// screen. `--output json` for scripting.
    Hardware(hardware::HardwareArgs),

    /// Manage the local model caches under `~/.neoth/models/`.
    ///
    /// `list` shows every known model + cache status; `pull <name>`
    /// downloads artifacts for `clip` / `whisper`; `prune <name>`
    /// deletes a model directory. Operators run `pull` once after
    /// `neoth init` so the first media-extract doesn't block on a
    /// multi-GiB HF download.
    #[command(visible_alias = "model")]
    Models(models::ModelsArgs),

    /// AI code review (GOLD-ADOPT-15) — wraps OpenCodeReview (`ocr`).
    ///
    /// No flags reviews the working-tree changes; `--from/--to` reviews a
    /// branch against its base; `--commit <sha>` a single commit. `--output
    /// json` emits machine-readable findings. OCR keeps its own LLM config
    /// (`ocr config`); NEOTH only invokes it.
    Review(review::ReviewArgs),

    /// Goal/Grind dispatch-loop nudges (GOLD-ADOPT-22).
    ///
    /// `show` prints the active goal + grind (a live grind is loudly flagged);
    /// `set <text>` / `grind <text>` arm them; `off` clears both. A grind makes
    /// the model keep working every turn until the iteration cap — clear it when
    /// the objective is done.
    Goal(goal::GoalArgs),

    /// Multimodal asset ingest pipeline.
    ///
    /// Detect kind from file extension, route through the matching
    /// extractor (PDF / image / audio / video), persist any produced
    /// CLIP embedding into `idx_embedding`. Prints a JSON or table
    /// report of the extracted text + metadata. R-9 Phase 2b.
    Ingest(ingest::IngestArgs),

    /// Inspect + test the Hysteria encrypted-egress transport (R-3).
    ///
    /// `status` prints the current freedom.yaml::hysteria config + binary
    /// location. `render-config` writes the YAML the subprocess would
    /// receive. `test` TCP-probes the local SOCKS5 port. Daemon
    /// spawns the subprocess automatically on `neothd serve`.
    Hysteria(hysteria::HysteriaArgs),

    /// Mirror the session archive into the operator's cloud-client
    /// local folder (R-8). NEOTH writes into `<dest>/<subdir>/`; the
    /// cloud vendor's desktop client (Dropbox / GDrive / OneDrive /
    /// iCloud) handles the actual upload. `status` shows the wired
    /// destination + last sync state, `sync` runs a pass right now.
    Cloud(cloud::CloudArgs),

    /// Cluster status + routing-plan rehearsal (R-7).
    ///
    /// v0.1.x is single-node by design; the Hyperswarm transport that
    /// would discover peers is gated by R-A1. `status` shows what the
    /// daemon would report today, `plan` runs the `LocalOnly` /
    /// `LeastLoaded` policies against a synthetic peer table.
    #[cfg(feature = "cluster")]
    Cluster(cluster::ClusterArgs),

    /// Inspect the Ouro thinking-models provider (O-3).
    ///
    /// `list` enumerates every supported ByteDance Ouro checkpoint
    /// (1.4B / 2.6B × base / -Thinking) with size + thinking-flag +
    /// recommended-use hint. `status` reports the operator's
    /// currently-configured Ouro state from freedom.yaml.
    Ouro(ouro::OuroArgs),

    /// Estimate the cost of a provider call BEFORE dispatching it (C-14).
    ///
    /// Dry-run only — no provider is invoked. Reports projected token
    /// count + euro cost for the configured provider/model (or
    /// overrides). Addresses the reddit "$131/day surprise bill"
    /// failure mode by making cost explicit before the operator
    /// commits.
    Cost(cost::CostArgs),

    /// Fetch a URL + return its text content (A-21).
    ///
    /// HTTP GET via the `providers::http_client` (so Hysteria proxy
    /// is honoured) + HTML→text extraction for `text/html` responses.
    /// Other content types return their byte count without conversion.
    Fetch(fetch::FetchArgs),

    /// Search ArXiv for papers (A-24).
    ///
    /// Public API, no key required. Use `neoth fetch <pdf_url>` on a
    /// result to pipe the paper through the PDF extractor + into
    /// recall via `neoth ingest`.
    Arxiv(arxiv::ArxivArgs),

    /// Web search via Brave / Tavily (A-20).
    ///
    /// API key from `--api-key` flag, `NEOTH_WEB_SEARCH_KEY` env, or
    /// `credentials.yaml::web_search_key`. Returns up to N hits.
    Search(search::SearchArgs),

    /// GitHub workflow shim — wraps the operator's `gh` CLI (A-3 + A-4).
    ///
    /// `issues`, `issue-create`, `prs`, `pr-view`, `pr-review`. Uses
    /// the operator's existing gh auth (OAuth + scopes already
    /// configured). NEOTH never touches the token directly.
    Github(github::GithubArgs),

    /// Slack pre-flight (A-7). `test` validates xoxb + xapp tokens by
    /// calling `auth.test` + `apps.connections.open` and reports the
    /// WSS URL Phase-2 socket-mode loop will dial.
    Slack(slack::SlackArgs),

    /// Todoist task management (TD-01). `list` / `add <content>` /
    /// `close <id>` via the Todoist REST v2 API. Token from `--token`,
    /// `credentials.yaml::todoist_token`, or `NEOTH_TODOIST_TOKEN`.
    Todo(todo::TodoArgs),

    /// SL-01a — capability leases. Grant a paired peer or a plugin a
    /// TTL-bounded scoped capability (`grant <to> <scope> --ttl 1h`),
    /// `list` active grants, or `revoke <id>`. Each mutation is audited
    /// (`neoth wal show --type lease_granted`). Foundation for cluster
    /// task delegation (SL-01) + proactive bounded writes (G-01).
    Lease(lease::LeaseArgs),

    /// G-03 — `feedback summary [--window 7d]`: aggregate the operator
    /// self-correction (`0xBB`) signals into an actionable report (count, top
    /// correction patterns, pressure level). The consumer side of the
    /// self-correction loop; the same aggregate drives the profile-adapt cron's
    /// sustained-pushback self-dev proposal.
    Feedback(feedback::FeedbackArgs),

    /// `fs read <path>` — read a file through the PC-01 OS-tool gate:
    /// allowlist (`freedom.yaml::tools.os.allowed_paths`, default deny-all) +
    /// autonomy gate + WAL audit (`0xA8`/`0xA9`). The gated alternative to an
    /// ungated filesystem read.
    Fs(fs::FsArgs),

    /// `os launch <program>` — launch a program through the PC-01 OS-tool gate:
    /// exec-allowlist (`freedom.yaml::tools.os.allowed_exec_paths`, exact
    /// canonical match, default deny-all) + autonomy gate (Full-only auto-allow)
    /// + WAL audit (`0xAC`/`0xAD`). No arguments, no shell. The gated
    /// alternative to an ungated process spawn.
    Os(os::OsArgs),

    /// Text-to-speech synthesis (A-45). `speak` writes audio bytes to
    /// a file via ElevenLabs (cloud) or piper-rs (Phase 2 local).
    Tts(tts::TtsArgs),

    /// Run operator health checks (freedom/credentials/db/wal/hmac/quota/...).
    /// Exit code non-zero on any FAIL. CI-friendly: `neoth doctor --quiet`.
    Doctor(doctor::DoctorArgs),

    /// HO-07 alert sidecar summary. `status` reads the WAL + crash.log and
    /// prints a 3-row table of WAL-CRC / crash / channel-silence alert counts.
    /// Exit code 1 when any alert fired in the look-back window.
    Monitor(monitor::MonitorArgs),

    /// Apply schema migrations to `~/.neoth/views.db`. `neoth serve` runs
    /// migrations automatically on startup; this command exposes them
    /// offline + supports `--dry-run` and `--to <version>`.
    Migrate(migrate::MigrateArgs),

    /// HMAC key management — show / rotate / list archived keys. Phase 33b
    /// SP-2 follow-up. Rotation is non-destructive: archived keys still
    /// verify historical compaction markers.
    Keys(keys::KeysArgs),

    /// Browse the WAL event-type registry. Self-documenting audit trail —
    /// `neoth events` lists every code NEOTH writes, `--code 0xNN` looks
    /// up a single byte, `--band 0x90` filters to memory-tier events.
    Events(events::EventsArgs),

    /// Inspect the live SQLite schema in `~/.neoth/views.db`. Lists tables +
    /// row counts; `--columns` shows the PRAGMA table_info per table.
    Schema(schema::SchemaArgs),

    /// Read-only WAL segment inspector. `stats <file>` counts frames per
    /// event-type; `show <file>` pretty-prints frames (offset, code,
    /// importance, ts_ns, payload hash). Works on backups too.
    Wal(wal::WalArgs),

    /// Emit a shell-completion script. `neoth completions zsh > _neoth`,
    /// `neoth completions bash > /etc/bash_completion.d/neoth`, etc.
    Completions(completions::CompletionsArgs),

    /// GDPR-style operator data export — JSONL or markdown dump of every
    /// row NEOTH stores about the operator, plus a copy of the archive.
    /// Phase 33c BS-8.
    Export(export::ExportArgs),

    /// One-way sync of the session archive into an Obsidian vault.
    /// Phase 13 R-5. Idempotent — re-runs skip unchanged files.
    Obsidian(obsidian::ObsidianArgs),

    /// Inspect the user profile materialised from `idx_profile`
    /// (Phase 2 SPEC_proactive_learning §1). `show [--field X]` lists
    /// every applied claim; `summary` collapses to one row per field
    /// — highest-confidence non-superseded claim. Read-only.
    Profile(profile::ProfileArgs),

    /// Per-provider quota visibility — show backoff windows + daily counters,
    /// reset a provider, record an estimated cap.
    ///
    /// Backed by `~/.neoth/quota.json`. Updated by the chat dispatcher
    /// whenever a remote provider returns HTTP 429. Council-budget commands
    /// (`set max_debates_per_day`, …) ship later, gated by the council
    /// module landing. See `PLAN/SPEC_council_governance.md` §2.4.
    Quota(quota::QuotaArgs),

    /// Inspect TOML hooks loaded from `~/.neoth/hooks/*.toml` (Phase 29 R-15).
    ///
    /// `list` shows every parsed hook grouped by stage. `validate` parses
    /// each file + compiles the matcher regex so bad configs fail before
    /// the daemon picks them up at request time.
    Hooks(hooks::HooksArgs),

    /// Inspect sub-agents loaded from `~/.neoth/agents/*.toml` + built-ins
    /// (code-reviewer, security-reviewer, planner, critic).
    ///
    /// `list` shows every agent with source + description. `show <name>`
    /// dumps the full system prompt so operators see exactly what a
    /// `/agent <name>` dispatch will activate.
    Agents(agents::AgentsArgs),

    /// Inspect slash commands loaded from `~/.neoth/commands/*.toml` plus
    /// the built-ins (`/help`, `/recall`, `/status`, ...).
    ///
    /// `list` shows every command with source + description. `show <name>`
    /// dumps the prompt template + help text so operators see what a
    /// `/<name> args` invocation will render.
    Slash(slash::SlashArgs),

    /// Inspect operator customisation loaded from `~/.neoth/tweaks.toml`
    /// (Phase 32 R-20). `show` dumps statusline / theme / model default /
    /// persona override + the prompt-snippet list. `snippet <id>` renders
    /// one named snippet so it can be inspected or copied.
    Tweaks(tweaks::TweaksArgs),

    /// Inspect the autonomy-gate decision matrix (Phase 28b R-23).
    /// `show [--level X]` prints the active level + per-action decisions
    /// across all 5 levels (strict / standard / elevated / full / custom).
    /// `check <action>` runs a single permission evaluation against the
    /// configured level for any of the 8 `Action` variants.
    Permissions(permissions::PermissionsArgs),

    /// Test the Schicht-0 mirror-refusal detector against arbitrary
    /// text. `classify <text>` runs the deterministic classifier;
    /// `patterns` dumps the pattern dictionaries the classifier uses.
    Refusal(refusal::RefusalArgs),

    /// Manage first-run outbound-LLM consent (V03-08). `list` shows recorded
    /// grants, `show <provider>` reports state for one provider,
    /// `grant <provider>` records consent, `revoke <provider>` removes it.
    /// Cloud-bound provider calls bail until consent is recorded.
    Consent(consent::ConsentArgs),

    /// LLM-provider model catalog (K-Models-Discovery, Session 14). `refresh`
    /// queries every configured provider's list-models endpoint + caches
    /// results at `~/.neoth/models_catalog.json`. `list` / `show` print
    /// cached entries. `defaults` reports the recommended model per
    /// provider — the wizard reads this on next `neoth init` run. `clear`
    /// wipes the cache to force a full rediscovery.
    Catalog(catalog::CatalogArgs),

    /// Repository code-map (K-Repo-Map Phase 1, Session 14 Pick #13). `scan`
    /// walks the operator's project root, classifies files by language,
    /// counts LOC + bytes. Honours .gitignore / .neothignore. Phase 2
    /// adds tree-sitter symbol extraction; Phase 3 persists into a
    /// `~/.neoth/code_map.db` SQLite for recall integration.
    CodeMap(code_map::CodeMapArgs),

    /// Council (smartest-wins) configuration + introspection (Pick #14,
    /// Session 14). `show` prints the active config block; `tune`
    /// atomically mutates it (`--selection-mode`, `--self-reflect`,
    /// `--refine-threshold`, `--max-calls`, `--daily-usd-cap`);
    /// `weights` inspects the memory-routing acceptance history per
    /// `(topic_hash, hemisphere_role)` from
    /// `~/.neoth/routing_weights.json`.
    Council(council::CouncilArgs),

    /// B-Rollback / CDX-02: query pre-mutation snapshots captured in
    /// the WAL. `list` walks every `*.wal` segment and renders the
    /// `PRE_MUTATION_SNAPSHOT` (0xF2) frames so operators see which
    /// mutations were captured + when. Per-MutationKind restoration
    /// dispatcher ships in a follow-up.
    Rollback(rollback::RollbackArgs),

    /// Model Context Protocol (MCP) client operations. `list` shows
    /// configured servers from `~/.neoth/mcp_servers.yaml`; `tools
    /// <server>` spawns the server + dumps its tool catalogue; `call
    /// <server> <tool> [--args JSON]` invokes one tool.
    Mcp(mcp::McpArgs),

    /// Per-hemisphere provider configuration (Left/Right/Cerebellum).
    /// `show` displays the current binding; `set --role X --provider Y`
    /// mutates `freedom.yaml::inference.<role>` atomically; `test --role X`
    /// builds the adapter without making a live LLM call.
    /// See `PLAN/SPEC_hemisphere_provider_selection.md`.
    Hemispheres(hemispheres::HemispheresArgs),

    /// QM-9 Phase 1: render the persisted usage log as a human-readable
    /// or JSON rollup. Aggregates the last 24h by default; `--days N`
    /// widens the window; `--since-unix … --until-unix …` pins an
    /// explicit range. Source files: `~/.neoth/usage/YYYY-MM-DD.jsonl`.
    Usage(usage::UsageArgs),

    /// QM-8 Phase 1: named provider+config preset bundles.
    /// `list` enumerates saved bundles; `show <name>` dumps one; `activate
    /// <name>` marks a bundle active; `deactivate` clears the marker;
    /// `delete <name>` removes (idempotent). Source: `~/.neoth/presets.yaml`.
    Preset(preset::PresetArgs),

    /// P-04 proactive self-development workflow. `review` lists pending
    /// proposals; `accept <id>` applies + emits 0x1D SELF_DEV_ACCEPTED;
    /// `decline <id>` records refusal + emits 0x1E SELF_DEV_DECLINED;
    /// `propose --from-profile <p>` generates proposals from a recorded
    /// BehaviouralProfile + emits 0x1C SELF_DEV_PROPOSED per proposal.
    /// Local store at `~/.neoth/self_dev/proposals.json`.
    SelfDev(self_dev::SelfDevArgs),

    /// LLM provider catalogue (C-1 Session 13). `list` enumerates all
    /// supported `InferenceProvider` variants + their implementation
    /// status + the OpenAI-compatible endpoint examples that the
    /// `openai_compat` adapter covers. `show <id>` prints details for
    /// one provider. `add` / `test` / `remove` are reserved for a
    /// future session — operators configure providers via `neoth init`
    /// or `neoth hemispheres set` today.
    #[command(visible_alias = "providers")]
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },

    /// UX-01 — discover messaging channels + how to connect them.
    /// Read-only post-wizard on-ramp: shows which channels (Telegram,
    /// Slack, WhatsApp, …) are connected + the steps to wire the rest.
    Connect(connect::ConnectArgs),

    /// UX-03 — show the last N state-mutating WAL frames + how to
    /// reverse each. Read-only discovery; the confirm-gated
    /// auto-reverser is a separate step.
    Undo(undo::UndoArgs),

    /// Manage channels (Telegram, WhatsApp, etc.) (Day 7+).
    #[command(hide = true, alias = "channels")]
    Channel {
        #[command(subcommand)]
        action: ChannelAction,
    },

    /// D-102 (Session 21) — WASM plugin activation management. Newly
    /// discovered plugins default to PENDING and don't auto-instantiate
    /// until the operator opts in. `list` shows discovered plugins +
    /// their state, `enable <id>` flips to Active, `disable <id>` to
    /// Disabled, `pending` lists only the Pending entries.
    Plugin(plugin::PluginArgs),
}

#[derive(Subcommand, Debug)]
pub enum ProviderAction {
    /// Add a new LLM provider (reserved — use `neoth init`)
    Add,
    /// List every supported LLM provider with status + compat-endpoint examples.
    List,
    /// Show details for one provider by id (e.g. `claude_cli`, `openai_compat`).
    Show { provider: String },
    /// List well-known OpenAI-compatible endpoints (DeepSeek, xAI Grok,
    /// Mistral, Moonshot Kimi, Z.ai GLM, Groq, OpenRouter, Together,
    /// Fireworks, Perplexity, plus local Ollama / LM Studio / vLLM)
    /// with their endpoint URL, default model, and doc link.
    Known,
    /// Show where a provider is wired into the hemispheres (live round-trip:
    /// `neoth hemispheres test --role <r> --live`).
    Test { provider: String },
    /// Remove a provider (reserved — use `neoth init`)
    Remove { provider: String },
}

#[derive(Subcommand, Debug)]
pub enum ChannelAction {
    /// Add a channel (e.g. telegram)
    Add { channel: String },
    /// List configured channels
    List,
    /// Test a channel connection
    Test { channel: String },
    /// Remove a channel
    Remove { channel: String },
}

/// Dispatch CLI commands.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    // Snapshot the global flags before destructuring `cli.command` so the
    // per-subcommand branches can copy them into their own ArgsArgs.
    let global_stream = cli.stream;
    let global_output = cli.effective_output();

    match cli.command {
        Commands::Init(args) => {
            init::run_init(args).await?;
        }
        Commands::Serve(args) => {
            serve::run_serve(args).await?;
        }
        Commands::Chat(mut args) => {
            args.stream = global_stream;
            chat::run_chat(args).await?;
        }
        Commands::RiskConfirm(mut args) => {
            args.output = global_output;
            risk_confirm::run_risk_confirm(args).await?;
        }
        Commands::FactCheck(mut args) => {
            args.output = global_output;
            fact_check::run_fact_check(args)?;
        }
        Commands::Recall(mut args) => {
            args.output = global_output;
            recall::run_recall(args).await?;
        }
        Commands::RecallScore(mut args) => {
            args.output = global_output;
            recall_score::run_recall_score(args).await?;
        }
        Commands::Update(mut args) => {
            args.output = global_output;
            update::run_update(args).await?;
        }
        Commands::Release(mut args) => {
            args.output = global_output;
            release::run_release(args)?;
        }
        Commands::Supervisor(mut args) => {
            args.output = global_output;
            supervisor::run_supervisor(args)?;
        }
        Commands::Jobs(mut args) => {
            args.output = global_output;
            jobs::run_jobs(args).await?;
        }
        Commands::Code(mut args) => {
            args.output = global_output;
            code::run_code(args).await?;
        }
        Commands::Kanban(mut args) => {
            args.output = global_output;
            kanban::run_kanban(args).await?;
        }
        Commands::Autonomy(args) => {
            autonomy::run_autonomy(args, global_output).await?;
        }
        Commands::Sudomode => {
            autonomy::run_autonomy(
                autonomy::AutonomyArgs {
                    action: autonomy::AutonomyAction::FullAuto,
                },
                global_output,
            )
            .await?;
        }
        Commands::Recipe(mut args) => {
            args.output = global_output;
            recipe::run_recipe(args).await?;
        }
        Commands::Cron(args) => {
            cron::run_cron(args, global_output).await?;
        }
        Commands::N8n(args) => {
            n8n::run_n8n(args, global_output)?;
        }
        Commands::Credential(args) => {
            credential::run_credential(args, global_output)?;
        }
        Commands::Dream(args) => {
            dream::run_dream(args, global_output).await?;
        }
        Commands::Transfer(args) => {
            transfer::run_transfer(args, global_output).await?;
        }
        Commands::Identity(args) => {
            identity::run_identity(args, global_output).await?;
        }
        Commands::Gui(args) => {
            gui::run_gui(args, global_output)?;
        }
        Commands::GuiStream(args) => {
            gui_stream::run_gui_stream(args).await?;
        }
        Commands::Memory(mut args) => {
            args.output = global_output;
            memory::run_memory(args).await?;
        }
        Commands::Ctx(mut args) => {
            args.output = global_output;
            ctx::run_ctx(args).await?;
        }
        Commands::Skills(mut args) => {
            args.output = global_output;
            skills::run_skills(args).await?;
        }
        Commands::Mode(mut args) => {
            args.output = global_output;
            mode::run_mode(args).await?;
        }
        Commands::Glossary(mut args) => {
            args.output = global_output;
            glossary::run_glossary(args)?;
        }
        Commands::Privacy(mut args) => {
            args.output = global_output;
            privacy::run_privacy(args).await?;
        }
        Commands::Tour(mut args) => {
            args.output = global_output;
            tour::run_tour(args)?;
        }
        Commands::Groundtruth(mut args) => {
            args.output = global_output;
            groundtruth::run_groundtruth(args).await?;
        }
        Commands::Telemetry(mut args) => {
            args.output = global_output;
            telemetry::run_telemetry(args).await?;
        }
        Commands::Adr(mut args) => {
            args.output = global_output;
            adr::run_adr(args).await?;
        }
        Commands::Backup(mut args) => {
            args.output = global_output;
            backup::run_backup(args).await?;
        }
        Commands::Paperless(args) => {
            paperless::run_paperless(args)?;
        }
        Commands::Proactive(args) => {
            proactive::run_proactive(args)?;
        }
        Commands::Webhook(args) => {
            webhook::run_webhook(args).await?;
        }
        Commands::Installer(args) => {
            installer::run_installer(args).await?;
        }
        Commands::Updater(args) => {
            updater::run_updater(args)?;
        }
        Commands::Reload(mut args) => {
            args.output = global_output;
            reload::run_reload(args).await?;
        }
        Commands::Status(mut args) => {
            args.output = global_output;
            status::run_status(args).await?;
        }
        Commands::Hardware(mut args) => {
            args.output = global_output;
            hardware::run_hardware(args).await?;
        }
        Commands::Models(mut args) => {
            args.output = global_output;
            models::run_models(args).await?;
        }
        Commands::Review(mut args) => {
            args.output = global_output;
            review::run_review(args).await?;
        }
        Commands::Goal(mut args) => {
            args.output = global_output;
            goal::run_goal(args).await?;
        }
        Commands::Ingest(mut args) => {
            args.output = global_output;
            ingest::run_ingest(args).await?;
        }
        Commands::Hysteria(mut args) => {
            args.output = global_output;
            hysteria::run_hysteria(args).await?;
        }
        Commands::Cloud(mut args) => {
            args.output = global_output;
            cloud::run_cloud(args).await?;
        }
        #[cfg(feature = "cluster")]
        Commands::Cluster(mut args) => {
            args.output = global_output;
            cluster::run_cluster(args).await?;
        }
        Commands::Ouro(mut args) => {
            args.output = global_output;
            ouro::run_ouro(args).await?;
        }
        Commands::Cost(mut args) => {
            args.output = global_output;
            cost::run_cost(args).await?;
        }
        Commands::Fetch(mut args) => {
            args.output = global_output;
            fetch::run_fetch(args).await?;
        }
        Commands::Arxiv(mut args) => {
            args.output = global_output;
            arxiv::run_arxiv(args).await?;
        }
        Commands::Search(mut args) => {
            args.output = global_output;
            search::run_search(args).await?;
        }
        Commands::Github(mut args) => {
            args.output = global_output;
            github::run_github(args).await?;
        }
        Commands::Slack(mut args) => {
            args.output = global_output;
            slack::run_slack(args).await?;
        }
        Commands::Todo(mut args) => {
            args.output = global_output;
            todo::run_todo(args).await?;
        }
        Commands::Calendar(mut args) => {
            args.output = global_output;
            calendar::run_calendar(args).await?;
        }
        Commands::Lease(mut args) => {
            args.output = global_output;
            lease::run_lease(args).await?;
        }
        Commands::Feedback(mut args) => {
            args.output = global_output;
            feedback::run_feedback(args).await?;
        }
        Commands::Fs(mut args) => {
            args.output = global_output;
            fs::run_fs(args).await?;
        }
        Commands::Os(mut args) => {
            args.output = global_output;
            os::run_os(args).await?;
        }
        Commands::Tts(mut args) => {
            args.output = global_output;
            tts::run_tts(args).await?;
        }
        Commands::Doctor(mut args) => {
            args.output = global_output;
            doctor::run_doctor(args).await?;
        }
        Commands::Monitor(args) => {
            monitor::run(args).await?;
        }
        Commands::Migrate(mut args) => {
            args.output = global_output;
            migrate::run_migrate(args).await?;
        }
        Commands::Keys(mut args) => {
            args.output = global_output;
            keys::run_keys(args).await?;
        }
        Commands::Events(mut args) => {
            args.output = global_output;
            events::run_events(args).await?;
        }
        Commands::Schema(mut args) => {
            args.output = global_output;
            schema::run_schema(args).await?;
        }
        Commands::Wal(mut args) => {
            args.output = global_output;
            wal::run_wal(args).await?;
        }
        Commands::Completions(args) => {
            completions::run_completions(args).await?;
        }
        Commands::Export(mut args) => {
            args.output = global_output;
            export::run_export(args).await?;
        }
        Commands::Obsidian(mut args) => {
            args.output = global_output;
            obsidian::run_obsidian(args).await?;
        }
        Commands::Restore(mut args) => {
            args.output = global_output;
            backup::run_restore(args).await?;
        }
        Commands::Verify(mut args) => {
            args.output = global_output;
            verify::run_verify(args).await?;
        }
        Commands::Trust(mut args) => {
            args.output = global_output;
            trust::run_trust(args).await?;
        }
        Commands::Email(mut args) => {
            args.output = global_output;
            email::run_email(args).await?;
        }
        Commands::Ecology(mut args) => {
            args.output = global_output;
            ecology::run_ecology(args).await?;
        }
        Commands::Checkpoint(mut args) => {
            args.output = global_output;
            checkpoint::run_checkpoint(args).await?;
        }
        Commands::Security(args) => {
            // SC-04: security audit aggregator has its own output
            // shape (checklist with status markers), so it doesn't
            // share the global_output channel-switch.
            security::run_security(args).await?;
        }
        Commands::Profile(mut args) => {
            args.output = global_output;
            profile::run_profile(args).await?;
        }
        Commands::Connect(mut args) => {
            args.output = global_output;
            connect::run_connect(args)?;
        }
        Commands::Undo(mut args) => {
            args.output = global_output;
            undo::run_undo(args)?;
        }
        Commands::Quota(mut args) => {
            args.output = global_output;
            quota::run_quota(args).await?;
        }
        Commands::Hooks(mut args) => {
            args.output = global_output;
            hooks::run_hooks(args).await?;
        }
        Commands::Agents(mut args) => {
            args.output = global_output;
            agents::run_agents(args).await?;
        }
        Commands::Slash(mut args) => {
            args.output = global_output;
            slash::run_slash(args).await?;
        }
        Commands::Tweaks(mut args) => {
            args.output = global_output;
            tweaks::run_tweaks(args).await?;
        }
        Commands::Permissions(mut args) => {
            args.output = global_output;
            permissions::run_permissions(args).await?;
        }
        Commands::Refusal(mut args) => {
            args.output = global_output;
            refusal::run_refusal(args).await?;
        }
        Commands::Consent(mut args) => {
            args.output = global_output;
            consent::run_consent(args).await?;
        }
        Commands::Catalog(mut args) => {
            args.output = global_output;
            catalog::run_catalog(args).await?;
        }
        Commands::CodeMap(mut args) => {
            args.output = global_output;
            code_map::run_code_map(args).await?;
        }
        Commands::Council(mut args) => {
            args.output = global_output;
            council::run_council(args).await?;
        }
        Commands::Rollback(mut args) => {
            args.output = global_output;
            rollback::run_rollback(args).await?;
        }
        Commands::Mcp(mut args) => {
            args.output = global_output;
            mcp::run_mcp(args).await?;
        }
        Commands::Hemispheres(mut args) => {
            args.output = global_output;
            hemispheres::run_hemispheres(args).await?;
        }
        Commands::Provider { action } => match action {
            ProviderAction::List => providers::run_list(&global_output)?,
            ProviderAction::Show { provider } => providers::run_show(&provider, &global_output)?,
            ProviderAction::Known => providers::run_known(&global_output)?,
            ProviderAction::Test { provider } => providers::run_test(&provider, &global_output)?,
            ProviderAction::Add | ProviderAction::Remove { .. } => {
                anyhow::bail!(
                    "`neoth provider {{add,remove}}` not in this release. Use \
                     `neoth init` (full wizard), `neoth hemispheres set`, or \
                     edit ~/.neoth/freedom.yaml. `neoth status` shows the \
                     active provider; `neoth provider list` enumerates every \
                     supported backend; `neoth provider test <id>` shows where \
                     a provider is wired."
                );
            }
        },
        Commands::Usage(args) => {
            let home = crate::config::FreedomConfig::default_neoth_home();
            usage::run(&home, args)?;
        }
        Commands::Preset(args) => {
            let home = crate::config::FreedomConfig::default_neoth_home();
            preset::run(&home, args).await?;
        }
        Commands::SelfDev(args) => {
            let home = crate::config::FreedomConfig::default_neoth_home();
            // CLI invocation runs without a live daemon writer; the
            // accept/decline/propose paths record locally + warn that
            // the matching WAL frames will land when the daemon picks
            // up the change on next start. Invocation from inside the
            // daemon supplies the writer via a different call path.
            self_dev::run(&home, args, None).await?;
        }
        Commands::Channel { action } => match action {
            ChannelAction::List => channel::run_list(&global_output)?,
            ChannelAction::Test { channel: ch } => channel::run_test(&ch, &global_output).await?,
            ChannelAction::Add { channel: ch } => channel::run_add(&ch, &global_output).await?,
            ChannelAction::Remove { channel: ch } => channel::run_remove(&ch, &global_output)?,
        },
        Commands::Plugin(mut args) => {
            args.output = global_output;
            plugin::run_plugin(args).await?;
        }
    }
    Ok(())
}
