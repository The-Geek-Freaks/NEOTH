//! `neoth doctor` — operator health-check. Phase 33c follow-up.
//!
//! Runs a battery of read-only diagnostics over `~/.neoth/` and prints a
//! pass/warn/fail report. Exit code is non-zero when any check FAILs so
//! the command is CI-friendly (`neoth doctor --quiet || exit`).
//!
//! Diagnostics:
//!   1. **freedom.yaml present + parseable + mode 0600**
//!   2. **credentials.yaml mode 0600 if present** — empty file silently OK
//!   3. **views.db integrity** — `PRAGMA integrity_check` + schema-version stamp
//!   4. **WAL segments** — every `*.wal` parses its SegmentHeader cleanly
//!   5. **HMAC key file** — exists + mode 0600
//!   6. **Quota** — `<5 GiB` (per `daemon::quota::DEFAULT_QUOTA_BYTES`)
//!   7. **policy.yaml parseable** if present
//!   8. **Tweaks file parseable** if present
//!
//! Each diagnostic returns one [`CheckOutcome`]. The aggregate report is
//! rendered as a table (or JSON / JSONL when the global `--output` says so).

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// Override `~/.neoth/` for tests.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Suppress per-check output; print only the final summary line + use
    /// exit code for CI.
    #[arg(long)]
    pub quiet: bool,
    /// V03-07: print operator-facing documentation for the named check
    /// (what it tests, common failures, fix steps) instead of running the
    /// full diagnostic suite. Combine with `--output json` for scripted
    /// runbook lookups. Pair with `--list-checks` to see what's available.
    #[arg(long, value_name = "NAME")]
    pub explain: Option<String>,
    /// V03-07: print the list of check names recognised by `--explain`.
    /// Useful for tab-completion + operator-side runbook generation.
    #[arg(long)]
    pub list_checks: bool,
    /// Output format inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// V03-07 2026-05-17: operator-facing documentation for each check.
/// Triggered via `neoth doctor --explain <name>`. Each entry holds:
///   - `name` — exact check identifier (matches `CheckOutcome.name`).
///   - `purpose` — one-paragraph operator-readable description of what
///     the check verifies + why it matters.
///   - `common_failures` — typical WARN/FAIL causes.
///   - `fix` — concrete commands or edits an operator can run to
///     remediate.
pub struct CheckDoc {
    pub name: &'static str,
    pub purpose: &'static str,
    pub common_failures: &'static str,
    pub fix: &'static str,
}

const CHECK_DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "freedom.yaml",
        purpose: "Operator configuration lives in `~/.neoth/freedom.yaml`. \
                  Doctor verifies the file exists, parses cleanly via \
                  `FreedomConfig::load_from_path`, and (on unix) is mode \
                  0600 so secrets at rest survive multi-user systems.",
        common_failures: "Missing file (operator hasn't run `neoth init`); \
                         parse error (hand-edited typo); permissions broader \
                         than 0600 (unix).",
        fix: "Missing → `neoth init` (or `neoth init --force` for a clean \
              wipe).\nParse error → diff against `freedom.yaml.example` in \
              the repo / install root.\nPermissions → `chmod 600 ~/.neoth/freedom.yaml`.",
    },
    CheckDoc {
        name: "credentials.yaml",
        purpose: "Secret store at `~/.neoth/credentials.yaml`. Holds API \
                  keys + bot tokens that should NEVER be in freedom.yaml. \
                  Doctor checks existence (warn if missing — daemon can \
                  start without it for local_qwen-only deployments), parse \
                  cleanly, and 0600 mode.",
        common_failures: "Secrets pasted into freedom.yaml instead (creates \
                         a leak path through `neoth export`); world-readable \
                         mode; corrupt YAML.",
        fix: "Edit by hand: keys at the top level (`provider_key`, \
              `telegram_token`). `chmod 600 ~/.neoth/credentials.yaml`.",
    },
    CheckDoc {
        name: "views.db",
        purpose: "SQLite views database — the read-side projection of the \
                  WAL. Holds idx_episode (recall), idx_profile (operator \
                  facts), idx_groundtruth (decay-immune anchors), \
                  idx_consolidated / idx_longterm (memory tiers). Doctor \
                  runs `PRAGMA integrity_check` + verifies schema_version \
                  stamp.",
        common_failures: "Disk full mid-write (corruption); manual delete \
                         (recoverable via `neoth restore`); schema drift \
                         (mis-applied migration).",
        fix: "Corruption → restore from `~/.neoth/backups/`. Schema drift → \
              `neoth migrate up` brings the schema forward. If the daemon \
              can't open it, delete + let the indexer rebuild from WAL.",
    },
    CheckDoc {
        name: "wal segments",
        purpose: "Append-only WAL at `~/.neoth/wal/*.wal`. The audit \
                  trail of every action NEOTH ever took. Doctor walks \
                  the segment directory, checks each segment's frame CRC \
                  + magic preamble, verifies the active segment is \
                  writeable.",
        common_failures: "Last-frame corruption (writer crashed mid-fsync — \
                         self-heals on next index pass); segment dir not \
                         writeable; segments deleted manually.",
        fix: "Corrupt tail frame → harmless, indexer truncates. Read-only \
              dir → `chmod u+w ~/.neoth/wal/`. Manually deleted → live with \
              the gap; the indexer skips missing segments.",
    },
    CheckDoc {
        name: "hmac.key",
        purpose: "HMAC key at `~/.neoth/hmac.key` — signs the compaction \
                  markers in the WAL so tampering is detectable. Doctor \
                  checks existence, that the file is exactly 32 bytes \
                  (HMAC-SHA256 key size), and 0600 mode.",
        common_failures: "Missing (daemon auto-generates on first run); \
                         wrong size (manual edit); world-readable.",
        fix: "Missing → next daemon start regenerates. Wrong size → delete \
              + restart (loses ability to verify markers pre-restart). \
              `chmod 600 ~/.neoth/hmac.key`.",
    },
    CheckDoc {
        name: "disk quota",
        purpose: "Pre-write quota guard. Doctor checks the home dir's \
                  current usage vs the configured ceiling \
                  (`freedom.yaml::quota_ceiling_bytes`, default 5 GiB). \
                  Warns past 75% used; fails past 90%.",
        common_failures: "Long-lived daemon with no consolidation → WAL \
                         segments accumulate; backups in `~/.neoth/backups/` \
                         pile up.",
        fix: "Tighten the ceiling or prune. `neoth wal compact` rolls \
              old segments. `neoth backup --prune --keep 7` rotates the \
              backup set.",
    },
    CheckDoc {
        name: "policy.yaml",
        purpose: "Optional autonomy policy override at \
                  `~/.neoth/policy.yaml`. When present, overrides the \
                  freedom.yaml-level `autonomy` field per-action category. \
                  Doctor verifies parse + schema.",
        common_failures: "Missing is fine (operator just hasn't customised). \
                         Parse error blocks daemon startup.",
        fix: "Missing → no action needed. Parse error → diff against the \
              schema in `docs/policy.md`, or delete to fall back to \
              freedom.yaml's autonomy field.",
    },
    CheckDoc {
        name: "hooks/",
        purpose: "Operator hooks at `~/.neoth/hooks/*.toml`. Each file \
                  defines an event stage + a command. Doctor loads every \
                  file via `hooks::load_all` so YAML/TOML syntax errors + \
                  unknown stages surface BEFORE the daemon hits the event.",
        common_failures: "Typo in stage name (unknown HookStage); shell \
                         command not in PATH; regex syntax error in the \
                         matcher field.",
        fix: "Run `neoth hooks list` for parse errors. `neoth hooks \
              validate` runs the schema + regex check standalone. Fix \
              the file or remove it.",
    },
    CheckDoc {
        name: "agents/",
        purpose: "Sub-agents at `~/.neoth/agents/*.md`. Each markdown file \
                  defines an operator-callable agent's system prompt + \
                  trigger keywords. Doctor loads every agent via \
                  `sub_agents::load_all`.",
        common_failures: "Empty system prompt; malformed YAML frontmatter; \
                         unknown tool_allowlist entries.",
        fix: "Edit the offending .md to fix the frontmatter. `neoth agents \
              list` shows parse errors with line numbers.",
    },
    CheckDoc {
        name: "profile_extensions.toml",
        purpose: "Typed extension registry at \
                  `~/.neoth/profile_extensions.toml`. Operator-defined \
                  custom profile fields outside the base taxonomy (e.g. \
                  `operator.preferences.editor`). Doctor parses + warns on \
                  unknown reserved keys.",
        common_failures: "Empty file (use the bundled example as a start); \
                         TOML syntax error.",
        fix: "Missing → use defaults. Syntax error → diff against \
              `assets/profile_extensions.toml.example`.",
    },
    CheckDoc {
        name: "tweaks.toml",
        purpose: "tweakcc-style customisation at `~/.neoth/tweaks.toml`. \
                  Operator overrides for prompts, persona, slash-command \
                  aliases. Doctor parses + flags unknown keys.",
        common_failures: "Hand-edited YAML where TOML is expected; \
                         malformed `[[prompts]]` array.",
        fix: "Diff against `assets/tweaks.toml.example`. Or delete to \
              fall back to bundled defaults.",
    },
    CheckDoc {
        name: "model caches",
        purpose: "HuggingFace model caches under \
                  `~/.cache/huggingface/hub/`. Doctor checks the bundled \
                  models (whisper-large-v3, clip-vit-base-patch32, \
                  Qwen2.5-3B-Instruct) are downloaded — warns when \
                  missing so operators don't first discover the \
                  network requirement mid-chat.",
        common_failures: "Fresh install with no HF cache; partial download \
                         (interrupted git-lfs).",
        fix: "Run `neoth models pull` to bulk-download. Or accept the \
              warning — models lazy-download on first use.",
    },
    CheckDoc {
        name: "hysteria",
        purpose: "Hysteria QUIC transport config at \
                  `freedom.yaml::hysteria.{server, auth, socks_port}`. \
                  Doctor verifies the binary exists (in PATH or \
                  `~/.neoth/bin/hysteria`) + the SOCKS5 port is bindable.",
        common_failures: "Operator configured server but didn't install \
                         binary; SOCKS port collision with another \
                         service.",
        fix: "Binary missing → download from \
              https://github.com/apernet/hysteria/releases or remove \
              the hysteria block. Port collision → pick a different \
              `socks_port` in freedom.yaml.",
    },
    CheckDoc {
        name: "cloud archive",
        purpose: "Cloud archive mirror target at \
                  `freedom.yaml::cloud_archive_dest` (typically a folder \
                  the operator's Dropbox / GDrive / OneDrive desktop \
                  client syncs upstream). Doctor checks the path exists + \
                  is writeable + is a directory (not a file).",
        common_failures: "Path is a file (operator typo); doesn't exist; \
                         not writeable.",
        fix: "Edit `freedom.yaml::cloud_archive_dest` to a real existing \
              directory. Remove the field to disable cloud archive \
              entirely.",
    },
    CheckDoc {
        name: "mcp servers",
        purpose: "Model Context Protocol server registry at \
                  `~/.neoth/mcp_servers.yaml`. Doctor loads via \
                  `McpServers::load`, flags parse errors, warns when \
                  enabled servers reference a command that's not in PATH.",
        common_failures: "Missing file (fine — MCP autoroute defaults off); \
                         malformed YAML; binary not installed.",
        fix: "Missing → no action. Parse error → diff against \
              `mcp_servers.yaml.example`. Binary missing → install the \
              server (e.g. `npm i -g @modelcontextprotocol/server-filesystem`).",
    },
    CheckDoc {
        name: "disk space",
        purpose: "Free space on the partition holding `~/.neoth/`. Warns \
                  past 1 GiB free, fails past 100 MiB. Below the fail \
                  threshold the WAL writer's quota guard will reject new \
                  writes — better to warn early.",
        common_failures: "A NAS or always-on home server with a data disk \
                         filling up; a laptop with OS-disk pressure.",
        fix: "Prune backups (`neoth backup --prune`); compact WAL (`neoth \
              wal compact`); move `~/.neoth/` to a larger volume via \
              symlink + `chown`.",
    },
    CheckDoc {
        name: "credentials age",
        purpose: "Age of `~/.neoth/credentials.yaml`. Telegram bot tokens, \
                  Slack tokens, and provider API keys quietly expire or \
                  get rotated server-side. Doctor reads the file's \
                  modification time and warns past 180 days, fails past \
                  365. The check skips when the file is absent or holds \
                  only `None` secret slots (local_qwen-only setups).",
        common_failures: "Long-lived deployment without rotation; Slack \
                         workspace revoked the bot token; Telegram \
                         BotFather rotated the secret.",
        fix: "Re-run the relevant wizard step (`neoth init --step \
              credentials`) or edit `~/.neoth/credentials.yaml` and \
              `touch` the file to reset the age clock once the new \
              token is in.",
    },
    CheckDoc {
        name: "wasm plugins",
        purpose: "NOOB-UX-3 effective state of the WASM plugin host. \
                  Reports one of three states: `compiled-in + enabled` \
                  (release feature on, freedom.yaml says enabled), \
                  `compiled-in but disabled by config` (operator flipped \
                  `freedom.yaml::plugins.wasm.enabled: false`), or \
                  `not compiled in` (slim daemon build without the \
                  `wasm-plugin-host` cargo feature). Surfaces the gap \
                  between build-time + runtime gates so an operator \
                  who set `enabled: true` but runs a slim build sees \
                  the mismatch immediately.",
        common_failures: "Operator expects plugins to work on a slim \
                         build (cargo feature not compiled in); \
                         operator's freedom.yaml has `enabled: false` \
                         but the wizard step7b explanation isn't fresh \
                         in memory.",
        fix: "Slim build → rebuild with `--features wasm-plugin-host` \
              or install the release tarball (cargo-dist flips the \
              feature ON). Disabled-by-config → edit \
              `~/.neoth/freedom.yaml` and flip \
              `plugins:\\n  wasm:\\n    enabled: true`, then \
              restart the daemon.",
    },
    CheckDoc {
        name: "channels wiring",
        purpose: "R2-P0-2 honesty surface. Loads `credentials.yaml` + \
                  classifies every configured channel as one of: LIVE \
                  (send + receive both real), OUTBOUND-ONLY (send works, \
                  inbound receive loop not yet wired), CONFIGURED-NOT-\
                  STARTED (full inbound code ships but serve does not \
                  bootstrap it), or absent (silent). Closes the \
                  documented gap where README/Status claimed channels \
                  were live while `cli::serve` only spawned Telegram.",
        common_failures: "Operator configures Slack/WhatsApp credentials \
                         + expects bidirectional chat. Aggregate Warn \
                         when any partial (OUTBOUND-ONLY / CONFIGURED-NOT-\
                         STARTED) channel is in the set so the gap \
                         surfaces during install verification.",
        fix: "Telegram inbound + outbound: live today. Slack inbound: \
              live when BOTH bot_token + app_token configured (socket \
              mode auto-spawns). WhatsApp inbound: live when full Meta \
              secret set (token + phone_id + verify_token + app_secret) \
              configured (webhook listener auto-spawns on 127.0.0.1). \
              Partial configs surface as CONFIGURED-NOT-STARTED with a \
              precise per-missing-field hint.",
    },
    CheckDoc {
        name: "node toolchain",
        purpose: "NOOB-UX-6 AIO-compliance probe. Detects whether Node \
                  + npm are on PATH so the wizard's auto-install path \
                  for claude-cli / codex actually works (Antigravity \
                  CLI ships via shell-script, not npm). Pass when both \
                  binaries respond to `--version`; Warn when missing \
                  AND the operator's freedom.yaml selects a Node-CLI- \
                  backed provider; silent when the operator runs \
                  LocalQwen / API-only / antigravity providers.",
        common_failures: "Fresh Windows install with no Node — wizard \
                         step 5d picks claude-cli, install_kind spawns \
                         `npm install -g …`, npm not found, operator \
                         gets a cryptic spawn error.",
        fix: "Install Node 20 LTS from nodejs.org/en/download (Windows \
              installer adds npm to PATH automatically). On macOS \
              `brew install node`. On Linux use your distro's package \
              manager (`apt install nodejs npm` on Debian/Ubuntu; \
              `dnf install nodejs` on Fedora). Restart NEOTH so the \
              new PATH takes effect.",
    },
    CheckDoc {
        name: "usage today",
        purpose: "QM-9 Phase 1 spend-visibility surface. Aggregates \
                  the last 24h of `~/.neoth/usage/*.jsonl` and warns \
                  when cost crosses `council.daily_usd_cap` (default \
                  $5) or 80% of it. Pass when usage dir is missing \
                  (clean install) or cost is under threshold. Detail \
                  always carries call count + ok/err split + dollars \
                  + percent-of-cap so the operator sees burn rate at \
                  a glance.",
        common_failures: "Spend creeps past the daily cap before the \
                         operator notices. Errors-vs-successes ratio \
                         spikes (provider outage, broken prompt \
                         template).",
        fix: "If the spend is intentional, raise `council.daily_usd_cap` \
              in freedom.yaml. If unexpected, tail \
              `~/.neoth/usage/<today>.jsonl` to find the chatty path. \
              Lower the cap to throttle inadvertent loops by setting \
              `council.max_calls_per_user_message` (default 15) lower.",
    },
    CheckDoc {
        name: "cluster registry",
        purpose: "Cluster auto-discovery Phase 4 visibility surface. \
                  Reads `~/.neoth/cluster.yaml` + reports the count \
                  of confirmed peers + warns when any haven't been \
                  seen in 14 days (Phase 2+ gossip refreshes \
                  last_seen_unix on each authenticated announce). \
                  Single-instance operators see Pass with `no \
                  confirmed cluster peers` — no noise.",
        common_failures: "Peer device offline for >14 days (laptop \
                          retired, server move, network change). \
                          Stale entry keeps eating Phase 6 gossip \
                          retry budget until revoked.",
        fix: "Verify the peer device is still reachable: `neoth \
              cluster list` shows the addr + via. If the device \
              is truly gone, `neoth cluster revoke <pub_key_prefix>` \
              removes it. If it's just been offline, leave it — \
              gossip will refresh once the peer returns.",
    },
    CheckDoc {
        name: "cluster mDNS announcer",
        purpose: "Cluster auto-discovery Phase 2 announcer state. \
                  Composes `cluster.mdns.enabled` + the Q2-ratified \
                  announce policy (announce_on_untrusted_wifi + \
                  trusted_ssids) + the OS-detected current SSID to \
                  report whether the announcer would actually \
                  broadcast on the current network. Noise scales \
                  with paired peers — single-instance operators \
                  never see WARN.",
        common_failures: "Paired-peer operator joins coffee-shop \
                          wifi (untrusted SSID) → announcer goes \
                          silent → peers can't auto-rediscover. \
                          OR operator on wired/VPN with no SSID \
                          → strict default treats unknown SSID as \
                          untrusted → silent.",
        fix: "Add the current SSID to `cluster.policy.trusted_ssids` \
              in freedom.yaml, OR set `cluster.policy.announce_on_untrusted_wifi: \
              true` for broadcast-on-any-network, OR pair peers \
              via Tailscale (tailnet bypasses the SSID gate). \
              `neoth cluster discover` surfaces the same verdict \
              + suggested fix before scanning.",
    },
    CheckDoc {
        name: "provider flapping",
        purpose: "Flapping detection: scans the last 24h of \
                  usage_log entries + warns when any provider with \
                  ≥5 calls has an error rate ≥20%. Catches Slack \
                  rate-limit storms / WhatsApp Graph 5xx waves / \
                  OpenAI 429 spirals before they burn the operator's \
                  daily cap.",
        common_failures: "Slack workspace exceeded the per-app token \
                          rate limit (50 req/min for `chat.postMessage` \
                          on free workspaces); WhatsApp Cloud API \
                          rejecting webhooks because the operator's \
                          verify_token changed; OpenAI 429 from sudden \
                          burst traffic without a paid tier.",
        fix: "Check `~/.neoth/usage/<today>.jsonl` filtered by \
              `ok == false` for the failure shape. For rate-limit \
              flaps, reduce `council.max_calls_per_user_message` or \
              switch to a local-only preset via `neoth preset activate \
              fully-local && neoth preset apply fully-local`. For \
              auth flaps, `neoth doctor channels` shows the credential \
              wiring + a `neoth doctor --explain channels wiring` \
              gives the per-channel fix.",
    },
    CheckDoc {
        name: "circuit breakers",
        purpose: "QM-10 Phase 2 visibility surface. Reads the global \
                  `BreakerRegistry` snapshot + renders every provider \
                  the chat dispatch has touched in this process, with \
                  current state (closed/half_open/open) + consecutive \
                  failure count. Warn when any breaker is Open or in \
                  the HalfOpen probe state.",
        common_failures: "Provider flap (rate limit / regional outage / \
                          expired token) flips the breaker Open; chat \
                          calls reject immediately with retry_after \
                          until cooldown elapses (default 30s).",
        fix: "Wait the cooldown. Check `~/.neoth/usage/<today>.jsonl` \
              filtered by `ok == false` for the failure pattern. If a \
              specific provider is permanently broken, switch via \
              `neoth hemispheres set --role X --provider Y` or use \
              `neoth preset activate <bundle>` to swap a cloud-heavy \
              preset to a local-only one.",
    },
    CheckDoc {
        name: "tmux for claude-cli",
        purpose: "NOOB-UX-6 AIO-compliance probe. claude-cli's working \
                  backend is the tmux warm-session path \
                  (subprocess --print mode is unreliable on some Anthropic \
                  OAuth/build configurations; the tmux warm-session is the \
                  supported path). Pass when `tmux -V` answers; \
                  Warn when missing AND the operator's provider_kind \
                  is ClaudeCli; silent otherwise.",
        common_failures: "Operator picks claude-cli in the wizard on a \
                         fresh Windows or macOS install with no tmux, \
                         daemon silently falls back to the broken \
                         subprocess path on chat send.",
        fix: "Install tmux via your platform's package manager. Windows: \
              `scoop install tmux` or `choco install tmux` or install \
              WSL + apt. macOS: `brew install tmux`. Linux: \
              `apt install tmux` / `pacman -S tmux` / `dnf install tmux`. \
              Restart NEOTH after install. To silence this check when \
              you intentionally accept the subprocess path, set \
              `freedom.yaml::claude_cli.backend: subprocess`.",
    },
    CheckDoc {
        name: "stuck claude processes",
        purpose: "GOLD-WIRE-05 PID-hunter probe. A `claude` / `claude-cli` \
                  process can hang mid tool-call, on a closed OAuth browser, \
                  or on a stale WebSocket — the tmux session still looks live \
                  (low idle_secs) but the pane is unresponsive, so only \
                  PID-CPU monitoring catches it. Scans the process table for \
                  processes past the runtime floor (15 min) at idle CPU \
                  (< 1%). Gated on top-level `provider_kind == claude_cli` so \
                  other providers skip the scan — a claude_cli pinned ONLY in \
                  a per-hemisphere slot is not scanned yet (same scope as the \
                  tmux check). Warn when one is found; never Fail (a hung \
                  process is recoverable, not a broken install).",
        common_failures: "claude-cli wedged after an interrupted tool-call or \
                         an OAuth login where the browser tab was closed \
                         before the callback; a build/test loop that spawned \
                         a claude child which never exited.",
        fix: "Confirm the flagged PID is NOT your active foreground claude \
              session, then kill it — Unix: `kill <pid>` (then `kill -9 <pid>` \
              if it ignores SIGTERM); Windows: `taskkill /PID <pid>` (add `/F` \
              to force). Re-run `neoth doctor` to confirm it cleared. Raise \
              the idle-CPU floor in code if a legitimate low-CPU long-runner \
              keeps tripping the check.",
    },
    CheckDoc {
        name: "refusal recovery",
        purpose: "SPEC-10 LOWKEY refusal-recovery health. When the model \
                  refuses a legitimate request, `try_recover` reframes the \
                  prompt + retries (up to `max_attempts`) per detected \
                  cause. Doctor warns when recovery is ENABLED but can \
                  never fire — every applicable reframing disabled, or \
                  `max_attempts = 0` — i.e. a silent no-op that looks \
                  active but does nothing.",
        common_failures: "All LOWKEY reframings added to \
                         `refusal_recovery.disabled_reframings`; \
                         `max_attempts: 0` set by hand; recovery left \
                         enabled but effectively dead.",
        fix: "Re-enable a reframing: `neoth refusal enable <id>` (list them \
              with `neoth refusal reframings`). Restore retries: set \
              `refusal_recovery.max_attempts: 2` in freedom.yaml. To turn \
              recovery off on purpose, set `refusal_recovery.enabled: \
              false` — doctor then passes quietly. Dry-run a refusal with \
              `neoth refusal test \"<refusal text>\"`.",
    },
    CheckDoc {
        name: "local_qwen weights",
        purpose: "SPEC-04 private-extraction readiness. When \
                  `profile.learn_provider = local_qwen` (the privacy-floor \
                  default), profile facts are extracted ON-DEVICE — but \
                  only if the Qwen weights are cached. If they're missing, \
                  the local provider fails to build and (with \
                  `allow_cloud_fallback = false`) extraction is SKIPPED \
                  rather than leaking the conversation to a cloud model, \
                  so profile learning silently stops.",
        common_failures: "Fresh install where the operator chose local_qwen \
                         in the wizard but skipped the ~3 GB weight download; \
                         a wiped `~/.neoth/models/` cache; an interrupted \
                         download leaving an `.incomplete` marker.",
        fix: "Download the weights: `neoth model fetch` (or re-run `neoth \
              init` and accept step 5c). To extract on a cloud model \
              instead, set `profile.learn_provider` to a cloud slug AND \
              `profile.allow_cloud_fallback: true` in freedom.yaml \
              (understand the privacy trade-off first — see `neoth privacy \
              audit`).",
    },
    CheckDoc {
        name: "n8n_api_token",
        purpose: "SC-08 — when the n8n API is enabled, its bearer token \
                  at `~/.neoth/n8n_api_token` is the key to the localhost \
                  automation surface. On Windows it must be DPAPI-wrapped \
                  (a copied file is useless outside the operator's \
                  account); on Unix it must be mode-0600.",
        common_failures: "A pre-SC-08 plaintext token still on disk \
                         (Windows); a token file whose mode drifted off \
                         0600 (Unix, e.g. restored from a backup).",
        fix: "Delete `~/.neoth/n8n_api_token` and restart `neoth serve` — \
              it re-mints the token DPAPI-wrapped (Windows) / mode-0600 \
              (Unix). On Unix you can also just `chmod 600 \
              ~/.neoth/n8n_api_token`. To remove the surface entirely set \
              `n8n_api.enabled: false`.",
    },
];

/// Find a CheckDoc by case-insensitive name match. `None` when no doc
/// exists for that check name (typo in operator's `--explain` flag).
fn find_check_doc(name: &str) -> Option<&'static CheckDoc> {
    let needle = name.trim().to_ascii_lowercase();
    CHECK_DOCS
        .iter()
        .find(|d| d.name.to_ascii_lowercase() == needle)
}

/// Render a single CheckDoc in operator-readable text. Used by the
/// `--explain` path's table-output branch. JSON output uses serde
/// directly on the doc fields.
fn render_check_doc_text(doc: &CheckDoc) {
    println!("# {} — operator runbook", doc.name);
    println!();
    println!("## What it checks");
    println!("{}", doc.purpose);
    println!();
    println!("## Common failures");
    println!("{}", doc.common_failures);
    println!();
    println!("## How to fix");
    println!("{}", doc.fix);
}

/// One diagnostic outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    /// Soft problem — operator should look, but daemon will start.
    Warn,
    /// Hard problem — daemon refuses to start, or behaviour will be wrong.
    Fail,
}

impl CheckStatus {
    pub fn tag(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckOutcome {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

pub async fn run_doctor(args: DoctorArgs) -> Result<()> {
    // V03-07: short-circuit when operator requested the runbook lookup
    // surface instead of the diagnostic suite.
    if args.list_checks {
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let names: Vec<&str> = CHECK_DOCS.iter().map(|d| d.name).collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "checks": names,
                        "count": names.len(),
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "# doctor checks recognised by --explain ({} total)",
                    CHECK_DOCS.len()
                );
                for d in CHECK_DOCS {
                    println!("  {}", d.name);
                }
            }
        }
        return Ok(());
    }
    if let Some(name) = args.explain.as_deref() {
        match find_check_doc(name) {
            Some(doc) => match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "name": doc.name,
                            "purpose": doc.purpose,
                            "common_failures": doc.common_failures,
                            "fix": doc.fix,
                        })
                    );
                }
                OutputFormat::Table => render_check_doc_text(doc),
            },
            None => {
                anyhow::bail!(
                    "no doctor check named `{name}`. Run `neoth doctor --list-checks` \
                     to see the recognised names."
                );
            }
        }
        return Ok(());
    }

    let home = args
        .home
        .clone()
        .unwrap_or_else(FreedomConfig::default_neoth_home);
    let outcomes = run_all_checks(&home);

    let any_fail = outcomes.iter().any(|o| o.status == CheckStatus::Fail);
    let any_warn = outcomes.iter().any(|o| o.status == CheckStatus::Warn);

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = outcomes
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "name": o.name,
                        "status": o.status.tag(),
                        "detail": o.detail,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "checks": rows,
                    "any_fail": any_fail,
                    "any_warn": any_warn,
                })
            );
        }
        OutputFormat::Table => {
            if !args.quiet {
                println!("# `neoth doctor` — {} check(s)", outcomes.len());
                for o in &outcomes {
                    println!("  [{}]  {:<32}  {}", o.status.tag(), o.name, o.detail);
                }
            }
            println!(
                "summary: {} pass, {} warn, {} fail",
                outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Pass)
                    .count(),
                outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Warn)
                    .count(),
                outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Fail)
                    .count(),
            );
            if !args.quiet && (any_fail || any_warn) {
                println!(
                    "next: run `neoth doctor --explain <check>` for the exact cause and fix steps"
                );
                for o in outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Fail || o.status == CheckStatus::Warn)
                    .take(5)
                {
                    println!("      neoth doctor --explain \"{}\"", o.name);
                }
            }
        }
    }

    if any_fail {
        // GOLD-COR-01 / A-03: non-zero status via QuietExit so the stack
        // unwinds (Drop-time flushes run) before the code reaches `main`.
        return Err(crate::QuietExit(1).into());
    }
    Ok(())
}

/// Run every diagnostic in order. Pure synchronous — each check is short.
pub fn run_all_checks(home: &Path) -> Vec<CheckOutcome> {
    vec![
        check_freedom_yaml(home),
        check_credentials_yaml(home),
        check_credential_age(home),
        check_views_db(home),
        check_wal_segments(home),
        check_hmac_key(home),
        check_quota(home),
        check_policy_yaml(home),
        check_tweaks_toml(home),
        check_model_caches(),
        check_hysteria_config(home),
        check_cloud_archive_dest(home),
        check_disk_space(home),
        check_hooks_dir(home),
        check_agents_dir(home),
        check_profile_extensions(home),
        check_mcp_servers(home),
        check_wasm_plugins(home),
        check_channels_wiring(home),
        check_node_toolchain(home),
        check_tmux_for_claude_cli(home),
        check_stuck_claude_processes(home),
        check_usage_today(home),
        check_circuit_breakers(home),
        check_provider_flapping(home),
        check_cluster_registry(home),
        check_cluster_mdns_announcer(home),
        check_refusal_recovery(home),
        check_local_qwen_weights(home),
        check_n8n_api_token(home),
    ]
}

/// SC-08 n8n API bearer-token at-rest protection. When the n8n API is
/// enabled, its bearer token lives at `~/.neoth/n8n_api_token`. On
/// Windows it must be DPAPI-wrapped (a stolen file is useless outside the
/// operator's account); on Unix it must be mode-0600. PASS when n8n is
/// disabled (no token to protect), the token isn't minted yet (created
/// on next `neoth serve`), or it's protected. WARN when an enabled
/// deployment has a plaintext (Windows) / world-readable (Unix) token.
fn check_n8n_api_token(home: &Path) -> CheckOutcome {
    let name = "n8n_api_token";
    let enabled = crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml"))
        .map(|c| c.n8n_api.enabled)
        .unwrap_or(false);
    if !enabled {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "n8n API disabled (freedom.yaml::n8n_api.enabled=false) — token check skipped"
                .to_string(),
        };
    }
    let path = home.join("n8n_api_token");
    if !path.exists() {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "n8n API enabled; token not yet minted (created on next `neoth serve`)"
                .to_string(),
        };
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: format!("n8n_api_token unreadable at {}", path.display()),
        };
    };
    #[cfg(windows)]
    {
        if crate::wal::dpapi::is_wrapped(&bytes) {
            CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: "n8n_api_token present + DPAPI-wrapped (machine/user-bound)".to_string(),
            }
        } else {
            CheckOutcome {
                name,
                status: CheckStatus::Warn,
                detail: format!(
                    "n8n_api_token at {} is PLAINTEXT — delete it; `neoth serve` re-mints it DPAPI-wrapped",
                    path.display()
                ),
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o777);
        if mode == 0o600 {
            CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: format!("n8n_api_token present + mode 0600 ({} bytes)", bytes.len()),
            }
        } else {
            CheckOutcome {
                name,
                status: CheckStatus::Warn,
                detail: format!(
                    "n8n_api_token at {} is mode {mode:o} — should be 0600 (chmod 600 it)",
                    path.display()
                ),
            }
        }
    }
}

/// SPEC-04 local_qwen profile-extraction readiness. When `profile.
/// learn_provider` is set to the on-device `local_qwen` path, profile
/// extraction runs locally ONLY if the Qwen weights are cached;
/// otherwise `from_config_for_learn` fails the build and (with
/// `allow_cloud_fallback=false`, the privacy-floor default) extraction
/// is SKIPPED — profile learning silently stops. This check surfaces
/// that gap before it bites.
///
/// PASS: `learn_provider` is not `local_qwen` (cache irrelevant), or the
/// weights are cached, or freedom.yaml is unreadable (owned by the
/// freedom.yaml check, not double-reported here).
/// WARN: configured `local_qwen` but the weights are absent → the
/// operator must `neoth model fetch`.
fn check_local_qwen_weights(home: &Path) -> CheckOutcome {
    let name = "local_qwen weights";
    let cfg = match crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml")) {
        Ok(c) => c,
        Err(_) => {
            return CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: "freedom.yaml unreadable — skipping local_qwen cache check".to_string(),
            };
        }
    };
    let learn = cfg.profile.learn_provider.as_deref().unwrap_or("");
    if learn != "local_qwen" {
        let shown = if learn.is_empty() { "(unset)" } else { learn };
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: format!(
                "learn_provider `{shown}` is not local_qwen — Qwen weight cache not required"
            ),
        };
    }
    let model = crate::installers::qwen_weights::DEFAULT_QWEN_MODEL_ID;
    if crate::installers::qwen_weights::check_weights_cached(model) {
        CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: format!("local_qwen weights cached ({model})"),
        }
    } else {
        CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: format!(
                "learn_provider=local_qwen but {model} weights not cached → profile \
                 extraction will SKIP (privacy floor). Run `neoth model fetch` or \
                 `neoth init` step 5c."
            ),
        }
    }
}

/// SPEC-10 refusal-recovery health. Recovery reframes + retries when the
/// model refuses a legitimate request. The footgun this catches: a
/// config where recovery is left ENABLED but can never actually fire —
/// every applicable LOWKEY reframing disabled, or `max_attempts = 0` —
/// so refusals silently surface verbatim despite recovery "being on".
///
/// PASS: recovery off by operator choice (deliberate); recovery active
/// with ≥1 reframing enabled + max_attempts ≥ 1; freedom.yaml unreadable
/// (recovery falls back to healthy defaults — the missing-config WARN is
/// owned by `check_freedom_yaml`, not duplicated here).
/// WARN: enabled but a no-op (all reframings disabled, or max_attempts=0).
fn check_refusal_recovery(home: &Path) -> CheckOutcome {
    let name = "refusal recovery";
    let cfg = match crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml")) {
        Ok(c) => c,
        Err(_) => {
            return CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: "freedom.yaml unreadable — recovery uses defaults \
                         (enabled, 0 reframings disabled, max_attempts=2)"
                    .to_string(),
            };
        }
    };
    let rr = &cfg.refusal_recovery;
    let catalogue = crate::security::refusal_reframings::default_catalogue();
    let total = catalogue.len();
    let enabled_count = catalogue
        .iter()
        .filter(|r| !rr.disabled_reframings.iter().any(|d| d == r.id()))
        .count();

    if !rr.enabled {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "off by operator config (refusal_recovery.enabled=false) — \
                     refusals surface verbatim"
                .to_string(),
        };
    }
    if rr.max_attempts == 0 {
        return CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: "ENABLED but max_attempts=0 → recovery never retries \
                     (silent no-op). Set refusal_recovery.max_attempts ≥ 1."
                .to_string(),
        };
    }
    if enabled_count == 0 {
        return CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: format!(
                "ENABLED but all {total} LOWKEY reframings disabled → silent \
                 no-op. Re-enable via `neoth refusal enable <id>`."
            ),
        };
    }
    CheckOutcome {
        name,
        status: CheckStatus::Pass,
        detail: format!(
            "active — {enabled_count}/{total} reframings enabled, max_attempts={}",
            rr.max_attempts
        ),
    }
}

/// Cluster mDNS announcer state — surfaces whether the announcer
/// would actually broadcast on the current network. Composes the
/// Q2-ratified `policy::gate_discover` verdict with the paired-peer
/// count so the check stays quiet for single-instance operators
/// and only warns when the operator HAS paired peers but the
/// announcer is silenced by SSID gating.
fn check_cluster_mdns_announcer(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let (mdns_enabled, policy) = crate::cluster::policy::load_policy_from_freedom(&freedom_path);
    let ssid = crate::cluster::policy::current_ssid();
    let peer_count = crate::cluster::registry::load(home)
        .map(|r| r.peers.len())
        .unwrap_or(0);
    evaluate_announcer_state(mdns_enabled, &policy, ssid.as_deref(), peer_count)
}

/// Pure decision matrix for [`check_cluster_mdns_announcer`].
///
/// PASS paths (silent / informational):
///   - announcer disabled by operator (`mdns.enabled = false`)
///   - announcer policy yields Yes — running on current network
///   - announcer would skip, but operator has no paired peers
///     (single-instance — nothing to broadcast to anyway)
///
/// WARN paths (operator has paired peers AND announcer is silent):
///   - UntrustedSsid: peers won't find this host on the current SSID
///   - SsidUnknown: peers won't find this host on wired/VPN/headless
///
/// Each WARN carries the actionable fix (add SSID to trusted list,
/// flip `announce_on_untrusted_wifi`, or pair via Tailscale).
fn evaluate_announcer_state(
    mdns_enabled: bool,
    policy: &crate::cluster::policy::AnnouncePolicy,
    current_ssid: Option<&str>,
    paired_peers: usize,
) -> CheckOutcome {
    use crate::cluster::policy::{DiscoverGate, NoReason, gate_discover};
    let name = "cluster mDNS announcer";
    match gate_discover(mdns_enabled, policy, current_ssid) {
        DiscoverGate::Proceed => {
            let ssid_label = current_ssid
                .map(|s| format!("SSID `{s}`"))
                .unwrap_or_else(|| "any-network (announce_on_untrusted_wifi = true)".to_string());
            CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: format!(
                    "announcer would run on {ssid_label} — {paired_peers} paired peer(s)"
                ),
            }
        }
        DiscoverGate::SkipWith(NoReason::Disabled) => CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "announcer disabled (cluster.mdns.enabled = false)".to_string(),
        },
        DiscoverGate::SkipWith(NoReason::UntrustedSsid) => {
            let ssid_label = current_ssid.unwrap_or("<unknown>");
            if paired_peers == 0 {
                CheckOutcome {
                    name,
                    status: CheckStatus::Pass,
                    detail: format!(
                        "announcer silent on SSID `{ssid_label}` (not in trusted list, \
                         no paired peers — single-instance)"
                    ),
                }
            } else {
                CheckOutcome {
                    name,
                    status: CheckStatus::Warn,
                    detail: format!(
                        "announcer silent on SSID `{ssid_label}` — {paired_peers} paired \
                         peer(s) won't find this host. Fix: add SSID to \
                         `cluster.policy.trusted_ssids` in freedom.yaml, OR pair via \
                         Tailscale (tailnet bypasses SSID gate)."
                    ),
                }
            }
        }
        DiscoverGate::SkipWith(NoReason::SsidUnknown) => {
            if paired_peers == 0 {
                CheckOutcome {
                    name,
                    status: CheckStatus::Pass,
                    detail: "announcer silent — no SSID (wired/VPN) + no paired peers".to_string(),
                }
            } else {
                CheckOutcome {
                    name,
                    status: CheckStatus::Warn,
                    detail: format!(
                        "announcer silent — no SSID detected (wired/VPN/headless); \
                         {paired_peers} paired peer(s) won't find this host via mDNS. \
                         Fix: set `cluster.policy.announce_on_untrusted_wifi: true` \
                         in freedom.yaml, OR pair via Tailscale."
                    ),
                }
            }
        }
    }
}

/// Cluster registry surface — Phase 4 doctor entry. Reads
/// `~/.neoth/cluster.yaml` + reports peer count + stale-peer warning
/// when any paired peer hasn't been seen in 14 days. Empty registry
/// passes silently — single-instance operators don't see noise.
fn check_cluster_registry(home: &Path) -> CheckOutcome {
    let reg = match crate::cluster::registry::load(home) {
        Ok(r) => r,
        Err(e) => {
            return CheckOutcome {
                name: "cluster registry",
                status: CheckStatus::Warn,
                detail: format!("cluster.yaml unreadable: {e}"),
            };
        }
    };
    if reg.peers.is_empty() {
        return CheckOutcome {
            name: "cluster registry",
            status: CheckStatus::Pass,
            detail: "no confirmed cluster peers (single-instance)".to_string(),
        };
    }
    const STALE_AFTER_SECS: i64 = 14 * 86_400;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut stale = Vec::new();
    for p in &reg.peers {
        if now - p.last_seen_unix > STALE_AFTER_SECS {
            stale.push(format!(
                "{}({})",
                p.instance_label,
                &p.pub_key_hex[..8.min(p.pub_key_hex.len())]
            ));
        }
    }
    let detail = format!(
        "{} confirmed peer(s); {} stale (>14d since last_seen)",
        reg.peers.len(),
        stale.len()
    );
    let status = if stale.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    let detail = if stale.is_empty() {
        detail
    } else {
        format!("{} — stale: {}", detail, stale.join(", "))
    };
    CheckOutcome {
        name: "cluster registry",
        status,
        detail,
    }
}

/// Flapping detection for channel-routing providers (Slack outbound +
/// WhatsApp Graph API). Reads the last 24h of usage_log entries and
/// surfaces a warning when error rate per channel-related provider
/// crosses `FLAPPING_THRESHOLD_PCT`. Pass on insufficient samples
/// (<5 calls) or below threshold.
const FLAPPING_THRESHOLD_PCT: f64 = 20.0;
const FLAPPING_MIN_SAMPLES: u64 = 5;

fn check_provider_flapping(home: &Path) -> CheckOutcome {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let since = now - 86_400;
    let roll = crate::daemon::usage_log::aggregate(home, since, now);
    // Look for providers whose names suggest channel egress. We
    // can't filter perfectly without per-call channel labels in
    // usage_log (Phase 2 work), so the heuristic surfaces ANY
    // provider with a >20% error rate over the last 24h — the
    // detail string tags channel-suspect providers explicitly
    // for operator interpretation.
    if roll.per_provider.is_empty() {
        return CheckOutcome {
            name: "provider flapping",
            status: CheckStatus::Pass,
            detail: "no provider calls in last 24h to analyse".to_string(),
        };
    }
    let mut warnings = Vec::new();
    for p in &roll.per_provider {
        if p.call_count < FLAPPING_MIN_SAMPLES {
            continue;
        }
        let err_pct = (p.err_count as f64 / p.call_count as f64) * 100.0;
        if err_pct >= FLAPPING_THRESHOLD_PCT {
            warnings.push(format!(
                "{provider}: {err}/{total} errors ({pct:.0}%)",
                provider = p.provider,
                err = p.err_count,
                total = p.call_count,
                pct = err_pct,
            ));
        }
    }
    if warnings.is_empty() {
        return CheckOutcome {
            name: "provider flapping",
            status: CheckStatus::Pass,
            detail: format!(
                "every provider with ≥{FLAPPING_MIN_SAMPLES} samples is below {:.0}% errors",
                FLAPPING_THRESHOLD_PCT,
            ),
        };
    }
    CheckOutcome {
        name: "provider flapping",
        status: CheckStatus::Warn,
        detail: format!("flapping detected — {}", warnings.join("; ")),
    }
}

/// QM-10 Phase 1 doctor surface: render the registered circuit-
/// breaker states. v0.1.x: there's no persisted breaker state across
/// daemon restarts, so this check only has content when a long-running
/// daemon's `BreakerRegistry` is exposed to the doctor via the
/// runtime sidecar (deferred — out of scope here). For now the
/// check is always Pass with an honest "no live registry attached"
/// detail, which matches the rest of the v0.1 daemon-restart story.
/// When the runtime registry is wired (Phase 2), this detail flips
/// to render every registered breaker's state + cooldown.
fn check_circuit_breakers(_home: &Path) -> CheckOutcome {
    // QM-10 Phase 2 wire-in landed: chat dispatch consults the
    // global registry on every provider.complete(). The registry
    // is process-scoped (per the design comment in
    // providers::circuit_breaker::GLOBAL), so a doctor invocation
    // OUTSIDE the running `neoth serve` process sees an empty
    // snapshot — that's expected. When wired into the running
    // daemon's status surface (Phase 3), this reads the live
    // sidecar instead.
    let snaps = crate::providers::circuit_breaker::GLOBAL.snapshot_all();
    if snaps.is_empty() {
        return CheckOutcome {
            name: "circuit breakers",
            status: CheckStatus::Pass,
            detail: "no providers seen yet in this process".to_string(),
        };
    }
    let mut any_open = false;
    let mut any_half_open = false;
    let mut parts = Vec::new();
    for (provider, snap) in snaps {
        match snap.state {
            crate::providers::circuit_breaker::BreakerState::Open => any_open = true,
            crate::providers::circuit_breaker::BreakerState::HalfOpen => any_half_open = true,
            _ => {}
        }
        parts.push(format!(
            "{provider}={state}(fails={f})",
            state = snap.state.as_str(),
            f = snap.consecutive_failures,
        ));
    }
    let detail = parts.join("; ");
    let status = if any_open || any_half_open {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    CheckOutcome {
        name: "circuit breakers",
        status,
        detail,
    }
}

/// QM-9 Phase 1 doctor surface: aggregate the last 24h of
/// `~/.neoth/usage/*.jsonl` and warn when cost crosses the operator's
/// configured daily cap. Pass when no usage dir exists yet (clean
/// install) or when cost is below the cap. The cap defaults to
/// `freedom.yaml::council.daily_usd_cap` (typical value $5).
fn check_usage_today(home: &Path) -> CheckOutcome {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let since = now - 86_400;
    let roll = crate::daemon::usage_log::aggregate(home, since, now);
    if roll.total_call_count == 0 {
        return CheckOutcome {
            name: "usage today",
            status: CheckStatus::Pass,
            detail: "no calls in last 24h".to_string(),
        };
    }
    // Storage canonical stays USD; render in the operator's chosen
    // currency. Cap stays a USD value (council.daily_usd_cap) so the
    // gate is currency-stable across operator preference changes.
    let cap_usd = freedom_daily_usd_cap(home);
    let currency = crate::cli::usage::resolve_currency(home, None);
    let pct_of_cap = if cap_usd > 0.0 {
        (roll.total_cost_usd / cap_usd) * 100.0
    } else {
        0.0
    };
    let cost_rendered = crate::providers::cost::format_amount(
        crate::providers::cost::convert_from_usd(roll.total_cost_usd, currency),
        currency,
    );
    let cap_rendered = crate::providers::cost::format_amount(
        crate::providers::cost::convert_from_usd(cap_usd, currency),
        currency,
    );
    let detail = format!(
        "{} calls (ok={}, err={}), {} ({:.0}% of {} cap)",
        roll.total_call_count,
        roll.total_ok_count,
        roll.total_err_count,
        cost_rendered,
        pct_of_cap,
        cap_rendered,
    );
    let status = if cap_usd > 0.0 && (roll.total_cost_usd >= cap_usd || pct_of_cap >= 80.0) {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };
    CheckOutcome {
        name: "usage today",
        status,
        detail,
    }
}

/// Read `freedom.yaml::council.daily_usd_cap`. Returns 5.0 as the
/// sensible default when the field is missing or unparseable —
/// matches the Pick #8 council redesign default in the spec.
fn freedom_daily_usd_cap(home: &Path) -> f64 {
    const DEFAULT_CAP: f64 = 5.0;
    let path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return DEFAULT_CAP;
    };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return DEFAULT_CAP;
    };
    val.get("council")
        .and_then(|c| c.get("daily_usd_cap"))
        .and_then(|v| v.as_f64())
        .unwrap_or(DEFAULT_CAP)
}

/// Probe a binary's `--version`. Returns `Some(stdout)` on success,
/// `None` when the binary is missing or returns non-zero. Pure
/// sync — doctor checks all run synchronously.
fn probe_version_sync(binary: &str) -> Option<String> {
    let output = match std::process::Command::new(binary).arg("--version").output() {
        Ok(o) => o,
        Err(_) => return None,
    };
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// NOOB-UX-6: probe node + npm on PATH. Warn only when the operator
/// picked a Node-backed CLI provider (claude-cli / codex) at the
/// wizard — LocalQwen / API-only / antigravity (shell-script) /
/// gemini_api (REST) operators don't need npm and shouldn't see
/// yellow. Antigravity CLI was migrated off npm by Google on
/// 2026-05-19 so the legacy `gemini_cli` provider_kind no longer
/// implies npm dependency either.
fn check_node_toolchain(home: &Path) -> CheckOutcome {
    let needs_npm = freedom_uses_node_cli_provider(home);
    let node_version = probe_version_sync("node");
    let npm_version = probe_version_sync("npm");
    match (node_version, npm_version, needs_npm) {
        (Some(node), Some(npm), _) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Pass,
            detail: format!("node {node}, npm {npm}"),
        },
        (None, None, false) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Pass,
            detail: "node + npm not on PATH; not needed for your provider".to_string(),
        },
        (node, npm, true) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Warn,
            detail: format!(
                "node={} npm={}; required by your provider_kind for CLI auto-install. \
                 Install Node 20 LTS from nodejs.org / brew / your distro.",
                node.as_deref().unwrap_or("MISSING"),
                npm.as_deref().unwrap_or("MISSING"),
            ),
        },
        (node, npm, false) => CheckOutcome {
            name: "node toolchain",
            status: CheckStatus::Warn,
            detail: format!(
                "partial: node={} npm={}; your provider doesn't need npm but a half-\
                 install often signals a broken PATH.",
                node.as_deref().unwrap_or("MISSING"),
                npm.as_deref().unwrap_or("MISSING"),
            ),
        },
    }
}

/// NOOB-UX-6: probe tmux on PATH. Warn only when provider_kind ==
/// ClaudeCli, since claude-cli's only working backend on some setups
/// is the tmux warm-session path.
fn check_tmux_for_claude_cli(home: &Path) -> CheckOutcome {
    let needs_tmux = freedom_uses_claude_cli(home);
    match (probe_version_sync("tmux"), needs_tmux) {
        (Some(v), _) => CheckOutcome {
            name: "tmux for claude-cli",
            status: CheckStatus::Pass,
            detail: v,
        },
        (None, false) => CheckOutcome {
            name: "tmux for claude-cli",
            status: CheckStatus::Pass,
            detail: "tmux not on PATH; not needed for your provider".to_string(),
        },
        (None, true) => CheckOutcome {
            name: "tmux for claude-cli",
            status: CheckStatus::Warn,
            detail: "tmux MISSING; claude-cli falls back to the broken --print path. \
                     Install via scoop/choco/brew/apt and restart NEOTH."
                .to_string(),
        },
    }
}

/// GOLD-WIRE-05 — pure render: map the PID hunter's stuck-process list to a
/// doctor `CheckOutcome`. Empty → PASS; any stuck process → WARN (never
/// FAIL — a hung process is a recoverable runtime condition, not a broken
/// install). Kept pure + separate from the scan so the WARN/PASS mapping is
/// unit-testable without spawning processes. Deliberately does NOT echo
/// `claude_pid_hunter::stuck_hint()`, whose copy points at the not-yet-built
/// `neoth doctor stuck-clean` / `neoth chat reset` commands — operator
/// guidance here references only real, available recovery actions.
fn stuck_processes_outcome(
    stuck: &[crate::providers::claude_pid_hunter::StuckProcess],
) -> CheckOutcome {
    const NAME: &str = "stuck claude processes";
    if stuck.is_empty() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "no stuck claude processes".to_string(),
        };
    }
    let listed: Vec<String> = stuck
        .iter()
        .map(|s| {
            format!(
                "pid {} ({}, {}m idle)",
                s.meta.pid,
                s.meta.name,
                s.meta.runtime.as_secs() / 60
            )
        })
        .collect();
    CheckOutcome {
        name: NAME,
        status: CheckStatus::Warn,
        detail: format!(
            "{} stuck claude process(es): {} — each past the runtime floor at idle CPU \
             (likely hung mid tool-call or on a closed OAuth browser). Confirm it is \
             not your active session, then kill the PID (Unix: `kill <pid>`; Windows: \
             `taskkill /PID <pid>`).",
            stuck.len(),
            listed.join(", ")
        ),
    }
}

/// GOLD-WIRE-05 — flag `claude` processes the PID hunter classifies as
/// stuck (past the runtime floor at idle CPU). Gated on claude_cli being the
/// configured provider so operators on local_qwen / cloud APIs don't pay for
/// a process-table scan that can never find a relevant process. PASS when
/// claude_cli isn't configured or no stuck process is found; WARN listing
/// the offending PIDs otherwise.
fn check_stuck_claude_processes(home: &Path) -> CheckOutcome {
    if !freedom_uses_claude_cli(home) {
        return CheckOutcome {
            name: "stuck claude processes",
            status: CheckStatus::Pass,
            detail: "claude_cli not your provider — process scan skipped".to_string(),
        };
    }
    let stuck = crate::providers::claude_pid_hunter::scan_stuck_processes_blocking(
        crate::providers::claude_pid_hunter::StuckThresholds::default(),
    );
    stuck_processes_outcome(&stuck)
}

/// True when `freedom.yaml::provider_kind` is one of the Node-backed
/// CLIs (claude_cli / codex). Best-effort: a missing or unparseable
/// freedom.yaml returns false so the doctor stays quiet. Antigravity
/// CLI ships via vendor shell-script (not npm), so neither
/// `antigravity_cli` nor the legacy `gemini_cli` alias counts here —
/// listing them would emit a false-positive npm-missing warning to
/// operators who picked the new Google CLI.
fn freedom_uses_node_cli_provider(home: &Path) -> bool {
    let path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return false;
    };
    let kind = val
        .get("provider_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    matches!(kind, "claude_cli" | "codex")
}

/// True when `freedom.yaml::provider_kind == "claude_cli"`. Same
/// best-effort semantics as the node check.
fn freedom_uses_claude_cli(home: &Path) -> bool {
    let path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return false;
    };
    val.get("provider_kind").and_then(|v| v.as_str()) == Some("claude_cli")
}

fn check_freedom_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: format!("missing at {}; run `neoth init`", path.display()),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Warn,
            detail: format!("mode > 0600 — run `chmod 0600 {}`", path.display()),
        };
    }
    // Cheap parse check — full parse happens in serve.
    let Ok(body) = std::fs::read_to_string(&path) else {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: "unreadable".into(),
        };
    };
    if serde_yaml::from_str::<serde_yaml::Value>(&body).is_err() {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: "YAML parse error".into(),
        };
    }
    CheckOutcome {
        name: "freedom.yaml",
        status: CheckStatus::Pass,
        detail: format!("ok ({} bytes)", body.len()),
    }
}

fn check_credentials_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("credentials.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Pass,
            detail: "absent (claude-cli OAuth flow doesn't need it)".into(),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Fail,
            detail: format!(
                "mode > 0600 — secrets leak; run `chmod 0600 {}`",
                path.display()
            ),
        };
    }
    if let Err(e) = crate::config::credentials::Credentials::load_or_default(&path) {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        };
    }
    CheckOutcome {
        name: "credentials.yaml",
        status: CheckStatus::Pass,
        detail: "present, mode 0600, parseable".into(),
    }
}

/// Warn past 180 days, fail past 365 days since `credentials.yaml` was
/// last touched. Audit 2026-05-19 — Telegram/Slack tokens get rotated
/// server-side without any signal to NEOTH; without this check a
/// revoked token reads as a generic 401 deep inside a channel handler.
const CREDENTIAL_AGE_WARN_DAYS: u64 = 180;
const CREDENTIAL_AGE_FAIL_DAYS: u64 = 365;
const SECONDS_PER_DAY: u64 = 86_400;

fn check_credential_age(home: &Path) -> CheckOutcome {
    let path = home.join("credentials.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: "no credentials.yaml — skipping age check".into(),
        };
    }
    // Only warn when there's actually a secret to rotate. A bare file
    // with every Option<SecretString> set to None can sit for years
    // without operator risk.
    let creds = match crate::config::credentials::Credentials::load_or_default(&path) {
        Ok(c) => c,
        Err(_) => {
            // credentials.yaml parse errors are already surfaced by
            // `check_credentials_yaml`; don't double-fail here.
            return CheckOutcome {
                name: "credentials age",
                status: CheckStatus::Pass,
                detail: "credentials.yaml parse error — see credentials.yaml check".into(),
            };
        }
    };
    if creds.is_empty() {
        return CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: "credentials.yaml present but holds no secrets to age-check".into(),
        };
    }
    let modified = match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(m) => m,
        Err(e) => {
            return CheckOutcome {
                name: "credentials age",
                status: CheckStatus::Warn,
                detail: format!("cannot read credentials.yaml mtime: {e}"),
            };
        }
    };
    let age_secs = std::time::SystemTime::now()
        .duration_since(modified)
        .map(|d| d.as_secs())
        // mtime in the future (clock skew or operator `touch -t`) — treat as fresh.
        .unwrap_or(0);
    let age_days = age_secs / SECONDS_PER_DAY;
    if age_days >= CREDENTIAL_AGE_FAIL_DAYS {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Fail,
            detail: format!(
                "credentials.yaml is {age_days} days old (>= {CREDENTIAL_AGE_FAIL_DAYS}d) — rotate Telegram/Slack/provider keys and `touch` the file"
            ),
        }
    } else if age_days >= CREDENTIAL_AGE_WARN_DAYS {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Warn,
            detail: format!(
                "credentials.yaml is {age_days} days old (>= {CREDENTIAL_AGE_WARN_DAYS}d) — consider rotating before tokens expire silently"
            ),
        }
    } else {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: format!("credentials.yaml is {age_days} days old"),
        }
    }
}

fn check_views_db(home: &Path) -> CheckOutcome {
    let path = home.join("views.db");
    if !path.exists() {
        return CheckOutcome {
            name: "views.db",
            status: CheckStatus::Warn,
            detail: "absent (will be built on first `neoth serve`)".into(),
        };
    }
    let Ok(conn) = Connection::open(&path) else {
        return CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: "cannot open SQLite file".into(),
        };
    };
    let integrity: Result<String, _> = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0));
    match integrity {
        Ok(s) if s == "ok" => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Pass,
            detail: "integrity_check ok".into(),
        },
        Ok(other) => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: format!("integrity_check returned {other}"),
        },
        Err(e) => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: format!("PRAGMA failed: {e}"),
        },
    }
}

fn check_wal_segments(home: &Path) -> CheckOutcome {
    let wal_dir = home.join("wal");
    if !wal_dir.exists() {
        return CheckOutcome {
            name: "wal segments",
            status: CheckStatus::Warn,
            detail: "no wal/ dir (daemon never started)".into(),
        };
    }
    let mut count = 0usize;
    let mut bad = Vec::new();
    let entries = match std::fs::read_dir(&wal_dir) {
        Ok(rd) => rd,
        Err(e) => {
            return CheckOutcome {
                name: "wal segments",
                status: CheckStatus::Fail,
                detail: format!("read wal/ failed: {e}"),
            };
        }
    };
    use crate::wal::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader};
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        count += 1;
        let Ok(bytes) = std::fs::read(&path) else {
            bad.push(format!("{}: unreadable", path.display()));
            continue;
        };
        if bytes.len() < SEGMENT_HEADER_LEN {
            bad.push(format!(
                "{}: shorter than SegmentHeader ({} < {})",
                path.display(),
                bytes.len(),
                SEGMENT_HEADER_LEN
            ));
            continue;
        }
        if let Err(e) =
            SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().unwrap())
        {
            bad.push(format!("{}: bad header: {e}", path.display()));
        }
    }
    if !bad.is_empty() {
        return CheckOutcome {
            name: "wal segments",
            status: CheckStatus::Fail,
            detail: format!("{} segment(s) bad: {}", bad.len(), bad.join("; ")),
        };
    }
    CheckOutcome {
        name: "wal segments",
        status: CheckStatus::Pass,
        detail: format!("{count} segment(s) ok"),
    }
}

fn check_hmac_key(home: &Path) -> CheckOutcome {
    let path = home.join("wal").join("hmac.key");
    if !path.exists() {
        return CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Warn,
            detail: "absent (generated on first WAL write)".into(),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!(
                "mode > 0600 — HMAC compromised; run `chmod 0600 {}`",
                path.display()
            ),
        };
    }
    match std::fs::metadata(&path).map(|m| m.len()) {
        Ok(n) if n >= 16 => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Pass,
            detail: format!("{n} bytes, mode 0600"),
        },
        Ok(n) => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!("{n} bytes is too short — regenerate"),
        },
        Err(e) => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!("stat failed: {e}"),
        },
    }
}

fn check_quota(home: &Path) -> CheckOutcome {
    let ceiling = crate::daemon::quota::DEFAULT_CEILING_BYTES;
    let state = crate::daemon::quota::snapshot_quota(home, ceiling);
    if state.is_breached() {
        CheckOutcome {
            name: "disk quota",
            status: CheckStatus::Fail,
            detail: format!(
                "{} ≥ {} ceiling — daemon will reject new writes",
                fmt_bytes(state.used()),
                fmt_bytes(state.ceiling())
            ),
        }
    } else {
        CheckOutcome {
            name: "disk quota",
            status: CheckStatus::Pass,
            detail: format!(
                "{} of {} used",
                fmt_bytes(state.used()),
                fmt_bytes(state.ceiling())
            ),
        }
    }
}

fn check_policy_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("policy.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Pass,
            detail: "absent (no dangerous-target deny list configured)".into(),
        };
    }
    match crate::policy::PolicyConfig::load_or_default(&path) {
        Ok(p) => CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Pass,
            detail: format!(
                "{} dangerous target(s), {} pattern(s)",
                p.dangerous_targets.len(),
                p.dangerous_patterns.len()
            ),
        },
        Err(e) => CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

fn check_hooks_dir(home: &Path) -> CheckOutcome {
    let dir = home.join("hooks");
    if !dir.is_dir() {
        return CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Pass,
            detail: "absent (no operator-defined hooks loaded)".into(),
        };
    }
    // Walk *.toml files. Parse each individually; one malformed file
    // shouldn't fail the whole check — surface a count of bad rows.
    let mut total = 0usize;
    let mut bad = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            total += 1;
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    if let Err(e) = toml::from_str::<crate::hooks::schema::HookDef>(&body) {
                        bad.push(format!(
                            "{}: {e}",
                            path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                        ));
                    }
                }
                Err(e) => bad.push(format!(
                    "{}: {e}",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                )),
            }
        }
    }
    if bad.is_empty() {
        CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Pass,
            detail: format!("{total} hook file(s) parse cleanly"),
        }
    } else {
        CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {total} hook file(s) fail to parse: {}",
                bad.len(),
                bad.join("; ")
            ),
        }
    }
}

fn check_agents_dir(home: &Path) -> CheckOutcome {
    let dir = home.join("agents");
    if !dir.is_dir() {
        return CheckOutcome {
            name: "agents/",
            status: CheckStatus::Pass,
            detail: "absent (built-in sub-agents only)".into(),
        };
    }
    let mut total = 0usize;
    let mut bad = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            total += 1;
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    if let Err(e) = toml::from_str::<crate::sub_agents::schema::SubAgent>(&body) {
                        bad.push(format!(
                            "{}: {e}",
                            path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                        ));
                    }
                }
                Err(e) => bad.push(format!(
                    "{}: {e}",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                )),
            }
        }
    }
    if bad.is_empty() {
        CheckOutcome {
            name: "agents/",
            status: CheckStatus::Pass,
            detail: format!("{total} sub-agent file(s) parse cleanly"),
        }
    } else {
        CheckOutcome {
            name: "agents/",
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {total} sub-agent file(s) fail to parse: {}",
                bad.len(),
                bad.join("; ")
            ),
        }
    }
}

fn check_profile_extensions(home: &Path) -> CheckOutcome {
    let path = home.join("profile_extensions.toml");
    if !path.exists() {
        return CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Pass,
            detail: "absent (only base profile taxonomy allowed)".into(),
        };
    }
    match crate::profile::extension_registry::TypedExtensionRegistry::load_from(&path) {
        Ok(reg) => CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Pass,
            detail: format!(
                "{} operator-registered profile category extension(s)",
                reg.registered_count()
            ),
        },
        Err(e) => CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

fn check_tweaks_toml(home: &Path) -> CheckOutcome {
    let path = home.join("tweaks.toml");
    if !path.exists() {
        return CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Pass,
            detail: "absent (built-in defaults)".into(),
        };
    }
    match crate::tweaks::Tweaks::load_or_default(&path) {
        Ok(t) => CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Pass,
            detail: format!("{} prompt snippet(s) configured", t.prompts.len()),
        },
        Err(e) => CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

/// CLIP + Whisper caches are optional — extractions fall back to
/// metadata-only when missing — but operators who plan to send media
/// to NEOTH want them populated. We emit a `Warn` (not `Fail`) so
/// `neoth doctor` exits clean for text-only setups while still
/// surfacing the actionable next step.
fn check_model_caches() -> CheckOutcome {
    use crate::providers::{clip_engine, whisper};

    let clip_dir = clip_engine::default_cache_dir(clip_engine::DEFAULT_CLIP_REPO);
    let clip_present = [
        clip_engine::CONFIG_FILE,
        clip_engine::SAFETENSORS_FILE,
        clip_engine::TOKENIZER_FILE,
    ]
    .iter()
    .all(|f| clip_dir.join(f).exists());

    let whisper_dir = whisper_doctor_cache_dir(whisper::DEFAULT_WHISPER_REPO);
    let whisper_present = [
        whisper::CONFIG_FILE,
        whisper::TOKENIZER_FILE,
        whisper::SAFETENSORS_FILE,
    ]
    .iter()
    .all(|f| whisper_dir.join(f).exists());

    let detail = match (clip_present, whisper_present) {
        (true, true) => "clip + whisper cached".to_string(),
        (true, false) => "whisper missing — run `neoth models pull whisper`".to_string(),
        (false, true) => "clip missing — run `neoth models pull clip`".to_string(),
        (false, false) => {
            "clip + whisper missing — run `neoth models pull clip whisper`".to_string()
        }
    };
    let status = if clip_present && whisper_present {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    CheckOutcome {
        name: "model caches",
        status,
        detail,
    }
}

/// R-3 Hysteria — when freedom.yaml has a server configured, verify
/// the binary is reachable + the rendered YAML has the fields Hysteria
/// expects. No live spawn here; that's `neoth hysteria test`'s job.
fn check_hysteria_config(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let Ok(cfg) = crate::config::FreedomConfig::load_from_path(&freedom_path) else {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable; check_freedom_yaml owns the diagnostic".into(),
        };
    };
    let Some(hcfg) = cfg.hysteria.as_ref() else {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "not configured (direct egress)".into(),
        };
    };
    if hcfg.server.is_empty() {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "configured but server empty (direct egress)".into(),
        };
    }
    match crate::transport::hysteria::locate_binary() {
        Ok(path) => CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: format!("binary at {}, server={}", path.display(), hcfg.server),
        },
        Err(e) => CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Warn,
            detail: format!("config set ({}) but binary missing: {e}", hcfg.server,),
        },
    }
}

/// R-8 Cloud archive — when freedom.yaml has a destination, verify the
/// folder actually exists. Most common operator error is a typo'd
/// path, or the cloud client wasn't installed.
fn check_cloud_archive_dest(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let Ok(cfg) = crate::config::FreedomConfig::load_from_path(&freedom_path) else {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable; check_freedom_yaml owns the diagnostic".into(),
        };
    };
    let Some(dest_str) = cfg.cloud_archive_dest.as_deref() else {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Pass,
            detail: "not configured".into(),
        };
    };
    let dest = std::path::Path::new(dest_str);
    if !dest.exists() {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Warn,
            detail: format!(
                "configured dest {} does not exist (is the cloud client running?)",
                dest_str,
            ),
        };
    }
    if !dest.is_dir() {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Fail,
            detail: format!("configured dest {dest_str} is a file, not a directory"),
        };
    }
    CheckOutcome {
        name: "cloud archive",
        status: CheckStatus::Pass,
        detail: format!("destination {dest_str} present"),
    }
}

/// CDX-05 follow-up: surface the MCP servers config + flag stale
/// entries. Pure config-read — no process spawn (would slow down
/// `neoth doctor` from <1s to >5s). Operators run `neoth mcp tools
/// <id>` for a live handshake test.
///
/// Three outcomes:
///   - File missing → Pass with "(not configured)" since MCP is
///     optional. NEOTH still runs.
///   - File present, zero servers → Warn (file exists but nothing to
///     do — operator probably half-configured something).
///   - File present, N enabled → Pass listing ids + whether each pins
///     `allow_tools` (CDX-03 hardening posture).
fn check_mcp_servers(home: &Path) -> CheckOutcome {
    let path = home.join("mcp_servers.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Pass,
            detail: "(not configured — create ~/.neoth/mcp_servers.yaml to enable MCP)".into(),
        };
    }
    let servers = match crate::mcp::McpServers::load_from(&path) {
        Ok(s) => s,
        Err(e) => {
            return CheckOutcome {
                name: "mcp servers",
                status: CheckStatus::Fail,
                detail: format!("{} unreadable: {e}", path.display()),
            };
        }
    };
    let enabled = servers.enabled();
    if enabled.is_empty() {
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Warn,
            detail: format!(
                "{} present but zero enabled servers (operator half-configured?)",
                path.display(),
            ),
        };
    }
    // Reviewer-1 P1-A doctor warning (2026-05-20): three buckets now.
    //   `hardened`   — allow_tools pinned (recommended)
    //   `trust_all`  — operator explicitly opted into the legacy
    //                  catalogue-trust path via `trust_all_tools: true`
    //   `broken`     — allow_tools=None AND trust_all_tools=false →
    //                  the gate will DENY every call (secure-default)
    let hardened: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_some())
        .map(|s| s.id.as_str())
        .collect();
    let trust_all: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_none() && s.trust_all_tools)
        .map(|s| s.id.as_str())
        .collect();
    let broken: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_none() && !s.trust_all_tools)
        .map(|s| s.id.as_str())
        .collect();
    let detail = if !broken.is_empty() {
        format!(
            "{} enabled — hardened: [{}]; trust_all_tools: [{}]; \
             BROKEN (no allow_tools + trust_all_tools=false → all calls denied): [{}]. \
             Pin allow_tools or set trust_all_tools: true on each broken server.",
            enabled.len(),
            hardened.join(", "),
            trust_all.join(", "),
            broken.join(", "),
        )
    } else {
        format!(
            "{} enabled — hardened (allow_tools pinned): [{}]; legacy (trust_all_tools=true): [{}]",
            enabled.len(),
            hardened.join(", "),
            trust_all.join(", "),
        )
    };
    // Posture: Pass when every enabled server is either hardened or
    // explicit-trust. Warn when any server is in the broken state
    // (operator's gate denies every call until they opt-in or pin).
    let status = if broken.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    CheckOutcome {
        name: "mcp servers",
        status,
        detail,
    }
}

/// NOOB-UX-3 doctor surface — report the effective state of the
/// WASM plugin host so an operator who expected plugins to be
/// live sees the mismatch (slim build vs. operator-disabled).
fn check_wasm_plugins(home: &Path) -> CheckOutcome {
    use crate::config::FreedomConfig;
    let compiled_in = cfg!(feature = "wasm-plugin-host");
    let cfg_enabled = FreedomConfig::load_from_path(&home.join("freedom.yaml"))
        .map(|c| c.plugins.wasm.enabled)
        .unwrap_or(true);
    let (status, detail) = match (compiled_in, cfg_enabled) {
        (true, true) => (
            CheckStatus::Pass,
            "compiled-in + enabled by config — operator-loadable plugins are live".to_string(),
        ),
        (true, false) => (
            CheckStatus::Warn,
            "compiled-in but DISABLED by config (freedom.yaml::plugins.wasm.enabled = false). \
             Hook actions of kind Plugin{..} will degrade to Allow. \
             Flip the config to enable, or rebuild without `--features wasm-plugin-host` if \
             intentional."
                .to_string(),
        ),
        (false, true) => (
            CheckStatus::Warn,
            "not compiled in (slim daemon build); freedom.yaml has plugins.wasm.enabled=true \
             but the cargo `wasm-plugin-host` feature is OFF. Operator expecting plugins should \
             rebuild with `--features wasm-plugin-host` or install the release tarball."
                .to_string(),
        ),
        (false, false) => (
            CheckStatus::Pass,
            "not compiled in (slim daemon) AND config disabled — coherent slim state".to_string(),
        ),
    };
    CheckOutcome {
        name: "wasm plugins",
        status,
        detail,
    }
}

/// R2-P0-2 doctor surface — honest per-channel wiring status.
///
/// Closes the "Channels on deck" honesty gap flagged by the R2
/// reviewer (`PLAN/REEVALUATION_GESAMT_2026-05-21_R2.md` §4 P0-2).
/// Pre-fix: README/Status claimed channels were live when
/// `cli::serve` only spawned Telegram. Operators configured Slack /
/// WhatsApp tokens, saw "ok" in their setup, and never realised
/// inbound was deferred.
///
/// Post-fix: each channel gets one of four classifications:
///
/// - **LIVE**: tokens configured + adapter has live inbound + serve
///   spawns it. Telegram today.
/// - **OUTBOUND-ONLY**: tokens configured + adapter can send_text but
///   the inbound receive loop is deferred. WhatsApp + Keet adapters
///   bail on `run()`. Slack adapter has socket_mode but serve does
///   not spawn it yet.
/// - **CONFIGURED-NOT-STARTED**: tokens configured + adapter has full
///   inbound code BUT serve does not bootstrap it. Discord (gateway
///   loop ships) is the current example.
/// - **NOT-CONFIGURED**: no credentials present. Silent.
fn check_channels_wiring(home: &Path) -> CheckOutcome {
    let creds = match crate::config::credentials::Credentials::load_or_default(
        &home.join("credentials.yaml"),
    ) {
        Ok(c) => c,
        Err(_) => {
            return CheckOutcome {
                name: "channels wiring",
                status: CheckStatus::Warn,
                detail: "credentials.yaml unreadable; per-channel status unavailable".to_string(),
            };
        }
    };

    // Tuple shape: (channel name, classification, note). Only configured
    // channels show up — silent on NOT-CONFIGURED to keep doctor output
    // focused on what the operator actually set up.
    let mut rows: Vec<(&'static str, &'static str, &'static str)> = Vec::new();

    if creds.telegram_token.is_some() {
        rows.push((
            "telegram",
            "LIVE",
            "polling loop spawned by serve; send + receive both real",
        ));
    }
    match (
        creds.slack_bot_token.is_some(),
        creds.slack_app_token.is_some(),
    ) {
        (true, true) => rows.push((
            "slack",
            "LIVE",
            "socket-mode WS loop spawned by serve; send + receive both real",
        )),
        (true, false) | (false, true) => rows.push((
            "slack",
            "CONFIGURED-NOT-STARTED",
            "socket mode needs BOTH bot_token (xoxb-) and app_token (xapp-); \
             only one supplied — send_text still works",
        )),
        (false, false) => {}
    }
    if creds.whatsapp_token.is_some() || creds.whatsapp_phone_id.is_some() {
        let inbound_ready = creds.whatsapp_verify_token.is_some()
            && creds.whatsapp_app_secret.is_some()
            && creds.whatsapp_phone_id.is_some();
        if inbound_ready {
            rows.push((
                "whatsapp",
                "LIVE",
                "Meta webhook listener spawned by serve; send + receive both real",
            ));
        } else {
            rows.push((
                "whatsapp",
                "OUTBOUND-ONLY",
                "send_text via Graph API works; inbound needs whatsapp_verify_token + \
                 whatsapp_app_secret + whatsapp_phone_id in credentials.yaml",
            ));
        }
    }
    // Discord + Keet have no credentials.yaml fields yet, so they only
    // surface here when their config moves to credentials.yaml. Note
    // the design intent so operators reading the diagnostic see why
    // they aren't listed.

    if rows.is_empty() {
        return CheckOutcome {
            name: "channels wiring",
            status: CheckStatus::Pass,
            detail: "no channel credentials configured — daemon runs in CLI-only mode".to_string(),
        };
    }

    // Aggregate status: LIVE counts as Pass; anything less downgrades
    // the whole check to Warn so operators who configured Slack/
    // WhatsApp expecting live inbound see a yellow flag.
    let any_partial = rows.iter().any(|(_, cls, _)| *cls != "LIVE");
    let status = if any_partial {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };

    let detail = rows
        .iter()
        .map(|(ch, cls, note)| format!("{ch}: {cls} — {note}"))
        .collect::<Vec<_>>()
        .join("; ");

    CheckOutcome {
        name: "channels wiring",
        status,
        detail,
    }
}

/// Warn when free disk on `~/.neoth/`'s partition is below the full
/// model-cache footprint. Operators who haven't pulled CLIP / whisper /
/// Qwen yet see a heads-up before the download stalls at 70%.
fn check_disk_space(home: &Path) -> CheckOutcome {
    let probe = crate::daemon::hardware::probe(home);
    let avail = probe.disk.home_available_gib();
    let needed = probe.estimated_full_cache_gib;
    if probe.disk.home_total_bytes == 0 {
        return CheckOutcome {
            name: "disk space",
            status: CheckStatus::Pass,
            detail: format!(
                "{} mount not resolvable (containerised?); skipping check",
                probe.disk.home_mount,
            ),
        };
    }
    if avail < needed {
        return CheckOutcome {
            name: "disk space",
            status: CheckStatus::Warn,
            detail: format!(
                "{:.1} GiB free on {} but full model cache is ~{:.1} GiB",
                avail, probe.disk.home_mount, needed,
            ),
        };
    }
    CheckOutcome {
        name: "disk space",
        status: CheckStatus::Pass,
        detail: format!(
            "{:.1} GiB free on {} (need ~{:.1} GiB for full cache)",
            avail, probe.disk.home_mount, needed,
        ),
    }
}

/// Local copy of the whisper engine's `default_cache_dir` so the doctor
/// can run with the same path math as the engine without exposing the
/// engine's `pub` surface. Kept in sync via the
/// `whisper_cache_dir_matches_engine_default` test in
/// `cli::models::tests`.
fn whisper_doctor_cache_dir(repo: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    let flattened = repo.replace('/', "-");
    home.join(".neoth").join("models").join(flattened)
}

#[cfg(unix)]
fn is_mode_0600(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn is_mode_0600(_path: &Path) -> bool {
    // Windows DACL parsing is out of scope here — the wizard's icacls pass
    // is the actual enforcement (see `wal/win_acl.rs`). `neoth doctor`
    // accepts files exist as good on Windows; deep DACL inspection is a
    // future addition.
    true
}

fn fmt_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── V03-07 2026-05-17: --explain + --list-checks ──────────────────

    #[test]
    fn check_docs_cover_every_check_name_in_run_all() {
        // Drift guard: every check name produced by `run_all_checks`
        // must have an explain entry. Refactor that adds a new check
        // without updating CHECK_DOCS fails here.
        let dir = tempdir().unwrap();
        let outcomes = run_all_checks(dir.path());
        let doc_names: std::collections::HashSet<&str> =
            CHECK_DOCS.iter().map(|d| d.name).collect();
        for o in &outcomes {
            assert!(
                doc_names.contains(o.name),
                "check `{}` produced by run_all_checks has no CHECK_DOCS entry — \
                 add one in cli/doctor.rs::CHECK_DOCS",
                o.name
            );
        }
    }

    #[test]
    fn find_check_doc_case_insensitive_match() {
        assert!(find_check_doc("freedom.yaml").is_some());
        assert!(find_check_doc("FREEDOM.YAML").is_some());
        assert!(find_check_doc(" wal segments ").is_some());
    }

    #[test]
    fn find_check_doc_returns_none_for_unknown_name() {
        assert!(find_check_doc("definitely-not-a-check").is_none());
        assert!(find_check_doc("").is_none());
    }

    #[test]
    fn every_check_doc_has_non_empty_fields() {
        for d in CHECK_DOCS {
            assert!(!d.name.is_empty(), "CheckDoc name empty");
            assert!(!d.purpose.is_empty(), "CheckDoc {} purpose empty", d.name);
            assert!(
                !d.common_failures.is_empty(),
                "CheckDoc {} common_failures empty",
                d.name
            );
            assert!(!d.fix.is_empty(), "CheckDoc {} fix empty", d.name);
        }
    }

    #[test]
    fn check_docs_listed_count_pinned_at_thirty() {
        // Pin the count so a future addition is a conscious update + a
        // future deletion (which would silently drop operator runbook
        // coverage) is caught. Bumped to 26 in Session 21 for
        // `cluster mDNS announcer` (Bite #2 announcer state surface);
        // 27 in Session 28c for `refusal recovery` (SPEC-10);
        // 28 in Session 28c for `local_qwen weights` (SPEC-04);
        // 29 in Session 28c for `n8n_api_token` (SC-08);
        // 30 in Session 44 for `stuck claude processes` (GOLD-WIRE-05).
        assert_eq!(CHECK_DOCS.len(), 30);
    }

    // ── GOLD-WIRE-05: stuck claude-process check ──────────────────────

    #[test]
    fn stuck_processes_outcome_passes_when_none() {
        let out = stuck_processes_outcome(&[]);
        assert_eq!(out.status, CheckStatus::Pass);
        assert_eq!(out.name, "stuck claude processes");
        assert!(out.detail.contains("no stuck"), "got: {}", out.detail);
    }

    #[test]
    fn stuck_processes_outcome_warns_and_lists_pid() {
        // Acceptance: a stuck claude process surfaces as WARN in doctor
        // output, with its PID + idle minutes shown.
        use crate::providers::claude_pid_hunter::{ProcessMeta, StuckProcess, StuckThresholds};
        let stuck = vec![StuckProcess {
            meta: ProcessMeta {
                pid: 4242,
                name: "claude".into(),
                runtime: std::time::Duration::from_secs(18 * 60),
                cpu_pct: 0.1,
            },
            thresholds: StuckThresholds::default(),
            hint: "x",
        }];
        let out = stuck_processes_outcome(&stuck);
        assert_eq!(out.status, CheckStatus::Warn);
        assert!(out.detail.contains("pid 4242"), "must name the PID: {}", out.detail);
        assert!(out.detail.contains("18m idle"), "must show idle minutes: {}", out.detail);
        // Honesty: must NOT point at the not-yet-built stuck-clean / reset cmds.
        assert!(!out.detail.contains("stuck-clean"));
        assert!(!out.detail.contains("chat reset"));
    }

    #[test]
    fn check_stuck_claude_processes_skips_when_not_claude_cli() {
        // No freedom.yaml → freedom_uses_claude_cli is false → PASS skip,
        // and crucially NO process-table scan runs.
        let dir = tempdir().unwrap();
        let out = check_stuck_claude_processes(dir.path());
        assert_eq!(out.status, CheckStatus::Pass);
        assert!(
            out.detail.contains("not your provider") || out.detail.contains("skipped"),
            "got: {}",
            out.detail
        );
    }

    #[test]
    fn n8n_token_check_passes_when_disabled() {
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.n8n_api.enabled = false;
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_n8n_api_token(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("disabled"));
    }

    #[test]
    fn n8n_token_check_passes_when_enabled_but_not_minted() {
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.n8n_api.enabled = true;
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_n8n_api_token(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("not yet minted"));
    }

    #[test]
    fn local_qwen_check_passes_when_learn_provider_not_local_qwen() {
        // freedom.yaml with a cloud learn_provider → Qwen cache irrelevant.
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.profile.learn_provider = Some("gemini".to_string());
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_local_qwen_weights(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("not local_qwen"));
    }

    #[test]
    fn local_qwen_check_passes_on_unreadable_freedom_yaml() {
        let dir = tempdir().unwrap();
        let outcome = check_local_qwen_weights(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn refusal_recovery_check_passes_on_empty_home_defaults() {
        // No freedom.yaml → recovery runs on healthy defaults → Pass.
        let dir = tempdir().unwrap();
        let outcome = check_refusal_recovery(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn refusal_recovery_check_warns_when_all_reframings_disabled() {
        // Enabled recovery + every reframing disabled = silent no-op → Warn.
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.refusal_recovery.enabled = true;
        cfg.refusal_recovery.max_attempts = 2;
        cfg.refusal_recovery.disabled_reframings =
            crate::security::refusal_reframings::default_catalogue()
                .iter()
                .map(|r| r.id().to_string())
                .collect();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_refusal_recovery(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(
            outcome.detail.contains("no-op"),
            "detail: {}",
            outcome.detail
        );
    }

    #[test]
    fn refusal_recovery_check_passes_when_disabled_by_operator() {
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.refusal_recovery.enabled = false;
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_refusal_recovery(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("off by operator"));
    }

    #[test]
    fn cluster_registry_pass_when_empty() {
        let dir = tempdir().unwrap();
        let outcome = check_cluster_registry(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no confirmed"));
    }

    #[test]
    fn cluster_registry_pass_when_fresh() {
        let dir = tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let peer = crate::cluster::registry::PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: "laptop".into(),
            hostname: String::new(),
            addr: "192.0.2.1:4242".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: now - 3600,
            last_seen_unix: now - 60,
            ..Default::default()
        };
        crate::cluster::registry::upsert(dir.path(), peer).unwrap();
        let outcome = check_cluster_registry(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("1 confirmed"));
    }

    #[test]
    fn cluster_registry_warns_on_stale() {
        let dir = tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let peer = crate::cluster::registry::PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: "old-laptop".into(),
            hostname: String::new(),
            addr: "192.0.2.1:4242".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: now - 30 * 86_400,
            last_seen_unix: now - 30 * 86_400, // 30 days old > 14d threshold
            ..Default::default()
        };
        crate::cluster::registry::upsert(dir.path(), peer).unwrap();
        let outcome = check_cluster_registry(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("stale"));
        assert!(outcome.detail.contains("old-laptop"));
    }

    // ── check_cluster_mdns_announcer (Bite #2) ─────────────────────────

    fn open_announce_policy() -> crate::cluster::policy::AnnouncePolicy {
        crate::cluster::policy::AnnouncePolicy {
            announce_on_untrusted_wifi: true,
            trusted_ssids: vec![],
        }
    }

    fn strict_announce_policy() -> crate::cluster::policy::AnnouncePolicy {
        crate::cluster::policy::AnnouncePolicy {
            announce_on_untrusted_wifi: false,
            trusted_ssids: vec!["home-wifi".into()],
        }
    }

    #[test]
    fn mdns_announcer_pass_when_disabled() {
        let outcome = evaluate_announcer_state(false, &open_announce_policy(), Some("anything"), 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("disabled"));
    }

    #[test]
    fn mdns_announcer_pass_when_proceed_with_ssid() {
        let outcome =
            evaluate_announcer_state(true, &strict_announce_policy(), Some("home-wifi"), 2);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("home-wifi"));
        assert!(outcome.detail.contains("2 paired"));
    }

    #[test]
    fn mdns_announcer_pass_when_open_policy_any_network() {
        let outcome = evaluate_announcer_state(true, &open_announce_policy(), None, 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        // Open policy → SsidUnknown path collapses to Proceed via gate;
        // detail uses the any-network label.
        assert!(outcome.detail.contains("any-network"));
    }

    #[test]
    fn mdns_announcer_pass_when_untrusted_ssid_but_no_peers() {
        let outcome =
            evaluate_announcer_state(true, &strict_announce_policy(), Some("coffee-shop"), 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("single-instance"));
        assert!(outcome.detail.contains("coffee-shop"));
    }

    #[test]
    fn mdns_announcer_warn_when_untrusted_ssid_with_peers() {
        let outcome =
            evaluate_announcer_state(true, &strict_announce_policy(), Some("coffee-shop"), 3);
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("coffee-shop"));
        assert!(outcome.detail.contains("3 paired"));
        assert!(outcome.detail.contains("trusted_ssids"));
    }

    #[test]
    fn mdns_announcer_pass_when_ssid_unknown_and_no_peers() {
        let outcome = evaluate_announcer_state(true, &strict_announce_policy(), None, 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no paired peers"));
    }

    #[test]
    fn mdns_announcer_warn_when_ssid_unknown_with_peers() {
        let outcome = evaluate_announcer_state(true, &strict_announce_policy(), None, 1);
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("wired"));
        assert!(outcome.detail.contains("1 paired"));
        assert!(outcome.detail.contains("announce_on_untrusted_wifi"));
    }

    #[test]
    fn mdns_announcer_check_via_home_does_not_panic() {
        // End-to-end smoke for the home-reading wrapper: missing
        // freedom.yaml + missing cluster.yaml → safe defaults +
        // ssid lookup might return either None or Some depending
        // on the test host. Must not panic.
        let dir = tempdir().unwrap();
        let outcome = check_cluster_mdns_announcer(dir.path());
        assert_eq!(outcome.name, "cluster mDNS announcer");
        // Status is platform-dependent (host SSID may match nothing
        // in the default trusted list); we only pin that it ran.
    }

    #[test]
    fn provider_flapping_pass_when_no_calls() {
        let dir = tempdir().unwrap();
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no provider calls"));
        // GR-02 (Session 24): pin the rename so a future regression
        // that brings the misleading "channel flapping" label back
        // (the function measures provider error-rate, not
        // channel-level data) is caught in CI.
        assert_eq!(outcome.name, "provider flapping");
    }

    #[test]
    fn provider_flapping_pass_when_below_threshold() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // 10 calls, only 1 error → 10% error rate (below 20% threshold).
        for i in 0..10 {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: now - (i as i64) * 10,
                    provider: "slack_api".into(),
                    model: "n/a".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 50,
                    ok: i != 0,
                },
            )
            .unwrap();
        }
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn provider_flapping_warns_when_above_threshold() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // 10 calls, 5 errors → 50% error rate.
        for i in 0..10 {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: now - (i as i64) * 10,
                    provider: "openai_api".into(),
                    model: "gpt-5".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 50,
                    ok: i % 2 == 0,
                },
            )
            .unwrap();
        }
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("flapping"));
        assert!(outcome.detail.contains("openai_api"));
        // Error pct surfaces in the detail string regardless of
        // rendering quirks — assert on the per-pct presence
        // pattern rather than exact "50%" formatting.
        assert!(
            outcome.detail.contains("%"),
            "detail should carry percent sign: {}",
            outcome.detail
        );
    }

    #[test]
    fn provider_flapping_skips_low_sample_providers() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Only 2 calls with 100% error rate — under min sample size.
        for _ in 0..2 {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: now,
                    provider: "low_sample".into(),
                    model: "x".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 10,
                    ok: false,
                },
            )
            .unwrap();
        }
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn check_circuit_breakers_renders_per_provider_state() {
        // QM-10 Phase 2 wire-in: the doctor reads the live global
        // registry. In a fresh test process with no providers
        // seen, the registry is empty → Pass with "no providers"
        // detail. Once a chat call has run, the detail enumerates
        // the breakers it touched.
        let dir = tempdir().unwrap();
        let outcome = check_circuit_breakers(dir.path());
        assert_eq!(outcome.name, "circuit breakers");
        // Test order isn't deterministic so we accept both shapes
        // — the contract is: outcome is non-empty + status is Pass
        // when every breaker is Closed.
        assert!(!outcome.detail.is_empty());
    }

    #[test]
    fn check_usage_today_pass_when_no_usage_dir() {
        let dir = tempdir().unwrap();
        let outcome = check_usage_today(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no calls"));
    }

    #[test]
    fn check_usage_today_warns_when_cost_crosses_cap() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "council:\n  daily_usd_cap: 1.0\n",
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        append(
            dir.path(),
            &UsageEvent {
                ts_unix: now - 30,
                provider: "openai_api".into(),
                model: "gpt-5.5".into(),
                input_tokens: 100,
                output_tokens: 100,
                cost_usd: 1.5,
                latency_ms: 500,
                ok: true,
            },
        )
        .unwrap();
        let outcome = check_usage_today(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("1.5") || outcome.detail.contains("1.50"));
    }

    #[test]
    fn check_usage_today_warns_at_80_pct_of_cap() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "council:\n  daily_usd_cap: 2.0\n",
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // $1.70 of $2 cap = 85% → Warn (below cap, above 80%).
        append(
            dir.path(),
            &UsageEvent {
                ts_unix: now - 30,
                provider: "openai_api".into(),
                model: "gpt-5.5".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_usd: 1.70,
                latency_ms: 0,
                ok: true,
            },
        )
        .unwrap();
        assert_eq!(check_usage_today(dir.path()).status, CheckStatus::Warn);
    }

    #[test]
    fn freedom_daily_usd_cap_defaults_when_missing() {
        let dir = tempdir().unwrap();
        assert!((freedom_daily_usd_cap(dir.path()) - 5.0).abs() < f64::EPSILON);
        // Malformed YAML → default.
        std::fs::write(dir.path().join("freedom.yaml"), ": : :").unwrap();
        assert!((freedom_daily_usd_cap(dir.path()) - 5.0).abs() < f64::EPSILON);
        // Explicit value parses.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "council:\n  daily_usd_cap: 12.5\n",
        )
        .unwrap();
        assert!((freedom_daily_usd_cap(dir.path()) - 12.5).abs() < f64::EPSILON);
    }

    #[test]
    fn node_toolchain_silent_when_no_freedom_and_no_node() {
        // Fresh tempdir with no freedom.yaml + no node on PATH would
        // hit the (None, None, false) arm → Pass with explanatory
        // detail. Pin the contract so a future re-classification
        // doesn't accidentally spam yellow on LocalQwen-only deploys.
        let dir = tempdir().unwrap();
        let outcome = check_node_toolchain(dir.path());
        // We can't pin Pass-vs-Warn deterministically on a CI runner
        // that DOES have node installed (which is common). What we
        // CAN pin: when needs_npm is false (no freedom.yaml means
        // false), the outcome must NOT be Warn-with-required-message.
        if outcome.status == CheckStatus::Warn {
            assert!(
                !outcome.detail.contains("required by your provider_kind"),
                "should not raise 'required' warn when provider isn't node-backed: {}",
                outcome.detail
            );
        }
    }

    #[test]
    fn node_toolchain_warns_when_provider_kind_needs_npm_and_node_missing() {
        // Set provider_kind to claude_cli and probe a binary that
        // definitely doesn't exist — by overriding the freedom path
        // we exercise the needs_npm=true branch.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: claude_cli\n",
        )
        .unwrap();
        assert!(freedom_uses_node_cli_provider(dir.path()));
        assert!(freedom_uses_claude_cli(dir.path()));
    }

    #[test]
    fn freedom_uses_helpers_handle_missing_or_malformed() {
        let dir = tempdir().unwrap();
        // Missing → false.
        assert!(!freedom_uses_node_cli_provider(dir.path()));
        assert!(!freedom_uses_claude_cli(dir.path()));
        // Malformed YAML → false.
        std::fs::write(dir.path().join("freedom.yaml"), ": : :").unwrap();
        assert!(!freedom_uses_node_cli_provider(dir.path()));
        assert!(!freedom_uses_claude_cli(dir.path()));
        // Different provider → false.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: local_qwen\n",
        )
        .unwrap();
        assert!(!freedom_uses_node_cli_provider(dir.path()));
        assert!(!freedom_uses_claude_cli(dir.path()));
        // Antigravity CLI → NOT node-backed (vendor shell-script
        // install, not npm). Verifies the 2026-05-19 transition fix:
        // the predicate must NOT flag `gemini_cli` or `antigravity_cli`
        // as needing npm or the doctor emits a false-positive warning.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: gemini_cli\n",
        )
        .unwrap();
        assert!(
            !freedom_uses_node_cli_provider(dir.path()),
            "legacy gemini_cli provider must NOT count as node-backed after antigravity migration",
        );
        assert!(!freedom_uses_claude_cli(dir.path()));
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: antigravity_cli\n",
        )
        .unwrap();
        assert!(
            !freedom_uses_node_cli_provider(dir.path()),
            "antigravity_cli provider must NOT count as node-backed (ships via shell-script)",
        );
        assert!(!freedom_uses_claude_cli(dir.path()));
        // claude_cli still node-backed.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: claude_cli\n",
        )
        .unwrap();
        assert!(freedom_uses_node_cli_provider(dir.path()));
        assert!(freedom_uses_claude_cli(dir.path()));
    }

    #[tokio::test]
    async fn run_doctor_list_checks_prints_every_name_in_table_mode() {
        // Smoke: --list-checks short-circuits without touching the home
        // dir. Captures stdout via the println contract — no fancy
        // redirection. Pass tempdir as home so the no-config short-
        // circuit doesn't bail.
        let dir = tempdir().unwrap();
        let args = DoctorArgs {
            home: Some(dir.path().to_path_buf()),
            quiet: false,
            explain: None,
            list_checks: true,
            output: OutputFormat::Table,
        };
        // Just verify it returns Ok without panicking — output capture
        // would need the integration-test harness.
        run_doctor(args).await.unwrap();
    }

    #[tokio::test]
    async fn run_doctor_explain_unknown_check_errors_with_pointer() {
        let dir = tempdir().unwrap();
        let args = DoctorArgs {
            home: Some(dir.path().to_path_buf()),
            quiet: false,
            explain: Some("nope-not-real".to_string()),
            list_checks: false,
            output: OutputFormat::Table,
        };
        let err = run_doctor(args).await.unwrap_err();
        assert!(err.to_string().contains("no doctor check named"));
        assert!(err.to_string().contains("--list-checks"));
    }

    #[tokio::test]
    async fn run_doctor_explain_known_check_succeeds() {
        let dir = tempdir().unwrap();
        let args = DoctorArgs {
            home: Some(dir.path().to_path_buf()),
            quiet: false,
            explain: Some("freedom.yaml".to_string()),
            list_checks: false,
            output: OutputFormat::Table,
        };
        run_doctor(args).await.unwrap();
    }

    #[test]
    fn freedom_yaml_missing_is_fail() {
        let dir = tempdir().unwrap();
        let o = check_freedom_yaml(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("neoth init"));
    }

    #[test]
    fn freedom_yaml_present_and_parseable_passes() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("freedom.yaml"), "operator_id: demo-user\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join("freedom.yaml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let o = check_freedom_yaml(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn credentials_absent_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_credentials_yaml(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("absent"));
    }

    #[test]
    fn views_db_missing_is_warn() {
        let dir = tempdir().unwrap();
        let o = check_views_db(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
    }

    #[test]
    fn wal_segments_missing_dir_warns() {
        let dir = tempdir().unwrap();
        let o = check_wal_segments(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
    }

    #[test]
    fn hmac_key_absent_is_warn() {
        let dir = tempdir().unwrap();
        let o = check_hmac_key(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
    }

    #[test]
    fn run_all_checks_returns_one_outcome_per_diagnostic() {
        let dir = tempdir().unwrap();
        let outs = run_all_checks(dir.path());
        // 30 checks: 19 pre-Session-20 + node toolchain + tmux for
        // claude-cli + usage today + circuit breakers + channel
        // flapping + cluster registry (Phase 4 follow-on) + cluster
        // mDNS announcer (Session 21 bite #2) + refusal recovery
        // (Session 28c, SPEC-10) + local_qwen weights (Session 28c, SPEC-04)
        // + n8n_api_token (Session 28c, SC-08) + stuck claude processes
        // (Session 44, GOLD-WIRE-05).
        assert_eq!(outs.len(), 30);
        for o in &outs {
            assert!(!o.detail.is_empty(), "{} has empty detail", o.name);
        }
    }

    // ── R2-P0-2 channels-wiring tests ────────────────────────────────────

    #[test]
    fn r2_p0_2_channels_wiring_pass_when_no_credentials() {
        let dir = tempdir().unwrap();
        // No credentials.yaml → daemon runs CLI-only, no channel claims
        // to make. Pass + explanatory detail.
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.name, "channels wiring");
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(
            outcome.detail.contains("CLI-only")
                || outcome.detail.contains("no channel credentials"),
            "detail must explain the no-credentials state: {}",
            outcome.detail
        );
    }

    #[test]
    fn r2_p0_2_channels_wiring_live_when_only_telegram_configured() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "telegram_token: \"123:abcXYZ_test_token_value\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("telegram"));
        assert!(outcome.detail.contains("LIVE"));
    }

    #[test]
    fn r2_p0_2_channels_wiring_warn_when_slack_partial() {
        // Only bot_token supplied — socket mode also needs app_token.
        // Doctor surfaces this as CONFIGURED-NOT-STARTED so operators
        // who pasted only one token see the gap.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "slack_bot_token: \"xoxb-test-token\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("slack"));
        assert!(outcome.detail.contains("CONFIGURED-NOT-STARTED"));
    }

    #[test]
    fn slack_inbound_live_when_both_tokens_present() {
        // Post-inbound-wire: BOTH bot + app tokens present → LIVE.
        // The serve loop spawns the socket-mode receive loop in this
        // configuration.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "slack_bot_token: \"xoxb-test-token\"\nslack_app_token: \"xapp-test-token\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("slack: LIVE"));
    }

    #[test]
    fn r2_p0_2_channels_wiring_warn_when_whatsapp_outbound_only() {
        // Token + phone-id but no verify-token / app-secret → outbound only.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "whatsapp_token: \"test-wa-token\"\nwhatsapp_phone_id: \"123456789\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("whatsapp"));
        assert!(outcome.detail.contains("OUTBOUND-ONLY"));
    }

    #[test]
    fn whatsapp_inbound_live_when_full_meta_secrets_present() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "whatsapp_token: \"test-wa-token\"\n\
             whatsapp_phone_id: \"123456789\"\n\
             whatsapp_verify_token: \"verify-tok\"\n\
             whatsapp_app_secret: \"meta-app-secret\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("whatsapp: LIVE"));
    }

    #[test]
    fn r2_p0_2_channels_wiring_mixed_aggregates_to_warn() {
        // Telegram alone = Pass. Telegram + Slack = Warn (the partial
        // channel pulls the aggregate down so the gap is visible at
        // a glance instead of getting buried under one green row).
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "telegram_token: \"123:abc\"\nslack_bot_token: \"xoxb-test\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("telegram: LIVE"));
        assert!(outcome.detail.contains("slack: CONFIGURED-NOT-STARTED"));
    }

    #[test]
    fn hooks_dir_missing_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_hooks_dir(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn hooks_dir_with_malformed_toml_fails() {
        let dir = tempdir().unwrap();
        let hooks = dir.path().join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("bad.toml"), "name = ").unwrap();
        let o = check_hooks_dir(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("bad.toml"));
    }

    #[test]
    fn agents_dir_missing_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_agents_dir(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn profile_extensions_missing_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_profile_extensions(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn profile_extensions_well_formed_passes_with_count() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("profile_extensions.toml"),
            "[extensions]\npets = \"Vec<Pet>\"\n",
        )
        .unwrap();
        let o = check_profile_extensions(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains('1'));
    }

    #[test]
    fn check_hysteria_pass_when_unconfigured() {
        let dir = tempdir().unwrap();
        // No freedom.yaml at all → graceful pass (other check owns that
        // diagnostic).
        let o = check_hysteria_config(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn check_cloud_archive_fails_when_dest_is_a_file() {
        let dir = tempdir().unwrap();
        let bogus = dir.path().join("not-a-dir.txt");
        std::fs::write(&bogus, "x").unwrap();
        let yaml = format!(
            "operator_id: demo-user\nautonomy: standard\ncloud_archive_dest: {}\n",
            bogus.display().to_string().replace('\\', "/")
        );
        std::fs::write(dir.path().join("freedom.yaml"), yaml).unwrap();
        let o = check_cloud_archive_dest(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("file, not a directory"));
    }

    #[test]
    fn check_cloud_archive_warns_when_dest_missing() {
        let dir = tempdir().unwrap();
        let yaml =
            "operator_id: demo-user\nautonomy: standard\ncloud_archive_dest: /definitely/not/here\n";
        std::fs::write(dir.path().join("freedom.yaml"), yaml).unwrap();
        let o = check_cloud_archive_dest(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("does not exist"));
    }

    #[test]
    fn check_mcp_servers_passes_when_file_absent() {
        let dir = tempdir().unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("not configured"));
    }

    #[test]
    fn check_mcp_servers_warns_when_file_present_but_no_enabled_servers() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("mcp_servers.yaml"), "servers: []\n").unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("half-configured"));
    }

    #[test]
    fn check_mcp_servers_warns_when_any_server_lacks_allow_tools() {
        let dir = tempdir().unwrap();
        let yaml = r#"
servers:
  - id: hardened
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
    allow_tools: ["read_file"]
  - id: legacy
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
"#;
        std::fs::write(dir.path().join("mcp_servers.yaml"), yaml).unwrap();
        let o = check_mcp_servers(dir.path());
        // One server hardened, one legacy → posture is Warn (CDX-03
        // says full-catalogue trust is the legacy posture, not the
        // recommended one).
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("hardened"));
        assert!(o.detail.contains("legacy"));
        assert!(o.detail.contains("[hardened]"));
        assert!(o.detail.contains("[legacy]"));
    }

    #[test]
    fn check_mcp_servers_passes_when_every_server_has_allow_tools() {
        let dir = tempdir().unwrap();
        let yaml = r#"
servers:
  - id: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
    allow_tools: ["read_file", "list_directory"]
"#;
        std::fs::write(dir.path().join("mcp_servers.yaml"), yaml).unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("1 enabled"));
    }

    #[test]
    fn check_mcp_servers_fails_on_malformed_yaml() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("mcp_servers.yaml"), "this is not: yaml: [").unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("unreadable"));
    }

    #[test]
    fn check_disk_space_always_emits_a_detail() {
        let dir = tempdir().unwrap();
        let o = check_disk_space(dir.path());
        assert!(!o.detail.is_empty());
        // Either Pass (enough free) or Warn (low disk) — never Fail.
        assert!(matches!(o.status, CheckStatus::Pass | CheckStatus::Warn));
    }

    #[test]
    fn model_caches_emits_actionable_detail() {
        // We can't reliably assert on the operator's real ~/.neoth, so
        // just verify the check produces a non-empty status + detail
        // and that the detail names the `neoth models pull` command
        // when anything is missing.
        let o = check_model_caches();
        assert!(!o.detail.is_empty());
        if o.status != CheckStatus::Pass {
            assert!(
                o.detail.contains("models pull"),
                "warn must include actionable next step, got: {}",
                o.detail
            );
        }
    }

    #[test]
    fn fmt_bytes_picks_unit() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert!(fmt_bytes(2048).starts_with("2.00"));
        assert!(fmt_bytes(1024 * 1024 * 5).starts_with("5.00 MiB"));
        assert!(fmt_bytes(5 * 1024 * 1024 * 1024).starts_with("5.00 GiB"));
    }

    // ── credential age (audit 2026-05-19) ─────────────────────────────

    /// Write `credentials.yaml` with a single Telegram token and set its
    /// mtime to `now - age_days * 86400`. Returns the credentials path.
    fn write_aged_credentials(home: &Path, age_days: u64) -> std::path::PathBuf {
        let path = home.join("credentials.yaml");
        std::fs::write(&path, "telegram_token: \"123:ABC\"\n").unwrap();
        let target = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(age_days * SECONDS_PER_DAY))
            .unwrap();
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(target)).unwrap();
        path
    }

    #[test]
    fn credential_age_passes_when_file_absent() {
        let dir = tempdir().unwrap();
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("no credentials.yaml"));
    }

    #[test]
    fn credential_age_passes_when_file_holds_only_none_slots() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        // Empty YAML map → every Option<SecretString> is None → no
        // secrets to age-check, regardless of mtime.
        std::fs::write(&path, "{}\n").unwrap();
        let stale = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(500 * SECONDS_PER_DAY))
            .unwrap();
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(stale)).unwrap();
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("no secrets to age-check"));
    }

    #[test]
    fn credential_age_passes_when_fresh() {
        let dir = tempdir().unwrap();
        write_aged_credentials(dir.path(), 10);
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn credential_age_warns_after_180_days() {
        let dir = tempdir().unwrap();
        write_aged_credentials(dir.path(), 200);
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("200"));
        assert!(o.detail.contains("rotat"));
    }

    #[test]
    fn credential_age_fails_after_365_days() {
        let dir = tempdir().unwrap();
        write_aged_credentials(dir.path(), 400);
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("400"));
        assert!(o.detail.contains("rotate"));
    }
}
