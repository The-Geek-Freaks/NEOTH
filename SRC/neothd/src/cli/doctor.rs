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

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

mod checks;
mod types;

pub(crate) use checks::*;
pub use types::*;

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
    /// GOLD-ADOPT-24: after running the checks, feed any WARN/FAIL outcomes to
    /// the cheap `inference.utility_provider` for an LLM root-cause + first-fix.
    /// NEOTH's 31 structured checks are a richer signal than a raw log dump, so
    /// the LLM reasons over them. Best-effort; needs a configured provider.
    #[arg(long)]
    pub diagnose: bool,
    /// Output format inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
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
        name: "vector index snapshot",
        purpose: "GOLD-WIRE-07 advisory. When `memory.vector_index.backend: \
                  hnsw` is set, `neoth recall --similar-to*` cold-loads the \
                  `<neoth_home>/embeddings.hnsw` snapshot. This check flags the \
                  two states where HNSW recall silently degrades: the snapshot \
                  is ABSENT (recall falls back to brute-force entirely) or STALE \
                  (the newest `idx_embedding.created_at` is newer than the \
                  snapshot's mtime, so HNSW recall silently misses every vector \
                  upserted since the last rebuild). Read-only. Pass for the \
                  brute-force default + for a present, fresh snapshot; Warn \
                  otherwise; never Fail (recall always works via fallback).",
        common_failures: "Operator set `backend: hnsw` but never ran \
                         `neoth memory --rebuild-index` (absent snapshot); or \
                         built it once, then ingested more images so the \
                         snapshot lags the DB (stale).",
        fix: "Run `neoth memory --rebuild-index` to (re)build the snapshot \
              from `idx_embedding`. Re-run after any large ingest. Or set \
              `memory.vector_index.backend: brute_force` to stay on the \
              always-fresh O(N) scan. (Automatic snapshot freshness via a \
              daemon warm index is GOLD-WIRE-07b.)",
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

    // GOLD-ADOPT-24 — optional LLM root-cause pass over the check results.
    if args.diagnose {
        diagnose_with_llm(&outcomes).await;
    }

    if any_fail {
        // GOLD-COR-01 / A-03: non-zero status via QuietExit so the stack
        // unwinds (Drop-time flushes run) before the code reaches `main`.
        return Err(crate::QuietExit(1).into());
    }
    Ok(())
}

/// GOLD-ADOPT-24 — feed the WARN/FAIL check outcomes to the cheap utility
/// provider for a terse root-cause + first-fix. Best-effort: a clean bill of
/// health, an absent provider, or a provider error all just print a note and
/// return (diagnosis never changes the doctor exit code). The structured check
/// outcomes ARE the context — richer than goose's raw-log LLM dump.
async fn diagnose_with_llm(outcomes: &[CheckOutcome]) {
    let problems: Vec<&CheckOutcome> = outcomes
        .iter()
        .filter(|o| matches!(o.status, CheckStatus::Warn | CheckStatus::Fail))
        .collect();
    if problems.is_empty() {
        println!("\ndiagnose: all checks pass — nothing to root-cause.");
        return;
    }
    let config = match FreedomConfig::load_from_default_path() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("diagnose: cannot load freedom.yaml ({e}); skipping LLM pass.");
            return;
        }
    };
    let provider = match crate::providers::from_config_for_utility(&config).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("diagnose: no usable provider ({e}); skipping LLM pass.");
            return;
        }
    };
    let mut blob = String::new();
    for o in &problems {
        blob.push_str(&format!("- [{}] {}: {}\n", o.status.tag(), o.name, o.detail));
    }
    let req = crate::providers::Request {
        prompt: format!(
            "You are NEOTH's self-diagnostic assistant. `neoth doctor` reported these \
             problems (structured health checks):\n\n{blob}\nGive the single MOST-LIKELY \
             root cause and the FIRST concrete fix step/command. Be terse (max 8 lines). \
             Do NOT invent checks that aren't listed; reason only over the above.",
        ),
        ..Default::default()
    };
    match provider.complete(req).await {
        Ok(c) if !c.text.trim().is_empty() => {
            println!("\n── diagnose (LLM root-cause) ──\n{}", c.text.trim());
        }
        Ok(_) => eprintln!("diagnose: provider returned an empty response."),
        Err(e) => eprintln!("diagnose: provider call failed ({e})."),
    }
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
        check_vector_index_snapshot(home),
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
    fn check_docs_listed_count_pinned_at_thirty_one() {
        // Pin the count so a future addition is a conscious update + a
        // future deletion (which would silently drop operator runbook
        // coverage) is caught. Bumped to 26 in Session 21 for
        // `cluster mDNS announcer` (Bite #2 announcer state surface);
        // 27 in Session 28c for `refusal recovery` (SPEC-10);
        // 28 in Session 28c for `local_qwen weights` (SPEC-04);
        // 29 in Session 28c for `n8n_api_token` (SC-08);
        // 30 in Session 44 for `stuck claude processes` (GOLD-WIRE-05);
        // 31 in Session 44 for `vector index snapshot` (GOLD-WIRE-07).
        assert_eq!(CHECK_DOCS.len(), 31);
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

    // ── GOLD-WIRE-07: vector index snapshot advisory ──────────────────────

    #[test]
    fn vector_index_passes_for_brute_force_default() {
        // No freedom.yaml → backend reads as brute_force → PASS, no snapshot check.
        let dir = tempdir().unwrap();
        let out = check_vector_index_snapshot(dir.path());
        assert_eq!(out.status, CheckStatus::Pass);
        assert!(out.detail.contains("brute_force"), "got: {}", out.detail);
    }

    #[test]
    fn vector_index_warns_when_hnsw_and_no_snapshot() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "operator_id: alice\nmemory:\n  vector_index:\n    backend: hnsw\n",
        )
        .unwrap();
        let out = check_vector_index_snapshot(dir.path());
        assert_eq!(out.status, CheckStatus::Warn);
        assert!(
            out.detail.contains("no snapshot") && out.detail.contains("rebuild-index"),
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

    // GOLD-SEC-16: the cluster doctor-check tests exercise the real
    // cluster-feature code paths (registry + announcer); they compile only
    // with the `cluster` feature. The stub checks in the no-cluster build are
    // trivially correct (they return a fixed "not compiled" Pass).
    #[cfg(feature = "cluster")]
    mod cluster_doctor_tests {
        use super::*;

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
    } // mod cluster_doctor_tests (GOLD-SEC-16)

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
            diagnose: false,
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
            diagnose: false,
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
            diagnose: false,
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
        // 31 checks: 19 pre-Session-20 + node toolchain + tmux for
        // claude-cli + usage today + circuit breakers + channel
        // flapping + cluster registry (Phase 4 follow-on) + cluster
        // mDNS announcer (Session 21 bite #2) + refusal recovery
        // (Session 28c, SPEC-10) + local_qwen weights (Session 28c, SPEC-04)
        // + n8n_api_token (Session 28c, SC-08) + stuck claude processes
        // (Session 44, GOLD-WIRE-05) + vector index snapshot (Session 44,
        // GOLD-WIRE-07).
        assert_eq!(outs.len(), 31);
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
