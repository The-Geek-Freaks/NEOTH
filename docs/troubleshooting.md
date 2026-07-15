# Troubleshooting

---

## Telegram webhook conflict

**Symptom:**

```
[neoth] ERROR: Telegram adapter failed to start
  cause: Another instance holds the lock at ~/.neoth/wal/telegram.lock
```

or:

```
[neoth] ERROR: Telegram polling: 409 Conflict — duplicate webhook
```

**Cause:** Another Neoth process (or a crashed one) is holding the Telegram lock file,
or a previous run registered a webhook that conflicts with polling mode.

**Fix:**

Check if another Neoth is actually running:

```
ps aux | grep neoth
```

If a process is running: stop it first (`kill $(cat ~/.neoth/neothd.pid)`, or Ctrl-C if
it is running in the foreground), then start again. To check: `cat ~/.neoth/neothd.pid`
then `ps -p <pid>` (or `neoth status`).

If no process is running but the lock file exists (crashed process):

```
rm ~/.neoth/wal/telegram.lock
neoth serve
```

If you previously registered a webhook with Telegram (e.g., for WhatsApp testing) and now
want polling:

```
neoth channel telegram clear-webhook
neoth serve
```

---

## Cargo build errors

**Symptom:** `cargo build --release` fails.

**Rust version too old:**

```
error: package `neoth v1.0.0` cannot be built because it requires rustc 1.90.0 or newer
```

Fix:

```
rustup update stable
rustc --version    # verify 1.90+
cargo build --release
```

**Missing system dependencies (Linux):**

```
error: failed to run custom build command for `openssl-sys`
```

Fix (Debian/Ubuntu):

```
sudo apt install libssl-dev pkg-config build-essential
```

**CUDA not found (for local model support):**

```
error: CUDA not found. Set CUDA_HOME or disable GPU features.
```

If you don't need GPU: build without GPU feature:

```
cargo build --release
```

If you have CUDA: ensure `nvcc` is in PATH and `CUDA_HOME` is set:

```
export CUDA_HOME=/usr/local/cuda
cargo build --release
```

---

## WAL CRC errors

**Symptom:**

```
[neoth] ERROR: WAL frame CRC mismatch at offset 12345678 in segment 0004.wal
[neoth] Attempting recovery from last checkpoint...
```

**Cause:** The WAL segment was corrupted — typically from a power loss, disk full event,
or disk error.

**Recovery procedure:**

Neoth attempts automatic recovery from the last valid checkpoint file (`.cpt`). If that works,
you will see:

```
[neoth] Recovery OK: applied checkpoint 0004.cpt, 1,234 events replayed
[neoth] Discarded 45 events after corruption point
```

The discarded events are lost. Profile learning and recall may be slightly behind — this is
acceptable.

If automatic recovery fails:

```
neoth verify              # identify the corrupted segment (HMAC audit-chain check)
```

NEOTH recovers automatically from the newest valid checkpoint on the next
`neoth serve` start; there is no manual recover subcommand.

**Prevention:** Do not use a WAL directory on a network filesystem or unreliable USB storage.
Keep `~/.neoth/wal/` on a local disk. The default disk thresholds in freedom.yaml prevent
writing when disk is near full (`refuse_start_pct: 95`).

---

## LLM CLI auth failures

**Symptom:**

```
[neoth] ERROR: Left Hemisphere request failed
  cause: claude: authentication required. Run `claude login` first.
```

or similar for `codex` or `gemini`.

**Fix:**

Authenticate the CLI tool directly:

```
claude login          # opens browser for OAuth
codex login           # same
gemini auth login     # same
```

After login, run `neoth serve` again.

**API key mode:** If you're using API keys instead of OAuth:

Check the key is set and not expired:

```
echo $ANTHROPIC_API_KEY | head -c 20    # should start with sk-ant-
```

Test directly:

```
claude --model claude-opus-4-7 "ping"
```

If this fails, the key is invalid or the env variable is not set in the shell Neoth is running in.

---

## Local model OOM

**Symptom:**

```
local inference failed: ... out of memory ...
profile.learn pass skipped: learn_provider build failed and
allow_cloud_fallback=false
```

**Cause:** The selected local checkpoint plus its activation/KV-cache budget
does not fit the available GPU or system memory, or another process already
occupies that memory.

**Fixes:**

Option 1 — Stop the running `neoth serve`, free GPU memory, and start it again:

```bash
# stop the foreground service with Ctrl-C, then stop other GPU workloads
neoth serve
```

Option 2 — Ask the hardware-aware selectors what fits, then re-run onboarding
with a compatible local provider/checkpoint:

```bash
neoth hardware
neoth models recommend
neoth models fit
neoth init --force
```

Option 3 — Force CPU inference. Configuration lives in
`~/.neoth/freedom.yaml`, not `inference.toml`:

```yaml
inference:
  accelerator_override: cpu
```

CPU inference can be much slower. Keep `profile.learn_enabled: false` when the
extra extraction latency is not acceptable.

Option 4 — Allow cloud fallback for profile extraction only when that egress is
intentional:

```yaml
# ~/.neoth/freedom.yaml
profile:
  allow_cloud_fallback: true
```

This may send the profile-extraction conversation window to the configured main
cloud provider when the local learn provider cannot be built. Read
[local-models.md](local-models.md) before enabling it.

---

## Disk full — Neoth refusing inbound

**Symptom:**

```
[neoth] CRITICAL: Disk usage 96% — above refuse_start_pct threshold
[neoth] Refusing to process inbound messages until disk is freed.
```

**Fix:**

Check what is taking disk:

```
du -sh ~/.neoth/wal/
neoth wal stats ~/.neoth/wal/000001.wal   # per-segment frame count + sizes
```

The daemon compacts the WAL automatically (it writes periodic HMAC checkpoint
markers and rolls segments). To reclaim space, free disk elsewhere, or back up
and archive old segments:

```
neoth backup                 # snapshot ~/.neoth/ before pruning by hand
# then remove old ~/.neoth/wal/NNNNNN.wal segments you have archived
```

Or free disk space elsewhere, then:

```
neoth serve               # will resume if disk is now below refuse_start_pct
```

Adjust thresholds in freedom.yaml if you want earlier warnings:

```yaml
storage:
  disk_thresholds:
    warn_pct: 60           # warn earlier
    refuse_start_pct: 90   # refuse earlier
```
