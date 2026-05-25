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

If a process is running: stop it first (`neoth stop` or `kill <pid>`), then start again.

If no process is running but the lock file exists (crashed process):

```
rm ~/.neoth/wal/telegram.lock
neoth start
```

If you previously registered a webhook with Telegram (e.g., for WhatsApp testing) and now
want polling:

```
neoth channel telegram clear-webhook
neoth start
```

---

## Cargo build errors

**Symptom:** `cargo build --release` fails.

**Rust version too old:**

```
error: package `neoth v1.0.0` cannot be built because it requires rustc 1.86.0 or newer
```

Fix:

```
rustup update stable
rustc --version    # verify 1.86+
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
cargo build --release --no-default-features --features cli,wal,channels
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
neoth wal verify          # identify the corrupted segment
neoth wal recover --from-checkpoint 0003.cpt   # recover from an earlier checkpoint
```

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

After login, run `neoth start` again.

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
[neoth] WARN: Local inference unavailable — CUDA out of memory
[neoth] Profile extraction skipped (allow_cloud_fallback=false)
event 0x3A LOCAL_INFERENCE_UNAVAILABLE
```

**Cause:** Another process is using the GPU memory that Qwen3-4B needs (~3 GB VRAM).

**Fixes:**

Option 1 — Free GPU memory and restart Neoth:

```
neoth stop
# stop whatever is using the GPU
neoth start
```

Option 2 — Configure Neoth to use a different GPU:

```toml
# ~/.neoth/inference.toml
[runtime]
device = "cuda:1"      # try the second GPU if you have one
```

Option 3 — Use a smaller model (less VRAM):

```
neoth model fetch qwen3-1.7b-int4   # ~1.5 GB VRAM
```

Update `inference.toml`:

```toml
[models.generative.priority]
order = ["local_qwen3_1b7", "local_qwen3_4b"]
```

Option 4 — CPU fallback (slow but works):

```toml
[runtime]
device = "cpu"
```

Extraction will take several minutes per turn on CPU. Consider reducing extraction frequency.

Option 5 — Allow cloud fallback when local is down:

```yaml
# freedom.yaml
inference:
  allow_cloud_fallback: true
```

This sends conversation text to the cloud for extraction when local is unavailable. Read
[local-models.md](local-models.md) before enabling.

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
neoth wal stats           # show segment sizes and count
```

Delete old WAL segments you no longer need:

```
neoth wal compact --force     # run compaction immediately
neoth wal prune --older-than 90d   # remove segments older than 90 days
```

Or free disk space elsewhere, then:

```
neoth start               # will resume if disk is now below refuse_start_pct
```

Adjust thresholds in freedom.yaml if you want earlier warnings:

```yaml
storage:
  disk_thresholds:
    warn_pct: 60           # warn earlier
    refuse_start_pct: 90   # refuse earlier
```
