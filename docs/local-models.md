# Local Models

Local models let NEOTH learn, transcribe, embed, and reason without sending the
input to a cloud model. The model families do not share one installer: Qwen is
selected through onboarding, Ouro has its own catalogue and fetch command, and
the `models` command manages the CLIP and Whisper media caches.

## Model roles

| Model | Role | Why it exists |
| :-- | :-- | :-- |
| **Qwen** | Local profile extraction, embeddings, and an optional local chat provider. | Keeps sensitive learning and inference on the operator's machine. |
| **Ouro** | Optional local thinking/reasoning provider. | Provides an operator-owned LoopLM reasoning path. |
| **CLIP** | Image and text embeddings. | Enables image recall and visual file search. |
| **Whisper** | Audio/video transcription. | Handles voice notes, meetings, videos, calls, and audio attachments. |
| **Ollama/GGUF models** | Optional local answer providers selected for the available hardware. | Lets operators trade cloud quality for local control. |

## Install and inspect

Managed media models:

```bash
neoth models list
neoth models pull clip
neoth models pull whisper
```

`whisper` follows the effective `media.stt` configuration. Use
`whisper-candle` or `whisper-faster` when you deliberately want one backend:

```bash
neoth models pull whisper-candle
neoth models pull whisper-faster
```

Qwen is intentionally not a `neoth models pull` target because onboarding
sizes the local-inference topology before choosing the repository. Configure it
through the wizard or explicitly re-run onboarding:

```bash
neoth init --force --provider local_qwen \
  --provider-model Qwen/Qwen2.5-3B-Instruct
neoth doctor
```

When the selected Qwen artifacts are not present, the provider downloads them
on first construction subject to `updater.allow_huggingface_downloads` and the
model-download audit gate. For an offline machine, populate the exact cache path
reported by the error on a connected machine first.

Ouro has a separate, pinned checkpoint catalogue:

```bash
neoth ouro list
neoth ouro fetch --checkpoint ByteDance/Ouro-1.4B-Thinking
neoth init --force --provider local_ouro \
  --provider-model ByteDance/Ouro-1.4B-Thinking
neoth ouro status
```

For Ollama/GGUF choices, ask the hardware-aware selector instead of guessing a
model that may not fit:

```bash
neoth models recommend
neoth models fit
```

## Configuration

Model configuration lives in `~/.neoth/freedom.yaml`; there is no separate
`inference.toml`. A local-Qwen main provider with local, fail-closed profile
learning looks like this:

```yaml
provider_kind: local_qwen
provider_model: Qwen/Qwen2.5-3B-Instruct

profile:
  learn_enabled: true
  learn_provider: local_qwen
  allow_cloud_fallback: false

inference:
  mode: single
  accelerator_override: cuda  # optional; omit for auto-detection
  max_new_tokens: 256
```

The main chat provider can remain cloud-backed while profile extraction stays
local:

```yaml
provider_kind: openai_api

profile:
  learn_enabled: true
  learn_provider: local_qwen
  allow_cloud_fallback: false
```

With `allow_cloud_fallback: false`, a missing or unusable local learn provider
skips that learning pass instead of silently sending the conversation window to
the main cloud provider. Set it to `true` only when that egress is intended.

## Cache contract

Qwen and Ouro runtime artifacts are copied into repository-derived directories
under `~/.neoth/models/` (for example
`Qwen-Qwen2.5-3B-Instruct/` or
`ByteDance-Ouro-1.4B-Thinking/`). CLIP, Whisper, and Piper use their canonical
media cache layouts under the same root. Do not depend on guessed folder names:
`neoth models list`, `neoth ouro status`, `neoth tts status`, and `neoth doctor`
report the relevant configured paths and readiness.

Model downloads are explicit or first-use operations, subject to the updater
policy. A verified, complete cache is reused; pending or incomplete downloads
must not be treated as ready.

## Privacy and audit

```bash
neoth privacy audit --last 30d
neoth wal show --type model_download_start
neoth doctor
```

`privacy audit` reports configured posture and the sensitive event categories
recorded in the selected window. It does not prove that every possible outbound
surface emits a WAL frame; see the documented audit exceptions in
[the threat model](security/threat-model.md).

## OOM and performance

```bash
neoth doctor
neoth status
neoth hardware
neoth models fit
```

| Symptom | Fix |
| :-- | :-- |
| GPU OOM | Pick a smaller checkpoint/quant, reduce context, or unload another model. |
| CPU too slow | Keep profile extraction local and use a configured cloud provider for responses. |
| Whisper slow | Select a smaller `media.stt.model_size` or use the configured accelerated backend. |
| CLIP/Whisper missing | Run the matching `neoth models pull <name>` command. |
| Qwen missing | Re-run onboarding/check policy, then let the selected provider populate its exact cache. |
| Ouro missing | Run `neoth ouro fetch [--checkpoint <HF_ID>]`. |
| Privacy fallback warning | Keep fallback disabled or explicitly accept the cloud-egress tradeoff. |

Cloud providers remain useful for high-end reasoning. The contract is operator
choice plus visible routing, not a claim that every laptop can run every model.

## Daemon-owned Ollama operations

When `neoth serve` is running with a configured loopback Ollama endpoint, it
owns the local model inventory, readiness probes, and mutable Ollama work. The
CLI communicates with that daemon through private same-user IPC; it does not
start another controller and it does not send direct Ollama HTTP requests.

```bash
neoth models ollama status --output json
neoth models ollama pull qwen2.5:7b-instruct --output json
neoth models ollama update qwen2.5:7b-instruct --output json
neoth models ollama prune qwen2.5:7b-instruct --output json
neoth models ollama cancel <operation-id> --output json
neoth models ollama retry <operation-id> --output json
neoth models ollama --config "D:/NEOTH Instances/blue/freedom.yaml" status --output json
```

`status` returns the daemon's typed snapshot. It fails visibly when the daemon
or its private local-model service is unavailable. `pull`, `update`, `prune`,
`cancel`, and `retry` return a typed action acknowledgement immediately; a
transfer or reconciliation can continue in the daemon after that response.
Only exact Ollama selectors and daemon-generated operation IDs are accepted.

`--config` is scoped to `models ollama`. Its parent directory selects the same
private IPC instance home as `neoth serve --config`; it does not change the
other `models` commands. Without `--config`, the normal NEOTH home selection
applies, including `NEOTH_HOME`. The desktop GUI inherits its child process
environment, so set `NEOTH_HOME` before launching it when selecting a
nondefault instance; the GUI does not add a separate model-instance switch.

Ready means more than an open port or a model listed by Ollama. NEOTH requires
a successful bounded model-specific inference probe followed by a fresh
matching `/api/ps` digest. A listed, loaded, or reachable model can therefore
remain explicitly unready. A configured non-loopback endpoint is displayed as
unsupported and is not managed.

Only one mutable operation is active at a time. Cancellation is a request, not
proof that the remote engine discarded work. A restart or transport ambiguity
is retained as `interrupted_unknown` and is never automatically replayed.
`retry` is explicit and can only repeat the retained operation's exact action
and model after a confirmed failure; unknown outcomes cannot be retried. Prune first rejects absent, non-exact, or loaded targets, and is
complete only after a fresh inventory proves the selector is gone.
