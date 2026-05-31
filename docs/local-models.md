# Local Models

Local models let NEOTH learn, recall, transcribe, embed, and reason without sending private context to a cloud provider by default.

## Model roles

| Model | Role | Why it exists |
| :-- | :-- | :-- |
| **Qwen** | Local profile extraction and lightweight reasoning. | Keeps continuous learning private and cheap. |
| **Ouro** | Local thinking/reasoning provider. | Gives NEOTH an operator-owned reasoning path. |
| **CLIP** | Image embeddings. | Enables image recall and visual file search. |
| **Whisper** | Audio/video transcription. | Voice notes, meetings, videos, calls, and audio attachments. |
| **Llama/Unsloth-family models** | Optional local answer providers when hardware allows. | Lets operators trade cloud quality for local control. |

## Install models

```bash
neoth model list
neoth model fetch qwen
neoth model fetch ouro
neoth model fetch clip
neoth model fetch whisper
```

Inspect:

```bash
neoth models list
neoth doctor
```

## Hardware guidance

| Hardware | Good for |
| :-- | :-- |
| CPU-only | Recall, WAL, profile browsing, small local tasks, slower transcription. |
| 4-8 GB VRAM | Small Qwen/Ouro profile learning, CLIP, Whisper smaller modes. |
| 12-24 GB VRAM | Stronger local reasoning, larger Whisper, richer multimodal work. |
| 24+ GB VRAM | Larger local models and cluster/resource sharing. |

The wizard should recommend models based on detected RAM, VRAM, GPU family, disk, and operator goals.

## Configuration

Typical `~/.neoth/inference.toml`:

```toml
[inference]
allow_cloud_fallback = false

[models.qwen]
enabled = true
path = "~/.neoth/models/qwen"

[models.ouro]
enabled = true
path = "~/.neoth/models/ouro"

[models.clip]
enabled = true
path = "~/.neoth/models/clip"

[models.whisper]
enabled = true
path = "~/.neoth/models/whisper"
```

## Privacy posture

| Setting | Meaning |
| :-- | :-- |
| `allow_cloud_fallback = false` | If local extraction fails, skip learning instead of sending private context to cloud. |
| `allow_cloud_fallback = true` | Cloud fallback is allowed and should be visible in privacy audit. |
| Local model missing | NEOTH should surface the missing model and show the fetch command. |
| Model cache verified | NEOTH can use the model without re-downloading. |

Audit:

```bash
neoth privacy audit --last 30d
neoth doctor
```

## Cache layout

```text
~/.neoth/models/
  qwen/
  ouro/
  clip/
  whisper/
```

NEOTH should treat model downloads as explicit operator actions, log them, and avoid repeated downloads when a verified cache exists.

## OOM and performance

If local models are slow or failing:

```bash
neoth doctor
neoth status
neoth hardware
```

Common fixes:

| Symptom | Fix |
| :-- | :-- |
| GPU OOM | Pick a smaller quant, reduce context, unload another model. |
| CPU too slow | Use cloud for response generation but keep profile extraction local. |
| Whisper slow | Use a smaller Whisper profile or GPU acceleration. |
| Model missing | `neoth model fetch <name>`. |
| Privacy fallback warning | Keep fallback disabled or explicitly accept the tradeoff. |

## Local provider selection

NEOTH can use local models for:

- profile extraction
- embeddings
- recall enrichment
- transcription
- visual search
- coding support
- reasoning when hardware is sufficient

Cloud providers remain useful for high-end reasoning. The point is operator choice and visible routing, not pretending every laptop can run every model well.
