---
tags: [local-ai, llm, quantization, vram]
---
# Local AI: Inference & Quantization

Als Offline-Daemon muss NEOTH den Operator beim Management lokaler Modelle unterstützen.

## Inference Engines
- **llama.cpp:** Standard für GGUF-Formate. Fokus auf CPU/Apple-Silicon und Partial-GPU-Offloading.
- **vLLM:** Fokus auf High-Throughput (Server), PagedAttention für extrem lange Kontexte, Continuous Batching.
- **ExLlamaV2:** Geringster VRAM-Overhead, höchste Tokens/s (t/s) für reine GPU-Setups (braucht EXL2 Formate).

## Quantisierung
- **GGUF (K-Quants):** Q4_K_M ist der Sweetspot zwischen VRAM-Ersparnis und Perplexitäts-Verlust.
- **EXL2 (Variable Bitrate):** Erlaubt exakte bpw (bits-per-weight) Zielgrößen, um Modelle präzise in z.B. 24GB VRAM (RTX 4090/3090) einzupassen (z.B. 4.5 bpw für ein 34B Modell).

## Memory & Context
- **KV-Cache:** Wächst linear mit der Kontextlänge. Bei OOM-Gefahr den KV-Cache quantisieren (8-bit) oder Flash Attention aktivieren.
- **RoPE Scaling:** Um Modelle über ihre trainierte Kontextlänge zu strecken (z.B. YaRN).
