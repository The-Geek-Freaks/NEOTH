---
title: "Local AI & Fast Inference: Architektur und Core-Mechanismen"
date: "2026-07-06"
tags: [local-ai, inference, vllm, sglang, llama.cpp, mlx, tensorrt-llm]
author: "Trending Local AI Scout"
type: "wiki-entry"
---

# Local AI & Fast Inference: Architektur und Core-Mechanismen
*RAG-Optimierte Knowledge Base für High-Performance LLM Inference*

[INTENT: Übersicht Local AI & Fast Inference Frameworks]
## Übersicht der Top-Trending Repositories
Die Landschaft der lokalen KI-Inferenz wird maßgeblich von Frameworks dominiert, die sich auf die Reduzierung von Latenz (Time-to-First-Token) und die Maximierung des Durchsatzes konzentrieren. Zu den führenden GitHub-Repositories gehören:
- **vLLM**: Spezialisiert auf extrem hohen Durchsatz bei Server-Workloads durch PagedAttention.
- **SGLang**: Fokussiert auf agentische Workloads und komplexe Prompt-Pipelines via RadixAttention.
- **llama.cpp**: Der Standard für CPU/Mac/Consumer-Hardware-Inferenz dank GGUF und extremer Quantisierung ohne externe Abhängigkeiten.
- **MLX**: Apples natives Framework zur maximalen Ausnutzung der Unified Memory Architecture auf Apple Silicon.
- **TensorRT-LLM**: NVIDIAs High-Performance-Compiler und Runtime für maximale Auslastung von Data-Center-GPUs.

[INTENT: Funktionsweise PagedAttention vLLM Architektur]
## vLLM & PagedAttention
**Das Problem:** Traditionelle LLM-Inferenz reserviert für jede Sequenz einen zusammenhängenden Block im GPU-Speicher basierend auf der Maximallänge der Sequenz. Das führt zu massiver Fragmentierung und Speicherverschwendung (oft über 60%), da generierte Sequenzen meist kürzer sind als das Maximum.

**Der Mechanismus (PagedAttention):**
Inspiriert von virtuellem Speichermanagement in Betriebssystemen, unterteilt PagedAttention den Key-Value (KV) Cache in Seiten (Pages) bzw. Blöcke. 
- Jeder Block speichert Keys und Values für eine feste Anzahl von Token (z. B. 16).
- Anstatt zusammenhängenden Speicher zu verlangen, werden Blöcke dynamisch und nicht-zusammenhängend im physischen VRAM allokiert.
- Eine **Block Table** mappt die logischen Token auf ihre physischen Speicherorte.
- Der spezielle PagedAttention-CUDA-Kernel liest diese Tabellen "on-the-fly" während der Attention-Berechnung aus.

**Vorteile:** Nahezu keine interne Speicherfragmentierung (<4%), einfaches Memory-Sharing (z. B. bei Parallel Sampling) und bis zu 24x höherer Durchsatz bei vielen gleichzeitigen Requests.

[INTENT: Funktionsweise RadixAttention SGLang Architektur]
## SGLang & RadixAttention
**Das Problem:** Bei agentischen Workflows, RAG-Anwendungen oder Multi-Turn-Chats teilen viele Anfragen denselben System-Prompt oder Kontext. Standard-Engines berechnen den KV-Cache für diese identischen Präfixe bei jeder neuen Anfrage komplett neu, was extrem rechen- und speicherintensiv ist.

**Der Mechanismus (RadixAttention):**
SGLang speichert den KV-Cache nicht als flache Liste, sondern als **Radix Tree (komprimierter Trie)**.
- Token-Sequenzen bilden Pfade im Baum.
- Wenn eine neue Anfrage eintrifft, führt der SGLang-Scheduler ein **Prefix-Matching** im Radix-Tree durch. Er sucht die längste bereits berechnete Token-Sequenz (z.B. den System-Prompt).
- Der KV-Cache für dieses Präfix wird direkt wiederverwendet (Zero-Overhead). Die GPU berechnet im "Prefill"-Schritt nur noch die tatsächlich neuen Token.
- Eine LRU-Eviction-Policy (Least Recently Used) sorgt dafür, dass selten genutzte Äste bei VRAM-Mangel gelöscht werden, während häufige Prompts im Speicher bleiben.

**Vorteile:** Drastisch reduzierte Latenz (TTFT) bei RAG/Agenten-Systemen und stark verringerter VRAM-Bedarf.

[INTENT: Funktionsweise Speculative Decoding LLM Inference]
## Speculative Decoding (Spekulative Dekodierung)
**Das Problem:** Die autoregressive Textgenerierung (Token für Token) ist extrem **Memory-Bandwidth-Bound**. Die GPU-Compute-Kerne (ALUs) langweilen sich, während sie darauf warten, dass die riesigen Modellgewichte für jedes einzelne Token aus dem HBM-Speicher (VRAM) geladen werden.

**Der Mechanismus:**
Speculative Decoding ändert das Paradigma zu **"Draft-then-Verify"**:
1. **Drafting (Entwurf):** Ein viel kleineres, extrem schnelles "Draft"-Modell (oder N-Grams) generiert parallel mehrere Token (z. B. $K=4$ Token) auf einmal.
2. **Verification (Verifizierung):** Das große, genaue "Target"-Modell erhält diese $K$ Token und verarbeitet sie in einem *einzigen* parallelen Forward-Pass.
3. Stimmen die Vorhersagen des großen Modells mit den Entwürfen überein, werden alle Token direkt akzeptiert. 
4. Bei einer Abweichung wird die Sequenz am Fehlerpunkt abgeschnitten, das Token des Target-Modells wird übernommen, und der Prozess startet neu.

**Vorteile:** 2-3x höhere Generierungsgeschwindigkeit (Tokens/sec) **ohne jeglichen Verlust an Output-Qualität**, da das große Modell stets das finale Wort hat.

[INTENT: Funktionsweise MLX Apple Silicon Architecture]
## MLX Framework (Apple Silicon)
**Das Problem:** Traditionelle Frameworks wie PyTorch wurden primär für diskrete GPUs (NVIDIA/AMD) entwickelt. Auf Macs führt dies oft zu ineffizienten Datenkopien zwischen CPU-RAM und GPU.

**Der Mechanismus:**
MLX ist tief auf Hardwareebene an Apples Architektur angepasst:
- **Unified Memory Architecture (UMA):** Arrays und Tensoren leben im geteilten Arbeitsspeicher. CPU, GPU (Metal) und Neural Engine greifen mit **Zero-Copy-Semantics** auf dieselben Daten zu. PCIe-Flaschenhälse entfallen komplett.
- **Lazy Computation:** Operationen werden nicht sofort ausgeführt. MLX baut einen verzögerten Computation Graph auf. Dies ermöglicht **Automatic Kernel Fusion**, bei der mehrere kleine Berechnungen in einen einzigen, hocheffizienten GPU-Aufruf verschmolzen werden.

[INTENT: Funktionsweise TensorRT-LLM NVIDIA Architecture]
## TensorRT-LLM (NVIDIA Fast Inference)
**Der Mechanismus:**
TensorRT-LLM ist kein einfaches Framework, sondern ein hochoptimierter Compiler und eine Runtime.
- **Offline Build Phase:** Modelle werden vorab via `trtllm-build` in statische, hardware-optimierte Engines (Binaries) kompiliert, welche auf exakt die vorliegende GPU-Architektur (z.B. Hopper / Ampere) zugeschnitten sind. Hierbei werden Kernels fusioniert.
- **In-Flight (Continuous) Batching:** Statt zu warten, bis alle Anfragen eines Batches fertig sind, schleust TensorRT-LLM neue Requests millisekundengenau in den aktuell laufenden Batch ein (Ersatz fertiggestellter Sequenzen). Das maximiert die Sättigung der GPU-Compute-Ressourcen.

[INTENT: Funktionsweise llama.cpp GGUF Architecture]
## llama.cpp & GGUF Format
**Der Mechanismus:**
- **Zero-Dependency C/C++:** Verzichtet auf Python und externe Frameworks. Nutzt direkt nativen Code mit handoptimierten SIMD-Instruktionen (AVX2, AVX-512, NEON) und Metal/CUDA-Backends.
- **mmap (Memory-Mapping) & GGUF:** GGUF ist ein All-in-One Dateiformat. Via `mmap` werden Modelle nicht aktiv in den RAM kopiert, sondern das Betriebssystem lagert nur die physischen Speicherseiten in den RAM ein, auf die aktuell zugegriffen wird (Instant-Loading).
- **K-Quants:** Hochkomplexe blockweise Quantisierungen (z. B. Q4_K_M), die den VRAM-/RAM-Bandbreitenbedarf massiv reduzieren, während die Genauigkeit der Modelle aufrechterhalten wird.
