---
title: "Advanced RAG & Knowledge Graphs"
date: "2026-07-06"
tags: [rag, knowledge-graph, graphrag, llamaindex, ragas, lightrag]
author: "Trending RAG Scout"
type: "wiki-entry"
---

# Advanced RAG & Knowledge Graphs: Technisches Deep-Dive

[INTENT: TRENDING_REPOSITORIES]
## Top-Trending GitHub Repositories im Bereich Advanced RAG & Knowledge Graphs
*   **[microsoft/graphrag](https://github.com/microsoft/graphrag)**: Fokussiert sich auf "Global Search" über den gesamten Korpus mittels hierarchischer Graphen-Extraktion und Community-Detection.
*   **[HKUDS/LightRAG](https://github.com/HKUDS/LightRAG)**: Bietet leichtgewichtiges, graphenbasiertes RAG ("Graph-Enhanced Indexing") mit Dual-Level-Retrieval (Low-Level-Entitäten und High-Level-Konzepte), um Kosten und Latenz zu reduzieren.
*   **[run-llama/llama_index](https://github.com/run-llama/llama_index)**: Das Standard-Framework für Daten-Ingestion und Advanced Chunking-Strategien (z.B. `SemanticSplitterNodeParser`).
*   **[explodinggradients/ragas](https://github.com/explodinggradients/ragas)**: Framework für die automatisierte Evaluierung von RAG-Pipelines nach dem "LLM-as-a-Judge"-Prinzip ohne den zwingenden Bedarf an manuell annotierten Ground-Truth-Datenbanken.

[INTENT: COMMUNITY_DETECTION]
## GraphRAG & Community Detection Algorithmen
Klassisches RAG (Vector Search) scheitert oft an "globalen" Fragen (z.B. "Was sind die Hauptthemen dieses Datensatzes?"), da es nur isolierte Text-Chunks abruft. **GraphRAG** löst dies durch den Einsatz von Community-Detection-Algorithmen und baut eine strukturierte Hierarchie auf.

**Funktionsweise der Pipeline:**
1.  **Knowledge Graph Construction:** Ein LLM extrahiert in der Ingestion-Phase Entitäten (Nodes), Beziehungen (Edges) und Claims aus den Rohdaten und baut so einen weitreichenden Graphen auf.
2.  **Hierarchical Clustering (Community Detection):** Auf diesen Graphen wird ein Algorithmus – typischerweise der **Hierarchical Leiden Algorithmus** – angewendet. Er partitioniert den Graphen rekursiv in sogenannte "Communities" (Cluster stark vernetzter Entitäten). Alternativ evaluiert die Forschung hierfür auch *k-core Decomposition* für spärliche Graphen.
3.  **Community Summarization:** Für jede identifizierte Community generiert das LLM eine strukturierte Zusammenfassung (Summary). Dieser Prozess erfolgt Bottom-Up: Lokale Neighborhood-Summaries verschmelzen rekursiv zu großen thematischen Summaries.
4.  **Retrieval:** Bei einer globalen Anfrage aggregiert das System nicht einfach rohe Chunks, sondern wendet sich den vorberechneten hierarchischen Summaries zu. Das LLM kann so über globale Zusammenhänge schlussfolgern ("Global Reasoning").

[INTENT: SEMANTIC_CHUNKING]
## Semantic Chunking
Anstatt Dokumente stumpf nach Zeichenlänge oder Tokens zu zerschneiden (Fixed-Size Chunking), unterteilt *Semantic Chunking* Texte in Abhängigkeit von ihrer logischen und semantischen Bedeutung.

**Der algorithmische Ablauf (wie in LlamaIndex implementiert):**
1.  **Segmentierung & Embedding:** Der Text wird zunächst in kleinste syntaktische Einheiten (z.B. Einzelsätze) zerlegt. Jeder Satz wird durch ein schnelles Embedding-Modell in einen hochdimensionalen Vektor übersetzt.
2.  **Divergence Analysis:** Das System berechnet sequenziell die Distanz (meist Cosine Distance) zwischen den Embeddings benachbarter Sätze.
3.  **Boundary Detection:** Wenn die semantische Ähnlichkeit zwischen zwei Segmenten unter einen dynamisch ermittelten Schwellenwert fällt (z.B. `breakpoint_percentile_threshold=95` im LlamaIndex `SemanticSplitterNodeParser`), erkennt der Algorithmus einen Themenwechsel. An dieser "Bruchstelle" wird der Cut gesetzt und ein neuer Chunk erzeugt.

*Architektur-Tipp:* Dies verursacht beim Indizieren zusätzliche Embedding-Kosten, erhöht aber die inhaltliche Integrität der abgerufenen Kontexte massiv.

[INTENT: RAG_EVALUATION]
## RAG-Evaluierung mit Ragas
**Ragas (Retrieval-Augmented Generation Assessment)** zerlegt die Evaluierung der RAG-Pipeline in unabhängige Komponenten für das **Retrieval** (Suchqualität) und die **Generation** (Antwortqualität). Anstatt sich auf reine Wortüberschneidungen (ROUGE/BLEU) zu verlassen, nutzt Ragas das **"LLM-as-a-Judge"-Pattern**.

**Die 4 zentralen Metriken:**
1.  **Faithfulness (Generation):** Prüft rigoros, ob die Aussagen in der generierten Antwort *strikt* durch die abgerufenen Dokumenten-Chunks belegt werden können. Die Metrik dient der automatisierten Erkennung von Halluzinationen.
2.  **Answer Relevancy (Generation):** Analysiert, ob die Antwort direkt und zielsicher die initiale Frage klärt, und bestraft Abschweifungen ("Fluff") in der Ausgabe.
3.  **Context Precision (Retrieval):** Wertet das Ranking-System aus. Ein hoher Wert signalisiert, dass die wirklich relevanten Dokumente im abgerufenen Kontext ganz oben platziert wurden.
4.  **Context Recall (Retrieval):** Prüft die Vollständigkeit des Context-Windows. Die Metrik ermittelt, ob die abgerufenen Chunks *alle* notwendigen Puzzleteile enthalten, um die gestellte Frage abschließend beantworten zu können.

Ragas kann durch integrierte Tools automatisch synthetische Frage-Kontext-Antwort-Paare generieren, was kontinuierliche CI/CD-Tests für RAG-Systeme ohne teures manuelles Labeling ermöglicht.
