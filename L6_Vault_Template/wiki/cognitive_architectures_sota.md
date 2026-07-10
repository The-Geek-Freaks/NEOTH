---
title: "Cognitive Architectures & State of the Art AI Agents"
date: "2026-07-06"
tags:
  - ai
  - agents
  - cognitive-architecture
  - dspy
  - react
  - reflexion
  - rag
aliases:
  - "SOTA AI Agents"
  - "LLM Cognitive Architectures"
---

[INTENT: Einführung in Kognitive Architekturen für LLMs]
# Kognitive Architekturen für LLMs

Kognitive Architekturen (wie z. B. das **CoALA**-Framework - Cognitive Architectures for Language Agents) transformieren Large Language Models (LLMs) von reaktiven, zustandslosen Textgeneratoren hin zu autonomen Systemen. Das LLM dient hierbei als "kognitive Engine" (Reasoning Core), die durch modulare Systemkomponenten für Gedächtnis, Planung und Interaktion mit der Außenwelt erweitert wird. 

[INTENT: Absolutes Grundwissen für Autonomie (Selbstmodell)]
## Das absolute Grundwissen eines autonomen Agenten

Um autonom und iterativ zu funktionieren, muss ein Agentensystem zwingend ein rudimentäres "Selbstmodell" (Metakognition) besitzen. Folgendes Grundwissen ist dafür erforderlich:

1. **Self-State & Task Awareness (Zustandsbewusstsein):** Der Agent muss zu jedem Zeitpunkt wissen, *was* sein übergeordnetes Ziel ist, *welche* Teilschritte bereits abgeschlossen wurden und *wo* er sich im Lösungsraum aktuell befindet (verankert im Working Memory).
2. **Tool Space Perception (Handlungsspielraum):** Der Agent muss seine eigenen Fähigkeiten kennen. Er muss wissen, welche APIs, Werkzeuge oder Sandbox-Umgebungen ihm zur Verfügung stehen, welche Parameter diese benötigen und welche Form von Output sie erzeugen.
3. **Memory Access (Erinnerungsvermögen):** Der Agent muss um die Existenz seines eigenen Speichers wissen, um aktiv historische Daten (Episodic Memory) oder Fakten (Semantic Memory) suchen und abrufen zu können.
4. **Self-Reflection & Critique (Selbstreflexion):** Das System muss wissen, wie es eigene Outputs und Tool-Ergebnisse kritisch bewertet. Es muss den Unterschied zwischen "Ziel erreicht" und "Fehler aufgetreten" erkennen, um seine Strategie dynamisch anzupassen.
5. **Constraint Awareness (Einschränkungen):** Wissen über Systemgrenzen, wie Token-Limits, API-Rate-Limits oder ethische/sicherheitsspezifische Grenzen.

[INTENT: State-of-the-Art Frameworks und Prompt-Pattern]
## Führende Architekturen und Frameworks (SOTA)

Die State-of-the-Art-Entwicklung verläuft weg von linearen LLM-Aufrufen hin zu zyklischen Laufzeitumgebungen (Orchestrators), die auf dem "Perceive, Reason, Act, Reflect" (PRAR) Zyklus basieren.

### 1. ReAct (Reasoning and Acting)
ReAct ist das fundamentale Paradigma zur Reduktion von Halluzinationen und der Lösung mehrstufiger Aufgaben. Es zwingt den Agenten in einen expliziten Loop:
* **Thought (Gedanke):** Der Agent plant den nächsten Schritt ("Ich muss das aktuelle Wetter abfragen, bevor ich antworte").
* **Action (Handlung):** Konstruktion eines Tool-Aufrufs (`Search[Wetter in Berlin]`).
* **Observation (Beobachtung):** Das System empfängt das reale Tool-Ergebnis und speist es als Fakt in den Kontext ein.
* *Vorteil:* Grounding in der Realität. Der Pfad der Kognition wird auditierbar und transparent.

### 2. Reflexion (Verbal Reinforcement Learning)
Reflexion baut auf ReAct auf und verleiht dem Agenten die Fähigkeit zur iterativen Selbstreparatur ohne teures Modell-Finetuning (Gewichts-Updates).
* **Actor:** Generiert eine Lösung oder führt eine Aktion aus.
* **Evaluator:** Bewertet das Ergebnis (z.B. anhand von Code-Tests oder Compiler-Meldungen).
* **Self-Reflection:** Ist das Ergebnis fehlerhaft, generiert der Agent eine textuelle "Kritik" seiner eigenen Handlung. Diese wird im episodischen Gedächtnis gespeichert, damit das System im nächsten Durchlauf nicht exakt denselben Fehler begeht.

### 3. DSPy (Declarative Self-improving Python)
DSPy der Stanford NLP Group revolutioniert die Entwicklung von kognitiven Pipelines, indem es von manuellem "Prompt Engineering" zu systematischer "Programmierung" wechselt.
* **Declarative Signatures:** Statt langer Text-Prompts werden Modul-Signaturen definiert (z.B. `Context, Question -> Answer`).
* **Modularität:** Komplexe Architekturen werden aus Bausteinen (wie `ChainOfThought` oder `ReAct`) als Python-Programm zusammengesetzt.
* **Teleprompter (Optimizer):** DSPy trennt Programmlogik vom Prompt. Algorithmen optimieren automatisch die tatsächlichen Prompts und Few-Shot-Beispiele für ein spezifisches LLM basierend auf Erfolgsmetriken (Self-Improvement).

[INTENT: Memory-Architekturen]
## Memory-Architekturen für Agenten-Kognition

Um echte kognitive Prozesse abzubilden, implementieren moderne SOTA-Agenten Konzepte der Kognitionswissenschaft (in Anlehnung an klassische Systeme wie ACT-R):

1. **Working Memory (Kurzzeitgedächtnis):** Das "Scratchpad" und aktuelle Context Window des Agenten. Hier liegen der momentane State, die letzten Observations und aktive "Thoughts". Da es flüchtig und in der Token-Anzahl begrenzt ist, muss es effizient gemanagt werden.
2. **Episodic Memory (Episodisches Gedächtnis):** Speichert vergangene Konversationen, Handlungsstränge und Reflexionen chronologisch (oft mittels Vector Databases abgebildet). Es erlaubt dem Agenten, aus Erfahrung zu lernen ("Letztes Mal hat dieser API-Endpunkt einen Timeout geworfen, ich nehme einen anderen").
3. **Semantic Memory (Semantisches Gedächtnis):** Langfristiges, kontextfreies Faktenwissen und Domäneninformationen. Realisiert durch Knowledge Graphs oder klassische RAG-Pipelines.
4. **Procedural Memory (Prozedurales Gedächtnis):** Das Wissen über das "Wie". Dies umfasst die Modellgewichte selbst, aber auf Architektur-Ebene auch vordefinierte DSPy-Programme, System-Prompts, Tool-Code und Standardarbeitsanweisungen (SOPs).
