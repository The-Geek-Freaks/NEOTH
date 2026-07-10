---
title: "AI Agent Frameworks & Orchestration"
date: "2026-07-06"
tags: [ai-agents, orchestration, langgraph, pydanticai, crewai, autogen, swarm]
author: "Trending AI Agents Scout"
type: "wiki-entry"
---

# [INTENT: AI Agent Frameworks & Orchestration - Executive Summary]
Dieser Artikel liefert eine technische Analyse der Top-Trending Open-Source AI Agent Frameworks (Stand 2024/2025): **LangGraph**, **PydanticAI**, **CrewAI**, **Microsoft AutoGen** und **OpenAI Swarm**. Fokus liegt auf dem Systemdesign für State-Management, Tool-Orchestration und internem Routing, um architektonische Entscheidungen für Multi-Agent-Systeme zu fundieren.

# [INTENT: LangGraph - State Management, Orchestration & Routing]
**LangGraph** (von LangChain) modelliert Multi-Agent-Workflows als zyklische, endliche Zustandsautomaten (Finite State Machines - FSM) und ist der De-facto-Standard für komplexe, produktionsnahe Agenten-Graphen.

*   **State-Management:** Der State wird als globaler, geteilter Datensatz (meist ein `TypedDict` oder Pydantic-Modell) definiert. Jeder Knoten (Node) im Graph liest diesen State, mutiert ihn und gibt ein Update zurück. Ein wesentliches Kern-Feature ist das native **Checkpointing**: Jeder Zustandsübergang kann in einer Datenbank (z.B. SQLite, Postgres) persistiert werden. Dies ermöglicht Time-Travel (Zurückspulen zu einem früheren State), Fault-Tolerance und "Human-in-the-Loop"-Pausen.
*   **Tool-Orchestration:** Werkzeuge werden als `ToolNode` abstrahiert. Wenn das LLM einen Tool-Call (gemäß OpenAI Function Calling Schema) emittiert, pausiert der Agent-Knoten. Die Ausführung wird an den `ToolNode` übergeben, welcher die Python-Funktion sicher ausführt und das Resultat (als `ToolMessage`) an den State anhängt, bevor der LLM-Knoten re-evaluiert.
*   **Routing:** Das Routing erfolgt über **Conditional Edges** (Bedingte Kanten). Im Gegensatz zu klassischen DAGs (Directed Acyclic Graphs) erlaubt LangGraph Zyklen. Eine Router-Funktion evaluiert den aktuellen State zur Laufzeit und steuert den Fluss dynamisch (z.B. zurück zur Evaluierung, falls ein Tool-Fehler vorliegt, oder an einen spezialisierten Sub-Agenten).

# [INTENT: PydanticAI - State Management, Orchestration & Routing]
**PydanticAI** fokussiert sich auf strikte Typsicherheit, Validierung und Developer Ergonomics, getrieben durch das Pydantic-Ökosystem.

*   **State-Management:** Setzt primär auf **Dependency Injection**. Anstatt globalen State zu verwalten, werden Agents zustandslos (stateless) konzipiert. Der State wird über ein `RunContext[T]` Objekt injiziert. Für persistente Workflows (Durable Execution) integriert PydanticAI sich tief mit Orchestratoren wie **Temporal** oder **Restate**, um Ausführungszustände über Server-Neustarts hinweg zu erhalten.
*   **Tool-Orchestration:** Tools werden via `@agent.tool` Decorator an den Agenten gebunden. Die Ein- und Ausgaben werden automatisch durch Pydantic-Modelle validiert und in JSON-Schema übersetzt. Bei komplexen Agenten ermöglicht PydanticAI das "Lazy Loading" von Capabilities, um den LLM-Kontext nicht mit irrelevanten Tool-Definitionen zu überladen.
*   **Routing:** Routing passiert entweder programmatisch im Applikationscode (ein Router-Agent klassifiziert die Intention und übergibt Pydantic-validierte Outputs an den nächsten Agenten) oder – für komplexere Abläufe – über das zugrundeliegende `pydantic-graph` Modul, welches eine formale FSM abbildet.

# [INTENT: CrewAI - State Management, Orchestration & Routing]
**CrewAI** abstrahiert die Komplexität durch rollenbasierte Konstrukte (Crews, Agents, Tasks) und eignet sich für stark strukturierte, delegierende Workflows.

*   **State-Management:** Die neueste Iteration führt **CrewAI Flows** ein. Der State wird entweder unstrukturiert (Dictionaries) oder strukturiert (via Pydantic-Modelle) auf der Flow-Ebene gehalten. Der State überlebt die Grenzen einzelner Tasks und kann als persistentes Gedächtnis zwischen komplett unterschiedlichen Agenten-Ausführungen geteilt werden.
*   **Tool-Orchestration:** Tools werden auf Agenten- oder Task-Ebene zugewiesen. Ein Agent nutzt autonom "Delegation Tools", um Sub-Tasks an andere Agenten abzugeben. Ein integriertes Control-Plane sorgt für Telemetrie und Audit-Trails bei jedem Tool-Aufruf.
*   **Routing:** Das Routing innerhalb der *Flows* wird über Event-Driven-Decorators gesteuert. Einstiegspunkte werden mit `@start()` markiert. Abhängigkeiten werden über `@listen()` (inklusive AND/OR-Logikgattern) aufgelöst. Konditionales Branching passiert über `@router()`-Methoden, die den Status auswerten und dynamisch den nächsten Ausführungspfad bestimmen.

# [INTENT: Microsoft AutoGen - State Management, Orchestration & Routing]
**AutoGen** (insb. ab v0.4 / Microsoft Agent Framework) basiert auf einer asynchronen, ereignisgesteuerten Architektur, bei der Kommunikation zwingend über nachrichtenbasierten Chat erfolgt.

*   **State-Management:** Historisch oft In-Memory-Message-Buffers. Mit dem Sprung zu v0.4 und dem "Microsoft Agent Framework" gibt es nun formale Checkpointing-APIs (`save_state()` / `load_state()`), um Sessions robust auf die Festplatte oder in Datenbanken zu serialisieren. Für "Long-Term Memory" nutzt AutoGen Vektor-Datenbank-Kopplungen (z.B. über `TeachableAgent`), die faktisches Wissen sitzungsübergreifend persistieren.
*   **Tool-Orchestration:** Neben Standard-Python-Funktionen glänzt AutoGen durch "Agent-as-a-Tool". Ein übergeordneter Orchestrator kann einen kompletten Sub-Agenten (oder eine ganze GroupChat-Runde) als isoliertes Tool aufrufen. Besonderer Fokus liegt auf Code-Execution-Tools (z.B. in sicheren Docker-Containern).
*   **Routing:** Routing ist "Conversation-First". Anstatt starrer Kanten steuern Konversationsmuster den Ablauf. Ein "GroupChatManager" agiert als Router, der anhand des Konversationsverlaufs, Speaker-Selection-Prompts und konfigurierbaren Transitions-Regeln dynamisch entscheidet, welcher Agent als nächstes sprechen (und agieren) darf.

# [INTENT: OpenAI Swarm - State Management, Orchestration & Routing]
**OpenAI Swarm** ist ein hoch-experimentelles, minimalistisches Educational-Framework von OpenAI, das auf maximale Entwicklerergonomie ausgelegt ist.

*   **State-Management:** Swarm ist **Stateless by Design**. Es gibt keinen internen Speicher oder Checkpointing. Der State wird alleinig über `context_variables` abgebildet – ein Dictionary, das der Entwickler in die zentrale `client.run()`-Schleife injiziert und das von Tools gelesen/mutiert werden kann.
*   **Tool-Orchestration:** Tools sind simple Python-Funktionen, die dem Agenten im Array übergeben werden. Die Framework-Schleife führt die von der Chat Completions API angeforderten Funktionen automatisch aus und hängt die Ergebnisse an den Message-Thread an.
*   **Routing:** Swarm populärisiert das **Handoff-Pattern**. Ein Agent kann als Rückgabewert eines Tools einfach eine Instanz eines *anderen* Agenten zurückgeben. Die Orchestrierungs-Schleife erkennt dies und überträgt den Execution Context sofort und nahtlos auf den neuen Agenten, ohne externe Graph-Logik zu benötigen.
