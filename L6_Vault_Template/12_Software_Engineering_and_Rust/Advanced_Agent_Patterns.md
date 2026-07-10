---
tags: [ai, agents, mcts, tot]
---
# Advanced Agent Patterns

Um komplexe Programmieraufgaben ohne massive Cloud-Modelle (nur mit lokalen 7B-34B Modellen) zu lösen, wendet NEOTH frontier AI Patterns an.

## MCTS (Monte Carlo Tree Search) auf AST-Basis
- Normale Token-basierte Rollouts erzeugen oft Syntaxfehler. NEOTH macht MCTS-Schritte basierend auf **Abstract Syntax Trees (AST)**.
- Der Rust-Compiler (Borrow-Checker, Lifetime-Analyse) dient als **Value-Network** zur Evaluierung von Tree-Branches, bevor Backpropagation erfolgt.

## Activation Steering & Mechanistic Interpretability
- Lokale Modelle neigen zu "Sycophancy" (dem User nach dem Mund reden). 
- NEOTH wendet hartes Clamping auf spezifische Attention-Heads an und nutzt **Contrastive Activation Addition (CAA)** im Residual Stream, um das Modell zwingend auf "Honesty" und korrekten, sicheren Code zu primen.

## Semantic Degradation Fallback
- Wenn der Agent sich in endlosen Refactoring-Loops verfängt, greift das Entropy-Monitoring.
- **Aktion:** Harter Context-Window-Purge (zurück zur Ground Truth), Switch von Greedy-Decoding zu Min-P mit hoher Temperatur, um das logische Minimum zu durchbrechen.
