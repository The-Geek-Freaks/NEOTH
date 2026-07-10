---
id: maigret-osint-tool
title: Maigret - OSINT Username Checker
description: Maigret sammelt Informationen über Personen basierend auf ihrem Benutzernamen über 3000+ Seiten hinweg.
tags: [pkm, rag, osint, maigret, security, profiling, ai]
source: sources/maigret_readme.md
---
# Maigret: OSINT & Username Profiling

[INTENT: Kernfunktionen und Einsatzmöglichkeiten des OSINT-Tools Maigret erfassen]

## Funktionsweise & Features
[INTENT: Detaillierte Eigenschaften und Architektur des Maigret-Scrapers verstehen]
- **Suchumfang:** Überprüft Accounts auf über 3.000 Webseiten (Standard-Run prüft die Top 500) allein anhand des Benutzernamens (`maigret YOUR_USERNAME`).
- **Keine API-Keys:** Sammelt verfügbare Informationen aus Webseiten direkt, ohne externe API-Schlüssel zu benötigen.
- **AI Profiling:** Nutzt ein optionales AI-Analyse-Modul (`--ai`), das Rohdaten mittels einer OpenAI-kompatiblen API in eine kurze Ermittlungszusammenfassung umwandelt.
- **Erweiterte Techniken:** Bietet teilweisen Bypass von Blocks, Censorship und CAPTCHAs. Unterstützt Tor- und I2P-Websites.
- **Integration & Output:** Kann als Modul in Python-Projekte eingebettet werden. Generiert PDF/HTML-Reports sowie XMind-Graphen.
