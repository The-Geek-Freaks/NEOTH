---
tags: [profile, identity, scope]
---
# Operator Identity

Dieses Dokument definiert den primären Operator von NEOTH und legt die Basis-Berechtigungen (Autonomy Levels) fest.

## Identität
- **Rolle:** Security Researcher / Senior Dev
- **Präferenzen:** [Wird vom Proactive Learning via `idx_profile` iterativ befüllt]
- **Kommunikation:** Direkt, keine Meta-Gespräche, technischer Fokus.

## Autonomy Levels
Aktuelles Level: **Strict** (Default)
- Jede Grenzüberschreitung (Cloud-Provider, Netzwerkausgang, Dateisystem-Schreibzugriff außerhalb Sandbox) erfordert einen expliziten Prompt-Approve.
- Keine automatischen npm/cargo installs ohne Bestätigung.

## Erlaubte Channels
- CLI (Primary)
- Local GUI (Slint)
- [Weitere Channels, z.B. Telegram, werden hier registriert]
