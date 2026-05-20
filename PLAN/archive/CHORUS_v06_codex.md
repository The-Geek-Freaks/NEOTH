# Chorus v0.6 — Codex Review

> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; not build instructions.

Verdict: **NOT approve in BUILD-READY form**. Konzept stark, aber 10 Blocker.

## Hauptblocker

1. **EventHeader nicht wirklich binary-format locked.** `Option<u8>` in `#[repr(C)]` ist für persistiertes WAL-Format falsch — Layout/Niche-Encoding kein stabiles Datei-Contract. Nimm `brain_region: u8` mit `0 = None`, `1..6 = Region`. Explizit Little-Endian-Encoding definieren, nicht Rust-Struct direkt dumpen.

2. **WAL-Header braucht echtes Framing.** `total_len` + trailing CRC32c reicht nur wenn klar ist, ob `total_len` Header+Payload+CRC oder nur Payload meint. Fehlen: `header_len`/`reserved_len` für spätere Migrationen.

3. **`schema_version: 0x03` bei v0.6 erklärungsbedürftig.** WAL v2 aber Header schema v3 → Versionierung getrennt dokumentieren: `wal_format_version`, `event_schema_version`. Sonst Migrationsverwirrung an Tag 3.

4. **Day-45 zu breit für MVP.** 3 Channels + WAL + mmap repair + candle embeddings + vector store + effect adapters + WASM host + plugin loader + LOWKEY injection + MCP endpoint + E2E in 45 Tagen = "vertical slice + prototypes" nicht build-ready. Härter schneiden: 1 Channel, WAL, recall, one provider, effect adapter, minimal plugin host. Telegram/WhatsApp/Slack parallel erst danach.

5. **Channel-Ingress Auth/Replay/Idempotency fehlt.** Egress sauberer als Ingress definiert. Für Webhooks brauchst du: Signaturprüfung, replay window, dedup key, rate limits, attachment quarantine, normalized identity mapping. Sonst `CHANNEL_INBOUND` = offene Angriffsfläche.

6. **`FinalizeResponseArtifact` zu untyped.** Definiere mindestens: `channel`, `recipient`, `reply_to`, `body`, `attachments`, `safety_state`, `idempotency_key`, `trace_id`. Sonst wandert Logik in Adapter.

7. **LOWKEY "always-injected base stack" architektonisch riskant.** Nicht Stil — Debuggability + deterministisches Verhalten. Alles permanent in Block-B beeinflusst Council/refusal/routing/Memory. Mach es: versioniert, hashbar, abschaltbar pro eval, WAL-logge exakten prompt bundle hash pro Turn.

8. **Needle direct tool-call path zu mächtig.** "Skip main LLM" nur für read-only oder explizit whitelisted low-risk intents. `telegram.send` direkt aus 26M Router = falsch. Für send/write: confirmation policy oder deterministic approval gate.

9. **WASM Plugin Host braucht Capability-API statt nur Manifest-Permissions.** Manifest sagt was Plugin will. Entscheidend was Host-Funktionen überhaupt exponieren. Definiere: `hostcall`-Surface, fuel/timeout, memory limits, no ambient filesystem/network, deterministic logging.

10. **`subprocess.exec` als Effect Adapter zu grob.** Praktisch escape hatch. Muss: per-command allowlist, argv-schema, cwd policy, env allowlist, timeout, output cap, secret redaction.

## Nicht-blockierend, aber ändern

- `idx_episodic` vs `idx_episode` inkonsistent.
- "Egress Effect Adapter (Schicht-0)" widerspricht Section 4 wo Effect Adapters "Schicht-1 boundary". Entscheide: Schicht-0 pure, Effect Adapter = Schicht-1 boundary.
- "all 13 anti-patterns compliant" zu früh — Ziel nicht Fakt ohne enforcement tests.
- `ring` + `rustls` + `hyper full` Day 1 dependency-first. Erst minimal `tokio`, `serde`, `tracing`, `thiserror`, `crc32c`, `uuid`; Rest wenn Slice es braucht.
- `cargo add candle-*` Day 1 zieht Build-Komplexität rein bevor WAL/Runtime stabil.

## DONE
