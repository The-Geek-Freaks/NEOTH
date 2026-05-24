# Reviewer 3 (GUI/UX/Design) Audit — `SRC/neothd-gui`

Datum: 2026-05-20
Scope: `SRC/neothd-gui` + relevante Design-Dokumente.

## Kurzfazit
Die Grundlage ist stark (Tokenisierung, wiederverwendbare Komponenten, klare Step-Logik), aber es gibt aktuell Inkonsistenzen zwischen Design-Spezifikation und tatsächlicher UI-Implementierung in drei Kernbereichen: **Accessibility**, **Informationshierarchie**, **DAU-vs-Pro-Flow-Progression**.

## Stärken (bereits kohärent)
1. **Token-First Ansatz**: Farben, Radii, Typografie und Motion sind zentralisiert in `theme.slint`; das stützt systemische Konsistenz. (`Theme` global).【F:SRC/neothd-gui/ui/theme.slint†L16-L107】
2. **Komponenten-System**: Buttons, Cards, Header, Progress und ComboBox abstrahieren Patterns sauber. Das reduziert „UI drift“.【F:SRC/neothd-gui/ui/components.slint†L20-L313】
3. **Wizard-Informationsstruktur**: Schrittzähler, Labels, konditionales Keys-Step-Verhalten sind nachvollziehbar und klar kommentiert. 【F:SRC/neothd-gui/ui/main.slint†L95-L136】

## Lücken + konkrete Designentscheidungen

### 1) Accessibility: Kontrast von sekundären Texten ist zu schwach (AA-Risiko)
**Befund:** `text-muted` (`#aaaaaa`) und besonders `text-dim` (`#6b6b6b`) auf dunklen Flächen (`#1a1a1a`, `#242424`) werden extensiv für Labels, Step-Meta und Status benutzt. Kleinere Schriftgrade (12px) sind betroffen. 【F:SRC/neothd-gui/ui/theme.slint†L24-L46】【F:SRC/neothd-gui/ui/components.slint†L150-L165】

**Designentscheidung:**
- `text-dim` auf `#7f7f7f` anheben (Meta bleibt sekundär, wird aber lesbarer).
- `font-size-caption` global von 12px auf 13px erhöhen ODER `font-size-caption` bei kritischen Meta-Infos explizit 13–14px.
- Ziel: mindestens WCAG AA für häufige 12/13px-Metaelemente.

### 2) Motion-System: Micro-Interaktionen unterschreiten DS-Minimumdauer
**Befund:** Design-Spec fordert min. 600ms für Transitions; Implementierung nutzt 220ms bei mehreren Hover-/Farb-Animationen. Das ist inhaltlich inkonsistent und wirkt „snappier“ als „majestic“.【F:docs/superpowers/specs/2026-05-15-neoth-uix-design-system.md†L26-L31】【F:SRC/neothd-gui/ui/theme.slint†L105-L107】【F:SRC/neothd-gui/ui/components.slint†L42-L45】

**Designentscheidung:**
- Spezifikation präzisieren: **Screen transitions ≥600ms, micro-interactions 180–260ms**.
- Falls Spec nicht geändert werden soll: `duration-micro` auf 600ms (nicht empfohlen für Usability).
- Empfehlung: Spec update statt UI-Verlangsamung.

### 3) DAU vs Pro: Modus-Auswahl nutzt zwar große Karten, aber keine Keyboard-First-Selektion
**Befund:** ModeCards sind TouchArea-basiert; es fehlt sichtbare Keyboard-Navigation/Fokuszustand und direkte Shortcut-Kommunikation für Pro-User. 【F:SRC/neothd-gui/ui/components.slint†L199-L284】【F:SRC/neothd-gui/ui/main.slint†L255-L295】

**Designentscheidung:**
- Tastaturschnellwahl auf Mode-Screen: `G` = GUI, `C` = CLI, `Enter` = Continue.
- Sichtbare Fokusrahmen (2px Accent + inset halo) für aktive Tastatur-Fokuselemente.
- Microcopy unter den Cards: „Shortcuts: G / C / Enter“.

### 4) Informationshierarchie: Channels-Screen ist inhaltlich dicht, aber scannability leidet
**Befund:** Viele deaktivierte CheckBoxen erzeugen „Liste mit grauen Gräbern“; DAUs müssen irrelevante Einträge visuell mitverarbeiten. 【F:SRC/neothd-gui/ui/main.slint†L657-L760】

**Designentscheidung:**
- Im Wizard nur „Always On“ + „Ready Now“ zeigen.
- „Setup later“ und „Roadmap“ hinter einklappbarer „Show future channels“ Sektion.
- Dadurch schneller Abschluss für DAUs; Pro-User können expandieren.

### 5) Form-UX: Identity validiert nur auf Nicht-Leerstring, nicht auf angekündigte Regeln
**Befund:** Copy sagt „lowercase letters, digits, dashes only, 3–32 chars“, aber Enable-Logik prüft nur `!= ""`. 【F:SRC/neothd-gui/ui/main.slint†L462-L507】

**Designentscheidung:**
- Inline-Validierung live: Regex `^[a-z0-9-]{3,32}$`.
- Continue nur bei validem Format.
- Fehlertext präzise + konstruktiv: „Use 3–32 chars: a-z, 0-9, -“.

### 6) Chat-Composer Accessibility: Placeholder ist lang; Label fehlt
**Befund:** Lange Placeholder-Instruction ersetzt funktionales Label; sobald getippt wird, verschwindet Guidance. 【F:SRC/neothd-gui/ui/chat.slint†L215-L229】

**Designentscheidung:**
- Sichtbares, persistentes Label über Input: „Message“.
- Placeholder kürzen: „Type message or /command…“.
- Darunter kurze Helper-Line (konstant): „Enter sends · Shift+Enter coming soon“.

### 7) Typografische Konsistenz: Mehrere harte Letter-Spacing-Werte statt Tokens
**Befund:** Neben Tokens tauchen fixe Werte wie `1px`, `1.5px`, `2px`, `4px` in unterschiedlichen Komponenten auf; das kann das System über Zeit verwässern. 【F:SRC/neothd-gui/ui/components.slint†L102-L103】【F:SRC/neothd-gui/ui/components.slint†L143-L144】【F:SRC/neothd-gui/ui/chat.slint†L286-L287】

**Designentscheidung:**
- Neue Typography-Tokens: `letter-spacing-tight`, `normal`, `wide`, `hero`.
- Harte Werte schrittweise migrieren.

### 8) Platform-Spec-Lücke: „Frameless + custom title bar“ ist im DS genannt, aber im GUI-File nicht erkennbar umgesetzt
**Befund:** Spec fordert frameless/custom title bar, MainWindow arbeitet nur mit Standardtitel + Größenconstraints; kein sichtbarer Custom-Titlebar-Layer. 【F:docs/superpowers/specs/2026-05-15-neoth-uix-design-system.md†L41-L44】【F:SRC/neothd-gui/ui/main.slint†L54-L73】

**Designentscheidung:**
- Entweder DS an Realität anpassen („optional on desktop platforms“) oder Implementierung auf frameless mit eigener Drag-Region hochziehen.
- Empfehlung: kurzfristig Spec-Relaxation, mittelfristig Custom-Chrome nur, wenn es A11y/Window-Controls nicht verschlechtert.

## Priorisierte Maßnahmen (R3)
1. **P1 (A11y + Trust):** Kontrast + Caption-Size + Identity-Validation fixen.
2. **P1 (Flow):** Channels-Screen entdichten (expand/collapse).
3. **P2 (Pro-Workflow):** Keyboard-Shortcuts + Fokusstile für Moduswahl.
4. **P2 (Systempflege):** Letter-spacing tokenisieren.
5. **P3 (Spec Alignment):** Motion-Regel präzisieren, Frameless-Vorgabe entscheiden.

## Ergebnis
Designsystem-Basis ist stark und bereits näher an „Steve-Jobs-artiger Klarheit“ als typische Internal-Tools. Für echte 12/10-Kohärenz fehlen v.a. **A11y-Finalisierung**, **kognitive Entlastung im Wizard**, und **echte Keyboard-First-Pfade** für Pro-User.
