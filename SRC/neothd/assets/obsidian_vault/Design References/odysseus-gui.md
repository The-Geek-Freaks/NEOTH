# GUI Design Reference — odysseus

> GOLD-ADOPT-09. Deep-read of [odysseus](https://github.com/pewdiepie-archdaemon/odysseus)
> (a self-hosted Python AI workspace; web SPA = `static/index.html` + `static/app.js`)
> for GUI/UX ideas NEOTH's Slint GUI (`neothd-gui/ui/`) could adopt. Per the GOLD
> plan: **inspiration + design reference, NOT direct code adoption** (odysseus is a
> Python web app; NEOTH's GUI is native Slint). GUI implementation is display-gated
> (not visually verifiable in this harness) — these are documented for an operator-
> driven Slint pass.

## What NEOTH's Slint GUI has today
Wizard (mode-select → identity → provider → autonomy → channels → finish) · Chat
view · Settings with sub-panels: kanban, safe-rail, trust, hemispheres, skills,
plugins, memory, channels (`ui/{main,chat,settings,components,theme}.slint`).

## odysseus UI surfaces (from index.html / app.js)
Persistent **sidebar + chat-history** list · welcome-active chat container ·
**attach-strip** (file attachments on the input bar) · **chat-meta count/overlay**
(live token/usage in chat) · **character/persona templates** (`char-template-select`,
`char-prompt-wrap`) · rich **admin panel** (provider buttons w/ logos, model forms,
sliders, toggles, user list, tabs) · **a11y** classes (`a11y-visually-hidden`) ·
**auto-sort** (AI-driven list sorting w/ spinner).

## Top-3 highest-impact for NEOTH (recommended Slint pass)
1. **Conversation-history sidebar** — NEOTH already persists `HindsightCard`s
   (`memory/hindsight.rs`, now with `display_name` from ADOPT-21). Surface them as a
   left sidebar to browse/resume past sessions — the single biggest UX gap vs
   odysseus. Data already exists; this is pure presentation.
2. **In-chat context-window meta** — port the ADOPT-24c context bar
   (`cli/chat_display.rs::render_context_bar`, limit = `tokens.max_per_request`) into
   the GUI chat header as a live usage chip. Reuses the exact renderer; consistent
   with the CLI.
3. **Attachment strip on the chat input** — NEOTH has the media pipeline + clipboard
   (PC-01); a drag/attach strip surfaces it in the GUI (file → media-ingest → prompt).

## Deliberately skipped
- odysseus's **multi-provider admin panel w/ logos / per-model sliders** — NEOTH
  configures providers via the wizard + `neoth hemispheres`/`autonomy`; replicating a
  web admin UI is redundant + the model-version-agnostic rule discourages per-model UI.
- **auto-sort / character-template marketplace** — odysseus is a multi-user workspace;
  NEOTH is a sovereign solo daemon (different product).

## Verdict
GROUND-TRUTH + GUI-INSPIRATION (matches the GOLD plan table). No direct code adoption
(Python web ≠ native Slint). The 3 above are the recommended operator-verified Slint
improvements; data/logic for all 3 already exists in NEOTH (cards, context renderer,
media pipeline) — only presentation is missing.
