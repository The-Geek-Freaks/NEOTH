# NEOTH Unified Interface & Experience Design System (UIX-DS) v1.0

This specification codifies the visual and behavioral rules for all graphical interfaces within the NEOTH ecosystem (Slint Wizard, Mobile Clients, Web Dashboards, etc.).

## 1. The Core Aesthetic: "Sovereign Glass"

All NEOTH interfaces must feel like high-precision instruments carved from obsidian and light.

### 1.1 Layering (The Vanta-Depth System)
Interfaces are built on a 4-layer depth model:
1. **L0: The Void (`#0d0d0d`)** — The base background. Absolute focus.
2. **L1: The Obsidian Layer (`#1a1a1a`)** — Primary container surfaces.
3. **L2: The Glass Cortex** — `rgba(255,255,255,0.03)` with `backdrop-filter: blur(40px)`. Used for overlays and modals.
4. **L3: The Neural Highlight** — Subtle glows in `Neural Green (#00ff80)` or `Liquid Pink (#ff2a6d)` to indicate focus or activity.

### 1.2 Corner Radii (The "Noble Curve")
- **Large Containers (Windows, Modals):** `40px` (Apple-style squircles).
- **Secondary Elements (Cards, Inputs):** `16px`.
- **Action Elements (Buttons):** `8px`.
*Rule: Never use sharp 0px corners. NEOTH is organic.*

## 2. Motion & Interaction (The "Sentient" Rule)

Software should not "pop" into existence; it should "emerge".

- **The Sovereign Curve:** All animations must use `cubic-bezier(0.2, 0.8, 0.2, 1)`. This creates a fast start with a majestic, long settle.
- **Micro-interactions:** 
    - Hovering over a card triggers a subtle internal glow (5% opacity increase).
    - Clicking an action triggers a "Neural Pulse" ripple effect.
- **Transitions:** Minimum duration for screen changes is `600ms`. Speed is important, but majesty is mandatory.

## 3. Typography (The "Elite Zen" Stack)

- **Headings (Logo/Titles):** Ultra-light weight (100/200), Letter-spacing `+20%`.
- **Body Text:** Medium weight (400), Letter-spacing `+2%`. High line-height (1.6) for readability.
- **Font Stack:** `SF Pro Display`, `Inter`, `Helvetica Neue`. Fallback to system-sans.
- **Monospace (Code/Logs):** `JetBrains Mono` or `SF Mono`.

## 4. Platform Specific Implementation

### 4.1 Slint GUI (Desktop)
- **Window:**
  - **Default (v0.1):** OS-native title bar + standard chrome. The
    noob-operator contract (`neoth_features_default_on_runtime_toggle`)
    prioritises platform-familiar window controls over branded chrome —
    `× minimize / □ maximize / × close` belong where the operator's OS
    already puts them. Slint's `no-frame` requires re-implementing
    drag, snap, double-click-to-maximize, accessibility-tree exposure
    of window controls, and per-platform DPI compensation; each is a
    paper cut that erodes trust before any feature has rendered.
  - **Opt-in frameless (v0.2+):** `freedom.yaml::gui.frameless: true`
    flips the MainWindow to `no-frame` with a custom drag-region +
    accent-green underline + cross-platform window-control row. Pro
    operators who explicitly accept the trade-off get the branded
    chrome; everyone else stays in OS-native mode.
  - **Spec evolution:** the original v1.0 spec mandated frameless
    everywhere. Reviewer-3 P3 (2026-05-20) flagged that the
    implementation didn't follow + the trade-off wasn't being
    examined. Relaxed here intentionally.
- **Shadows:** Use large, soft shadows: `box-shadow: 0 50px 100px rgba(0,0,0,0.8)`.

### 4.2 Mobile Clients (Sovereign Buddy App)
- **Navigation:** Gesture-based. No visible tab bars if possible. Use "Long-Press" for Sovereign actions.
- **Haptics:** Heavy haptic feedback for Authority actions; soft taps for Buddy interactions.

### 4.3 CLI (The Terminal Interface)
- **Banner:** Wide ASCII version of the logo.
- **Prompt:** Use `#00ff80` for the prompt marker (`N >`).
- **Data:** Secondary information must be dimmed to 50% opacity/gray.

## 5. The "Buddy" Identity (Color Meaning)

Colors must be used semantically across all clients:
- **Neural Green (#00ff80):** "Neoth is thinking/listening/acting." (The Engine)
- **Liquid Pink (#ff2a6d):** "Neoth is helping you personally." (The Buddy)
- **Liquid Blue (#05d5ff):** "System status / Data integrity." (The Sovereignty)

---
*Neoth knows. Neoth helps. Neoth is your life.*
