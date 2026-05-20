# NEOTH Design Specification — Insanely Great Identity v1.1

> **Brand Narrative:** The convergence of Thoth (Egyptian God of Knowledge), the Emperor of Mankind (Warhammer 40k), and the Neural Engine Obligated To Help.

## 1. Core Visual Concept: "The Sovereign Buddy"
NEOTH is not just a tool; it is a **presence**. The design must balance the absolute authority of a god-emperor with the approachable reliability of a lifelong buddy.

### Key Pillars:
- **Zen Simplicity:** Radical reduction in the spirit of Steve Jobs.
- **Material Depth:** High-end industrial design. Layers of glass, obsidian, and refracted light.
- **Organic Intelligence:** A living, breathing neural pulse that represents "Neural Engine Obligated To Help".

## 2. Visual Assets

### 2.1 The Master Logo (Dark Mode)
Refinement v1.1: 5% darker center mask (`#0d0d0d`) for ultimate typographical focus.

```svg
<svg width="800" height="400" viewBox="0 0 800 400" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="synapse-grad" x1="0%" y1="50%" x2="100%" y2="50%">
      <stop offset="0%" stop-color="#00ff80" stop-opacity="0" />
      <stop offset="50%" stop-color="#00ff80" stop-opacity="0.8" />
      <stop offset="100%" stop-color="#00ff80" stop-opacity="0" />
    </linearGradient>
    <radialGradient id="center-dim" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#0d0d0d" />
      <stop offset="100%" stop-color="#1a1a1a" />
    </radialGradient>
  </defs>
  <!-- Background with 5% darker center focus -->
  <rect width="800" height="400" fill="url(#center-dim)" rx="40" />
  
  <!-- Neural Pulse -->
  <path d="M100,200 C250,50 550,350 700,200" fill="none" stroke="url(#synapse-grad)" stroke-width="2" opacity="0.4">
    <animate attributeName="d" dur="12s" repeatCount="indefinite" 
             values="M100,200 C250,50 550,350 700,200; M100,200 C250,350 550,50 700,200; M100,200 C250,50 550,350 700,200" />
  </path>

  <!-- Typography -->
  <text x="400" y="210" font-family="sans-serif" font-weight="100" font-size="72" letter-spacing="32" fill="#ffffff" text-anchor="middle">NEOTH</text>
  <text x="400" y="280" font-family="sans-serif" font-weight="300" font-size="12" letter-spacing="10" fill="#aaaaaa" text-anchor="middle" text-transform="uppercase">Your Buddy, Your Life</text>
</svg>
```

### 2.2 The Alpine Logo (Light Mode)
Uses "Noble Silver" and Apple-Day aesthetics.

```svg
<svg width="800" height="400" viewBox="0 0 800 400" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="light-pulse" x1="0%" y1="50%" x2="100%" y2="50%">
      <stop offset="0%" stop-color="#007aff" stop-opacity="0" />
      <stop offset="50%" stop-color="#007aff" stop-opacity="0.4" />
      <stop offset="100%" stop-color="#007aff" stop-opacity="0" />
    </linearGradient>
  </defs>
  <rect width="800" height="400" fill="#fbfbfd" rx="40" />
  <path d="M100,200 Q250,100 400,200 T700,200" fill="none" stroke="url(#light-pulse)" stroke-width="1" opacity="0.3" />
  <text x="400" y="210" font-family="sans-serif" font-weight="200" font-size="72" letter-spacing="32" fill="#1d1d1f" text-anchor="middle">NEOTH</text>
  <text x="400" y="280" font-family="sans-serif" font-weight="400" font-size="12" letter-spacing="10" fill="#86868b" text-anchor="middle" text-transform="uppercase">Your Buddy, Your Life</text>
</svg>
```

## 3. GitHub "Mega-Cool" Assets

To make the repository stand out, we use **High-Contrast Cinematic Visuals**.

### 3.1 Social Preview (1280x640)
- **Background:** Deep Obsidian (`#0d0d0d`) with a subtle 40k-style "Cog" watermark in the bottom corner.
- **Center:** The Master Logo (2.1) with an added outer glow in `#00ff80`.
- **Tagline:** "The Sovereign AI Buddy. God-speed Knowledge."

### 3.2 README Banner (High-Impact)
A wide, thin version of the logo with an active code-trace running through the background.

### 3.3 Feature Icons (Brutalist Modern)
- **Memory:** A crystalline cube with inner light.
- **Inference:** A lightning bolt composed of binary code.
- **Buddy:** Two intertwined glowing circles (Eternal Bond).

## 4. Color Palette

| Name | Hex | Usage |
| :--- | :--- | :--- |
| **Obsidian Dark** | `#0d0d0d` | Ultimate background, terminal deep-space. |
| **Obsidian Core** | `#1a1a1a` | Standard background, card surfaces. |
| **Neural Green** | `#00ff80` | Knowledge activity, prompt markers. |
| **Liquid Pink** | `#ff2a6d` | Life, emotion, "Buddy" state. |
| **Liquid Blue** | `#05d5ff` | Logic, system status, light-leaks. |
| **Alpine Silver** | `#fbfbfd` | Light mode surface. |
| **Text Primary** | `#ffffff` | Sovereign typography. |

## 5. Global CSS Variables

```css
:root {
  --neoth-bg-deep: #0d0d0d;
  --neoth-bg-core: #1a1a1a;
  --neoth-accent: #00ff80;
  --neoth-life: #ff2a6d;
  --neoth-logic: #05d5ff;
  --neoth-glass: rgba(255, 255, 255, 0.03);
  --neoth-blur: blur(40px);
  --neoth-font: 'SF Pro Display', -apple-system, sans-serif;
}
```

---
*Neoth knows. Neoth helps. Neoth is your life.*
