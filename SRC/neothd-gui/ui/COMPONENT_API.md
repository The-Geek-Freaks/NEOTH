# neothd-gui component API — authoritative prop names

Read this BEFORE writing any new `.slint` view. Guessing prop names is the
#1 cause of Slint compile failures in this codebase. All from `components.slint`.

## NeothButton
- `label: string` (NOT `text`), `primary: bool`, `enabled: bool`, `loading: bool`,
  `size: string` ("sm"|"md"|"lg"), `danger: bool`, `shimmer: bool`
- callback `clicked()`
- `.focus()` forwards to the button's keyboard focus scope.

## ConfirmDialog

- `title: string`, `body: string`, `preview-text: string` (default empty)
- `confirm-label: string` (default "Confirm"), `cancel-label: string` (default "Cancel")
- `danger: bool`, `confirm-enabled: bool` (default true),
  `actions-enabled: bool` (default true)
- callbacks `confirmed()` and `cancelled()`; Escape and scrim invoke `cancelled()`
  only while actions are enabled.
- A nonempty preview is complete read-only text in a bounded scroll surface.
  Keep Confirm disabled until the exact current preview is ready. Set
  `actions-enabled: false` synchronously during one-use response submission.
- Tab, Shift+Tab and Backtab stay within the dialog actions. Empty previews keep
  ordinary dialog sizing; long body content scrolls without hiding the actions.
- Run/approval identity, expiry and authority remain responsibilities of the
  controller and Core broker; the component only presents and emits callbacks.

## Card  — `shimmer: bool`. Wrap content as `@children`.

## SegBar  — `segments: int`, `fraction: float` (0..1, NOT `value`), `fill: color`

## Led  — `state: string` = **"live" | "connecting" | "error" | "off"** (NOT "active"/"idle"),
  `dot-size: length`. Has NO `vertical-alignment` (it is a Rectangle — center it via `y:`).

## Expander  — `title: string`, `hint: string`, `expanded: bool` (in-out). `@children` = body.

## NeothComboBox  — `model: [string]`, `current-index: int` (in-out). callback `selected(int)`.

## NeothCheckBox  — `checked: bool` (in-out), `enabled: bool`, `text: string`. callback `toggled(bool)`.

## NeothLineEdit  — `text: string` (in-out), `placeholder-text: string` (NOT `placeholder`),
  `password: bool`, `enabled: bool`. callbacks `accepted(string)`, `edited(string)`.

## ScreenHeader  — `title: string`, `subtitle: string`
## ProgressIndicator  — `current-step: int`, `total-steps: int`, `step-label: string`
## EntranceFade / SideIn  — wrap `@children`; opacity entrance on if-remount (no props).
## Toast / ToastStack  — `toasts: [ToastData]` on the stack. ToastData{id,kind,title,body}.

## Slint 1.8 gotchas (real, hit repeatedly)
- `ScrollView` needs `import { ScrollView } from "std-widgets.slint";`
- `@children` cannot sit inside an `if` block.
- `visible: false` still reserves layout space → use `if` to add/remove, or animate `width`/`height` with `clip: true`.
- No `.starts-with()` / regex in Slint expressions → Rust computes the bool, pushes it back.
- `transform-rotation` only on bare `Text`/`Image`, never `Rectangle`.
- Layout children: the layout owns their `x`/`y` → x/y offset animations on them are ignored (entrance = opacity only).
- Structs used by Rust must be `export`ed from the view file AND re-exported from `main.slint`.
- PopupWindow `x`/`y` are relative to the instantiating element.
- Colors: Theme tokens only, never inline hex outside `theme.slint`.
