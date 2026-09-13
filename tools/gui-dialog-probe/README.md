# Native confirmation dialog probe

This isolated developer executable imports the production `ConfirmDialog`
from `SRC/neothd-gui/ui/components.slint`. It renders that component with
Slint 1.16.1's public software renderer and injects real Slint keyboard events.
It does not link the NEOTH desktop or start a daemon, provider, or native window.

Run from the repository root on Windows after creating an artifact directory:

```powershell
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_PROFILE_DEV_DEBUG = '0'
$env:CARGO_TARGET_DIR = Join-Path (Get-Location) 'SRC/target'
New-Item -ItemType Directory -Force -Path 'work/gui-dialog-probe'
.\SRC\_gui_check.bat run --manifest-path ..\tools\gui-dialog-probe\Cargo.toml --locked --offline -j1 -- ..\work\gui-dialog-probe
```

On a clean dependency cache, omit `--offline` for the first build. Keep the
checked-in lockfile. The isolated `[workspace]` keeps this tool out of the
shipping workspace's package and installer targets.

The run checks complete synthetic preview-property preservation, normal and
small-window rendering, Tab and Shift+Tab reachability of both responses,
Escape after focus movement, disabled Confirm while rejection remains available,
disabled responses during submission, pointer actions, wheel scrolling, and
modal isolation from a background control. It exits with an error at the first
failed assertion. Seven PNGs retain normal, scrolled, small, small-scrolled,
keyboard-focus, disabled-confirm and ordinary-dialog presentations; inspect
them for actual layout and clipping rather than treating file existence as a
visual pass.

The fixture disables its response controls after its first Confirm callback,
matching the caller's one-use submission behavior. The production controller
and Core broker have separate tests for opaque ID, cancellation, replay and
durable effect authority; a component callback cannot prove those boundaries.

The full patch is synthetic and never applied. A scrolled screenshot displays
only a viewport; exact full-text assertions and review of the imported binding
complement that visual evidence. Pointer coordinates are based on the retained
960x640 production-component render and assertions verify the actual callbacks.
This probe does not qualify Winit/Femtovg/GPU
rendering, the complete MainWindow, OS accessibility trees, screen readers or
release artifacts.

Public versioned API references: [MinimalSoftwareWindow](https://docs.rs/slint/1.16.1/slint/platform/software_renderer/struct.MinimalSoftwareWindow.html),
[WindowEvent](https://docs.rs/slint/1.16.1/slint/platform/enum.WindowEvent.html),
and Slint's [own partial-renderer test](https://github.com/slint-ui/slint/blob/v1.16.1/api/rs/slint/tests/partial_renderer.rs).
