//! Render and exercise the real shared Slint dialog without the desktop binary.

use std::cell::Cell;
use std::error::Error;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{
    Key, Platform, PlatformError, PointerEventButton, WindowAdapter, WindowEvent,
};
use slint::{ComponentHandle, LogicalPosition, PhysicalSize, Rgb8Pixel};

slint::include_modules!();

struct ProbePlatform {
    window: Rc<MinimalSoftwareWindow>,
    clock: Rc<Cell<Duration>>,
}

impl Platform for ProbePlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }

    fn duration_since_start(&self) -> Duration {
        self.clock.get()
    }
}

struct Probe {
    app: DialogProbe,
    window: Rc<MinimalSoftwareWindow>,
    clock: Rc<Cell<Duration>>,
    width: u32,
    height: u32,
}

impl Probe {
    fn draw(&self, destination: Option<&Path>) -> Result<Vec<Rgb8Pixel>, Box<dyn Error>> {
        self.clock.set(self.clock.get() + Duration::from_secs(1));
        slint::platform::update_timers_and_animations();
        self.window.request_redraw();
        let mut pixels = vec![Rgb8Pixel::default(); (self.width * self.height) as usize];
        assert!(self.window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, self.width as usize);
        }));
        assert!(pixels.windows(2).any(|pair| pair[0] != pair[1]));
        if let Some(destination) = destination {
            let rgb = pixels.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
            image::RgbImage::from_raw(self.width, self.height, rgb)
                .ok_or("invalid frame dimensions")?
                .save(destination)?;
        }
        Ok(pixels)
    }

    fn reset(&mut self, width: u32, height: u32) -> Result<(), Box<dyn Error>> {
        self.app.set_dialog_visible(false);
        self.width = width;
        self.height = height;
        self.app.set_viewport_width(width.try_into()?);
        self.app.set_viewport_height(height.try_into()?);
        self.window.set_size(PhysicalSize::new(width, height));
        self.draw(None)?;
        self.app.set_confirmed_count(0);
        self.app.set_cancelled_count(0);
        self.app.set_background_count(0);
        self.app.set_confirm_enabled(true);
        self.app.set_actions_enabled(true);
        self.app.set_dialog_visible(true);
        self.draw(None)?;
        assert_eq!(self.app.window().size(), PhysicalSize::new(width, height));
        Ok(())
    }

    fn key(&self, key: Key) {
        let text: slint::SharedString = key.into();
        self.app
            .window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        self.app
            .window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }

    fn tab(&self, reverse: bool) {
        let window = self.app.window();
        if reverse {
            window.dispatch_event(WindowEvent::KeyPressed {
                text: Key::Shift.into(),
            });
        }
        self.key(Key::Tab);
        if reverse {
            window.dispatch_event(WindowEvent::KeyReleased {
                text: Key::Shift.into(),
            });
        }
    }

    fn click(&self, x: f32, y: f32) {
        let position = LogicalPosition::new(x, y);
        let window = self.app.window();
        window.dispatch_event(WindowEvent::PointerMoved { position });
        window.dispatch_event(WindowEvent::PointerPressed {
            position,
            button: PointerEventButton::Left,
        });
        window.dispatch_event(WindowEvent::PointerReleased {
            position,
            button: PointerEventButton::Left,
        });
    }

    fn scroll(&self, x: f32, y: f32, delta_y: f32) {
        let position = LogicalPosition::new(x, y);
        let window = self.app.window();
        window.dispatch_event(WindowEvent::PointerMoved { position });
        window.dispatch_event(WindowEvent::PointerScrolled {
            position,
            delta_x: 0.0,
            delta_y,
        });
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let output = std::env::args()
        .nth(1)
        .ok_or("provide an existing artifact directory")?;
    let output = Path::new(&output);
    if !output.is_dir() {
        return Err("artifact directory must already exist".into());
    }
    let clock = Rc::new(Cell::new(Duration::ZERO));
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(ProbePlatform {
        window: window.clone(),
        clock: clock.clone(),
    }))?;
    let app = DialogProbe::new()?;
    app.show()?;
    let mut probe = Probe {
        app,
        window,
        clock,
        width: 960,
        height: 640,
    };
    let mut patch = String::from(
        "diff --git a/src/example.rs b/src/example.rs\n--- a/src/example.rs\n+++ b/src/example.rs\n@@ -1,1 +1,120 @@\n-old behavior\n",
    );
    for line in 1..=120 {
        patch.push_str(&format!("+// Accepted change {line:03}: retain the complete exact patch in the scrollable preview.\n"));
    }
    probe.app.set_preview_text(patch.clone().into());
    probe.app.set_detail(
        concat!(
            "Task 42 will change C:/Project/NEOTH. Review the complete patch below. ",
            "This approval applies to this one patch only.\n\n",
            "Patch fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "Changed files: src/example.rs\n",
            "Review reference: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n",
            "Expires: 2026-09-07T18:00:00Z"
        )
        .into(),
    );

    probe.reset(960, 640)?;
    assert_eq!(probe.app.get_preview_text().as_str(), patch);
    let initial = probe.draw(Some(&output.join("dialog-normal.png")))?;
    // These viewport and action coordinates were established from the actual
    // production-component 960x640 render, not from a guessed hidden hitbox.
    probe.scroll(480.0, 400.0, -10000.0);
    let scrolled = probe.draw(Some(&output.join("dialog-scrolled-end.png")))?;
    assert!(
        initial != scrolled,
        "wheel input must reveal a different preview viewport"
    );
    assert_eq!(
        probe.app.get_preview_text().as_str(),
        patch,
        "scrolling preserves all accepted bytes"
    );
    probe.reset(960, 640)?;
    probe.key(Key::Tab);
    probe.draw(Some(&output.join("dialog-keyboard-focus.png")))?;
    probe.key(Key::Escape);
    assert_eq!(
        probe.app.get_cancelled_count(),
        1,
        "Escape after Tab rejects"
    );

    probe.reset(320, 220)?;
    let small_initial = probe.draw(Some(&output.join("dialog-small.png")))?;
    probe.scroll(160.0, 90.0, -10000.0);
    probe.draw(None)?;
    probe.scroll(160.0, 90.0, -10000.0);
    let small_scrolled = probe.draw(Some(&output.join("dialog-small-scrolled.png")))?;
    assert!(
        small_initial != small_scrolled,
        "small-window content remains scrollable"
    );

    probe.reset(960, 640)?;
    probe.app.set_confirm_enabled(false);
    probe.draw(Some(&output.join("dialog-disabled-confirm.png")))?;
    let mut disabled_confirm_can_reject = [false; 2];
    for (reverse, tabs) in [false, true]
        .into_iter()
        .flat_map(|reverse| (1..=6).map(move |tabs| (reverse, tabs)))
    {
        probe.reset(960, 640)?;
        probe.app.set_confirm_enabled(false);
        for _ in 0..tabs {
            probe.tab(reverse);
        }
        probe.key(Key::Return);
        assert_eq!(
            probe.app.get_confirmed_count(),
            0,
            "loading preview cannot be approved"
        );
        assert_eq!(
            probe.app.get_background_count(),
            0,
            "disabled confirm retains modal isolation"
        );
        disabled_confirm_can_reject[usize::from(reverse)] |= probe.app.get_cancelled_count() == 1;
    }
    assert!(
        disabled_confirm_can_reject
            .into_iter()
            .all(|reachable| reachable),
        "Reject stays reachable while preview loads"
    );

    let mut reachable_confirm = [false; 2];
    let mut reachable_cancel = [false; 2];
    for (reverse, tabs) in [false, true]
        .into_iter()
        .flat_map(|reverse| (1..=6).map(move |tabs| (reverse, tabs)))
    {
        probe.reset(960, 640)?;
        for _ in 0..tabs {
            probe.tab(reverse);
        }
        probe.key(Key::Return);
        assert_eq!(
            probe.app.get_background_count(),
            0,
            "modal Tab must not activate the underlying UI"
        );
        reachable_confirm[usize::from(reverse)] |= probe.app.get_confirmed_count() == 1;
        reachable_cancel[usize::from(reverse)] |= probe.app.get_cancelled_count() == 1;
        if probe.app.get_confirmed_count() == 1 {
            probe.key(Key::Return);
            assert_eq!(
                probe.app.get_confirmed_count(),
                1,
                "submitting is one-shot in the caller"
            );
        }
    }
    assert!(
        reachable_confirm.into_iter().all(|reachable| reachable),
        "Confirm must be keyboard reachable in both directions"
    );
    assert!(
        reachable_cancel.into_iter().all(|reachable| reachable),
        "Reject must be keyboard reachable in both directions"
    );

    probe.reset(960, 640)?;
    probe.app.set_actions_enabled(false);
    for step in 0..12 {
        probe.tab(step >= 6);
        probe.key(Key::Return);
        probe.key(Key::Escape);
    }
    assert_eq!(
        probe.app.get_confirmed_count(),
        0,
        "disabled approval cannot fire"
    );
    assert_eq!(
        probe.app.get_cancelled_count(),
        0,
        "disabled response cannot fire"
    );
    assert_eq!(
        probe.app.get_background_count(),
        0,
        "submitting modal retains keyboard isolation"
    );

    probe.reset(960, 640)?;
    probe.click(0.0, 0.0);
    assert_eq!(probe.app.get_cancelled_count(), 1, "scrim click rejects");
    probe.reset(960, 640)?;
    probe.app.set_confirm_enabled(false);
    probe.click(836.0, 560.0);
    assert_eq!(
        probe.app.get_confirmed_count(),
        0,
        "disabled confirm rejects pointer activation"
    );
    probe.click(714.0, 560.0);
    assert_eq!(
        probe.app.get_cancelled_count(),
        1,
        "Reject remains clickable while preview loads"
    );
    probe.reset(960, 640)?;
    probe.click(836.0, 560.0);
    probe.click(836.0, 560.0);
    assert_eq!(
        probe.app.get_confirmed_count(),
        1,
        "pointer confirmation is one-shot"
    );
    assert_eq!(
        probe.app.get_background_count(),
        0,
        "modal pointer clicks cannot reach background"
    );

    probe.app.set_preview_text("".into());
    probe.app.set_dialog_title("Discard draft?".into());
    probe.app.set_confirm_label("Discard".into());
    probe.app.set_cancel_label("Cancel".into());
    probe.app.set_detail(
        "Discard the selected draft? This ordinary confirmation has no patch preview.".into(),
    );
    probe.reset(960, 640)?;
    probe.draw(Some(&output.join("dialog-ordinary.png")))?;
    probe.tab(true);
    probe.key(Key::Escape);
    assert_eq!(
        probe.app.get_cancelled_count(),
        1,
        "ordinary dialog retains Escape after reverse Tab"
    );
    println!(
        "DIALOG_PROBE_PASS: full preview, normal/small/ordinary rendering, forward/reverse keyboard, pointer actions, scrolling, Escape, disabled actions, modal isolation"
    );
    Ok(())
}
