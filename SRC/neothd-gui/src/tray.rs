//! Platform tray abstraction.
//!
//! Windows and macOS use their native `tray-icon` backends. Linux speaks the
//! StatusNotifierItem D-Bus protocol directly through `ksni`, keeping release
//! binaries free of GTK/AppIndicator build and runtime dependencies.

use crate::MainWindow;

const ICON_SIZE: u32 = 32;
const TOOLTIP: &str = "NEOTH — your buddy, your life";

fn orb_rgba(size: u32) -> Vec<u8> {
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let center = (size as f32) / 2.0 - 0.5;
    let radius = center - 2.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let distance = (dx * dx + dy * dy).sqrt();
            if distance <= radius {
                let offset = ((y * size + x) * 4) as usize;
                rgba[offset] = 0x00;
                rgba[offset + 1] = 0xFF;
                rgba[offset + 2] = 0x80;
                rgba[offset + 3] = if distance > radius - 1.5 {
                    (255.0 * (radius - distance).max(0.0) / 1.5) as u8
                } else {
                    255
                };
            }
        }
    }

    rgba
}

fn orb_argb(size: u32) -> Vec<u8> {
    let mut argb = orb_rgba(size);
    for pixel in argb.chunks_exact_mut(4) {
        pixel.rotate_right(1);
    }
    argb
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::mpsc::{self, Sender};
    use std::time::Duration;

    use ksni::blocking::TrayMethods;

    use super::{ICON_SIZE, MainWindow, TOOLTIP, orb_argb};

    #[derive(Clone, Copy, Debug)]
    enum Command {
        Show,
        Quit,
    }

    #[derive(Debug)]
    struct NeothTray {
        commands: Sender<Command>,
        icon: ksni::Icon,
    }

    impl NeothTray {
        fn send(&self, command: Command) {
            let _ = self.commands.send(command);
        }
    }

    impl ksni::Tray for NeothTray {
        fn id(&self) -> String {
            "neoth".into()
        }

        fn category(&self) -> ksni::Category {
            ksni::Category::ApplicationStatus
        }

        fn title(&self) -> String {
            TOOLTIP.into()
        }

        fn status(&self) -> ksni::Status {
            ksni::Status::Active
        }

        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            vec![self.icon.clone()]
        }

        fn activate(&mut self, _x: i32, _y: i32) {
            self.send(Command::Show);
        }

        fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
            use ksni::menu::StandardItem;

            vec![
                StandardItem {
                    label: "Show NEOTH".into(),
                    activate: Box::new(|tray: &mut Self| tray.send(Command::Show)),
                    ..Default::default()
                }
                .into(),
                StandardItem {
                    label: "Quit".into(),
                    icon_name: "application-exit".into(),
                    activate: Box::new(|tray: &mut Self| tray.send(Command::Quit)),
                    ..Default::default()
                }
                .into(),
            ]
        }
    }

    pub(super) struct TrayHandle {
        _service: ksni::blocking::Handle<NeothTray>,
        _timer: slint::Timer,
    }

    pub(super) fn setup(window: &MainWindow) -> Option<TrayHandle> {
        let (commands, receiver) = mpsc::channel();
        let tray = NeothTray {
            commands,
            icon: ksni::Icon {
                width: ICON_SIZE as i32,
                height: ICON_SIZE as i32,
                data: orb_argb(ICON_SIZE),
            },
        };

        // No watcher (headless CI, unsupported desktop) is a normal no-tray
        // fallback and must never prevent the GUI from starting.
        let service = match tray.spawn() {
            Ok(service) => service,
            Err(error) => {
                tracing::debug!(%error, "Linux tray unavailable; continuing without it");
                return None;
            }
        };
        let weak = window.as_weak();
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(200),
            move || {
                while let Ok(command) = receiver.try_recv() {
                    match command {
                        Command::Show => {
                            if let Some(window) = weak.upgrade() {
                                let _ = window.show();
                            }
                        }
                        Command::Quit => {
                            let _ = slint::quit_event_loop();
                        }
                    }
                }
            },
        );

        Some(TrayHandle {
            _service: service,
            _timer: timer,
        })
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod desktop {
    use std::time::Duration;

    use tray_icon::{
        TrayIconBuilder, TrayIconEvent,
        menu::{Menu, MenuEvent, MenuItem},
    };

    use super::{ICON_SIZE, MainWindow, TOOLTIP, orb_rgba};

    pub(super) struct TrayHandle {
        _icon: tray_icon::TrayIcon,
        _timer: slint::Timer,
    }

    pub(super) fn setup(window: &MainWindow) -> Option<TrayHandle> {
        let icon = tray_icon::Icon::from_rgba(orb_rgba(ICON_SIZE), ICON_SIZE, ICON_SIZE).ok()?;
        let menu = Menu::new();
        let show_item = MenuItem::new("Show NEOTH", true, None);
        let quit_item = MenuItem::new("Quit", true, None);
        menu.append_items(&[&show_item, &quit_item]).ok()?;

        let icon = TrayIconBuilder::new()
            .with_icon(icon)
            .with_tooltip(TOOLTIP)
            .with_menu(Box::new(menu))
            .build()
            .ok()?;

        let show_id = show_item.id().clone();
        let quit_id = quit_item.id().clone();
        let weak = window.as_weak();
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(200),
            move || {
                while let Ok(event) = MenuEvent::receiver().try_recv() {
                    if event.id == show_id {
                        if let Some(window) = weak.upgrade() {
                            let _ = window.show();
                        }
                    } else if event.id == quit_id {
                        let _ = slint::quit_event_loop();
                    }
                }
                while let Ok(event) = TrayIconEvent::receiver().try_recv() {
                    if let TrayIconEvent::Click {
                        button: tray_icon::MouseButton::Left,
                        button_state: tray_icon::MouseButtonState::Up,
                        ..
                    } = event
                        && let Some(window) = weak.upgrade()
                    {
                        let _ = window.show();
                    }
                }
            },
        );

        Some(TrayHandle {
            _icon: icon,
            _timer: timer,
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod unsupported {
    use super::MainWindow;

    pub(super) struct TrayHandle;

    pub(super) fn setup(_window: &MainWindow) -> Option<TrayHandle> {
        None
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub(super) use desktop::{TrayHandle, setup};
#[cfg(target_os = "linux")]
pub(super) use linux::{TrayHandle, setup};
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub(super) use unsupported::{TrayHandle, setup};

#[cfg(test)]
mod tests {
    use super::{orb_argb, orb_rgba};

    #[test]
    fn procedural_orb_buffers_are_valid() {
        const SIZE: u32 = 32;
        let rgba = orb_rgba(SIZE);
        let argb = orb_argb(SIZE);

        assert_eq!(rgba.len(), (SIZE * SIZE * 4) as usize);
        assert_eq!(argb.len(), rgba.len());
        assert_eq!(&rgba[..4], &[0, 0, 0, 0]);
        let center = (((SIZE / 2) * SIZE + SIZE / 2) * 4) as usize;
        assert_eq!(&rgba[center..center + 4], &[0x00, 0xFF, 0x80, 0xFF]);
        assert!(
            rgba.chunks_exact(4)
                .any(|pixel| (1..255).contains(&pixel[3]))
        );

        for (rgba, argb) in rgba.chunks_exact(4).zip(argb.chunks_exact(4)) {
            assert_eq!(argb, &[rgba[3], rgba[0], rgba[1], rgba[2]]);
        }
    }

    #[test]
    fn linux_tray_source_and_manifest_exclude_tray_icon() {
        let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
        let dependencies = manifest["dependencies"].as_table().unwrap();
        assert!(!dependencies.contains_key("tray-icon"));

        let targets = manifest["target"].as_table().unwrap();
        let linux = targets[r#"cfg(target_os = "linux")"#]["dependencies"]
            .as_table()
            .unwrap();
        assert!(linux.contains_key("ksni"));
        assert!(!linux.contains_key("tray-icon"));

        let desktop =
            targets[r#"cfg(any(target_os = "windows", target_os = "macos"))"#]["dependencies"]
                .as_table()
                .unwrap();
        assert!(desktop.contains_key("tray-icon"));

        let source = include_str!("tray.rs");
        let linux_source = source
            .split_once("mod linux {")
            .unwrap()
            .1
            .split_once("mod desktop {")
            .unwrap()
            .0;
        assert!(!linux_source.contains("tray_icon"));
        assert!(!include_str!("main.rs").contains("tray_icon"));

        let lock = include_str!("../../Cargo.lock");
        assert!(lock.contains("name = \"ksni\"\nversion = \"0.3.6\""));
        for forbidden in [
            "name = \"libappindicator\"",
            "name = \"libappindicator-sys\"",
            "name = \"gtk\"\nversion = \"0.18.",
            "name = \"gtk-sys\"\nversion = \"0.18.",
            "name = \"glib\"\nversion = \"0.18.",
            "name = \"glib-sys\"\nversion = \"0.18.",
        ] {
            assert!(!lock.contains(forbidden), "lockfile contains {forbidden}");
        }
    }
}
