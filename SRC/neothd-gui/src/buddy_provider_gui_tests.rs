//! Real-CLI GUI regression coverage for the Buddy provider configuration panel.
//!
//! These tests deliberately use the `neoth` binary built beside the hosted GUI
//! test executable.  No shell replacement or canned JSON is installed: the
//! Slint callbacks spawn the actual core CLI against an owned `NEOTH_HOME`.

#![cfg(test)]

#[cfg(not(windows))]
use super::*;
#[cfg(not(windows))]
use slint::{ComponentHandle as _, Model as _, ModelRc, VecModel};
#[cfg(not(windows))]
use std::{
    cell::Cell,
    ffi::OsString,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};
#[cfg(not(windows))]
use tempfile::TempDir;

#[cfg(not(windows))]
struct NeothHomeGuard(Option<OsString>);

#[cfg(not(windows))]
impl NeothHomeGuard {
    fn install(home: &Path) -> Self {
        let previous = std::env::var_os("NEOTH_HOME");
        unsafe { std::env::set_var("NEOTH_HOME", home.as_os_str()) };
        Self(previous)
    }
}

#[cfg(not(windows))]
struct PathGuard(Option<OsString>);

#[cfg(not(windows))]
impl PathGuard {
    fn prepend(directory: &Path) -> Self {
        let previous = std::env::var_os("PATH");
        let mut entries = vec![directory.to_path_buf()];
        if let Some(ref value) = previous {
            entries.extend(std::env::split_paths(value));
        }
        let joined = std::env::join_paths(entries).expect("assemble hosted helper PATH");
        unsafe { std::env::set_var("PATH", joined) };
        Self(previous)
    }
}

#[cfg(not(windows))]
impl Drop for PathGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => unsafe { std::env::set_var("PATH", value) },
            None => unsafe { std::env::remove_var("PATH") },
        }
    }
}

#[cfg(not(windows))]
impl Drop for NeothHomeGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => unsafe { std::env::set_var("NEOTH_HOME", value) },
            None => unsafe { std::env::remove_var("NEOTH_HOME") },
        }
    }
}

#[cfg(not(windows))]
fn write_real_cli_home(home: &Path, legacy_fallback: bool) {
    std::fs::create_dir_all(home).expect("create owned NEOTH_HOME");
    let fallback = if legacy_fallback {
        "fallback:\n  max_hops: 2\n  chain:\n    - provider: claude_cli\n      model: legacy-model\n"
    } else {
        "fallback:\n  max_hops: 2\n  chain:\n    - provider_instance_id: route_a\n"
    };
    std::fs::write(home.join("freedom.yaml"), format!(
        "provider_kind: openai_api\nprovider_model: gpt-4o\ninference:\n  mode: custom\n  provider_instances:\n    - id: route_a\n      descriptor: openai_api\n      model: gpt-4o\n    - id: route_b\n      descriptor: claude_cli\n      model: b-model\n  left:\n    provider_instance_id: route_a\n  right:\n    provider_instance_id: route_b\n  cerebellum:\n    provider_instance_id: route_a\n{fallback}"
    )).expect("write real CLI freedom configuration");
    // A synthetic per-instance credential gives the adapter construction path
    // a real configured secret without any external endpoint or live request.
    std::fs::write(
        home.join("credentials.yaml"),
        "inference_provider_instance_keys:\n  route_a: hosted-test-synthetic-key\n",
    )
    .expect("write real CLI credential fixture");
}

#[cfg(not(windows))]
fn pump(window: &MainWindow, purpose: &str) {
    let done = Rc::new(Cell::new(false));
    let observed = Rc::clone(&done);
    let weak = window.as_weak();
    let ticks = Rc::new(Cell::new(0_u16));
    let observed_ticks = Rc::clone(&ticks);
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(10),
        move || {
            if let Some(window) = weak.upgrade() {
                if !window.get_bc_provider_config_busy() {
                    observed.set(true);
                    let _ = slint::quit_event_loop();
                    return;
                }
            }
            let next = observed_ticks.get().saturating_add(1);
            observed_ticks.set(next);
            // Core bounds a provider command plus mandatory fresh readback at 120
            // seconds. Leave a scheduling margin, then drain a second bounded
            // interval before this test can release NEOTH_HOME or its TempDir.
            if next >= 13_000 {
                let _ = slint::quit_event_loop();
            }
        },
    );
    let _ = window.hide();
    slint::run_event_loop_until_quit().expect("drain real Buddy callback");
    drop(timer);
    if !done.get() {
        let drained = Rc::new(Cell::new(false));
        let observed = Rc::clone(&drained);
        let weak = window.as_weak();
        let drain_ticks = Rc::new(Cell::new(0_u16));
        let observed_drain_ticks = Rc::clone(&drain_ticks);
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(10),
            move || {
                if weak
                    .upgrade()
                    .is_some_and(|window| !window.get_bc_provider_config_busy())
                {
                    observed.set(true);
                    let _ = slint::quit_event_loop();
                    return;
                }
                let next = observed_drain_ticks.get().saturating_add(1);
                observed_drain_ticks.set(next);
                if next >= 13_000 {
                    let _ = slint::quit_event_loop();
                }
            },
        );
        let _ = window.hide();
        slint::run_event_loop_until_quit().expect("drain timed-out real Buddy callback");
        drop(timer);
        assert!(
            drained.get(),
            "real Buddy callback did not settle after bounded core timeout: {purpose}"
        );
    }
}

#[cfg(not(windows))]
fn install_real_cli_path() -> PathGuard {
    let current = std::env::current_exe().expect("resolve hosted GUI test executable");
    let helper_dir = current
        .parent()
        .and_then(Path::parent)
        .expect("GUI test executable must be in target/debug/deps");
    let expected = helper_dir.join("neoth");
    assert!(
        expected.is_file(),
        "hosted fixture must build target/debug/neoth: {}",
        expected.display()
    );
    let path = PathGuard::prepend(helper_dir);
    let resolved = which_neothd().expect("resolve exact hosted neoth helper");
    assert_eq!(
        std::fs::canonicalize(resolved).expect("canonicalize resolved helper"),
        std::fs::canonicalize(&expected).expect("canonicalize expected target/debug/neoth"),
        "an installed or unrelated PATH neoth cannot satisfy this real-core test"
    );
    path
}

#[cfg(not(windows))]
fn assert_accepted(window: &MainWindow, receipt_fragment: &str) {
    assert!(
        window.get_bc_provider_config_status_valid(),
        "callback must publish only verified fresh readback"
    );
    assert!(
        window.get_bc_provider_config_error().is_empty(),
        "accepted callback must clear stale error"
    );
    assert!(
        window
            .get_bc_provider_config_receipt()
            .to_string()
            .contains(receipt_fragment),
        "callback must project its typed receipt"
    );
}

/// The real core writer receives every configuration callback.  Each accepted
/// receipt is followed by an actual `provider show`; source bytes and WAL
/// prove that the owned configuration changed, without any network request.
#[cfg(not(windows))]
#[cfg_attr(not(all(target_os = "macos", feature = "macos-native-gui-test")), test)]
pub(crate) fn w2263_buddy_provider_callbacks_execute_canonical_receipts_then_refresh_readback() {
    let _serial = GUI_CALLBACK_ENV_LOCK
        .lock()
        .expect("serialize real GUI environment");
    let fixture = TempDir::new().expect("create real CLI fixture");
    write_real_cli_home(fixture.path(), false);
    let _path = install_real_cli_path();
    let _home = NeothHomeGuard::install(fixture.path());
    let before = std::fs::read_to_string(fixture.path().join("freedom.yaml"))
        .expect("read initial configuration");

    let window = MainWindow::new().expect("construct real provider GUI");
    register_buddy_provider_callbacks(&window);
    window.invoke_bc_buddy_provider_show();
    pump(&window, "initial real provider show");
    assert!(window.get_bc_provider_config_status_valid());
    assert_eq!(window.get_bc_provider_config_instances().row_count(), 2);

    // No question means construction-only. `dry_run` is true so the GUI path
    // cannot promote it into a live provider call.
    let receipt_before_test = window.get_bc_provider_config_receipt().to_string();
    window.invoke_bc_buddy_provider_test("left".into(), "".into(), true);
    pump(&window, "construction-only provider test");
    if cfg!(target_os = "macos") {
        // macOS deliberately has no contained provider-test execution tree.
        // The safe terminal state is an unavailable result; supported core
        // configuration commands below must still use the real CLI.
        assert!(!window.get_bc_provider_config_status_valid());
        assert!(
            window
                .get_bc_provider_config_error()
                .to_string()
                .contains("unavailable")
        );
        assert_eq!(
            window.get_bc_provider_config_receipt().to_string(),
            receipt_before_test,
            "unsupported macOS test must not publish a new success receipt"
        );
        window.invoke_bc_buddy_provider_show();
        pump(&window, "macOS supported provider show after rejected test");
        assert_accepted(&window, "configuration verified");
    } else {
        assert_accepted(&window, "construction test completed");
    }

    window.invoke_bc_buddy_provider_set("left".into(), "openai_api".into(), "gpt-4o-mini".into());
    pump(&window, "real provider set plus fresh show");
    assert_accepted(&window, "role update was accepted");
    let left = window
        .get_bc_provider_config_roles()
        .row_data(0)
        .expect("fresh left binding");
    assert_eq!(left.role.to_string(), "left");
    assert_eq!(left.provider.to_string(), "openai_api");
    assert_eq!(left.model.to_string(), "gpt-4o-mini");
    window.invoke_bc_buddy_provider_select("right".into(), "route_b".into());
    pump(&window, "real named selection plus fresh show");
    assert_accepted(&window, "Named provider selection");
    let right = window
        .get_bc_provider_config_roles()
        .row_data(1)
        .expect("fresh right binding");
    assert_eq!(right.provider_instance_id.to_string(), "route_b");
    let order = ModelRc::new(VecModel::from(vec!["route_b".into(), "route_a".into()]));
    window.invoke_bc_buddy_fallback_replace(order);
    pump(&window, "real fallback replacement plus fresh show");
    assert_accepted(&window, "Fallback order was accepted");
    assert_eq!(
        window
            .get_bc_provider_config_current_fallback_selectors()
            .row_count(),
        2
    );
    assert_eq!(
        window
            .get_bc_provider_config_current_fallback_selectors()
            .row_data(0)
            .unwrap()
            .provider_instance_id
            .to_string(),
        "route_b"
    );
    assert_eq!(
        window
            .get_bc_provider_config_current_fallback_selectors()
            .row_data(1)
            .unwrap()
            .provider_instance_id
            .to_string(),
        "route_a"
    );
    assert_eq!(window.get_bc_provider_config_fallback_max_hops(), 2);
    window.invoke_bc_buddy_fallback_clear();
    pump(&window, "real fallback clear plus fresh show");
    assert_accepted(&window, "Fallback order was cleared");
    assert_eq!(
        window
            .get_bc_provider_config_current_fallback_selectors()
            .row_count(),
        0
    );
    window.invoke_bc_buddy_provider_mode("local_qwen".into(), "".into());
    pump(&window, "real provider mode plus fresh show");
    assert_accepted(&window, "mode update was accepted");
    assert_eq!(
        window.get_bc_provider_config_mode().to_string(),
        "single",
        "mode receipt must be followed by its canonical single-mode readback"
    );
    window.invoke_bc_buddy_provider_preset("single".into(), "".into(), "".into());
    pump(&window, "real provider preset plus fresh show");
    assert_accepted(&window, "preset was accepted");
    assert_eq!(
        window.get_bc_provider_config_mode().to_string(),
        "single",
        "single preset must retain the canonical single-mode readback"
    );

    assert!(window.get_bc_provider_config_status_valid());
    assert!(window.get_bc_provider_config_error().is_empty());
    let after = std::fs::read_to_string(fixture.path().join("freedom.yaml"))
        .expect("read persisted configuration");
    assert_ne!(
        after, before,
        "real core mutations must persist owned config changes"
    );
    assert!(
        after.contains("mode: single"),
        "mode/preset must persist through canonical writer"
    );
    let wal = fixture.path().join("wal");
    assert!(
        wal.is_dir()
            && std::fs::read_dir(wal)
                .expect("read owned WAL")
                .next()
                .is_some(),
        "real mutation must leave a WAL receipt in owned home"
    );
}

/// Legacy inline fallback entries are visible but non-editable. Invalid input
/// and a real corrupted `freedom.yaml` must retain the last verified Slint
/// projection and avoid another configuration mutation.
#[cfg(not(windows))]
#[cfg_attr(not(all(target_os = "macos", feature = "macos-native-gui-test")), test)]
pub(crate) fn w2263_buddy_provider_callbacks_preserve_legacy_and_last_good_on_rejected_or_malformed_readback()
 {
    let _serial = GUI_CALLBACK_ENV_LOCK
        .lock()
        .expect("serialize real GUI environment");
    let fixture = TempDir::new().expect("create legacy real CLI fixture");
    write_real_cli_home(fixture.path(), true);
    let _path = install_real_cli_path();
    let _home = NeothHomeGuard::install(fixture.path());
    let window = MainWindow::new().expect("construct legacy provider GUI");
    register_buddy_provider_callbacks(&window);
    window.invoke_bc_buddy_provider_show();
    pump(&window, "real legacy provider show");
    assert!(window.get_bc_provider_config_status_valid());
    assert!(window.get_bc_provider_config_current_fallback_has_legacy());
    assert_eq!(
        window
            .get_bc_provider_config_current_fallback_selectors()
            .row_data(0)
            .unwrap()
            .binding_source
            .to_string(),
        "legacy_inline"
    );
    let before =
        std::fs::read_to_string(fixture.path().join("freedom.yaml")).expect("capture prior config");

    window.invoke_bc_buddy_fallback_replace(ModelRc::new(VecModel::from(vec!["route_a".into()])));
    assert_eq!(
        std::fs::read_to_string(fixture.path().join("freedom.yaml")).unwrap(),
        before,
        "legacy fallback replacement must be rejected before a real writer starts"
    );
    assert!(
        window
            .get_bc_provider_config_error()
            .to_string()
            .contains("named provider instances")
    );
    window.invoke_bc_buddy_provider_preset("single".into(), "4096".into(), "256".into());
    assert_eq!(
        std::fs::read_to_string(fixture.path().join("freedom.yaml")).unwrap(),
        before,
        "out-of-range numeric count must not write config"
    );
    window.invoke_bc_buddy_provider_preset("single".into(), "4096".into(), "0".into());
    assert_eq!(
        std::fs::read_to_string(fixture.path().join("freedom.yaml")).unwrap(),
        before,
        "zero numeric count must not write config"
    );
    #[cfg(target_os = "macos")]
    {
        window.invoke_bc_buddy_provider_preset("local-abliterated".into(), "".into(), "".into());
        pump(
            &window,
            "macOS local-abliterated preset without explicit VRAM",
        );
        assert_eq!(
            std::fs::read_to_string(fixture.path().join("freedom.yaml")).unwrap(),
            before,
            "macOS local-abliterated preset without explicit VRAM must not write config"
        );
        let error = window.get_bc_provider_config_error().to_string();
        assert!(
            error.contains("explicit VRAM") || error.contains("unavailable"),
            "macOS must project a safe explicit-VRAM/unavailable reason: {error}"
        );
    }

    std::fs::write(fixture.path().join("freedom.yaml"), "inference: [corrupt")
        .expect("corrupt only owned config");
    window.invoke_bc_buddy_provider_show();
    pump(&window, "real malformed provider show");
    assert!(!window.get_bc_provider_config_status_valid());
    assert!(
        window
            .get_bc_provider_config_error()
            .to_string()
            .contains("prior configuration remains displayed")
    );
    assert_eq!(
        window
            .get_bc_provider_config_current_fallback_selectors()
            .row_data(0)
            .unwrap()
            .binding_source
            .to_string(),
        "legacy_inline",
        "failed real readback must keep the prior verified projection"
    );
}
