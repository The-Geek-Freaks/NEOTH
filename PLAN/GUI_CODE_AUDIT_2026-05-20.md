# NEOTH GUI Code Audit 2026-05-20

Scope: SRC/neothd-gui/src/main.rs, ui/main.slint, ui/chat.slint, ui/settings.slint, ui/components.slint, Cargo.toml.

---

## CRITICAL

### C-1: chat-send-clicked callback never bound in Rust

File: main.rs (no binding exists)

Root cause: MainWindow declares callback chat-send-clicked(string) in main.slint:162.
ChatView wires it at line 840. main.rs has ZERO calls to window.on_chat_send_clicked().
The Rust closure is never registered. Clicking Send or pressing Enter fires the Slint-side
callback into a void -- no action, no error, no message appears.

Fix (add before window.run()):

    let weak_chat = window.as_weak();
    window.on_chat_send_clicked(move |text| {
        if let Some(w) = weak_chat.upgrade() {
            info!(text = %text, "chat: send");
            use slint::{ModelRc, VecModel};
            let mut msgs: Vec<ChatMessage> = w.get_chat_messages().iter().collect();
            msgs.push(ChatMessage { role: "operator".into(), text: text.clone(),
                timestamp: "".into(), streaming: false });
            w.set_chat_messages(ModelRc::new(VecModel::from(msgs)));
        }
    });

---

### C-2: Identity screen Continue disabled -- placeholder/value confusion

File: ui/main.slint:408-423

Root cause: LineEdit uses text <=> root.operator-id (correct two-way binding).
operator-id initialises to empty string (line 80). Continue button gated on
enabled: operator-id != empty string (line 423). Slint placeholder-text is cosmetic;
it does NOT populate text. Operator sees "alex" in the empty field and believes
the value is already set. Button stays disabled until they actively type.
Reproduces the reported bug exactly.

Fix (main.rs before window.run()):

    if let Ok(user) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
        if !user.is_empty() { window.set_operator_id(user.into()); }
    }
    // Also update placeholder-text: "Type your handle (e.g. alex)"

---

### C-3: Hardware probe ANSI escape codes corrupt FooterBar and hardware card

File: main.rs:548-568 (probe_hardware_via_subprocess)

Root cause: Subprocess spawned without NO_COLOR=1 or RUST_LOG_STYLE=never.
The daemon tracing-subscriber emits ANSI color codes on stdout by default.
Those codes are captured via .output() and set verbatim into window.set_hardware_summary().
Slint Text renders them as literal escape sequences (ESC[32m...). FooterBar shows
root.hardware-summary on every screen (main.slint:850) -- corruption is global.

Fix: Add to Command in probe_hardware_via_subprocess AND both Commands in
fetch_kanban_board_snapshot (lines ~427, ~471):
    .env("NO_COLOR", "1")
    .env("RUST_LOG_STYLE", "never")

---

## HIGH

### H-1: chat-channel-switched callback never bound in Rust

File: main.rs (no binding); declared main.slint:164

Root cause: Same pattern as C-1. window.on_chat_channel_switched() is never registered.
Sidebar clicks update active-channel-index in Slint (UI reacts), but Rust is never notified.

Fix:
    let weak_ch = window.as_weak();
    window.on_chat_channel_switched(move |idx| {
        info!(channel_index = idx, "chat: channel switched");
        if let Some(_w) = weak_ch.upgrade() { /* dispatch to daemon */ }
    });

---

### H-2: Autonomy ComboBox visual/default mismatch -- wrong value on first run

File: ui/main.slint:492-534

Root cause: No current-index two-way binding; selected only fires on user interaction.
At startup: ComboBox renders at index 0 ("strict") while autonomy-choice defaults to
"standard" (line 82). Operator who clicks Continue without touching ComboBox gets
autonomy: standard in freedom.yaml even though they saw "strict" on screen.

Fix: Align property default to ComboBox index 0:
    in-out property <string> autonomy-choice: "strict";
Or set current-index: 1 on the ComboBox to display "standard" initially.

---

### H-3: probe_hardware_via_subprocess blocks the main/UI thread at startup

File: main.rs:71-72

Root cause: Blocking Command::new(bin).output() on main thread before window.run().
If neothd hardware hangs (GPU driver stall, NVML init deadlock), the window never appears.

Fix (background thread with upgrade_in_event_loop):
    let weak_hw = window.as_weak();
    window.set_hardware_summary("Probing hardware...".into());
    std::thread::spawn(move || {
        let s = probe_hardware_via_subprocess();
        let _ = weak_hw.upgrade_in_event_loop(move |w| { w.set_hardware_summary(s.into()); });
    });

---

### H-4: fetch_kanban_board_snapshot blocks the main thread at startup

File: main.rs:158

Root cause: Two sequential subprocess calls (kanban list + kanban show) run
synchronously before window.run(), delaying GUI open.

Fix: Same background-thread pattern as H-3 using upgrade_in_event_loop.

---

### H-5: Six of nine Settings tabs are PendingPanel stubs

File: ui/settings.slint:411-449 (Chat, Hemispheres, Channels, Skills, Plugins, Memory)

Intentional stubs -- no code defect. The Re-run wizard and Reload config buttons
in the Config tab ARE fully wired in main.rs (lines 133-183) and functional.
Operator report that these buttons do not work is INCORRECT.
Channels tab being PendingPanel is confirmed. No code fix needed.

---

## MEDIUM

### M-1: Re-entry Done screen shows blank Operator, wrong Provider, wrong Autonomy

File: main.rs:81-103

Root cause: When freedom.yaml exists, step jumps to Done and license_accepted is
set to true. freedom.yaml is never parsed back into operator-id, provider-choice,
autonomy-choice. Done summary card renders defaults instead of actual config values.

Fix: Add Deserialize to MinimalFreedomYaml (see L-2), then:
    if let Ok(body) = std::fs::read_to_string(neoth_dir.join("freedom.yaml")) {
        if let Ok(cfg) = serde_yaml::from_str::<MinimalFreedomYaml>(&body) {
            window.set_operator_id(cfg.operator_id.into());
            window.set_provider_choice(cfg.provider_kind.into());
            window.set_autonomy_choice(cfg.autonomy.into());
        }
    }

---

### M-2: init_tracing emits ANSI codes to stderr

File: main.rs:599-608

Root cause: tracing_subscriber::fmt().compact().init() enables ANSI on TTY.
Breaks operator log files and capture pipelines.

Fix: Add .with_ansi(false) to the tracing subscriber builder chain.

---

### M-3: safe_username allows space -- wider than necessary

File: main.rs:403-410

Root cause: Windows USERNAME allowlist includes space character. While Win32
CreateProcess passes args atomically (no shell-split risk), space should be excluded.

Fix: Change: matches!(c, '.' | '_' | '-' | ' ')
     To:     matches!(c, '.' | '_' | '-')

---

### M-4: serde_json is an implicit transitive dependency

File: Cargo.toml

Root cause: serde_json::from_slice used at main.rs:452 and 495 but serde_json
is absent from [dependencies]. Resolves via transitive dep; not stable.

Fix: Add serde_json = "1" to Cargo.toml [dependencies].

---

## LOW

### L-1: println! calls in on_cli_mode_chosen bypass tracing

File: main.rs:120-125

Four println! statements where the rest of the codebase uses tracing.
Process exits immediately after so no functional impact, but inconsistent.

---

### L-2: MinimalFreedomYaml missing Deserialize -- required for M-1 fix

File: main.rs:251-262

Add #[derive(Serialize, Deserialize)] to MinimalFreedomYaml struct.

---

### L-3: Unsafe set_var in tests without thread-isolation guard

File: main.rs:706-720

finish_rejects_unaccepted_license mutates HOME/USERPROFILE with unsafe set_var.
Parallel test threads observe the mutated env. In Rust 1.81+ set_var is deprecated.

Fix: Refactor finish() to accept neoth_dir: &Path as a parameter instead of
calling default_neoth_home() internally, eliminating the env mutation in tests.

---

## Summary

| ID  | Severity | Title                                                          |
|-----|----------|----------------------------------------------------------------|
| C-1 | CRITICAL | chat-send-clicked never bound -- Send button dead              |
| C-2 | CRITICAL | Identity Continue blocked -- placeholder not a value           |
| C-3 | CRITICAL | Hardware probe ANSI codes corrupt FooterBar text               |
| H-1 | HIGH     | chat-channel-switched never bound -- silent                    |
| H-2 | HIGH     | Autonomy ComboBox visual/default mismatch -- wrong value       |
| H-3 | HIGH     | Hardware probe blocks main thread -- window may never appear   |
| H-4 | HIGH     | Kanban fetch blocks main thread at startup                     |
| H-5 | HIGH     | 6/9 Settings tabs are stubs (Config tab buttons DO work)       |
| M-1 | MEDIUM   | Re-entry Done screen shows blank/wrong config values           |
| M-2 | MEDIUM   | init_tracing emits ANSI to stderr                              |
| M-3 | MEDIUM   | safe_username allows space in Windows username                 |
| M-4 | MEDIUM   | serde_json implicit transitive dep, not in Cargo.toml          |
| L-1 | LOW      | println! in cli-mode-chosen -- bypass tracing                  |
| L-2 | LOW      | MinimalFreedomYaml missing Deserialize (required for M-1)      |
| L-3 | LOW      | Unsafe set_var in tests without thread-isolation guard         |

Verdict: BLOCK.
C-1 makes the primary daily surface (chat) completely non-functional.
C-2 blocks first-run identity entry for any operator who reads the placeholder as pre-filled.
C-3 corrupts the hardware card and FooterBar on every screen.
Fix all three CRITICALs before the next operator test session.
H-2, H-3, H-4 should follow in the same pass.
