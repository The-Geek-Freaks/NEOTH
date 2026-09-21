//! Operator-triggered verification of the published Ouro Q8 cache.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use slint::ComponentHandle;

use super::gui_action::{OuroQ8VerifyError, OuroQ8VerifyOutcome};
use super::MainWindow;

static VERIFY_ACTIVE: AtomicBool = AtomicBool::new(false);
static VERIFY_REVISION: AtomicU64 = AtomicU64::new(0);

pub(super) fn register(window: &MainWindow) {
    let weak = window.as_weak();
    window.on_ouro_q8_verify_clicked(move || {
        let Some(window) = weak.upgrade() else {
            return;
        };
        if VERIFY_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let revision = VERIFY_REVISION.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        window.set_ouro_q8_verify_running(true);
        window.set_ouro_q8_verify_unavailable(false);
        clear_verification(&window);
        window.set_ouro_q8_verify_status(
            "Checking the published cache through the Q8 model loader…".into(),
        );

        let weak = weak.clone();
        std::thread::spawn(move || {
            let result = match super::neothd_json_command(&["ouro", "verify-q8"]) {
                Ok(mut command) => {
                    super::gui_action::run_ouro_q8_verify(&mut command, "Ouro Q8 verification")
                }
                Err(detail) => Err(OuroQ8VerifyError {
                    // Command construction failed before a process existed.
                    process_exit_observed: true,
                    detail,
                }),
            };
            let retry_safe = result
                .as_ref()
                .map_or_else(|error| error.process_exit_observed, |_| true);
            let scheduled = slint::invoke_from_event_loop(move || {
                if VERIFY_REVISION.load(Ordering::Acquire) != revision {
                    return;
                }
                if retry_safe {
                    VERIFY_ACTIVE.store(false, Ordering::Release);
                }
                let Some(window) = weak.upgrade() else {
                    return;
                };
                window.set_ouro_q8_verify_running(false);
                window.set_ouro_q8_verify_unavailable(!retry_safe);
                match result {
                    Ok(OuroQ8VerifyOutcome::Verified(receipt)) => {
                        window.set_ouro_q8_verify_configured_mode(
                            receipt.configured_quant_mode.into(),
                        );
                        window.set_ouro_q8_verify_receipt(receipt.receipt.into());
                        window.set_ouro_q8_verify_device(receipt.resolved_device.into());
                        window.set_ouro_q8_verify_forward_summary(
                            format!(
                                "{} model loops · two distinct Q8 forwards verified",
                                receipt.loop_steps
                            )
                            .into(),
                        );
                        window.set_ouro_q8_verify_status("Published Q8 cache verified.".into());
                        window.set_ouro_q8_verify_verified(true);
                    }
                    Ok(OuroQ8VerifyOutcome::Failed {
                        configured_quant_mode,
                        detail,
                    }) => {
                        clear_verification(&window);
                        window.set_ouro_q8_verify_configured_mode(configured_quant_mode.into());
                        window.set_ouro_q8_verify_status(format!("Not verified: {detail}").into());
                    }
                    Err(error) => {
                        clear_verification(&window);
                        let detail = neothd::security::redact::sanitize_tool_output(&error.detail);
                        let status = if retry_safe {
                            format!("Not verified: {detail}")
                        } else {
                            format!(
                                "Verification state unavailable: {detail} A second check is disabled because the previous process has not been observed to exit."
                            )
                        };
                        window.set_ouro_q8_verify_status(status.into());
                    }
                }
            });
            if scheduled.is_err()
                && retry_safe
                && VERIFY_REVISION.load(Ordering::Acquire) == revision
            {
                VERIFY_ACTIVE.store(false, Ordering::Release);
            }
        });
    });
}

fn clear_verification(window: &MainWindow) {
    window.set_ouro_q8_verify_verified(false);
    window.set_ouro_q8_verify_configured_mode("".into());
    window.set_ouro_q8_verify_receipt("".into());
    window.set_ouro_q8_verify_device("".into());
    window.set_ouro_q8_verify_forward_summary("".into());
}
