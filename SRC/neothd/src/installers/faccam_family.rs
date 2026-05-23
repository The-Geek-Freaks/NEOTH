//! FC-1 + FC-2 + FC-4 — FacCam family wizard-link primitive.
//!
//! Per R-A3 + R-A6 research (Session 21):
//!   - **FC-1 (FacCam Android)** does NOT exist as a shipping project.
//!     The anonfaded org ships **FadCam** (Android, GPL-3.0, mature).
//!     FC-1 closed as nonexistent-dep + redirected to FadCam.
//!   - **FC-2 (FadCam Android)** ships as a wizard-link-only integration
//!     (FadCam exposes no programmable API — only `ACTION_MAIN` intent).
//!   - **FC-3 (Desktop)** picked: OBS Studio Virtual Camera. Installer
//!     primitive lives in `installers/obs.rs`.
//!   - **FC-4 (Wizard step)** = platform detection → show the
//!     right link + install hint. This module ships the data.
//!
//! No `freedom.yaml::plugins.faccam` Rust binding crate to ship.
//! The wizard step IS the integration surface — show operator the
//! platform-appropriate option + install link, honour the "no
//! silent install" hard rule from PROGRESS.md.

/// One platform-specific FacCam-family recommendation. Pinned
/// exhaustively per OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FacCamFamilyOption {
    /// Android — FadCam via F-Droid (preferred) or GitHub Releases.
    FadcamAndroid,
    /// Desktop (Linux + Windows + macOS) — OBS Studio Virtual Camera
    /// per R-A6 pick.
    ObsVirtualCameraDesktop,
    /// Operator's platform has no recommended FacCam-family option.
    /// (Currently: iOS / BSD other than FreeBSD — none of the family
    /// ships there. Honest "not available" surface beats a fake
    /// recommendation.)
    NotAvailable,
}

impl FacCamFamilyOption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FadcamAndroid => "fadcam_android",
            Self::ObsVirtualCameraDesktop => "obs_virtual_camera_desktop",
            Self::NotAvailable => "not_available",
        }
    }

    /// One-line operator-facing description shown in the wizard
    /// FC-4 step.
    pub fn description(self) -> &'static str {
        match self {
            Self::FadcamAndroid => {
                "FadCam (Android) — GPL-3.0 background/covert camera recorder by anonfaded. \
                 Install from F-Droid (recommended) or GitHub Releases. Privacy-first, no trackers."
            }
            Self::ObsVirtualCameraDesktop => {
                "OBS Studio Virtual Camera (Linux/Windows/macOS) — GPLv2 virtual webcam with rich \
                 anonymity-plugin ecosystem (blur, mask, AI background removal). Drives via obs-websocket."
            }
            Self::NotAvailable => {
                "No FacCam-family option shipped for this platform. iOS / minor BSDs are not supported."
            }
        }
    }

    /// Operator-readable install URL. Wizard renders as a clickable
    /// link / opens default browser. Empty for `NotAvailable`.
    pub fn install_url(self) -> &'static str {
        match self {
            Self::FadcamAndroid => "https://f-droid.org/packages/com.fadcam",
            Self::ObsVirtualCameraDesktop => "https://obsproject.com/download",
            Self::NotAvailable => "",
        }
    }

    /// Project repo URL for operators who want to inspect source.
    pub fn repo_url(self) -> &'static str {
        match self {
            Self::FadcamAndroid => "https://github.com/anonfaded/FadCam",
            Self::ObsVirtualCameraDesktop => "https://github.com/obsproject/obs-studio",
            Self::NotAvailable => "",
        }
    }
}

/// Pick the FacCam-family option for the operator's host OS.
/// `is_android` is operator-supplied (NEOTH desktop daemon can't
/// detect Android directly; companion-app wizard passes the flag in
/// when running on a paired Android device).
pub fn recommend_for_host(is_android: bool) -> FacCamFamilyOption {
    if is_android {
        return FacCamFamilyOption::FadcamAndroid;
    }
    if cfg!(target_os = "linux") || cfg!(target_os = "windows") || cfg!(target_os = "macos") {
        return FacCamFamilyOption::ObsVirtualCameraDesktop;
    }
    FacCamFamilyOption::NotAvailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_as_str_pinned() {
        assert_eq!(FacCamFamilyOption::FadcamAndroid.as_str(), "fadcam_android");
        assert_eq!(
            FacCamFamilyOption::ObsVirtualCameraDesktop.as_str(),
            "obs_virtual_camera_desktop"
        );
        assert_eq!(FacCamFamilyOption::NotAvailable.as_str(), "not_available");
    }

    #[test]
    fn descriptions_distinct_per_option() {
        let descs = [
            FacCamFamilyOption::FadcamAndroid.description(),
            FacCamFamilyOption::ObsVirtualCameraDesktop.description(),
            FacCamFamilyOption::NotAvailable.description(),
        ];
        let unique: std::collections::HashSet<_> = descs.iter().collect();
        assert_eq!(descs.len(), unique.len());
    }

    #[test]
    fn fadcam_install_url_points_at_fdroid_first() {
        // Drift guard — F-Droid is the recommended path (per R-A3
        // privacy-first ethos). A future copy edit must not silently
        // demote it to GitHub Releases as the primary URL.
        let url = FacCamFamilyOption::FadcamAndroid.install_url();
        assert!(url.contains("f-droid.org"));
        assert!(url.contains("com.fadcam"));
    }

    #[test]
    fn obs_install_url_points_at_canonical_download_page() {
        let url = FacCamFamilyOption::ObsVirtualCameraDesktop.install_url();
        assert_eq!(url, "https://obsproject.com/download");
    }

    #[test]
    fn fadcam_repo_url_matches_r_a3_finding() {
        let url = FacCamFamilyOption::FadcamAndroid.repo_url();
        assert_eq!(url, "https://github.com/anonfaded/FadCam");
    }

    #[test]
    fn obs_repo_url_matches_r_a6_finding() {
        let url = FacCamFamilyOption::ObsVirtualCameraDesktop.repo_url();
        assert_eq!(url, "https://github.com/obsproject/obs-studio");
    }

    #[test]
    fn not_available_has_empty_urls() {
        assert!(FacCamFamilyOption::NotAvailable.install_url().is_empty());
        assert!(FacCamFamilyOption::NotAvailable.repo_url().is_empty());
    }

    #[test]
    fn recommend_android_returns_fadcam_regardless_of_host_os() {
        // Operator paired Android device sends is_android=true even
        // when the daemon runs on Linux desktop. FadCam wins.
        assert_eq!(
            recommend_for_host(true),
            FacCamFamilyOption::FadcamAndroid
        );
    }

    #[test]
    fn recommend_desktop_picks_obs_on_supported_oss() {
        let r = recommend_for_host(false);
        if cfg!(target_os = "linux")
            || cfg!(target_os = "windows")
            || cfg!(target_os = "macos")
        {
            assert_eq!(r, FacCamFamilyOption::ObsVirtualCameraDesktop);
        }
    }

    #[test]
    fn fadcam_description_mentions_gpl_license() {
        // Drift guard — operators auditing license posture need to
        // see GPL-3.0 in the picker without clicking through.
        let d = FacCamFamilyOption::FadcamAndroid.description();
        assert!(d.to_lowercase().contains("gpl"));
    }

    #[test]
    fn obs_description_mentions_obs_websocket() {
        // Drift guard — the obs-websocket dependency is what makes
        // OBS programmable from NEOTH. Loss-of-mention would let a
        // future option swap drop the load-bearing feature.
        let d = FacCamFamilyOption::ObsVirtualCameraDesktop.description();
        assert!(d.to_lowercase().contains("obs-websocket"));
    }
}
