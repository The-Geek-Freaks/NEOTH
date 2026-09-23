# W325 — managed browser engine and runtime decision

**Status:** W325 decision corrected after independent review. It selects the future implementation architecture; source implementation and its repository gates are owned by the follow-on workflow.

## Decision

Select **chromiumoxide v0.9.1**, upstream tag a7e2bb835b9643410f9e3dc044f0d947e96cbfa4, only as the Rust CDP client. It does **not** launch the browser. NEOTH launches the exact manifest-resolved Chrome for Testing headless-shell executable through its own contained-child primitive, then attaches with Browser::connect to one request-owned private CDP endpoint.

The browser pin is Chrome for Testing Stable **154.0.8037.57**, revision **1689415**. The initial target set is Windows win64, Linux linux64, macOS mac-x64 and macOS mac-arm64. Each target needs a NEOTH manifest/provenance receipt that binds exact official CFT URL, version, revision, computed archive SHA-256, expected relative executable and licence/notice record. The observed CFT feed supplies version, revision, platform and URL but no vendor digest. That is not an upstream blocking defect: NEOTH's reviewed acquisition is the trust boundary, and its retained SHA-256 is the reproducibility/integrity pin thereafter. Missing local receipt/manifest data simply makes installation fail closed.

Every browser is headless, per-request and unauthenticated. There is no persistent daemon, ambient Chrome/CDP/profile fallback, browser registry/PATH/HOME/USERPROFILE lookup or automatic chromiumoxide fetcher.

## Why chromiumoxide

The upstream README documents an async Tokio Chrome DevTools Protocol API and headless operation. Its v0.9.1 API documents Browser::connect and Browser::connect_with_config for an already-running Chromium; an HTTP(S) attach address reads json/version. Its Cargo manifest declares MIT OR Apache-2.0, Rust 1.85 and a separately optional fetcher. AGENTER declares Rust 1.91, so metadata shows no MSRV conflict; dependency resolution and lockfile proof remain implementation acceptance evidence.

Reject playwright-rs v0.18.1 for this narrow Chromium-only delivery. Its README describes a Rust API backed by a bundled Playwright Server over JSON-RPC, driver assembly in the build script and browser installation through its installer. That adds a Node/driver artifact lifecycle which is unnecessary when AGENTER needs one contained Chromium executable. The rejection does not claim playwright-rs cannot work.

## Evidence

| Subject | Evidence observed 2026-09-23 | Consequence |
| --- | --- | --- |
| Road | PLAN/ROAD_TO_1_0_GOLD.md:8650 requires engine choice plus managed runtime, policy, network, credential, progress, cancellation and clean-machine lifecycle. | W325 fixes the implementation direction and gates. |
| Existing request seam | SRC/neothd/src/tools/web_fetch.rs:256-275 canonicalizes URL, records/obtains ExternalHttpRequest Fetch authorization, requires permit, validates DNS/SSRF, then uses no-redirect HTTP. | Rendered fetch remains downstream of this authorization/WAL seam. |
| Selected engine | [chromiumoxide v0.9.1](https://github.com/mattsse/chromiumoxide/tree/v0.9.1) and [Browser API](https://docs.rs/chromiumoxide/0.9.1/chromiumoxide/browser/struct.Browser.html). | Use connect only. Browser::launch is prohibited because it launches before NEOTH can place the child in containment. |
| Alternative | [playwright-rs v0.18.1](https://github.com/padamson/playwright-rust/tree/v0.18.1) README. | Its bundled driver and installer lifecycle is outside the selected minimum. |
| Browser source | [Chrome for Testing Stable feed](https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json). | Reviewed acquisition writes the local provenance receipt and manifest SHA-256. |
| Child containment | SRC/neothd/src/updater/process_containment.rs and SRC/neothd/src/providers/recursive_mas_adapter.rs:68-121,278-288. | Windows creates suspended then assigns Job Object before resume; Unix owns a process group. |

## Containment and private CDP contract

The resolved executable is launched externally through NEOTH's existing containment model. On Windows, its first runnable instruction occurs only after suspended creation, Job Object assignment and resume. On Unix, it belongs to the owned process group before browser work. Chromium descendants remain inside the same boundary.

The CDP endpoint is per-request, private and passed as the exact Browser::connect endpoint. It is neither discovered nor shared: implementation must not scan ports, query a default localhost port, reuse a DevTools service or attach to an ambient browser. Any json/version request is limited to that exact contained endpoint. Endpoint and token data are secret operational state and stay out of WAL, progress, errors and diagnostics. Shutdown closes CDP, then reaps the owned tree, then removes the owned profile.

## Browser-wide network boundary

**CDP interception is observability/control assistance, not the egress boundary.** Pre-navigation validation and CDP alone cannot constrain Chromium sockets, redirects, rebinding, subresources, workers/service workers, WebSockets, WebRTC/STUN, speculative traffic, file origins or loopback/internal targets.

Before any external rendered navigation, the managed browser must have an enforceable browser-process egress boundary. The selected design target is a request-owned contained policy proxy as the browser's only allowed egress, with a platform firewall/sandbox/network-namespace boundary of equivalent strength acceptable only if reviewed to the same contract. The browser launches with direct egress denied; loss or unavailability of the enforcement point fails the request before navigation.

The proxy boundary must:

1. accept only the contained browser and use an authenticated per-request control endpoint;
2. deny file/data and every non-HTTP(S) destination, including WebSocket and WebRTC/STUN traffic; disable or deny service workers and speculative/preload paths unless their mediated behavior is specifically implemented;
3. canonicalize every main-frame redirect candidate before it is followed, obtain a fresh ExternalHttpRequest permit and WAL correlation, and reject it when that fails;
4. resolve and connect upstream itself through the existing authorized HTTP transport, pin the reviewed DNS answer to that request's connection, and prohibit the browser from independently resolving/connecting;
5. reject private, loopback, link-local, metadata and internal destinations at every origin/subresource request; and
6. enforce request count, redirect count, response/extracted bytes, total deadline and session concurrency.

The egress proxy is a prerequisite for implementation acceptance of externally rendered navigation. It is a repository design/work item, not a missing third-party vendor capability.

## Runtime and credential contract

Managed data is an explicit NEOTH-home child, proposed as .neoth/managed-browser, with immutable platform/version generations, authenticated current pointer and private per-session profiles. Install verifies the reviewed SHA-256 before unpacking, checks paths/version/revision/executable, then publishes pointer-last. Update/repair preserve a valid prior generation until the new verified generation is published; uninstall revokes pointer before deleting only managed data. Package records retain Chrome for Testing licence/notices and chromiumoxide's MIT OR Apache-2.0 notice.

The initial mode imports no cookies, profile, session or OS credentials and exposes no credential field. Any authenticated mode remains a later separately designed capability using opaque secret references and the existing authorization/audit model. Browser profiles, cookies and secret values never reach WAL, progress, extraction or errors.

## Lifecycle

Phases are resolve_runtime, create_profile, establish_egress_boundary, launch_contained_browser, connect_private_cdp, authorize_navigate, navigate, extract and cleanup. One total deadline and bounded resources apply. Cancellation/timeout follow the same order: CDP close, owned-tree termination/reap, profile removal.
