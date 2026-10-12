# W2564 — Companion device access inspection

The paired companion can explicitly check the permission the daemon currently grants to this device. The Device access card shows a pseudonymous device ID, the last confirmed scope, grant revision and server observation time. The check does not send a chat message, invoke a model/tool, or acquire microphone/camera/speaker access.

This extends JARVIS-ADOPT-01 through the existing companion authority. It is not the complete hardware-capability or exclusive-resource-lease requirement. Those remain open, along with physical-device acceptance.

## Contract

A new optional capability_inventory_v1 envelope sibling advertises support on both existing status and chat challenges. Old clients continue to use their frozen challenge bodies. A new client sends an inventory request only after a valid offer; a missing offer fails explicitly without a fallback status request or chat.

The command passed to the additive native FFI has inventory_schema_version=1, the persisted enrollment revision and the exact expected_scope string (companion.status.read or companion.chat.send). This scope is only a route and consistency hint. The signed network request has no scope or hardware-capability input. Its separate domain binds device, revision, listener generation, daemon boot identity, one-use nonce and request UUID. DeviceAuthority determines the returned scope from the active grant.

The existing delivery marker is published before response I/O. An active-grant/marker recheck precedes the write. Once admitted, the retained listener owns the write and checked carrier drain before completing the lease. Inventory shares existing global delivery serialization and never grants a provider-start effect. Revocation before admission denies; an admitted delivery must drain before revoke finalization.

The native bridge pins the daemon key and validates request, device, revision, scope, listener and boot bindings. The Flutter controller independently checks persisted enrollment and authority epoch, serializes the existing native operation owner and discards late completions after Forget. Success does not mark status readiness. No new secret, store, background polling or resource owner is introduced.

## Verification boundary

Nine new Rust cases cover signed fields, compatibility, malformed identities, challenge replay, cross-scope admission, stale/expired/revoked requests, delivery drain, provider-effect denial, pre-write negotiation and public response binding. Seven Flutter cases cover both grant types, foreign/malformed results, Forget races, operation serialization, idempotent cancellation, delayed-cancel isolation and unsupported ABI behavior.

The existing hosted interop runner performs actual bridge/daemon inventory exchanges for its separate status and chat devices. It verifies fresh server time, exact identity/revision/scope, distinct device IDs and zero additional provider requests. The new FFI export is retained in Android/host symbol manifests and iOS linker roots.

These are candidate changes, not executable acceptance. No local build, formatter, parser, test, product or GUI runtime was started. The ongoing full CI on 53eff2f6 does not contain this candidate. Fresh hosted preflight, exact interop/bridge cases and mobile software builds are required after publication. Physical device behavior and complete JARVIS-ADOPT-01 remain open.