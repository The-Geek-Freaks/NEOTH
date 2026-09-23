# W347 managed-browser install operation

`tools::managed_browser::install_reviewed_managed_browser` is the contained, default-off acquisition operation for W333's reviewed Chrome for Testing headless-shell target. It accepts an explicit NEOTH home, explicit `ManagedBrowserPlatform`, `ManagedBrowserConfig`, `ExternalHttpAuthorizer`, and caller-owned `AtomicBool` cancellation signal.

It first refuses when the configuration is disabled or cancellation is already requested. A matching generation that resolves through W333 returns `VerifiedExisting` without HTTP or mutation. For a missing generation, it selects only the compiled-in manifest target, creates an exact `ExternalHttpRequest` with the `ManagedBrowserInstall` surface, and calls `permit.require` inside the authorizer's transport closure before building a no-redirect HTTP client. Redirects, non-success responses, cancellation, stream overflow, and archive SHA-256 mismatch refuse the operation.

The reviewed CFT manifest binds each archive's exact byte length and SHA-256. W347 requires a declared `Content-Length`, when present, to match exactly; it also rejects every stream that exceeds or finishes short of that reviewed length. The 512 MiB manifest ceiling remains an independent admission invariant.

After archive verification, extraction takes place only in a freshly allocated, capability-relative private stage beneath `managed-browser/generations`. ZIP traversal, absolute paths, duplicate or case-colliding members, link/special members, unexpected roots, more than 10,000 members, oversized members, and excessive aggregate output are refused. The staged executable is opened no-follow and checked against the reviewed path, length, and SHA-256; on Unix, only that verified executable receives owner execute permission (`0700`). Only then is the exact W333 marker written and the entire stage exclusively renamed to the deterministic immutable generation. The final postcondition is W333 resolution; no browser process is started.

The stage retains a no-follow identity binding. It is revalidated before extract, marker write, and final rename; pre-publication cleanup uses that exact binding with the bounded capability-relative tree remover. Once the generation rename has occurred, an error remains an observable recovery boundary and is not retried or cleaned up by this operation.

## Next integration boundary

W352 wires the operator-only `neoth browser install` command through `SRC/neothd/src/cli/browser.rs`. The handler rejects `managed_browser.enabled: false`, binds the normal `ExternalHttpAuthorizer`/WAL route to the explicit canonical NEOTH home, passes the runtime platform and cancellation signal, and reports `VerifiedExisting` versus `Installed`. The companion `browser status` command reports artifact integrity only. See `docs/gold-wave352-managed-browser-cli.md`. Neither command adds launch, CDP, navigation, automatic update or background retries.

## Acceptance boundary

The operation accepts static artifact state only: exact manifest target, audited authorization, verified archive, safe extraction, exact executable, marker, and W333 resolver output. Browser launch, contained process tree, private CDP attachment, browser egress enforcement, rendered navigation, credentials, profile handling, repair, update, cleanup, and uninstall remain separate work.
