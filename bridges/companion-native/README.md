# NEOTH Companion native bridge

`companion-native` is the small native boundary used by NEOTH Companion on
Android and iOS. It owns the v3 pairing and reconnect transport, derives the
device Noise and signing identities from protected seed bytes supplied by the
phone, and returns only public enrollment or redacted-status results to the
Flutter layer.

The Flutter client does not implement a second peer transport, an HTTP/bearer
fallback, or a separate server-frame codec. Pairing accepts the one-time v3
invite issued by:

```text
neoth companion pair-mobile
```

Device authority stays at the daemon. Operators can inspect or revoke grants
through:

```text
neoth companion devices list
neoth companion devices status <device-id>
neoth companion devices revoke <device-id>
```

The bridge must never expose the seed, invite URL, PSK, signing key, bearer,
or prompt/provider data in a return value or error. Its public result data is
limited to the accepted enrollment descriptor, device identifier, redacted
status, and machine-readable denial/failure state. The app cancels and drains
an owned operation before freeing its bridge handle.

## Hosted materialization

The repository workflow
`.github/workflows/mobile-companion.yml` materializes reviewed Android and iOS
bridge outputs through
`.github/scripts/mobile/materialize-neoth-companion.ps1`. It copies only
manifest-listed, hash-verified native leaves to the platform package paths.

For a new dependency set, `bootstrap_locks=true` creates hosted candidate lock
artifacts and provenance only. Root reviews the original artifact and commits
the reviewed lock files before a normal qualification can use exact lock
hashes. Bootstrap is not a native build, application signing, release, or
phone acceptance result.

The iOS build binds the local framework directory and verifies all seven
bridge exports in the final Runner binary. Until the platform builds and
these checks pass, this bridge is not
evidence of an installable Android/iOS application or a release-ready binary.
