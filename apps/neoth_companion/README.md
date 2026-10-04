# NEOTH Companion

NEOTH Companion is the phone client for a narrowly scoped NEOTH v3 device
grant. It pairs once with an invite issued by a running daemon, retains a
device identity locally, and shows the redacted status for that device. It is
not a chat client, a prompt client, a file client, or a general remote-control
surface.

## Pairing and device management

Run the daemon with `companion.enabled` and `companion.p2p_enabled` set to true, then mint a one-time mobile invite:

```text
neoth companion pair-mobile
```

Open the displayed QR/deep link on the phone or paste the invite into the app.
An invite is short-lived and single-use. The app never silently retries an
ambiguous pairing and never silently pairs again after a denial or revocation.

The daemon keeps authority for device records. These commands talk to the
running daemon through its same-user control path:

```text
neoth companion devices list
neoth companion devices status <device-id>
neoth companion devices revoke <device-id>
```

`<device-id>` is the UUID reported by `devices list`. Revocation is durable;
the phone shows its revoked/denied state and requires a person to explicitly
forget its public enrollment before a newly minted invite can be used.

## What the app keeps private

On Android, the device seed is protected by Android Keystore-backed secure
storage. On iOS, it is protected by Keychain storage with device-only
accessibility. The native bridge derives the signing and Noise identities from
that seed; the app does not display, log, sync, or include the seed in errors.

After a successful enrollment, the app persists only the public enrollment
descriptor and device identifier needed for reconnect. The invite is visible only in the pairing input and is cleared after the attempt.
The app does not persist that URL or its PSK, bearer credentials, private signing material,
prompt content, or provider data. A denied or revoked result does not erase
the protected device identity or create a fallback network path.

## Hosted build and lock custody

The tracked hosted workflow is
`.github/workflows/mobile-companion.yml`; its materializer is
`.github/scripts/mobile/materialize-neoth-companion.ps1`.

The first run deliberately uses the workflow-dispatch input
`bootstrap_locks=true`. That hosted-only step produces original candidate lock
artifacts and provenance; it does not build a native library, sign an app, or
qualify a release. Root reviews the original artifact, command logs and
provenance before committing the reviewed lock files. A later normal
qualification uses the committed locks and requires their exact hashes before
and after dependency resolution.

The materializer starts from a pinned Flutter 3.24.5 template, preserves its
generated Gradle/wrapper/plugin files, and packages only explicitly
hash-verified bridge inputs. CocoaPods consumes the local framework directory. The iOS gate requires all
seven bridge entry points to be present in the final Runner binary. These
checks still require a successful hosted execution.

## Acceptance boundary

This documentation describes the intended integration path. It is not proof
that an Android APK or iOS app has been built, installed, signed, accepted by
a physical device, or released. Device pairing, reconnect, revocation and the
final native-symbol linkage remain subject to the hosted qualification and
physical-device acceptance gates.
