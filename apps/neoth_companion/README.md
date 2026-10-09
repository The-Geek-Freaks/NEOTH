# NEOTH Companion

NEOTH Companion is the phone client for scoped NEOTH v3 device grants. It pairs
with an invite issued by a running daemon and retains its device identity in
protected local storage. A status grant shows redacted daemon status. A chat
grant allows ordinary messages, live visible answers and tool progress. The
daemon owns model calls and the canonical conversation transcript.

## Pairing and device management

Run the daemon with `companion.enabled` and `companion.p2p_enabled` enabled,
then mint a one-time mobile invite:

```text
neoth companion pair-mobile --scope status-read
neoth companion pair-mobile --scope chat-send
```

Open the QR/deep link on the phone or paste the invite into the app. Invites
are short-lived and single-use. A status grant cannot send chat; changing the
scope requires deliberate new pairing. An ambiguous pairing is never retried
automatically.

The daemon owns device grants. These commands use its same-user control path:

```text
neoth companion devices list
neoth companion devices status <device-id>
neoth companion devices revoke <device-id>
```

Revocation is durable. **Forget this device** clears the local enrollment and
conversation checkpoint before another invite can be used. The protected
device seed is retained. This local action does not delete the daemon's saved
transcript or replace a daemon-side revocation.

## Conversations, history and recovery

Send one ordinary message at a time, up to 640 UTF-8 bytes. Compatible daemon
and native bridge versions provide **New conversation** and a selector for up
to eight saved conversations per device revision. Continuing a conversation
uses its daemon-authorized history as bounded context. A different device or
grant revision cannot resume that conversation.

**Load saved history** reads the most recent canonical messages without a
provider call. This view contains at most 32 records, 16 KiB per available
record and 64 KiB of text; escaped JSON has its own limit. Older records can
fall outside the view. Oversized records show an explicit notice while their
full text remains in the daemon's canonical storage. A confirmed answer is
shown once when its visible history row matches its accepted terminal; model
and provider information remain visible.

Before sending, the phone stores the public request identifier. If delivery or
completion cannot be confirmed, further sending is blocked until **Recover
previous send** checks the saved history. This read can recover a newly created
conversation after loss of the local admission, including after a daemon
restart. It does not resend the message, start a model request, or infer a new
successful turn from the presence of older messages. A restored conversation
is never silently downgraded to a legacy one-off send when native support is
unavailable.

**Incognito** uses no saved conversation context, creates no persistent
conversation binding and saves no canonical conversation history. There is no
saved history to recover for an unconfirmed incognito send.

**Stop waiting** signals the current native operation once. It does not claim
that an already started daemon/provider effect was undone. An accepted terminal
can still win that race. Slash actions, attachments, remote turn cancellation,
notification delivery and offline message queues remain unavailable.

## What stays on the phone

Android protects the device seed with Keystore-backed secure storage; iOS uses
device-only Keychain storage. The native bridge derives the signing and Noise
identities from that seed. It does not display or return private key material.

Protected storage contains the public enrollment, device revision, public
conversation identifiers and any pending request identifier. It does not
persist prompts, answers, private daemon session identifiers or provider data.
An invite is cleared from the pairing input after its attempt; its URL and PSK
are not retained. Enrollment and conversation checkpoint writes share one
ordering so an older in-flight write cannot recreate a forgotten checkpoint.

## Hosted build and acceptance

`.github/workflows/mobile-companion.yml` uses pinned Flutter 3.24.5 and the
committed Rust/Flutter locks. Native inputs and locks are hash-bound. The iOS
gate requires all fourteen FFI exports in the final Runner binary, including
the additive conversation start/poll pair. Legacy chat APIs keep their original
result limits and behavior. `bootstrap_locks=true` is a historical recovery
path, not normal qualification.

The hosted interop workflow checks the actual daemon and encrypted native
client. The conversation journey sends two messages around a daemon/native
owner restart, verifies restored context and four canonical records, proves
that recovery/history reads add no provider calls, checks durable revocation
and drains both daemon generations. Its controlled provider and hosted client
do not establish physical phone acceptance.

The new conversation path still requires fresh successful hosted execution and
independent original-artifact admission on its exact producer. Android/iOS
builds, physical-device operation, signing and release acceptance are separate
gates. This document does not itself establish any of those results.
