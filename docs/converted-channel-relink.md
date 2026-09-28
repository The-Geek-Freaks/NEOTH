# Converted OpenClaw channel relink

Implementation status: W1772 source review passed; hosted compilation and
behavioral validation are pending. The command described here is not yet an
accepted release capability.

`neoth channel relink-openclaw` links one explicitly selected OpenClaw account
to NEOTH's default BlueBubbles iMessage or Google Chat Pub/Sub transport.
The OpenClaw account supplies migration provenance. Supply and verify fresh
credentials for the NEOTH transport separately: an `imsg` account cannot
authenticate to BlueBubbles, and an OpenClaw webhook configuration cannot
authenticate a NEOTH Pub/Sub subscriber.

Choose the source account and exact outbound destination explicitly:

```text
neoth channel relink-openclaw imessage_bluebubbles --config openclaw.json --source-account personal --target "iMessage;-;+49123456789"
neoth channel relink-openclaw google_chat --config openclaw.json --source-account work --target spaces/AAAA
```

Each command reads one JSON credential envelope from standard input, up to
8 KiB. Use the same canonical channel name in the envelope and command.
The command accepts no password, token or service-account credential flag.
Both transports currently support only the default NEOTH account; the
OpenClaw source account remains independently selected.

For BlueBubbles, provide these envelope fields through the private stdin
channel:

```json
{
  "schema_version": 1,
  "channel": "imessage_bluebubbles",
  "fields": {
    "url": "http://127.0.0.1:1234",
    "password": "your-bluebubbles-password",
    "allowed_sender": "+49123456789",
    "channels_csv": "iMessage;-;+49123456789"
  }
}
```

`allowed_sender` is required. `channels_csv` optionally limits inbound chats;
it does not replace the explicit outbound `--target`. Relink verifies the
authenticated server and selected chat without sending a message.

For Google Chat, the existing setup envelope uses `url` for the local
service-account JSON path and `server` for the full Pub/Sub subscription:

```json
{
  "schema_version": 1,
  "channel": "google_chat",
  "fields": {
    "url": "C:/private/google-chat-service-account.json",
    "server": "projects/example/subscriptions/neoth",
    "allowed_sender": "users/123456789"
  }
}
```

The key file stays at its configured path. The binary needs the
`gchat-channel` feature. Relink verifies both the subscription and the exact
Chat space through authenticated read-only requests. A missing runtime
feature or unsuccessful target probe cannot make the import ready.

Importing a conversion first blocks that destination's traffic. Source
changes, malformed persisted state, failed probes and incomplete publication
keep it blocked. Successful completion requests a daemon reload; the command
reports that request separately from durable completion. A reload request
does not itself prove that a running adapter has restarted or that an
external provider is reachable.

The migration index stores source commitments and state, without copying
OpenClaw credentials, raw source-account labels or targets into provenance.
Ordinary scalar installations that have no imported conversion retain their
existing behavior.

Relink binds a fresh target probe to a 60-second publication window. If it
expires, rerun the command with the same source, credentials and target. A
reserved or interrupted request remains bound to those inputs, including the
service-account file content. Supplying a different request cannot replace an
ambiguous in-flight operation. The same request resumes its exact durable
credential/routing postimages; an already completed identical request does
not rewrite encrypted credentials. Each converted destination has its own
receipt, so completing Google Chat preserves a valid iMessage relink.
