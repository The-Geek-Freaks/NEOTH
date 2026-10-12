# Native companion bridge ABI contract

`neoth_companion_bridge_new` copies exactly 32 bytes from protected platform
storage. Android Keystore and iOS Keychain are responsible for supplying and
zeroing that buffer. The FFI surface never accepts a bearer token, WebChat
cookie, raw private key, or a daemon filesystem path.

Every `*_start` call returns an owned operation. `poll` is non-blocking and
returns `pending` until terminal. Calling `cancel` or `free` requests the
operation's cooperative shutdown and joins its Peeroxide task before return.
The caller may call `poll` repeatedly, then must call `free` exactly once.
All UTF-8 inputs and outputs have hard byte bounds. Null pointers, invalid
UTF-8, malformed descriptors, noncanonical QR fields, and impossible states
return null or a documented terminal code; they never unwind across FFI.

`neoth_companion_chat_start_v2` and `neoth_companion_operation_poll_v2` are
additive. They do not change the original start/poll, cancellation, free, or
terminal-result semantics. A v2 start with `request_tool_activity=1` sends the
signed opt-in only after the encrypted server ChatChallenge advertises it;
without that advertisement it sends the exact legacy request once. A write
ambiguity remains terminal `indeterminate` and is never replayed.

The v2 poll returns result code `6` only for a bounded redacted
`chat_activity_snapshot` JSON envelope. It uses the existing code `5` size
probe without consuming the snapshot; a successful code `6` sized read consumes
that snapshot. A terminal result always wins an
activity snapshot under the same operation state lock. Activity is coalesced
by its authenticated request UUID and maximum event sequence; a same-sequence
transition from `incomplete:false` to `incomplete:true` is retained as a loss
notice, while stale or fabricated sequence progress is rejected.

## C ownership and concurrency preconditions

Each opaque bridge and operation pointer has one C owner. Any non-null input
pointer must be correctly aligned and valid to read for its supplied length;
each non-null output pointer must be valid to write for its supplied length.
The caller must not invoke `poll`, `cancel`, `*_start`, `operation_free`, or
`bridge_free` concurrently on the same opaque handle, and must not retain or
reuse an alias after its corresponding `free`. These are C memory-safety
preconditions: `catch_unwind` maps Rust panics to documented errors, but cannot
recover undefined behavior from a dangling, misaligned, or concurrently freed
C pointer.

The pair result is deliberately public:

```json
{
  "state": "paired",
  "device_id": "UUID",
  "revision": 1,
  "descriptor": {
    "schema_version": 3,
    "carrier": "peeroxide-hyperswarm-v3",
    "rendezvous_topic_hex": "64 lower-case hex characters",
    "daemon_noise_public_key_hex": "64 lower-case hex characters",
    "descriptor_generation": 1
  }
}
```

The Flutter owner persists only that descriptor and device id. It must not
persist the QR PSK after operation start. The descriptor contains a daemon
public Noise key, rendezvous topic, and generation; it cannot authorize a
status request by itself.

## Pair ordering

1. Parse the exact v3 QR URL and derive device keys with distinct HKDF labels.
2. Derive the exact invite-specific v2 Noise key using `HKDF-SHA256(topic,
   psk, NEOTH/companion/noise-static/v2)` and join Peeroxide as client-only.
3. Compare Peeroxide's authenticated remote static key to the QR `server_pk`.
4. Only when equal, write the 16-byte PSK as one encrypted Peeroxide message.
5. Write W2306/R4 canonical `EnrollmentProof` as one bounded encrypted frame;
   it carries the separate persistent v3 client Noise public key.
6. Accept only the canonical envelope `enrollment_accepted`; ensure its
   reconnect daemon key is also the QR-pinned key.

## Reconnect ordering

The R4 server maps the authenticated persistent client Noise key to its grant
and sends `status_challenge` immediately. The client writes the canonical
`StatusProof`, then accepts only `status_snapshot` or the bounded canonical
`denied` response. A different actual remote key, stale descriptor generation,
wrong schema, malformed JSON, denied response, cancellation, or deadline ends
the operation without a fallback capability.

The bridge uses the exact W2306 R4 `ServerFrame` source by `#[path]`; its
protocol owner controls the adjacent `type`/`body` encoding. The bridge does
not contain a second envelope codec.

## Capability inventory v1

The additive `neoth_companion_capability_inventory_start_v1` takes the paired
public descriptor and device ID, plus at most 512 UTF-8 bytes containing exactly
`inventory_schema_version: 1`, the persisted positive `revision` and
`expected_scope` (`companion.status.read` or `companion.chat.send`). These scopes
are disjoint. The command selects the expected challenge route; it grants no
authority. The daemon derives the returned scope from the active device grant.

The operation sends a separately signed request only when the encrypted
challenge advertises `capability_inventory_v1: true` outside its frozen body.
An older daemon produces `capability_inventory_unavailable`, with no fallback
chat or status operation. Exact device/revision/challenge/request bindings are
validated before returning the flat `state: capability_inventory` terminal.
It contains `inventory_schema_version`, `request_id`, `device_id`, `revision`,
`effective_scope`, `listener_generation`, `daemon_boot_id` and `observed_at_unix`.
This is a last observed grant, not a hardware-availability or resource-lease claim.

The existing original operation poll returns terminal code 1 with normal code-5
buffer discovery. Existing serialized cancel/free ownership applies unchanged.
This adds one start symbol to the prior 14-symbol host/mobile manifests; there
is no new polling protocol. Missing optional FFI support is reported without
starting a different operation.
