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
