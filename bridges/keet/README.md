# NEOTH Keet/Pear bridge

`neoth-keet-bridge` is NEOTH's repository-owned, full-duplex text companion for a private Pear/Hyperswarm channel. It uses Holepunch's current building blocks (`hyperswarm`, `protomux-rpc`, `hypercore-crypto`) and `keet-identity-key` for portable sender identities.

## Exact product boundary

This is a **Keet-identity Pear channel**, not an automation API for the existing Keet desktop/mobile application. Keet does not publish a supported room/message API that a third-party daemon can safely adopt. Consequently:

- the bridge does not read or write existing Keet application rooms;
- a NEOTH topic is its own encrypted Hyperswarm conversation;
- sender IDs are Keet identity public keys produced by the official `keet-identity-key` package;
- no Keet seed phrase is sent to or stored by the Rust daemon;
- existing Keet-room interoperability must remain unclaimed until Holepunch publishes and supports such an API.

This boundary is intentional. It provides a real, testable P2P channel without reviving the former outbound-only localhost stub or guessing a proprietary Keet room protocol.

## Zero-dependency release binary

The release build uses Holepunch's `bare-build --standalone` path. The resulting `neoth-keet-bridge` executable includes the Bare runtime and requires no Node.js, Pear CLI, or global package install on the operator's computer. Dependency resolution is pinned by `pnpm@10.32.1`; release and CI installs must use the committed lock with `--frozen-lockfile`.

Supported build targets:

- Windows x64 and arm64
- Linux x64 and arm64
- macOS x64 and arm64

The Linux standalone targets the normal glibc desktop contract. It is not
placed in NEOTH's explicitly headless musl archive.

For development:

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm test
node bin.mjs setup
node bin.mjs serve
```

For the current host release binary:

```sh
pnpm run make
```

The release matrix invokes the explicit `make:<host>` script, verifies the
standalone reports the exact release version, and packages it transactionally
with the matching NEOTH core/GUI artifacts.

## First setup

Run once:

```sh
neoth-keet-bridge setup
```

It creates private, append-only configuration snapshots under `~/.neoth/keet-bridge` and prints one sensitive JSON record:

```json
{
  "bridge_url": "http://127.0.0.1:9130",
  "bearer_token": "local-control-secret",
  "topic": "nk1_shared-topic-capability",
  "self_id": "stable-identity-public-key",
  "storage": "..."
}
```

Protect the bearer token like a password. It authenticates only the local HTTP boundary. Protect the topic like an invite secret. It grants access to the P2P topic.

Start the companion:

```sh
neoth-keet-bridge serve
```

On another machine, run `setup`, join the first machine's topic, and restart its companion:

```sh
neoth-keet-bridge topic join nk1_<shared-topic-capability>
neoth-keet-bridge serve
```

Each operator shares only their `self_id` with the other operators. Configure NEOTH's `allowed_sender` list with those exact, case-sensitive IDs. The Rust channel rejects every sender not in that list.

Topic provisioning is a control-plane operation. `GET /v1/topics/{topic}` is strictly read-only and never joins an unknown topic.

## Local data-plane contract

The server binds only to numeric loopback (`127.0.0.1` by default, optionally `::1`). Every request requires the exact configured `Authorization: Bearer ...` token.

| Method | Endpoint | Contract |
|---|---|---|
| `GET` | `/v1/health` | Protocol/version handshake; `ready: true` advertises both `send_text` and `receive_text` |
| `GET` | `/v1/topics/{topic}` | Joined state, current high-water cursor, exact local sender ID |
| `GET` | `/v1/topics/{topic}/messages?after=...&wait_ms=25000&limit=50` | Bounded cursor long-poll |
| `POST` | `/v1/topics/{topic}/messages` | Durable idempotent send; repeated key returns the original message ID |

The wire schema is pinned by the Rust client in `SRC/neothd/src/channels/keet_bridge.rs` and by the tests in this package.

## Security and durability

- Hyperswarm provides Noise-encrypted peer connections.
- The shared topic capability is hashed before DHT discovery; it is never announced directly.
- A directional connection proof prevents a DHT observer that sees the discovery hash from opening the topic protocol.
- Every message carries a `keet-identity-key` device/identity attestation. The received exact sender ID is derived from the verified proof, never trusted from plain JSON.
- Local HTTP bearer comparison is constant-time and all request/response bodies are bounded.
- Message bodies are limited to 64 KiB, poll pages to 50 messages, and peer sync pages to 512 KiB.
- The local message journal is append-only and fsync'd before acknowledgement or cursor advancement.
- A torn final journal write is truncated on recovery; corruption in a complete record fails closed.
- Idempotency keys and their request fingerprints are durable across restarts.
- Topic cursors are local, monotonic journal positions. The first NEOTH run begins at the current high-water cursor and never imports arbitrary old history.
- Configuration snapshots are generation-numbered and never overwritten, so Windows and Unix recover the last complete snapshot after a crash.
- One storage directory admits one writer. Lock ownership binds PID plus process-start identity; a provably dead owner is recovered automatically, while live or ambiguous ownership fails closed.
- `repair-lock` is not a blind delete. It first proves the configured loopback port has no listener and that no matching bridge/Bare serve process is visible, then removes only the verified-idle lock. Use `neoth-keet-bridge repair-lock --storage <dir>` after an invalid/torn lock error.
- Any journal durability failure marks the service unready, closes HTTP and peer transports, releases its owned lock, and terminates non-zero. The process never continues after acknowledging state it could not persist.
- File data and new journal/config records are fsync'd before acknowledgement. Directory fsync is attempted for namespace changes; platforms/filesystems that explicitly do not support directory handles fall back to generation-numbered snapshots and torn-tail recovery rather than claiming a stronger primitive.
- Configuration contains the bearer token and 24-word identity mnemonic. Unix enforces mode `0700`/`0600`; Windows replaces and verifies the directory and snapshot DACL with one owner-only full-control rule using the built-in Windows PowerShell/.NET runtime. Startup and setup fail closed if that protection cannot be proven.
- Message journals contain plaintext message bodies at rest inside the protected bridge storage directory. Noise encryption protects transport, not a copied local storage directory.

The v1 bridge is text-only by contract. Media/file transfer is not advertised as a capability.

## Upstream references

- [Pear: add Keet identity to a chat app](https://docs.pears.com/how-to/manage-identity/add-keet-identity-to-a-chat-app/)
- [Pear: create a portable identity with `keet-identity-key`](https://docs.pears.com/how-to/manage-identity/create-a-portable-identity-with-keet-identity-key/)
- [Pear: build a standalone Bare executable](https://docs.pears.com/how-to/run-on-native/bundle-a-bare-app/)
- [Pear runtime and language architecture](https://docs.pears.com/explanation/runtime-and-languages/)
