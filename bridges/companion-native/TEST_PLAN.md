# Source test plan — not executed locally

The included source unit tests cover canonical QR parsing and independent,
deterministic domain-separated device derivations, exact v2 bootstrap equality,
public descriptor round-trip, optional status inventory, and ABI terminal-code
separation. The hosted native bridge lane must additionally run these
behavioral cases against the integrated R4
daemon and vendored Peeroxide transport:

1. valid v3 pair has the actual remote public key equal to QR `server_pk`, then
   transmits PSK and an enrollment proof and receives a descriptor;
2. a different actual remote key causes `daemon_key_mismatch` before any PSK
   write, enrollment write, durable grant, or status request;
3. an accepted descriptor whose daemon key differs from the QR key is denied;
4. a reboot reconnect uses the same derived client Noise public key, receives a
   fresh server challenge, signs it, and obtains only a redacted status;
5. revoke/denied prevents a status snapshot and exposes only a bounded code;
6. cancel during discovery, read, or write destroys and joins the owned swarm
   task with no surviving connection or task;
7. FFI invalid/null/oversize inputs and repeated poll/cancel/free calls do not
   unwind or expose private key/PSK bytes.
8. entering every export from a Tokio context returns its documented code and
   never performs nested `Runtime::block_on`; cancel/free wait for worker drain.

No local Cargo, Rust, FFI, networking, or test runtime has been executed under
the BSOD hold.
