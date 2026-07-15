//! SL-00(1b) — cluster peer authorization proof.
//!
//! The Hyperswarm Noise channel already authenticates the channel + exchanges
//! both peers' static keys, so the remaining gap is AUTHORIZATION: does this
//! authenticated Noise peer hold our shared `cluster_key`? This module is the
//! pure crypto that closes it — a per-session HMAC proof carried in the Hello
//! frame. The handshake wiring (send + verify + transport activation) consumes
//! these two functions in SL-00(1b)-activation.
//!
//! **Construction (gremium-locked, `PLAN/DESIGN_cluster_transport.md`):**
//! `proof = HMAC-SHA256(cluster_key, DOMAIN || signer_pk || verifier_pk)`.
//! The order is **asymmetric (signer first)** ON PURPOSE — a *symmetric*
//! (sorted-key) proof is vulnerable to a REFLECTION attack: a non-member that
//! receives the token you sent it could echo it straight back and, being
//! symmetric, it would verify. Signer-first means A's proof
//! `proof(A,B)` only verifies on B's side (B recomputes `proof(A,B)` from
//! `verify_peer_proof(.., peer=A, own=B)`); an echoed `proof(A,B)` presented
//! as the reflector's own proof recomputes to `proof(reflector,A)` and fails.
//! No per-session nonce is needed: the Noise handshake's ephemeral keys make
//! every session unique, and the static-key binding makes a captured proof
//! useless in any other session/pair.

use crate::cluster::discovery::ClusterKey;

/// Domain separation — distinct from `CLUSTER_ANNOUNCE_NS` (mDNS announce
/// HMAC) so the same passphrase yields independent tokens per usage.
const CLUSTER_PEER_AUTH_NS: &[u8] = b"neoth-cluster-peer-auth/v1\0";

/// Compute the authorization proof a node with Noise static key `signer_pk`
/// sends to a peer with Noise static key `verifier_pk`. Both keys are exactly
/// 32 bytes (no length-prefix ambiguity). Never log the result — it is a
/// derived secret.
pub fn compute_cluster_key_proof(
    key: &ClusterKey,
    signer_pk: &[u8; 32],
    verifier_pk: &[u8; 32],
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(CLUSTER_PEER_AUTH_NS.len() + 64);
    msg.extend_from_slice(CLUSTER_PEER_AUTH_NS);
    msg.extend_from_slice(signer_pk);
    msg.extend_from_slice(verifier_pk);
    crate::util::hmac::sha256(&key.0, &msg)
}

/// Verify a peer's `claimed` proof. `peer_pk` is the peer's Noise static key
/// (the SIGNER of their proof); `own_pk` is ours (the VERIFIER). Recomputes
/// the expected `proof(peer_pk, own_pk)` and compares in constant time.
/// Returns `false` on any mismatch — the caller MUST treat that (and a missing
/// proof) as a hard rejection (fail-closed).
pub fn verify_peer_proof(
    key: &ClusterKey,
    claimed: &[u8; 32],
    peer_pk: &[u8; 32],
    own_pk: &[u8; 32],
) -> bool {
    let expected = compute_cluster_key_proof(key, peer_pk, own_pk);
    // Constant-time compare (XOR-accumulate; same pattern as discovery::verify_announce).
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(claimed.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::discovery::cluster_key;

    fn key(p: &str) -> ClusterKey {
        cluster_key(p).unwrap()
    }
    const A: [u8; 32] = [0xAA; 32];
    const B: [u8; 32] = [0xBB; 32];
    const X: [u8; 32] = [0xCC; 32]; // an outsider / different peer

    #[test]
    fn mutual_proof_verifies_between_two_members() {
        let k = key("alpha bravo charlie delta");
        // A sends proof(A, B); B verifies it as peer=A, own=B.
        let a_to_b = compute_cluster_key_proof(&k, &A, &B);
        assert!(
            verify_peer_proof(&k, &a_to_b, &A, &B),
            "B accepts A's proof"
        );
        // B sends proof(B, A); A verifies it as peer=B, own=A.
        let b_to_a = compute_cluster_key_proof(&k, &B, &A);
        assert!(
            verify_peer_proof(&k, &b_to_a, &B, &A),
            "A accepts B's proof"
        );
    }

    #[test]
    fn proof_is_asymmetric() {
        let k = key("alpha bravo charlie delta");
        assert_ne!(
            compute_cluster_key_proof(&k, &A, &B),
            compute_cluster_key_proof(&k, &B, &A),
            "signer-first ⇒ proof(A,B) != proof(B,A)"
        );
    }

    #[test]
    fn reflection_attack_is_rejected() {
        // An outsider X (no cluster_key) connects to A. A sends proof(A, X).
        // X echoes A's token straight back as its own Hello proof.
        let k = key("alpha bravo charlie delta");
        let a_sent = compute_cluster_key_proof(&k, &A, &X);
        // A verifies the echoed token as peer=X, own=A ⇒ recomputes proof(X, A).
        assert!(
            !verify_peer_proof(&k, &a_sent, &X, &A),
            "reflected proof(A,X) must NOT verify as X's proof (would be proof(X,A))"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let real = key("the real cluster phrase");
        let attacker = key("a guessed phrase");
        let claimed = compute_cluster_key_proof(&attacker, &X, &A);
        assert!(
            !verify_peer_proof(&real, &claimed, &X, &A),
            "a proof made with the wrong key must not verify"
        );
    }

    #[test]
    fn proof_byte_layout_is_pinned() {
        // Pin the exact construction so a future contributor reordering the
        // input (which would silently break interop / the asymmetry) fails.
        let k = key("pin");
        let got = compute_cluster_key_proof(&k, &A, &B);
        // Recompute the reference inline (domain || signer || verifier).
        let mut msg = Vec::new();
        msg.extend_from_slice(b"neoth-cluster-peer-auth/v1\0");
        msg.extend_from_slice(&A);
        msg.extend_from_slice(&B);
        let want = crate::util::hmac::sha256(&k.0, &msg);
        assert_eq!(got, want);
    }
}
