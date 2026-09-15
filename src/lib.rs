//! One-use member-bound voucher redemption with sponsor unlinkability.
//!
//! The sponsor signs a voucher code off-band. The redeemer presents it once,
//! bound to their member id. The host owns atomic single-use storage; the
//! library owns format, expiry, member binding and attestation bytes without
//! sponsor identity.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Voucher as issued by a sponsor. The code is presented once by the redeemer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Voucher {
    /// Opaque voucher id, unique per issuance.
    pub id: String,
    /// Expiry as unix seconds per host clock.
    pub valid_until: u64,
    /// Sponsor signature over issuance bytes (64 bytes, host verifies with sponsor key).
    pub signature: Vec<u8>,
}

/// Errors carry no sponsor identity or voucher secret.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Malformed voucher, bad signature, expired or already spent.
    /// Uniform to avoid oracle queries.
    #[error("voucher rejected")]
    Rejected,
}

/// Canonical issuance bytes the sponsor signs.
#[must_use]
pub fn issuance_bytes(voucher_id: &str, valid_until: u64, community_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cvch.issuance.v1",
        voucher_id,
        valid_until,
        community_id,
    ]))
    .expect("JSON serializes")
}

/// Verify sponsor signature and expiry. Returns unit on success.
/// Single-use enforcement belongs in the host atomic store; call this first.
pub fn verify(
    voucher: &Voucher,
    sponsor_key: &VerifyingKey,
    community_id: &str,
    now_secs: u64,
) -> Result<(), Error> {
    if voucher.id.is_empty() || voucher.id.len() > 128 {
        return Err(Error::Rejected);
    }
    if now_secs >= voucher.valid_until {
        return Err(Error::Rejected);
    }
    let msg = issuance_bytes(&voucher.id, voucher.valid_until, community_id);
    let sig = Signature::from_slice(&voucher.signature).map_err(|_| Error::Rejected)?;
    sponsor_key
        .verify(&msg, &sig)
        .map_err(|_| Error::Rejected)?;
    Ok(())
}

/// Redemption receipt id for host atomic store: hash of voucher id.
/// Concurrent attempts with the same id map to the same key and cannot both win.
#[must_use]
pub fn receipt_id(voucher_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"cvch.receipt.v1\n");
    h.update(voucher_id.as_bytes());
    hex(&h.finalize())
}

/// Member-bound redemption binding: hash of receipt + member.
/// Proves the voucher belongs to this member, not another holder.
#[must_use]
pub fn member_binding(receipt: &str, member_id: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"cvch.binding.v1\n");
    h.update(receipt.as_bytes());
    h.update(b"\n");
    h.update(member_id);
    hex(&h.finalize())
}

/// Host-owned single-use store. The host (e.g. cvld's receipt domain)
/// implements atomic first-claim-wins durably; the library only computes
/// keys. Returns `true` when this caller won the claim, `false` when spent.
/// Must survive restarts — a process-local store would re-arm vouchers.
pub trait SpendStore {
    /// Atomically claim `receipt`. Returns `true` when this caller won.
    fn try_claim(&mut self, receipt: &str) -> bool;
}

/// Successful redemption: member-bound proof input for cvld issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption {
    /// `member_binding(receipt, member)` — what the host attests.
    pub binding: String,
    /// Voucher expiry, carried into the attestation.
    pub valid_until: u64,
}

/// One audited redemption path: verify, atomically claim, then bind.
/// Failed verification never touches the store, so it cannot burn a
/// voucher. The first claim wins globally; later attempts — same or
/// different member — are rejected as spent.
pub fn redeem<S: SpendStore>(
    store: &mut S,
    voucher: &Voucher,
    sponsor_key: &VerifyingKey,
    community_id: &str,
    member_id: &[u8],
    now_secs: u64,
) -> Result<Redemption, Error> {
    verify(voucher, sponsor_key, community_id, now_secs)?;
    let receipt = receipt_id(&voucher.id);
    if !store.try_claim(&receipt) {
        return Err(Error::Rejected);
    }
    Ok(Redemption {
        binding: member_binding(&receipt, member_id),
        valid_until: voucher.valid_until,
    })
}

/// Attestation bytes the host signs with Ed25519 for cvld issuance.
/// Contains binding and expiry only: no sponsor identity, no voucher secret.
#[must_use]
pub fn attestation_bytes(binding: &str, valid_until: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cvch.attestation.v1",
        binding,
        valid_until
    ]))
    .expect("JSON serializes")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sponsor() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn other_sponsor() -> VerifyingKey {
        SigningKey::from_bytes(&[9u8; 32]).verifying_key()
    }

    fn issue(sk: &SigningKey, id: &str, valid_until: u64, community: &str) -> Voucher {
        use ed25519_dalek::Signer;
        let msg = issuance_bytes(id, valid_until, community);
        Voucher {
            id: id.into(),
            valid_until,
            signature: sk.sign(&msg).to_bytes().to_vec(),
        }
    }

    #[test]
    fn verify_roundtrip_and_expiry() {
        let (sk, vk) = sponsor();
        let v = issue(&sk, "v-1", 2000, "alpha");
        assert!(verify(&v, &vk, "alpha", 1000).is_ok());
        assert_eq!(verify(&v, &vk, "alpha", 2000), Err(Error::Rejected));
        assert_eq!(verify(&v, &vk, "beta", 1000), Err(Error::Rejected));
    }

    #[test]
    fn rejects_malformed_and_forged() {
        let (sk, vk) = sponsor();
        let good = issue(&sk, "v-1", 2000, "alpha");
        // Empty and oversized ids.
        let mut bad = good.clone();
        bad.id = String::new();
        assert_eq!(verify(&bad, &vk, "alpha", 1000), Err(Error::Rejected));
        bad = good.clone();
        bad.id = "x".repeat(129);
        assert_eq!(verify(&bad, &vk, "alpha", 1000), Err(Error::Rejected));
        // Truncated, padded and garbage signatures.
        for sig in [vec![0u8; 63], vec![0u8; 65], vec![0xabu8; 64], vec![]] {
            bad = good.clone();
            bad.signature = sig;
            assert_eq!(verify(&bad, &vk, "alpha", 1000), Err(Error::Rejected));
        }
        // Valid signature under another sponsor key.
        assert_eq!(
            verify(&good, &other_sponsor(), "alpha", 1000),
            Err(Error::Rejected)
        );
        // Bit-flipped voucher id under the original signature.
        bad = good.clone();
        bad.id = "v-2".into();
        assert_eq!(verify(&bad, &vk, "alpha", 1000), Err(Error::Rejected));
    }

    #[test]
    fn receipt_is_deterministic_and_distinct() {
        assert_eq!(receipt_id("v-1"), receipt_id("v-1"));
        assert_ne!(receipt_id("v-1"), receipt_id("v-2"));
        assert_eq!(receipt_id("v-1").len(), 64);
    }

    #[test]
    fn issuance_is_community_scoped() {
        assert_ne!(
            issuance_bytes("v-1", 2000, "alpha"),
            issuance_bytes("v-1", 2000, "beta")
        );
    }

    #[test]
    fn attestation_hides_sponsor_and_voucher() {
        let (sk, vk) = sponsor();
        let v = issue(&sk, "v-sensitive-id", 2000, "alpha");
        let receipt = receipt_id(&v.id);
        let binding = member_binding(&receipt, b"m1");
        let bytes = attestation_bytes(&binding, v.valid_until);
        let text = String::from_utf8(bytes).expect("attestation is JSON");
        assert!(text.contains(&binding), "binding must be present");
        assert!(
            !text.contains("v-sensitive-id"),
            "raw voucher id must not leak"
        );
        assert!(
            !text.contains(&hex(vk.as_bytes())),
            "sponsor key must not leak"
        );
    }

    #[test]
    fn binding_is_member_specific() {
        let r = receipt_id("v-1");
        assert_ne!(member_binding(&r, b"m1"), member_binding(&r, b"m2"));
    }

    /// Test-only store. Production hosts must implement `SpendStore`
    /// durably (e.g. cvld's receipt domain); a process-local set would
    /// re-arm vouchers on restart.
    #[derive(Default)]
    struct TestStore {
        spent: std::collections::HashSet<String>,
    }

    impl SpendStore for TestStore {
        fn try_claim(&mut self, receipt: &str) -> bool {
            self.spent.insert(receipt.to_owned())
        }
    }

    #[test]
    fn redeem_binds_member_and_wins_once() {
        let (sk, vk) = sponsor();
        let v = issue(&sk, "v-1", 2000, "alpha");
        let mut store = TestStore::default();
        let r = redeem(&mut store, &v, &vk, "alpha", b"m1", 1000).expect("first wins");
        assert_eq!(r.binding, member_binding(&receipt_id("v-1"), b"m1"));
        assert_eq!(r.valid_until, 2000);
        // Same member replay and another member's attempt both lose.
        assert_eq!(
            redeem(&mut store, &v, &vk, "alpha", b"m1", 1001),
            Err(Error::Rejected)
        );
        assert_eq!(
            redeem(&mut store, &v, &vk, "alpha", b"m2", 1001),
            Err(Error::Rejected)
        );
    }

    #[test]
    fn redeem_failure_burns_nothing() {
        let (sk, vk) = sponsor();
        let v = issue(&sk, "v-1", 2000, "alpha");
        let mut store = TestStore::default();
        // Wrong community fails before any claim; the voucher stays live.
        assert_eq!(
            redeem(&mut store, &v, &vk, "beta", b"m1", 1000),
            Err(Error::Rejected)
        );
        assert!(redeem(&mut store, &v, &vk, "alpha", b"m1", 1000).is_ok());
    }
}
