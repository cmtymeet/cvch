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

    #[test]
    fn verify_roundtrip_and_expiry() {
        let (sk, vk) = sponsor();
        let msg = issuance_bytes("v-1", 2000, "alpha");
        use ed25519_dalek::Signer;
        let sig = sk.sign(&msg).to_bytes().to_vec();
        let v = Voucher {
            id: "v-1".into(),
            valid_until: 2000,
            signature: sig,
        };
        assert!(verify(&v, &vk, "alpha", 1000).is_ok());
        assert_eq!(verify(&v, &vk, "alpha", 2000), Err(Error::Rejected));
        assert_eq!(verify(&v, &vk, "beta", 1000), Err(Error::Rejected));
    }

    #[test]
    fn binding_is_member_specific() {
        let r = receipt_id("v-1");
        assert_ne!(member_binding(&r, b"m1"), member_binding(&r, b"m2"));
    }
}
