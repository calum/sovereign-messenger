//! Signed P2P updates. A payload is accepted only if its Ed25519 signature
//! verifies against the developer key pinned on first contact.
//!
//! Security property: no byte of an update reaches the install step unless
//! `verify_update` (or `PinnedDeveloperKey::verify`) has accepted it. The key is
//! compiled in, so a network peer cannot substitute one; a second developer
//! key is refused. The signature is a detached 64-byte Ed25519 signature over
//! the whole APK file.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Domain separator for the fingerprint, so the same bytes hashed elsewhere do not collide.
const UPDATE_KEY_FINGERPRINT_DOMAIN: &[u8] = b"sovereign-p2p update key v1";

/// The developer's Ed25519 public key, compiled into the app. `None` means no
/// key has been pinned yet, so every update is refused. The owner sets this once
/// from the public half of the offline signing key (see PLAN.md, Decisions).
pub const DEVELOPER_PUBLIC_KEY: Option<[u8; 32]> = None;

pub struct PinnedDeveloperKey(VerifyingKey);

impl PinnedDeveloperKey {
    /// Pin the 32-byte developer public key. Fails on an invalid curve point.
    pub fn pin(bytes: &[u8; 32]) -> Result<Self, CoreError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CoreError::Malformed)
    }

    /// Verify an update. Returns the payload only if the signature is valid.
    pub fn verify<'a>(&self, payload: &'a [u8], sig: &[u8; 64]) -> Result<&'a [u8], CoreError> {
        let signature = Signature::from_bytes(sig);
        self.0
            .verify(payload, &signature)
            .map(|_| payload)
            .map_err(|_| CoreError::BadSignature)
    }

    /// As `verify`, but takes the signature as received. A signature that is not
    /// exactly 64 bytes is `Malformed`, so a truncated one is never checked.
    pub fn verify_bytes(&self, payload: &[u8], sig: &[u8]) -> Result<(), CoreError> {
        let sig: &[u8; 64] = sig.try_into().map_err(|_| CoreError::Malformed)?;
        self.verify(payload, sig).map(|_| ())
    }
}

/// Verifies `sig` over `payload` against the compiled-in developer key.
/// Refuses every update while `DEVELOPER_PUBLIC_KEY` is `None`.
pub fn verify_update(payload: &[u8], sig: &[u8]) -> Result<(), CoreError> {
    // No key compiled in: refuse. A missing key must never mean "accept".
    let key = DEVELOPER_PUBLIC_KEY.ok_or(CoreError::BadSignature)?;
    PinnedDeveloperKey::pin(&key)?.verify_bytes(payload, sig)
}

/// Short fingerprint of a developer key, shown on the update screen so the two
/// users can compare it in person. Same grouping as the identity fingerprint.
pub fn developer_key_fingerprint(key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(UPDATE_KEY_FINGERPRINT_DOMAIN);
    h.update(key);
    let digest = h.finalize();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    #[test]
    fn valid_update_accepted_and_tamper_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = PinnedDeveloperKey::pin(&sk.verifying_key().to_bytes()).unwrap();
        let payload = b"apk-bytes";
        let sig = sk.sign(payload).to_bytes();
        assert_eq!(pinned.verify(payload, &sig).unwrap(), payload);
        assert_eq!(
            pinned.verify(b"apk-bytez", &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn other_developer_key_rejected() {
        let real = SigningKey::generate(&mut OsRng);
        let evil = SigningKey::generate(&mut OsRng);
        let pinned = PinnedDeveloperKey::pin(&real.verifying_key().to_bytes()).unwrap();
        let sig = evil.sign(b"payload").to_bytes();
        assert_eq!(
            pinned.verify(b"payload", &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn valid_signature_bytes_accepted() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = PinnedDeveloperKey::pin(&sk.verifying_key().to_bytes()).unwrap();
        let sig = sk.sign(b"apk-bytes").to_bytes();
        assert_eq!(pinned.verify_bytes(b"apk-bytes", &sig), Ok(()));
    }

    #[test]
    fn tampered_apk_rejected_by_bytes_check() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = PinnedDeveloperKey::pin(&sk.verifying_key().to_bytes()).unwrap();
        let sig = sk.sign(b"apk-bytes").to_bytes();
        let mut apk = b"apk-bytes".to_vec();
        apk[0] ^= 0x01;
        assert_eq!(
            pinned.verify_bytes(&apk, &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn signature_from_another_developer_rejected_by_bytes_check() {
        let real = SigningKey::generate(&mut OsRng);
        let evil = SigningKey::generate(&mut OsRng);
        let pinned = PinnedDeveloperKey::pin(&real.verifying_key().to_bytes()).unwrap();
        let sig = evil.sign(b"apk-bytes").to_bytes();
        assert_eq!(
            pinned.verify_bytes(b"apk-bytes", &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn truncated_signature_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = PinnedDeveloperKey::pin(&sk.verifying_key().to_bytes()).unwrap();
        let sig = sk.sign(b"apk-bytes").to_bytes();
        assert_eq!(
            pinned.verify_bytes(b"apk-bytes", &sig[..63]),
            Err(CoreError::Malformed)
        );
        assert_eq!(
            pinned.verify_bytes(b"apk-bytes", &[]),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn no_compiled_in_key_refuses_every_update() {
        // Until the owner pins a key, nothing may pass the install gate.
        assert_eq!(DEVELOPER_PUBLIC_KEY, None);
        assert_eq!(
            verify_update(b"apk-bytes", &[0u8; 64]),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn developer_fingerprint_is_stable_and_key_specific() {
        let a = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let b = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert_eq!(developer_key_fingerprint(&a), developer_key_fingerprint(&a));
        assert_ne!(developer_key_fingerprint(&a), developer_key_fingerprint(&b));
        assert_eq!(developer_key_fingerprint(&a).len(), 39);
    }
}
