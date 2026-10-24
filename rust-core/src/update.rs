//! Signed P2P updates. A payload is accepted only if its Ed25519 signature
//! verifies against the developer key pinned on first contact.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::CoreError;

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
}
