//! Signed P2P updates. An update is accepted only if its Ed25519 signature
//! verifies against the developer key pinned on first contact, and its version
//! is strictly newer than the installed one.
//!
//! Security property: no byte of an update reaches the install step unless
//! `verify_update` (or `PinnedDeveloperKey::verify_update`) has accepted it. The
//! key is compiled in, so a network peer cannot substitute one; a second
//! developer key is refused. The signed message is the domain label, the version
//! as 8-byte big-endian, then the whole APK. Because the version is inside the
//! signed bytes, a peer cannot pair an old, validly signed APK with a newer
//! version number, and cannot change the version of an update in transit.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Domain separator for the fingerprint, so the same bytes hashed elsewhere do not collide.
const UPDATE_KEY_FINGERPRINT_DOMAIN: &[u8] = b"sovereign-p2p update key v1";

/// Domain label for the signed update message. The `v2` marks the message that
/// includes the version. A v1 signature over bare APK bytes does not verify
/// against this label, so an old signature cannot be replayed as a v2 update.
pub const UPDATE_SIGNED_DOMAIN: &[u8] = b"sovereign-p2p update v2";

/// The developer's Ed25519 public key, compiled into the app. `None` means no
/// key has been pinned yet, so every update is refused. The owner sets this once
/// from the public half of the offline signing key (see PLAN.md, Decisions).
pub const DEVELOPER_PUBLIC_KEY: Option<[u8; 32]> = None;

/// The bytes the developer signs: `UPDATE_SIGNED_DOMAIN || version (u64, big-endian) || apk`.
/// `scripts/sign-update.sh` builds the same bytes. The version is the integer
/// the install gate compares, so the signature binds it.
pub fn signed_message(version: u64, apk: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(UPDATE_SIGNED_DOMAIN.len() + 8 + apk.len());
    msg.extend_from_slice(UPDATE_SIGNED_DOMAIN);
    msg.extend_from_slice(&version.to_be_bytes());
    msg.extend_from_slice(apk);
    msg
}

pub struct PinnedDeveloperKey(VerifyingKey);

impl PinnedDeveloperKey {
    /// Pin the 32-byte developer public key. Fails on an invalid curve point.
    pub fn pin(bytes: &[u8; 32]) -> Result<Self, CoreError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CoreError::Malformed)
    }

    /// Checks the signature over the v2 message for `payload` at `version`.
    /// Checks the signature only; the downgrade rule is in `verify_update`.
    pub fn verify(&self, payload: &[u8], version: u64, sig: &[u8; 64]) -> Result<(), CoreError> {
        let signature = Signature::from_bytes(sig);
        self.0
            .verify(&signed_message(version, payload), &signature)
            .map_err(|_| CoreError::BadSignature)
    }

    /// As `verify`, but takes the signature as received. A signature that is not
    /// exactly 64 bytes is `Malformed`, so a truncated one is never checked.
    pub fn verify_bytes(&self, payload: &[u8], version: u64, sig: &[u8]) -> Result<(), CoreError> {
        let sig: &[u8; 64] = sig.try_into().map_err(|_| CoreError::Malformed)?;
        self.verify(payload, version, sig)
    }

    /// Full install gate for one update: the signature must verify over the
    /// version, and that version must be strictly newer than `installed_version`.
    /// The signature is checked first, so a bad signature is never reported as a
    /// downgrade.
    pub fn verify_update(
        &self,
        payload: &[u8],
        version: u64,
        sig: &[u8],
        installed_version: u64,
    ) -> Result<(), CoreError> {
        self.verify_bytes(payload, version, sig)?;
        refuse_downgrade(installed_version, version)
    }
}

/// Refuses any version that is not strictly greater than the installed one, so
/// an equal or older build is never offered. The installed version comes from
/// the app, not from the peer.
fn refuse_downgrade(installed_version: u64, offered_version: u64) -> Result<(), CoreError> {
    if offered_version > installed_version {
        Ok(())
    } else {
        Err(CoreError::Downgrade)
    }
}

/// Verifies `sig` over the v2 message for `apk` and `version` against the
/// compiled-in developer key, and refuses a version not newer than
/// `installed_version`. Refuses every update while `DEVELOPER_PUBLIC_KEY` is `None`.
pub fn verify_update(
    apk: &[u8],
    version: u64,
    sig: &[u8],
    installed_version: u64,
) -> Result<(), CoreError> {
    // No key compiled in: refuse. A missing key must never mean "accept".
    let key = DEVELOPER_PUBLIC_KEY.ok_or(CoreError::BadSignature)?;
    PinnedDeveloperKey::pin(&key)?.verify_update(apk, version, sig, installed_version)
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

    /// Signs the v2 message exactly as `scripts/sign-update.sh` does.
    fn sign_update(sk: &SigningKey, version: u64, apk: &[u8]) -> [u8; 64] {
        sk.sign(&signed_message(version, apk)).to_bytes()
    }

    fn pinned_for(sk: &SigningKey) -> PinnedDeveloperKey {
        PinnedDeveloperKey::pin(&sk.verifying_key().to_bytes()).unwrap()
    }

    #[test]
    fn valid_update_accepted_and_tamper_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&sk);
        let sig = sign_update(&sk, 7, b"apk-bytes");
        assert_eq!(pinned.verify(b"apk-bytes", 7, &sig), Ok(()));
        assert_eq!(
            pinned.verify(b"apk-bytez", 7, &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn signed_message_is_domain_then_big_endian_version_then_apk() {
        let version = 0x0102_0304_0506_0708u64;
        let mut want = b"sovereign-p2p update v2".to_vec();
        want.extend_from_slice(&version.to_be_bytes());
        want.extend_from_slice(b"apk");
        assert_eq!(signed_message(version, b"apk"), want);
    }

    #[test]
    fn other_developer_key_rejected() {
        let real = SigningKey::generate(&mut OsRng);
        let evil = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&real);
        let sig = sign_update(&evil, 2, b"apk-bytes");
        assert_eq!(
            pinned.verify(b"apk-bytes", 2, &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn version_changed_after_signing_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&sk);
        let sig = sign_update(&sk, 7, b"apk-bytes");
        assert_eq!(
            pinned.verify(b"apk-bytes", 8, &sig),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn v1_signature_over_bare_apk_rejected() {
        // The v1 format signed the APK bytes alone. That signature must not verify
        // under the v2 message, whatever version it is paired with.
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&sk);
        let sig = sk.sign(b"apk-bytes").to_bytes();
        assert_eq!(
            pinned.verify(b"apk-bytes", 7, &sig),
            Err(CoreError::BadSignature)
        );
        assert_eq!(
            pinned.verify_update(b"apk-bytes", 7, &sig, 1),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn newer_update_accepted() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&sk);
        let sig = sign_update(&sk, 2, b"apk-bytes");
        assert_eq!(pinned.verify_update(b"apk-bytes", 2, &sig, 1), Ok(()));
    }

    #[test]
    fn older_validly_signed_update_refused_as_downgrade() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&sk);
        let sig = sign_update(&sk, 1, b"apk-bytes");
        assert_eq!(
            pinned.verify_update(b"apk-bytes", 1, &sig, 2),
            Err(CoreError::Downgrade)
        );
    }

    #[test]
    fn equal_version_refused_as_downgrade() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&sk);
        let sig = sign_update(&sk, 2, b"apk-bytes");
        assert_eq!(
            pinned.verify_update(b"apk-bytes", 2, &sig, 2),
            Err(CoreError::Downgrade)
        );
    }

    #[test]
    fn bad_signature_is_reported_before_downgrade() {
        // An older update with a foreign signature is a signature failure, not a downgrade.
        let real = SigningKey::generate(&mut OsRng);
        let evil = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&real);
        let sig = sign_update(&evil, 1, b"apk-bytes");
        assert_eq!(
            pinned.verify_update(b"apk-bytes", 1, &sig, 5),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn other_developer_key_rejected_for_update() {
        let real = SigningKey::generate(&mut OsRng);
        let evil = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&real);
        let sig = sign_update(&evil, 2, b"apk-bytes");
        assert_eq!(
            pinned.verify_update(b"apk-bytes", 2, &sig, 1),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn truncated_signature_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pinned = pinned_for(&sk);
        let sig = sign_update(&sk, 2, b"apk-bytes");
        assert_eq!(
            pinned.verify_bytes(b"apk-bytes", 2, &sig[..63]),
            Err(CoreError::Malformed)
        );
        assert_eq!(
            pinned.verify_bytes(b"apk-bytes", 2, &[]),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn no_compiled_in_key_refuses_every_update() {
        // Until the owner pins a key, nothing may pass the install gate.
        assert_eq!(DEVELOPER_PUBLIC_KEY, None);
        assert_eq!(
            verify_update(b"apk-bytes", 2, &[0u8; 64], 1),
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
