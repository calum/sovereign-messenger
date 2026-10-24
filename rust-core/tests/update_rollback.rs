//! Rollback and framing tests for signed updates. The signed message binds the
//! version, so an older APK that is validly signed is refused as a downgrade,
//! and a version edited in transit fails the signature. These tests drive the
//! same path the app uses: the transfer frame, then the pinned key.
//!
//! Security property: a peer cannot make the receiver install an older build,
//! and cannot change the version it is checked against without breaking the
//! signature.

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

use rust_core::apk_transfer::{read_update, write_update, FRAME_VERSION, SIGNATURE_LEN};
use rust_core::update::{signed_message, PinnedDeveloperKey};
use rust_core::CoreError;

const APK: &[u8] = b"apk-bytes-for-rollback-tests";

fn developer() -> (SigningKey, PinnedDeveloperKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let pinned = PinnedDeveloperKey::pin(&sk.verifying_key().to_bytes()).unwrap();
    (sk, pinned)
}

fn sign_v2(sk: &SigningKey, version: u64, apk: &[u8]) -> [u8; SIGNATURE_LEN] {
    sk.sign(&signed_message(version, apk)).to_bytes()
}

/// Sends one update through the transfer frame and reads it back.
fn over_the_wire(
    version: u64,
    sig: &[u8; SIGNATURE_LEN],
    apk: &[u8],
) -> (u64, [u8; SIGNATURE_LEN], Vec<u8>) {
    let mut wire = Vec::new();
    write_update(&mut wire, version, sig, apk).unwrap();
    let mut got = Vec::new();
    let (v, s) = read_update(&mut wire.as_slice(), &mut got).unwrap();
    (v, s, got)
}

#[test]
fn newer_signed_update_accepted_through_transfer() {
    let (sk, pinned) = developer();
    let sig = sign_v2(&sk, 5, APK);
    let (version, sig, apk) = over_the_wire(5, &sig, APK);
    assert_eq!(pinned.verify_update(&apk, version, &sig, 4), Ok(()));
}

#[test]
fn older_validly_signed_apk_refused_as_downgrade() {
    let (sk, pinned) = developer();
    let sig = sign_v2(&sk, 3, APK);
    let (version, sig, apk) = over_the_wire(3, &sig, APK);
    assert_eq!(
        pinned.verify_update(&apk, version, &sig, 4),
        Err(CoreError::Downgrade)
    );
}

#[test]
fn equal_version_refused_as_downgrade() {
    let (sk, pinned) = developer();
    let sig = sign_v2(&sk, 4, APK);
    let (version, sig, apk) = over_the_wire(4, &sig, APK);
    assert_eq!(
        pinned.verify_update(&apk, version, &sig, 4),
        Err(CoreError::Downgrade)
    );
}

#[test]
fn v1_signature_over_bare_apk_refused() {
    // A v1 signer signed the APK bytes with no domain label and no version.
    let (sk, pinned) = developer();
    let v1_sig = sk.sign(APK).to_bytes();
    let (version, sig, apk) = over_the_wire(9, &v1_sig, APK);
    assert_eq!(
        pinned.verify_update(&apk, version, &sig, 1),
        Err(CoreError::BadSignature)
    );
}

#[test]
fn tampered_apk_refused() {
    let (sk, pinned) = developer();
    let sig = sign_v2(&sk, 5, APK);
    let mut tampered = APK.to_vec();
    tampered[0] ^= 0x01;
    let (version, sig, apk) = over_the_wire(5, &sig, &tampered);
    assert_eq!(
        pinned.verify_update(&apk, version, &sig, 4),
        Err(CoreError::BadSignature)
    );
}

#[test]
fn version_field_changed_in_transfer_refused() {
    // Sign version 5, then rewrite the version bytes on the wire to 6. The
    // receiver must check against the signed version, so this fails the signature
    // rather than passing the downgrade rule with the edited number.
    let (sk, pinned) = developer();
    let sig = sign_v2(&sk, 5, APK);
    let mut wire = Vec::new();
    write_update(&mut wire, 5, &sig, APK).unwrap();
    assert_eq!(wire[0], FRAME_VERSION);
    wire[1..9].copy_from_slice(&6u64.to_be_bytes());

    let mut got = Vec::new();
    let (version, sig) = read_update(&mut wire.as_slice(), &mut got).unwrap();
    assert_eq!(version, 6);
    assert_eq!(
        pinned.verify_update(&got, version, &sig, 4),
        Err(CoreError::BadSignature)
    );
}

/// Hex decode for the fixed vector below. Test-only.
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Output of `scripts/sign-update.sh` with openssl, for APK above at version 42. The
/// key was a throwaway Ed25519 key generated for this check; its private half was
/// discarded, so only the public key and the signature are kept here. The Rust
/// verifier must accept what the owner's script produces.
#[test]
fn signature_from_sign_update_script_verifies_in_rust() {
    const PUB: &str = "3d639d490a99b73db70268c16e5005fbbe64f9671dcbdd0581ba33525d368ed3";
    const SIG: &str = "b99af88550fbc8400dbd9e8c94b6df3d3e23e9cb4881ce2c46320124fc04d66652186ed9ac506cda0dfb9b502070a9c459d6c8dcd59513c07b105419727ac70d";
    let key: [u8; 32] = unhex(PUB).try_into().unwrap();
    let pinned = PinnedDeveloperKey::pin(&key).unwrap();
    let sig = unhex(SIG);
    assert_eq!(pinned.verify_update(APK, 42, &sig, 41), Ok(()));
    assert_eq!(
        pinned.verify_update(APK, 41, &sig, 40),
        Err(CoreError::BadSignature)
    );
}
