//! Sender-side update tests. `Messenger::send_update` forwards a bundle that the
//! developer signed on their PC: the APK, a 64-byte Ed25519 signature, and the
//! version. The phone never signs.
//!
//! Security property: the sender refuses a malformed bundle before it opens a
//! socket, and the receiver verifies the signature itself, so a bundle altered in
//! transit is refused on the receiving phone. Error messages carry no APK or key
//! bytes.

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

use rust_core::apk_transfer::{receive_update_on, MAX_APK_LEN, SIGNATURE_LEN};
use rust_core::ffi::{FacadeError, Messenger};
use rust_core::update::{signed_message, PinnedDeveloperKey};

const APK: &[u8] = b"sender-test-apk-bytes";
const VERSION: u64 = 12;

/// Address that is never dialled: the validation paths must refuse before any connect.
const UNUSED_ADDR: &str = "127.0.0.1:9";

#[test]
fn signature_of_63_bytes_refused_as_malformed() {
    let m = Messenger::new();
    let err = m
        .send_update(
            UNUSED_ADDR.to_string(),
            1,
            APK.to_vec(),
            VERSION,
            vec![0u8; 63],
        )
        .unwrap_err();
    assert_eq!(err, FacadeError::Malformed);
}

#[test]
fn empty_apk_refused_as_malformed() {
    let m = Messenger::new();
    let err = m
        .send_update(
            UNUSED_ADDR.to_string(),
            1,
            Vec::new(),
            VERSION,
            vec![0u8; SIGNATURE_LEN],
        )
        .unwrap_err();
    assert_eq!(err, FacadeError::Malformed);
}

#[test]
fn apk_over_cap_refused_as_malformed() {
    let m = Messenger::new();
    let err = m
        .send_update(
            UNUSED_ADDR.to_string(),
            1,
            vec![0u8; MAX_APK_LEN + 1],
            VERSION,
            vec![0u8; SIGNATURE_LEN],
        )
        .unwrap_err();
    assert_eq!(err, FacadeError::Malformed);
}

#[test]
fn bundle_sent_over_loopback_is_received_and_verifies() {
    // An in-test developer key stands in for the compiled-in one, which is not set
    // in this build. The receiver's check is the same signature check the app runs.
    let sk = SigningKey::generate(&mut OsRng);
    let pinned = PinnedDeveloperKey::pin(&sk.verifying_key().to_bytes()).unwrap();
    let sig = sk.sign(&signed_message(VERSION, APK)).to_bytes();

    let bind = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("127.0.0.1:{}", l.local_addr().unwrap().port())
    };
    let dial = bind.clone();

    let receiver = std::thread::spawn(move || {
        let mut got = Vec::new();
        let (version, sig) = receive_update_on(&bind, Duration::from_secs(10), &mut got).unwrap();
        (version, sig, got)
    });

    let sender = Messenger::new();
    let apk = APK.to_vec();
    let sig_bytes = sig.to_vec();
    let mut sent = false;
    for _ in 0..500 {
        if sender
            .send_update(dial.clone(), 1, apk.clone(), VERSION, sig_bytes.clone())
            .is_ok()
        {
            sent = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(sent, "sender never connected");

    let (version, got_sig, got_apk) = receiver.join().unwrap();
    assert_eq!(version, VERSION);
    assert_eq!(got_apk, APK);
    assert_eq!(got_sig.to_vec(), sig_bytes);
    assert_eq!(
        pinned.verify_update(&got_apk, version, &got_sig, VERSION - 1),
        Ok(())
    );
}
