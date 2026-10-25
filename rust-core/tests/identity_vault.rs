//! Identity persistence (owner decision 2026-10-25): the long-term identity and the
//! pinned contacts can be sealed under a data key and restored later. Messages and
//! sessions never enter the vault. These tests go through the facade Kotlin calls.

use std::sync::Arc;

use rust_core::ffi::{FacadeError, Messenger};
use rust_core::vault;

/// A persistent Messenger that has pinned one peer ("bob") from a scanned QR code.
fn alice_with_bob_pinned() -> (Arc<Messenger>, Arc<Messenger>) {
    let alice = Messenger::create_persistent();
    let bob = Messenger::new();
    alice
        .scan_pairing(
            "bob".into(),
            bob.own_pairing_payload("hint".into()).unwrap(),
        )
        .unwrap();
    (alice, bob)
}

#[test]
fn restored_messenger_has_the_same_identity_and_pins() {
    let (alice, bob) = alice_with_bob_pinned();
    let key = alice.data_key().unwrap();
    let blob = alice.export_vault().unwrap();

    let restored = Messenger::restore(key, blob).unwrap();

    // Same QR payload means the same X25519 key and the same ML-KEM encapsulation key.
    assert_eq!(
        restored.own_pairing_payload("hint".into()).unwrap(),
        alice.own_pairing_payload("hint".into()).unwrap()
    );
    assert_eq!(restored.pinned_peers().unwrap(), vec!["bob".to_string()]);
    assert_eq!(
        restored.pin_fingerprint("bob".into()).unwrap(),
        alice.pin_fingerprint("bob".into()).unwrap()
    );
    // The restored pin still refuses a different key for the same label.
    let mallory = Messenger::new();
    assert_eq!(
        restored
            .scan_pairing(
                "bob".into(),
                mallory.own_pairing_payload("hint".into()).unwrap()
            )
            .map(|_| ()),
        Err(FacadeError::PinChanged)
    );
    drop(bob);
}

#[test]
fn restored_identity_can_still_complete_a_handshake() {
    // Bob pinned Alice's QR before she restarted. After she restores from the vault,
    // Bob's handshake to her and her acceptance of Bob must still work: the ML-KEM
    // and X25519 secrets came back intact, not just their public halves.
    let (alice, bob) = alice_with_bob_pinned();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    let restored =
        Messenger::restore(alice.data_key().unwrap(), alice.export_vault().unwrap()).unwrap();
    drop(alice);

    let challenge = restored.responder_challenge().unwrap();
    let init = bob
        .start_session(
            "alice".into(),
            restored.own_identity().unwrap(),
            challenge.clone(),
        )
        .unwrap();
    restored
        .accept_session("bob".into(), init, challenge)
        .unwrap();

    let m = bob.send("alice".into(), "after restart".into()).unwrap();
    restored.receive("bob".into(), m).unwrap();
    assert_eq!(
        restored.history("bob".into()).unwrap(),
        vec!["after restart".to_string()]
    );
}

#[test]
fn messages_and_sessions_are_not_in_the_vault() {
    let (alice, bob) = alice_with_bob_pinned();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    let challenge = alice.responder_challenge().unwrap();
    let init = bob
        .start_session(
            "alice".into(),
            alice.own_identity().unwrap(),
            challenge.clone(),
        )
        .unwrap();
    alice.accept_session("bob".into(), init, challenge).unwrap();
    let m = bob.send("alice".into(), "never persisted".into()).unwrap();
    alice.receive("bob".into(), m).unwrap();
    assert_eq!(alice.history("bob".into()).unwrap().len(), 1);

    let restored =
        Messenger::restore(alice.data_key().unwrap(), alice.export_vault().unwrap()).unwrap();

    assert!(restored.peers().unwrap().is_empty());
    assert!(restored.history("bob".into()).unwrap().is_empty());
    assert_eq!(
        restored.send("bob".into(), "x".into()).map(|_| ()),
        Err(FacadeError::NoSession)
    );
}

#[test]
fn wrong_data_key_is_refused() {
    let (alice, _bob) = alice_with_bob_pinned();
    let blob = alice.export_vault().unwrap();
    let mut wrong = alice.data_key().unwrap();
    wrong[0] ^= 1;
    assert_eq!(
        Messenger::restore(wrong, blob).map(|_| ()),
        Err(FacadeError::AuthFailed)
    );
}

#[test]
fn another_messengers_key_is_refused() {
    let (alice, _bob) = alice_with_bob_pinned();
    let other = Messenger::create_persistent();
    assert_eq!(
        Messenger::restore(other.data_key().unwrap(), alice.export_vault().unwrap()).map(|_| ()),
        Err(FacadeError::AuthFailed)
    );
}

#[test]
fn every_single_byte_flip_in_the_blob_is_refused() {
    let (alice, _bob) = alice_with_bob_pinned();
    let key = alice.data_key().unwrap();
    let blob = alice.export_vault().unwrap();
    for i in 0..blob.len() {
        let mut bad = blob.clone();
        bad[i] ^= 0x01;
        let got = Messenger::restore(key.clone(), bad).map(|_| ());
        assert!(
            matches!(
                got,
                Err(FacadeError::AuthFailed) | Err(FacadeError::Malformed)
            ),
            "flip at byte {i} was accepted"
        );
    }
}

#[test]
fn truncated_or_empty_blob_is_malformed_or_refused() {
    let (alice, _bob) = alice_with_bob_pinned();
    let key = alice.data_key().unwrap();
    let blob = alice.export_vault().unwrap();
    for len in [0, 1, 12, 13, blob.len() - 1] {
        let got = Messenger::restore(key.clone(), blob[..len].to_vec()).map(|_| ());
        assert!(
            matches!(
                got,
                Err(FacadeError::AuthFailed) | Err(FacadeError::Malformed)
            ),
            "length {len} was accepted"
        );
    }
}

#[test]
fn data_key_must_be_32_bytes() {
    let (alice, _bob) = alice_with_bob_pinned();
    let blob = alice.export_vault().unwrap();
    assert_eq!(
        Messenger::restore(vec![0u8; 31], blob).map(|_| ()),
        Err(FacadeError::Malformed)
    );
}

#[test]
fn a_non_persistent_messenger_has_no_vault() {
    let m = Messenger::new();
    assert_eq!(m.data_key(), Err(FacadeError::Internal));
    assert_eq!(m.export_vault(), Err(FacadeError::Internal));
}

#[test]
fn export_changes_when_a_pin_is_added_and_uses_a_fresh_nonce() {
    let (alice, _bob) = alice_with_bob_pinned();
    let first = alice.export_vault().unwrap();
    let again = alice.export_vault().unwrap();
    // Same contents, fresh nonce: the blobs differ, so a repeated seal never reuses a nonce.
    assert_eq!(first.len(), again.len());
    assert_ne!(first, again);

    let carol = Messenger::new();
    alice
        .scan_pairing(
            "carol".into(),
            carol.own_pairing_payload(String::new()).unwrap(),
        )
        .unwrap();
    let with_carol = alice.export_vault().unwrap();
    assert!(with_carol.len() > first.len());
    let restored = Messenger::restore(alice.data_key().unwrap(), with_carol).unwrap();
    assert_eq!(
        restored.pinned_peers().unwrap(),
        vec!["bob".to_string(), "carol".to_string()]
    );
}

#[test]
fn restored_messenger_can_keep_exporting() {
    let (alice, _bob) = alice_with_bob_pinned();
    let restored =
        Messenger::restore(alice.data_key().unwrap(), alice.export_vault().unwrap()).unwrap();
    let again = Messenger::restore(
        restored.data_key().unwrap(),
        restored.export_vault().unwrap(),
    )
    .unwrap();
    assert_eq!(again.pinned_peers().unwrap(), vec!["bob".to_string()]);
}

// vault module: the sealing primitive on its own.

#[test]
fn sealed_bytes_do_not_contain_the_plaintext() {
    let key = vault::new_data_key();
    let marker = b"MARKER-0123456789-abcdefghijklmnop";
    let blob = vault::seal(&key, marker).unwrap();
    assert!(!blob.windows(marker.len()).any(|w| w == marker));
    assert_eq!(vault::open(&key, &blob).unwrap().expose(), marker);
}

#[test]
fn two_data_keys_are_different() {
    assert_ne!(vault::new_data_key().0, vault::new_data_key().0);
}

#[test]
fn unknown_version_byte_is_refused() {
    let key = vault::new_data_key();
    let mut blob = vault::seal(&key, b"x").unwrap();
    blob[0] = 0xFF;
    assert!(vault::open(&key, &blob).is_err());
}

#[test]
fn the_onion_address_survives_a_restore_and_matches_the_pinned_copy() {
    let (alice, bob) = alice_with_bob_pinned();
    let restored =
        Messenger::restore(alice.data_key().unwrap(), alice.export_vault().unwrap()).unwrap();
    assert_eq!(
        restored.own_onion_address().unwrap(),
        alice.own_onion_address().unwrap()
    );
    assert!(restored.own_onion_address().unwrap().ends_with(".onion"));
    // Bob's address as Alice pinned it is the address Bob reports for himself.
    assert_eq!(
        restored.pinned_onion_address("bob".into()).unwrap(),
        Some(bob.own_onion_address().unwrap())
    );
    assert_eq!(
        restored.pinned_onion_address("nobody".into()).unwrap(),
        None
    );
}
