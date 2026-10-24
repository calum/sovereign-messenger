//! Initiator authentication. The responder accepts a handshake only when the
//! initiator's static X25519 key equals the key pinned for that peer. Both
//! static keys feed the root through a static-static DH, so a wrong static key
//! on either side gives a different root and the first message does not open.

use rust_core::double_ratchet::DoubleRatchet;
use rust_core::ffi::{FacadeError, Messenger};
use rust_core::handshake::{self, Identity};
use rust_core::wire::{self, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR};
use rust_core::CoreError;

// Offsets in the handshake frame: tag, ephemeral key, initiator static key, ML-KEM ciphertext.
const EPHEMERAL_AT: usize = 1;
const STATIC_AT: usize = 1 + 32;
const KEM_AT: usize = 1 + 32 + 32;

#[test]
fn pinned_initiator_and_responder_derive_the_same_root_and_exchange_a_message() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();

    let (init, root_a) = handshake::initiate(&alice, &bob_pub).unwrap();
    let root_b = handshake::respond(&bob, &alice_pub.x25519, &init).unwrap();
    assert_eq!(root_a.0, root_b.0);

    let mut send = DoubleRatchet::new(&root_a, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR);
    let mut recv = DoubleRatchet::new(&root_b, RESPONDER_TO_INITIATOR, INITIATOR_TO_RESPONDER);
    let msg = send.seal(b"hello bob").unwrap();
    assert_eq!(recv.open(&msg).unwrap(), b"hello bob".to_vec());
}

#[test]
fn responder_refuses_an_initiator_whose_static_key_is_not_the_pinned_one() {
    let (bob, bob_pub) = Identity::generate();
    let (_alice, alice_pub) = Identity::generate();
    let (mallory, _) = Identity::generate();

    let (init, _) = handshake::initiate(&mallory, &bob_pub).unwrap();
    assert_eq!(
        handshake::respond(&bob, &alice_pub.x25519, &init).err(),
        Some(CoreError::Auth)
    );
}

#[test]
fn responder_with_a_wrong_static_key_cannot_complete_with_the_real_initiator() {
    let (_bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();
    let (impostor_bob, _) = Identity::generate();

    let (init, root_a) = handshake::initiate(&alice, &bob_pub).unwrap();
    let root_b = handshake::respond(&impostor_bob, &alice_pub.x25519, &init).unwrap();
    assert_ne!(root_a.0, root_b.0);

    let mut send = DoubleRatchet::new(&root_a, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR);
    let mut recv = DoubleRatchet::new(&root_b, RESPONDER_TO_INITIATOR, INITIATOR_TO_RESPONDER);
    let msg = send.seal(b"for bob only").unwrap();
    assert_eq!(recv.open(&msg), Err(CoreError::Auth));
}

#[test]
fn tampered_static_key_is_refused_by_the_pin() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();

    let (init, _) = handshake::initiate(&alice, &bob_pub).unwrap();
    let mut frame = wire::encode_handshake(&init);
    frame[STATIC_AT] ^= 0x01;
    let tampered = wire::decode_handshake(&frame).unwrap();

    assert_eq!(
        handshake::respond(&bob, &alice_pub.x25519, &tampered).err(),
        Some(CoreError::Auth)
    );
}

#[test]
fn tampered_ephemeral_key_gives_a_root_that_does_not_open_the_first_message() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();

    let (init, root_a) = handshake::initiate(&alice, &bob_pub).unwrap();
    let mut frame = wire::encode_handshake(&init);
    frame[EPHEMERAL_AT] ^= 0x01;
    let tampered = wire::decode_handshake(&frame).unwrap();
    let root_b = handshake::respond(&bob, &alice_pub.x25519, &tampered).unwrap();
    assert_ne!(root_a.0, root_b.0);

    let mut send = DoubleRatchet::new(&root_a, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR);
    let mut recv = DoubleRatchet::new(&root_b, RESPONDER_TO_INITIATOR, INITIATOR_TO_RESPONDER);
    let msg = send.seal(b"hello").unwrap();
    assert_eq!(recv.open(&msg), Err(CoreError::Auth));
}

#[test]
fn tampered_kem_ciphertext_gives_a_root_that_does_not_open_the_first_message() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();

    let (init, root_a) = handshake::initiate(&alice, &bob_pub).unwrap();
    let mut frame = wire::encode_handshake(&init);
    frame[KEM_AT + 10] ^= 0x01;
    let tampered = wire::decode_handshake(&frame).unwrap();
    let root_b = handshake::respond(&bob, &alice_pub.x25519, &tampered).unwrap();
    assert_ne!(root_a.0, root_b.0);

    let mut send = DoubleRatchet::new(&root_a, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR);
    let mut recv = DoubleRatchet::new(&root_b, RESPONDER_TO_INITIATOR, INITIATOR_TO_RESPONDER);
    let msg = send.seal(b"hello").unwrap();
    assert_eq!(recv.open(&msg), Err(CoreError::Auth));
}

#[test]
fn facade_responder_refuses_a_peer_with_no_pin() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let init = alice
        .start_session("bob".into(), bob.own_identity().unwrap())
        .unwrap();
    assert_eq!(
        bob.accept_session("alice".into(), init),
        Err(FacadeError::NotPinned)
    );
}

#[test]
fn facade_responder_refuses_a_handshake_from_a_key_other_than_the_pinned_one() {
    let alice = Messenger::new();
    let mallory = Messenger::new();
    let bob = Messenger::new();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();

    let init = mallory
        .start_session("bob".into(), bob.own_identity().unwrap())
        .unwrap();
    assert_eq!(
        bob.accept_session("alice".into(), init),
        Err(FacadeError::AuthFailed)
    );
    assert_eq!(bob.peers().unwrap(), Vec::<String>::new());
}

#[test]
fn facade_pinned_initiator_opens_a_session_and_messages_flow() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();

    let init = alice
        .start_session("bob".into(), bob.own_identity().unwrap())
        .unwrap();
    bob.accept_session("alice".into(), init).unwrap();

    bob.receive(
        "alice".into(),
        alice.send("bob".into(), "hello bob".into()).unwrap(),
    )
    .unwrap();
    alice
        .receive(
            "bob".into(),
            bob.send("alice".into(), "hi alice".into()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        bob.history("alice".into()).unwrap(),
        vec!["hello bob", "hi alice"]
    );
}
