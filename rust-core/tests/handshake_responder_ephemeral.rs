//! Handshake v2: the responder's challenge carries a fresh ephemeral X25519 key.
//! These tests cover the wire frame, the tag binding and the one-shot use of the
//! ephemeral secret. The forward-secrecy derivation test lives in `handshake.rs`
//! because it needs the private root derivation.

use rust_core::ffi::{FacadeError, Messenger};
use rust_core::handshake::{self, Identity};
use rust_core::wire;
use rust_core::CoreError;

fn paired() -> (std::sync::Arc<Messenger>, std::sync::Arc<Messenger>) {
    let alice = Messenger::new();
    let bob = Messenger::new();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    (alice, bob)
}

#[test]
fn challenge_frame_is_65_bytes_and_the_old_33_byte_frame_is_refused() {
    let challenge = handshake::new_challenge();
    let frame = wire::encode_challenge(&challenge.offer());
    assert_eq!(frame.len(), 65);
    assert_eq!(wire::decode_challenge(&frame).unwrap(), challenge.offer());
    let mut old = vec![wire::TAG_CHALLENGE];
    old.extend_from_slice(&challenge.offer().nonce);
    assert_eq!(old.len(), 33);
    assert!(matches!(
        wire::decode_challenge(&old),
        Err(CoreError::Malformed)
    ));
}

#[test]
fn both_sides_agree_on_the_root() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();
    let c = handshake::new_challenge();
    let (init, root_a) = handshake::initiate(&alice, &bob_pub, &c.offer()).unwrap();
    let root_b = handshake::respond(&bob, &alice_pub.x25519, &init, &c).unwrap();
    assert_eq!(root_a.0, root_b.0);
}

#[test]
fn swapped_responder_ephemeral_key_fails_the_tag() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();
    let c = handshake::new_challenge();
    // An attacker swaps the ephemeral key in the challenge frame in transit: the
    // initiator sees the genuine nonce with the attacker's key.
    let mut seen = c.offer();
    seen.ephemeral = handshake::new_challenge().offer().ephemeral;
    let (init, _) = handshake::initiate(&alice, &bob_pub, &seen).unwrap();
    assert_eq!(
        handshake::respond(&bob, &alice_pub.x25519, &init, &c).err(),
        Some(CoreError::Auth)
    );
}

#[test]
fn low_order_responder_ephemeral_is_refused_by_the_initiator() {
    let (_bob, bob_pub) = Identity::generate();
    let (alice, _) = Identity::generate();
    let mut offer = handshake::new_challenge().offer();
    offer.ephemeral = [0u8; 32];
    assert_eq!(
        handshake::initiate(&alice, &bob_pub, &offer).err(),
        Some(CoreError::Malformed)
    );
}

#[test]
fn wrong_challenge_is_refused() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();
    let c = handshake::new_challenge();
    let (init, _) = handshake::initiate(&alice, &bob_pub, &c.offer()).unwrap();
    let other = handshake::new_challenge();
    assert_eq!(
        handshake::respond(&bob, &alice_pub.x25519, &init, &other).err(),
        Some(CoreError::Auth)
    );
}

#[test]
fn facade_challenge_blob_is_64_bytes() {
    let (_alice, bob) = paired();
    assert_eq!(bob.responder_challenge().unwrap().len(), 64);
}

#[test]
fn facade_replaced_challenge_cannot_be_answered_and_spends_the_pending_one() {
    let (alice, bob) = paired();
    let c1 = bob.responder_challenge().unwrap();
    let c2 = bob.responder_challenge().unwrap();
    let old = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c1.clone())
        .unwrap();
    // The first ephemeral secret is gone: its blob is refused.
    assert_eq!(
        bob.accept_session("alice".into(), old, c1),
        Err(FacadeError::AuthFailed)
    );
    // The refusal also spent the second one, so it cannot be used afterwards.
    let again = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c2.clone())
        .unwrap();
    assert_eq!(
        bob.accept_session("alice".into(), again, c2),
        Err(FacadeError::AuthFailed)
    );
}

#[test]
fn facade_spent_ephemeral_cannot_serve_a_second_handshake() {
    let (alice, bob) = paired();
    let c = bob.responder_challenge().unwrap();
    let first = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c.clone())
        .unwrap();
    bob.accept_session("alice".into(), first, c.clone())
        .unwrap();
    let second = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c.clone())
        .unwrap();
    assert_eq!(
        bob.accept_session("alice".into(), second, c),
        Err(FacadeError::AuthFailed)
    );
}

#[test]
fn facade_short_challenge_blob_is_malformed() {
    let (alice, bob) = paired();
    assert_eq!(
        alice
            .start_session("bob".into(), bob.own_identity().unwrap(), vec![0u8; 32])
            .err(),
        Some(FacadeError::Malformed)
    );
}
