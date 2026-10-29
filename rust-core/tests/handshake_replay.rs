//! Handshake replay. The responder issues a fresh challenge per handshake and the
//! initiator binds it into the root and a key-confirmation tag. A captured
//! handshake replayed against a new challenge must be refused before any session
//! is stored, so a live session with the same peer is never replaced.

use rust_core::double_ratchet::{DoubleRatchet, Role};
use rust_core::ffi::{FacadeError, Messenger};
use rust_core::handshake::{self, Identity};
use rust_core::wire::{INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR};
use rust_core::CoreError;

#[test]
fn fresh_challenge_initiate_and_respond_derive_the_same_root() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();
    let challenge = handshake::new_challenge();

    let (init, root_a) = handshake::initiate(&alice, &bob_pub, &challenge).unwrap();
    // respond verifies the key-confirmation tag before it returns a root.
    let root_b = handshake::respond(&bob, &alice_pub.x25519, &init, &challenge).unwrap();
    assert_eq!(root_a.0, root_b.0);
}

#[test]
fn replayed_handshake_is_refused_and_the_live_session_keeps_working() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();

    // Session 1: a genuine handshake, answered with the challenge Bob issued for it.
    let c1 = bob.responder_challenge().unwrap();
    let captured = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c1.clone())
        .unwrap();
    bob.accept_session("alice".into(), captured.clone(), c1)
        .unwrap();
    bob.receive(
        "alice".into(),
        alice.send("bob".into(), "before replay".into()).unwrap(),
    )
    .unwrap();

    // An attacker replays the captured frame against Bob's next challenge.
    let c2 = bob.responder_challenge().unwrap();
    assert_eq!(
        bob.accept_session("alice".into(), captured, c2),
        Err(FacadeError::AuthFailed)
    );

    // Session 1 is untouched: Alice's next message still opens on Bob's side.
    bob.receive(
        "alice".into(),
        alice.send("bob".into(), "after replay".into()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        bob.history("alice".into()).unwrap(),
        vec!["before replay", "after replay"]
    );
}

#[test]
fn replayed_handshake_at_the_core_level_is_refused_and_derives_no_matching_root() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();

    let c1 = handshake::new_challenge();
    let (init1, root1) = handshake::initiate(&alice, &bob_pub, &c1).unwrap();
    let root1_b = handshake::respond(&bob, &alice_pub.x25519, &init1, &c1).unwrap();
    assert_eq!(root1.0, root1_b.0);

    // Session 1 is live. The replay uses a new challenge.
    let mut live_send = DoubleRatchet::new(
        &root1,
        Role::Initiator,
        INITIATOR_TO_RESPONDER,
        RESPONDER_TO_INITIATOR,
    );
    let mut live_recv = DoubleRatchet::new(
        &root1_b,
        Role::Responder,
        RESPONDER_TO_INITIATOR,
        INITIATOR_TO_RESPONDER,
    );
    let c2 = handshake::new_challenge();
    assert_eq!(
        handshake::respond(&bob, &alice_pub.x25519, &init1, &c2).err(),
        Some(CoreError::Auth)
    );
    let msg = live_send.seal(b"still here").unwrap();
    assert_eq!(live_recv.open(&msg).unwrap(), b"still here".to_vec());
}

#[test]
fn tampered_confirmation_tag_is_refused() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();
    let challenge = handshake::new_challenge();

    let (mut init, _) = handshake::initiate(&alice, &bob_pub, &challenge).unwrap();
    init.tag[0] ^= 0x01;
    assert_eq!(
        handshake::respond(&bob, &alice_pub.x25519, &init, &challenge).err(),
        Some(CoreError::Auth)
    );
}

#[test]
fn tampered_challenge_is_refused() {
    let (bob, bob_pub) = Identity::generate();
    let (alice, alice_pub) = Identity::generate();
    let challenge = handshake::new_challenge();

    let (init, _) = handshake::initiate(&alice, &bob_pub, &challenge).unwrap();
    let mut other = challenge;
    other[0] ^= 0x01;
    assert_eq!(
        handshake::respond(&bob, &alice_pub.x25519, &init, &other).err(),
        Some(CoreError::Auth)
    );
}

#[test]
fn challenge_cannot_be_reused_for_a_second_handshake() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();

    let c = bob.responder_challenge().unwrap();
    let first = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c.clone())
        .unwrap();
    bob.accept_session("alice".into(), first, c.clone())
        .unwrap();

    // A second handshake that reuses the spent challenge is refused.
    let second = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c.clone())
        .unwrap();
    assert_eq!(
        bob.accept_session("alice".into(), second, c),
        Err(FacadeError::AuthFailed)
    );
}
