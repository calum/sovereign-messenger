//! End-to-end check through the same facade Kotlin calls: handshake, then
//! ratchet traffic in both directions, then the failure paths (tamper, replay,
//! wrong identity, unknown peer). Two in-process parties stand in for two phones.

use std::sync::Arc;

use rust_core::ffi::{FacadeError, Messenger, WireMessage};

/// Alice initiates a session with Bob; Bob accepts it from the handshake message.
/// Bob has scanned Alice's code, so he has pinned the key his handshake must match.
fn paired() -> (Arc<Messenger>, Arc<Messenger>) {
    let alice = Messenger::new();
    let bob = Messenger::new();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    let bob_id = bob.own_identity().unwrap();
    let c = bob.responder_challenge().unwrap();
    let init = alice
        .start_session("bob".into(), bob_id, c.clone())
        .unwrap();
    bob.accept_session("alice".into(), init, c).unwrap();
    (alice, bob)
}

#[test]
fn handshake_and_ratchet_round_trip_both_directions() {
    let (alice, bob) = paired();

    let m1 = alice.send("bob".into(), "hello bob".into()).unwrap();
    bob.receive("alice".into(), m1).unwrap();
    let m2 = bob.send("alice".into(), "hi alice".into()).unwrap();
    alice.receive("bob".into(), m2).unwrap();

    assert_eq!(
        bob.history("alice".into()).unwrap(),
        vec!["hello bob".to_string(), "hi alice".to_string()]
    );
    assert_eq!(
        alice.history("bob".into()).unwrap(),
        vec!["hello bob".to_string(), "hi alice".to_string()]
    );
}

#[test]
fn tampered_ciphertext_rejected_and_state_unchanged() {
    let (alice, bob) = paired();
    let genuine = alice.send("bob".into(), "attack at dawn".into()).unwrap();
    let mut forged = WireMessage {
        ciphertext: genuine.ciphertext.clone(),
        ..genuine.clone()
    };
    forged.ciphertext[0] ^= 1;

    assert_eq!(
        bob.receive("alice".into(), forged),
        Err(FacadeError::AuthFailed)
    );
    assert!(bob.history("alice".into()).unwrap().is_empty());

    // A failed open must not advance the chain, so the genuine message still opens.
    bob.receive("alice".into(), genuine).unwrap();
    assert_eq!(
        bob.history("alice".into()).unwrap(),
        vec!["attack at dawn".to_string()]
    );
}

#[test]
fn replayed_message_rejected() {
    let (alice, bob) = paired();
    let m = alice.send("bob".into(), "once".into()).unwrap();
    let replay = WireMessage {
        ciphertext: m.ciphertext.clone(),
        ..m.clone()
    };
    bob.receive("alice".into(), m).unwrap();
    assert_eq!(
        bob.receive("alice".into(), replay),
        Err(FacadeError::Malformed)
    );
}

#[test]
fn wrong_identity_cannot_read_session() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let eve = Messenger::new();
    // Alice meant Bob's key, but Eve answers the handshake. Eve has pinned Alice,
    // so the handshake passes the pin check. The key-confirmation tag then fails,
    // because Eve derived a different root, and Eve stores no session.
    eve.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    let c = eve.responder_challenge().unwrap();
    let init = alice
        .start_session("bob".into(), bob.own_identity().unwrap(), c.clone())
        .unwrap();
    assert_eq!(
        eve.accept_session("alice".into(), init, c),
        Err(FacadeError::AuthFailed)
    );
    assert!(eve.peers().unwrap().is_empty());
    let m = alice.send("bob".into(), "for bob only".into()).unwrap();
    assert_eq!(eve.receive("alice".into(), m), Err(FacadeError::NoSession));
}

#[test]
fn unknown_peer_and_malformed_identity_rejected() {
    let (alice, _bob) = paired();
    assert_eq!(
        alice.send("carol".into(), "hi".into()),
        Err(FacadeError::NoSession)
    );

    let carol = Messenger::new();
    let mut bad = carol.own_identity().unwrap();
    bad.x25519.truncate(31);
    assert_eq!(
        alice
            .start_session("carol".into(), bad, vec![0u8; 32])
            .map(|_| ()),
        Err(FacadeError::Malformed)
    );
}

#[test]
fn wipe_all_clears_peers_and_history() {
    let (alice, bob) = paired();
    let m = alice.send("bob".into(), "gone soon".into()).unwrap();
    bob.receive("alice".into(), m).unwrap();

    bob.wipe_all().unwrap();
    assert!(bob.peers().unwrap().is_empty());
    assert!(bob.history("alice".into()).unwrap().is_empty());
}

#[test]
fn lock_report_counts_stored_messages() {
    let (alice, bob) = paired();
    for text in ["one", "two"] {
        let m = alice.send("bob".into(), text.into()).unwrap();
        bob.receive("alice".into(), m).unwrap();
    }
    let report = bob.lock_report().unwrap();
    assert_eq!(report.stored_total, 2);
    assert!(report.stored_locked <= report.stored_total);
}
