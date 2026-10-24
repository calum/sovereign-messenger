//! Pairing through the facade Kotlin calls: a scanned QR pins the peer's
//! identity (trust on first use), and a different key for a pinned peer is
//! refused with its own error. Pins live in RAM and survive `forget` and
//! `wipe_all`, so a later QR cannot silently replace a trusted key.

use rust_core::ffi::{FacadeError, Messenger};

fn scan_of(m: &Messenger) -> Vec<u8> {
    m.own_pairing_payload(String::new()).unwrap()
}

#[test]
fn scanned_payload_pins_identity_and_shows_fingerprint() {
    let alice = Messenger::new();
    let bob = Messenger::new();

    let shown = alice
        .scan_pairing("bob".into(), scan_of(&bob))
        .unwrap()
        .fingerprint;
    assert_eq!(shown, bob.own_fingerprint().unwrap());
    assert_eq!(alice.pin_fingerprint("bob".into()).unwrap(), Some(shown));
    assert_eq!(alice.pinned_peers().unwrap(), vec!["bob".to_string()]);
}

#[test]
fn handshake_works_after_scan() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();

    let init = alice
        .start_session("bob".into(), bob.own_identity().unwrap())
        .unwrap();
    bob.accept_session("alice".into(), init).unwrap();
    let m = alice.send("bob".into(), "paired".into()).unwrap();
    bob.receive("alice".into(), m).unwrap();
    assert_eq!(
        bob.history("alice".into()).unwrap(),
        vec!["paired".to_string()]
    );
}

#[test]
fn different_key_for_pinned_peer_is_refused() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mallory = Messenger::new();
    let pinned = alice
        .scan_pairing("bob".into(), scan_of(&bob))
        .unwrap()
        .fingerprint;

    assert_eq!(
        alice.scan_pairing("bob".into(), scan_of(&mallory)),
        Err(FacadeError::PinChanged)
    );
    // The original pin is untouched after the refusal.
    assert_eq!(alice.pin_fingerprint("bob".into()).unwrap(), Some(pinned));
}

#[test]
fn handshake_with_changed_key_is_refused_and_opens_no_session() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mallory = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();

    assert_eq!(
        alice
            .start_session("bob".into(), mallory.own_identity().unwrap())
            .map(|_| ()),
        Err(FacadeError::PinChanged)
    );
    assert!(alice.peers().unwrap().is_empty());
}

#[test]
fn rescanning_same_identity_is_duplicate_pin() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let payload = scan_of(&bob);
    alice.scan_pairing("bob".into(), payload.clone()).unwrap();

    assert_eq!(
        alice.scan_pairing("bob".into(), payload),
        Err(FacadeError::DuplicatePin)
    );
}

#[test]
fn malformed_payload_pins_nothing() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mut bad = scan_of(&bob);
    bad.truncate(bad.len() - 1);

    assert_eq!(
        alice.scan_pairing("bob".into(), bad),
        Err(FacadeError::Malformed)
    );
    assert_eq!(alice.pin_fingerprint("bob".into()).unwrap(), None);
    assert!(alice.pinned_peers().unwrap().is_empty());
}

#[test]
fn explicit_unpin_allows_a_new_key_to_be_pinned() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mallory = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();
    assert_eq!(
        alice.scan_pairing("bob".into(), scan_of(&mallory)),
        Err(FacadeError::PinChanged)
    );

    alice.unpin("bob".into()).unwrap();
    let shown = alice
        .scan_pairing("bob".into(), scan_of(&mallory))
        .unwrap()
        .fingerprint;
    assert_eq!(shown, mallory.own_fingerprint().unwrap());
}

#[test]
fn forget_keeps_the_pin() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mallory = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();

    alice.forget("bob".into()).unwrap();
    assert_eq!(
        alice.scan_pairing("bob".into(), scan_of(&mallory)),
        Err(FacadeError::PinChanged)
    );
}

#[test]
fn wipe_all_keeps_the_pin() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mallory = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();

    alice.wipe_all().unwrap();
    assert_eq!(
        alice.scan_pairing("bob".into(), scan_of(&mallory)),
        Err(FacadeError::PinChanged)
    );
}

#[test]
fn start_session_without_a_scan_pins_on_first_use() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mallory = Messenger::new();
    alice
        .start_session("bob".into(), bob.own_identity().unwrap())
        .unwrap();
    assert_eq!(
        alice.pin_fingerprint("bob".into()).unwrap(),
        Some(bob.own_fingerprint().unwrap())
    );
    assert_eq!(
        alice
            .start_session("bob".into(), mallory.own_identity().unwrap())
            .map(|_| ()),
        Err(FacadeError::PinChanged)
    );
}

#[test]
fn pin_changed_error_text_carries_no_key_material() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    let mallory = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();
    let err = alice
        .scan_pairing("bob".into(), scan_of(&mallory))
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(&mallory.own_fingerprint().unwrap()));
    assert_eq!(text, "pinned key changed; new key refused");
}

#[test]
fn each_messenger_generates_its_own_identity() {
    let a = Messenger::new();
    let b = Messenger::new();
    let ia = a.own_identity().unwrap();
    let ib = b.own_identity().unwrap();
    assert_eq!(ia.x25519.len(), 32);
    assert_eq!(ia.mlkem_ek.len(), 1184);
    assert_ne!(ia.x25519, ib.x25519);
    assert_ne!(ia.mlkem_ek, ib.mlkem_ek);
}
