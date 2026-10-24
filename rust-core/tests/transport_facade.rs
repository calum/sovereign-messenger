//! The UniFFI facade over TCP: two `Messenger` objects stand in for two phones.
//! Bob listens on a loopback port; Alice has pinned Bob by scanning his QR payload.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use rust_core::ffi::{FacadeError, Messenger};

/// Picks a port that is free right now. A small race with the listener is
/// accepted in tests.
fn free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    addr
}

#[test]
fn messages_flow_both_ways_over_tcp() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    alice
        .scan_pairing(
            "bob".into(),
            bob.own_pairing_payload(String::new()).unwrap(),
        )
        .unwrap();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();

    let addr = free_port();
    let bob_side: Arc<Messenger> = Arc::clone(&bob);
    let listen_addr = addr.clone();
    let listener = std::thread::spawn(move || {
        bob_side
            .listen_for_peer("alice".into(), listen_addr, 10)
            .unwrap();
    });

    connect_with_retry(&alice, &addr);
    listener.join().unwrap();

    alice
        .send_over_transport("bob".into(), "hello bob".into())
        .unwrap();
    assert!(bob.receive_from_peer("alice".into()).unwrap());
    assert_eq!(bob.history("alice".into()).unwrap(), vec!["hello bob"]);

    bob.send_over_transport("alice".into(), "hi alice".into())
        .unwrap();
    assert!(alice.receive_from_peer("bob".into()).unwrap());
    assert_eq!(
        alice.history("bob".into()).unwrap(),
        vec!["hello bob", "hi alice"]
    );
}

fn connect_with_retry(alice: &Messenger, addr: &str) {
    let mut last = None;
    for _ in 0..100 {
        match alice.connect_peer("bob".into(), addr.to_string()) {
            Ok(()) => return,
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    panic!("connect never succeeded: {last:?}");
}

#[test]
fn connect_refused_without_a_pinned_identity() {
    let alice = Messenger::new();
    assert_eq!(
        alice.connect_peer("bob".into(), "127.0.0.1:9".into()),
        Err(FacadeError::NotPinned)
    );
}

#[test]
fn send_refused_when_no_transport_is_open() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    alice
        .start_session("bob".into(), bob.own_identity().unwrap())
        .unwrap();
    assert_eq!(
        alice.send_over_transport("bob".into(), "x".into()),
        Err(FacadeError::NoLink)
    );
    assert_eq!(
        alice.receive_from_peer("bob".into()),
        Err(FacadeError::NoLink)
    );
}

#[test]
fn peer_disconnect_is_reported_as_a_network_error() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    alice
        .scan_pairing(
            "bob".into(),
            bob.own_pairing_payload(String::new()).unwrap(),
        )
        .unwrap();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    let addr = free_port();
    let bob_side = Arc::clone(&bob);
    let listen_addr = addr.clone();
    let listener = std::thread::spawn(move || {
        bob_side
            .listen_for_peer("alice".into(), listen_addr, 10)
            .unwrap();
    });
    connect_with_retry(&alice, &addr);
    listener.join().unwrap();

    bob.wipe_all().unwrap(); // drops Bob's socket
    assert_eq!(
        alice.receive_from_peer("bob".into()),
        Err(FacadeError::Network)
    );
}

#[test]
fn listen_times_out_when_nobody_connects() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    bob.scan_pairing(
        "alice".into(),
        alice.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        bob.listen_for_peer("alice".into(), free_port(), 1),
        Err(FacadeError::Network)
    );
}

#[test]
fn listen_refused_without_a_pinned_identity() {
    let bob = Messenger::new();
    assert_eq!(
        bob.listen_for_peer("alice".into(), free_port(), 1),
        Err(FacadeError::NotPinned)
    );
}
