//! The state the chat screen shows as "P2P mesh" comes from the core, not from
//! the UI. `linked_peers` lists only sessions that hold a live connection, and
//! `listening_peer` names the peer a listener is waiting for. An in-process
//! session with no connection must not count as connected, and a listener that
//! has stopped (timeout or peer connected) must not count as listening.

use rust_core::ffi::{FacadeError, Messenger};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

fn scan_of(m: &Messenger) -> Vec<u8> {
    m.own_pairing_payload(String::new()).unwrap()
}

/// A loopback address with a port nothing is listening on right now.
fn free_loopback_addr() -> SocketAddr {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

#[test]
fn fresh_messenger_has_no_links_and_no_listener() {
    let m = Messenger::new();
    assert_eq!(m.linked_peers().unwrap(), Vec::<String>::new());
    assert_eq!(m.listening_peer().unwrap(), None);
}

#[test]
fn in_process_session_is_listed_but_not_linked() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();
    alice
        .start_session("bob".into(), bob.own_identity().unwrap())
        .unwrap();

    // A session with no socket is not a connection to the contact.
    assert_eq!(alice.peers().unwrap(), vec!["bob".to_string()]);
    assert_eq!(alice.linked_peers().unwrap(), Vec::<String>::new());
}

#[test]
fn failed_listen_leaves_no_listener_behind() {
    let bob = Messenger::new();
    let alice = Messenger::new();
    bob.scan_pairing("alice".into(), scan_of(&alice)).unwrap();

    let addr = free_loopback_addr().to_string();
    // Nobody dials, so the one-second accept times out.
    assert_eq!(
        bob.listen_for_peer("alice".into(), addr, 1),
        Err(FacadeError::Network)
    );
    assert_eq!(bob.listening_peer().unwrap(), None);
}

#[test]
fn listener_then_connect_reports_listening_then_linked() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    alice.scan_pairing("bob".into(), scan_of(&bob)).unwrap();
    bob.scan_pairing("alice".into(), scan_of(&alice)).unwrap();

    let addr = free_loopback_addr().to_string();
    let listener_bob = bob.clone();
    let listen_addr = addr.clone();
    let waiter =
        thread::spawn(move || listener_bob.listen_for_peer("alice".into(), listen_addr, 10));

    // Wait until the listener is registered, so the test sees the state while it is up.
    let deadline = Instant::now() + Duration::from_secs(5);
    while bob.listening_peer().unwrap().is_none() {
        assert!(Instant::now() < deadline, "listener never reported itself");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(bob.listening_peer().unwrap(), Some("alice".to_string()));
    assert_eq!(bob.linked_peers().unwrap(), Vec::<String>::new());

    alice.connect_peer("bob".into(), addr).unwrap();
    waiter.join().unwrap().unwrap();

    assert_eq!(bob.listening_peer().unwrap(), None);
    assert_eq!(bob.linked_peers().unwrap(), vec!["alice".to_string()]);
    assert_eq!(alice.linked_peers().unwrap(), vec!["bob".to_string()]);
}
