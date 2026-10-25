//! A listener that does not know in advance who will call (an onion service accepts
//! any pinned contact). The caller is identified by the long-term key it proves in the
//! handshake, matched against the pins, never by a label the caller supplies.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use rust_core::ffi::{FacadeError, Messenger};

fn free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    addr
}

fn pin(on: &Messenger, label: &str, whom: &Messenger) {
    on.scan_pairing(
        label.into(),
        whom.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
}

fn connect_with_retry(from: &Messenger, label: &str, addr: &str) -> Result<(), FacadeError> {
    let mut last = Ok(());
    for _ in 0..100 {
        last = from.connect_peer(label.into(), addr.to_string());
        if last.is_ok() {
            return last;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

#[test]
fn the_listener_names_the_pinned_caller_by_its_key() {
    let bob = Messenger::new();
    let alice = Messenger::new();
    let carol = Messenger::new();
    pin(&bob, "alice", &alice);
    pin(&bob, "carol", &carol);
    pin(&carol, "bob", &bob);

    let addr = free_port();
    let bob_side: Arc<Messenger> = Arc::clone(&bob);
    let listen_addr = addr.clone();
    let listener = std::thread::spawn(move || bob_side.listen_for_any_peer(listen_addr, 10));

    connect_with_retry(&carol, "bob", &addr).unwrap();
    assert_eq!(listener.join().unwrap().unwrap(), "carol");

    carol
        .send_over_transport("bob".into(), "from carol".into())
        .unwrap();
    assert!(bob.receive_from_peer("carol".into()).unwrap());
    assert_eq!(bob.history("carol".into()).unwrap(), vec!["from carol"]);
    // Only the caller got a session.
    assert_eq!(bob.linked_peers().unwrap(), vec!["carol".to_string()]);
}

#[test]
fn an_unpinned_caller_is_refused_and_leaves_no_session() {
    let bob = Messenger::new();
    let alice = Messenger::new();
    let mallory = Messenger::new();
    pin(&bob, "alice", &alice);
    pin(&mallory, "bob", &bob);

    let addr = free_port();
    let bob_side: Arc<Messenger> = Arc::clone(&bob);
    let listen_addr = addr.clone();
    let listener = std::thread::spawn(move || bob_side.listen_for_any_peer(listen_addr, 10));

    let _ = connect_with_retry(&mallory, "bob", &addr);
    assert_eq!(listener.join().unwrap(), Err(FacadeError::NotPinned));
    assert!(bob.peers().unwrap().is_empty());
    assert!(bob.linked_peers().unwrap().is_empty());
}

#[test]
fn a_timeout_with_no_caller_is_a_network_error() {
    let bob = Messenger::new();
    assert_eq!(
        bob.listen_for_any_peer(free_port(), 1),
        Err(FacadeError::Network)
    );
}
