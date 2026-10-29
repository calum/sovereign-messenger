//! Per-peer state (a read receipt owed, the last-seen time) must not outlive the
//! contact. If it did, a receipt for a message id from the old conversation would be
//! sent into a fresh session with the same label, and a stale "last seen" would show.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use rust_core::ffi::Messenger;

fn free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    addr
}

/// `me` pins `other` under `other_label`.
fn pin(me: &Arc<Messenger>, other_label: &str, other: &Arc<Messenger>) {
    me.scan_pairing(
        other_label.into(),
        other.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
}

/// Bob dials `peer` (labelled `label` at Bob, `"bob"` at the peer).
fn connect(bob: &Arc<Messenger>, label: &str, peer: &Arc<Messenger>) {
    let addr = free_port();
    let side = Arc::clone(peer);
    let listen_addr = addr.clone();
    let handle = std::thread::spawn(move || {
        side.listen_for_peer("bob".into(), listen_addr, 10).unwrap();
    });
    for _ in 0..100 {
        if bob.connect_peer(label.into(), addr.clone()).is_ok() {
            handle.join().unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded");
}

/// Bob reads one message from `peer`, then the peer's link drops with the receipt unsent.
fn owe_receipt(bob: &Arc<Messenger>, label: &str, peer: &Arc<Messenger>) {
    peer.send_text("bob".into(), "hi".into()).unwrap();
    while bob.history(label.into()).unwrap().is_empty() {
        bob.receive_from_peer(label.into()).unwrap();
    }
    peer.wipe_all().unwrap();
    assert_eq!(bob.mark_read(label.into(), true).unwrap(), 1);
    assert!(bob.receive_from_peer(label.into()).is_err());
    assert!(bob.presence(label.into()).unwrap().last_seen_ms.is_some());
}

/// `repin` is true when `remove` also drops the pin (unpin); forget keeps it.
fn run(remove: impl Fn(&Messenger, &str), repin: bool) {
    let bob = Messenger::new();
    let alice = Messenger::new();
    let carol = Messenger::new();
    pin(&bob, "alice", &alice);
    pin(&bob, "carol", &carol);
    pin(&alice, "bob", &bob);
    pin(&carol, "bob", &bob);

    connect(&bob, "alice", &alice);
    owe_receipt(&bob, "alice", &alice);
    connect(&bob, "carol", &carol);
    owe_receipt(&bob, "carol", &carol);

    remove(&bob, "alice");
    assert_eq!(bob.presence("alice".into()).unwrap().last_seen_ms, None);
    assert!(bob.presence("carol".into()).unwrap().last_seen_ms.is_some());

    // Alice's label is reused for a fresh pairing and session. The old receipt must not
    // be sent into it: Alice sees silence, not a receipt for an id from before.
    if repin {
        pin(&bob, "alice", &alice);
    }
    connect(&bob, "alice", &alice);
    assert_eq!(bob.flush_pending("alice".into()).unwrap(), 0);
    assert_eq!(alice.receive_from_peer("bob".into()), Ok(false));

    // Carol's owed receipt survives and still goes out.
    connect(&bob, "carol", &carol);
    bob.flush_pending("carol".into()).unwrap();
    assert_eq!(carol.receive_from_peer("bob".into()), Ok(true));
}

#[test]
fn forget_clears_the_owed_receipt_and_last_seen_for_that_peer_only() {
    run(|m, peer| m.forget(peer.into()).unwrap(), false);
}

#[test]
fn unpin_clears_the_owed_receipt_and_last_seen_for_that_peer_only() {
    run(|m, peer| m.unpin(peer.into()).unwrap(), true);
}

#[test]
fn wipe_all_clears_every_owed_receipt_and_last_seen() {
    let bob = Messenger::new();
    let alice = Messenger::new();
    pin(&bob, "alice", &alice);
    pin(&alice, "bob", &bob);
    connect(&bob, "alice", &alice);
    owe_receipt(&bob, "alice", &alice);
    bob.wipe_all().unwrap();
    assert_eq!(bob.presence("alice".into()).unwrap().last_seen_ms, None);
    connect(&bob, "alice", &alice);
    assert_eq!(bob.flush_pending("alice".into()).unwrap(), 0);
    assert_eq!(alice.receive_from_peer("bob".into()), Ok(false));
}
