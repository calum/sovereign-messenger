//! Delivery and read receipts, the send queue and presence, over a real loopback link.
//! Two `Messenger` objects stand in for two phones that have scanned each other.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use rust_core::ffi::{FacadeError, MessageState, Messenger};

fn free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    addr
}

fn paired() -> (Arc<Messenger>, Arc<Messenger>) {
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
    (alice, bob)
}

/// Alice dials, Bob listens. Both end with a live link.
fn connect(alice: &Arc<Messenger>, bob: &Arc<Messenger>) {
    let addr = free_port();
    let bob_side = Arc::clone(bob);
    let listen_addr = addr.clone();
    let listener = std::thread::spawn(move || {
        bob_side
            .listen_for_peer("alice".into(), listen_addr, 10)
            .unwrap();
    });
    for _ in 0..100 {
        if alice.connect_peer("bob".into(), addr.clone()).is_ok() {
            listener.join().unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded");
}

/// Pumps `m` until `done` holds, so a test never depends on frame order.
fn pump(m: &Messenger, peer: &str, done: impl Fn() -> bool) {
    for _ in 0..40 {
        if done() {
            return;
        }
        m.receive_from_peer(peer.into()).unwrap();
    }
    panic!("condition never reached");
}

fn state_of(m: &Messenger, peer: &str, id: u64) -> MessageState {
    m.conversation(peer.into())
        .unwrap()
        .into_iter()
        .find(|c| c.id == id)
        .unwrap()
        .state
}

#[test]
fn a_message_goes_sent_then_delivered_then_read() {
    let (alice, bob) = paired();
    connect(&alice, &bob);

    let id = alice.send_text("bob".into(), "hello".into()).unwrap();
    assert_eq!(state_of(&alice, "bob", id), MessageState::Sent);

    // Bob receives it and acknowledges automatically.
    pump(&bob, "alice", || {
        bob.history("alice".into()).unwrap().len() == 1
    });
    let on_bob = bob.conversation("alice".into()).unwrap();
    assert_eq!(on_bob[0].text, "hello");
    assert!(!on_bob[0].outgoing);
    assert_eq!(on_bob[0].state, MessageState::Received);
    assert_eq!(bob.unread_count("alice".into()).unwrap(), 1);

    pump(&alice, "bob", || {
        state_of(&alice, "bob", id) == MessageState::Delivered
    });

    // Opening the chat on Bob's phone sends the read receipt.
    assert_eq!(bob.mark_read("alice".into(), true).unwrap(), 1);
    assert_eq!(bob.unread_count("alice".into()).unwrap(), 0);
    pump(&alice, "bob", || {
        state_of(&alice, "bob", id) == MessageState::Read
    });
}

#[test]
fn read_receipts_can_be_withheld() {
    let (alice, bob) = paired();
    connect(&alice, &bob);
    let id = alice.send_text("bob".into(), "hello".into()).unwrap();
    pump(&bob, "alice", || {
        bob.history("alice".into()).unwrap().len() == 1
    });
    pump(&alice, "bob", || {
        state_of(&alice, "bob", id) == MessageState::Delivered
    });

    assert_eq!(bob.mark_read("alice".into(), false).unwrap(), 1);
    // Nothing more arrives: the poll comes back empty and the message stays delivered.
    assert!(!alice.receive_from_peer("bob".into()).unwrap());
    assert_eq!(state_of(&alice, "bob", id), MessageState::Delivered);
}

#[test]
fn a_message_sent_while_offline_is_queued_and_goes_out_on_reconnect() {
    let (alice, bob) = paired();
    let first = alice.send_text("bob".into(), "one".into()).unwrap();
    let second = alice.send_text("bob".into(), "two".into()).unwrap();
    assert_eq!(state_of(&alice, "bob", first), MessageState::Pending);
    assert_eq!(state_of(&alice, "bob", second), MessageState::Pending);
    assert_eq!(alice.flush_pending("bob".into()).unwrap(), 0);

    connect(&alice, &bob);
    assert_eq!(alice.flush_pending("bob".into()).unwrap(), 2);
    assert_eq!(state_of(&alice, "bob", first), MessageState::Sent);
    // Flushing again sends nothing twice.
    assert_eq!(alice.flush_pending("bob".into()).unwrap(), 0);

    pump(&bob, "alice", || {
        bob.history("alice".into()).unwrap().len() == 2
    });
    assert_eq!(bob.history("alice".into()).unwrap(), vec!["one", "two"]);
}

#[test]
fn a_read_receipt_owed_while_offline_goes_out_with_the_next_flush() {
    let (alice, bob) = paired();
    connect(&alice, &bob);
    // Alice sends one message that Bob receives.
    alice.send_text("bob".into(), "hi".into()).unwrap();
    pump(&bob, "alice", || {
        bob.history("alice".into()).unwrap().len() == 1
    });

    // Alice's link drops before Bob opens the chat.
    alice.wipe_all().unwrap();
    assert_eq!(bob.mark_read("alice".into(), true).unwrap(), 1);
    assert!(bob.receive_from_peer("alice".into()).is_err());
    assert_eq!(bob.flush_pending("alice".into()).unwrap(), 0);

    // Bob reconnects (he now dials; roles do not matter on loopback) and the receipt follows.
    let addr = free_port();
    let alice_side = Arc::clone(&alice);
    let listen_addr = addr.clone();
    let listener = std::thread::spawn(move || {
        alice_side
            .listen_for_peer("bob".into(), listen_addr, 10)
            .unwrap();
    });
    for _ in 0..100 {
        if bob.connect_peer("alice".into(), addr.clone()).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    listener.join().unwrap();
    bob.flush_pending("alice".into()).unwrap();
    // The receipt reaches Alice. She wiped her history, so there is no message left to mark
    // and it is ignored; what matters here is that the owed receipt was sent at all.
    assert!(alice.receive_from_peer("bob".into()).unwrap());
    assert!(alice.conversation("bob".into()).unwrap().is_empty());
}

#[test]
fn send_text_refuses_an_unknown_contact() {
    let alice = Messenger::new();
    assert_eq!(
        alice.send_text("nobody".into(), "x".into()),
        Err(FacadeError::NotPinned)
    );
}

#[test]
fn presence_follows_the_link() {
    let (alice, bob) = paired();
    let before = alice.presence("bob".into()).unwrap();
    assert!(!before.online);
    assert_eq!(before.last_seen_ms, None);

    connect(&alice, &bob);
    let online = alice.presence("bob".into()).unwrap();
    assert!(online.online);
    assert!(online.last_seen_ms.is_some());

    // Bob goes away; Alice learns it from the failed read, and keeps the time.
    bob.wipe_all().unwrap();
    assert!(alice.receive_from_peer("bob".into()).is_err());
    let after = alice.presence("bob".into()).unwrap();
    assert!(!after.online);
    assert!(after.last_seen_ms.is_some());
    assert!(alice.linked_peers().unwrap().is_empty());
    assert_eq!(
        alice.receive_from_peer("bob".into()),
        Err(FacadeError::NoLink)
    );
}

#[test]
fn a_failed_send_leaves_the_message_queued() {
    let (alice, bob) = paired();
    connect(&alice, &bob);
    bob.wipe_all().unwrap(); // Bob's socket closes
                             // The first write after a peer close may still succeed in the kernel; keep
                             // sending until the failure shows, then check nothing was lost from the queue.
    let mut ids = Vec::new();
    for i in 0..50 {
        ids.push(alice.send_text("bob".into(), format!("m{i}")).unwrap());
        if alice.linked_peers().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        alice.linked_peers().unwrap().is_empty(),
        "the dead link was never noticed"
    );
    let last = *ids.last().unwrap();
    assert_eq!(state_of(&alice, "bob", last), MessageState::Pending);
}
