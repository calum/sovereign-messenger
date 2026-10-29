//! A session whose frames keep failing to open is declared dead, so the app redials and
//! runs a new handshake; a lone bad frame never kills a session.
//!
//! Alice reaches Bob through a relay on loopback that can flip a byte in the next N frames
//! she sends, standing in for an on-path attacker or a desynchronised ratchet.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rust_core::ffi::{FacadeError, Messenger};

fn free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    addr
}

/// Serves one connection: Alice -> relay -> Bob. While `corrupt` is above zero each
/// frame from Alice has its last byte flipped and the counter drops by one.
fn relay_once(bob_addr: String, corrupt: Arc<AtomicU32>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut from_alice, _) = listener.accept().unwrap();
        let mut to_bob = loop {
            match TcpStream::connect(&bob_addr) {
                Ok(s) => break s,
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let mut bob_reader = to_bob.try_clone().unwrap();
        let mut alice_writer = from_alice.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = bob_reader.read(&mut buf) {
                if n == 0 || alice_writer.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        });
        loop {
            let mut len = [0u8; 4];
            if from_alice.read_exact(&mut len).is_err() {
                break;
            }
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            if from_alice.read_exact(&mut body).is_err() {
                break;
            }
            let flip = corrupt
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |c| c.checked_sub(1))
                .is_ok();
            if flip {
                *body.last_mut().unwrap() ^= 0x55;
            }
            if to_bob.write_all(&len).is_err() || to_bob.write_all(&body).is_err() {
                break;
            }
        }
    });
    addr
}

fn pinned_pair() -> (Arc<Messenger>, Arc<Messenger>) {
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

/// Bob listens on `bob_addr`, Alice connects to `via`; returns once both sides are linked.
fn link(alice: &Arc<Messenger>, bob: &Arc<Messenger>, bob_addr: &str, via: &str) {
    let b = Arc::clone(bob);
    let a = bob_addr.to_string();
    let listener = std::thread::spawn(move || b.listen_for_peer("alice".into(), a, 10).unwrap());
    let mut last = None;
    for _ in 0..100 {
        match alice.connect_peer("bob".into(), via.to_string()) {
            Ok(()) => {
                listener.join().unwrap();
                return;
            }
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    panic!("connect never succeeded: {last:?}");
}

/// One receive that is not an idle poll.
fn receive(m: &Messenger) -> Result<(), FacadeError> {
    for _ in 0..100 {
        if m.receive_from_peer("alice".into())? {
            return Ok(());
        }
    }
    panic!("nothing arrived");
}

fn send_corrupted(alice: &Messenger, bob: &Messenger, corrupt: &AtomicU32, n: u32) {
    for i in 0..n {
        corrupt.store(1, Ordering::SeqCst);
        alice
            .send_over_transport("bob".into(), format!("bad {i}"))
            .unwrap();
        assert_eq!(receive(bob), Err(FacadeError::AuthFailed));
    }
}

#[test]
fn consecutive_bad_frames_drop_the_session_from_linked_peers() {
    let (alice, bob) = pinned_pair();
    let corrupt = Arc::new(AtomicU32::new(0));
    let bob_addr = free_port();
    let via = relay_once(bob_addr.clone(), Arc::clone(&corrupt));
    link(&alice, &bob, &bob_addr, &via);
    assert_eq!(bob.linked_peers().unwrap(), vec!["alice"]);

    send_corrupted(&alice, &bob, &corrupt, 4);
    assert_eq!(
        bob.linked_peers().unwrap(),
        vec!["alice"],
        "4 is below the threshold"
    );
    send_corrupted(&alice, &bob, &corrupt, 1);
    assert!(bob.linked_peers().unwrap().is_empty());
    assert_eq!(
        bob.receive_from_peer("alice".into()),
        Err(FacadeError::NoLink)
    );
}

#[test]
fn a_good_frame_resets_the_count() {
    let (alice, bob) = pinned_pair();
    let corrupt = Arc::new(AtomicU32::new(0));
    let bob_addr = free_port();
    let via = relay_once(bob_addr.clone(), Arc::clone(&corrupt));
    link(&alice, &bob, &bob_addr, &via);

    for round in 0..3 {
        send_corrupted(&alice, &bob, &corrupt, 4);
        alice
            .send_over_transport("bob".into(), format!("good {round}"))
            .unwrap();
        receive(&bob).unwrap();
        assert_eq!(bob.linked_peers().unwrap(), vec!["alice"]);
    }
    assert_eq!(bob.history("alice".into()).unwrap().len(), 3);
}

#[test]
fn a_new_handshake_after_the_session_died_restores_messages() {
    let (alice, bob) = pinned_pair();
    let corrupt = Arc::new(AtomicU32::new(0));
    let bob_addr = free_port();
    let via = relay_once(bob_addr.clone(), Arc::clone(&corrupt));
    link(&alice, &bob, &bob_addr, &via);
    send_corrupted(&alice, &bob, &corrupt, 5);
    assert!(bob.linked_peers().unwrap().is_empty());

    // The app's redial: a fresh connection and handshake replace the dead session.
    let bob_addr2 = free_port();
    link(&alice, &bob, &bob_addr2, &bob_addr2);
    assert_eq!(bob.linked_peers().unwrap(), vec!["alice"]);
    alice
        .send_over_transport("bob".into(), "after redial".into())
        .unwrap();
    receive(&bob).unwrap();
    assert_eq!(bob.history("alice".into()).unwrap(), vec!["after redial"]);
}
