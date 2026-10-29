//! Live Tor tests. They reach the real Tor network, take minutes, and are ignored by
//! default. Run them on a machine with unfiltered internet:
//!
//!     cargo test --features tor --test tor_live -- --ignored --nocapture --test-threads=1
//!
//! Each prints its timings, which PLAN.md asks the owner to record.
#![cfg(feature = "tor")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use rust_core::ffi::{Messenger, TorState};

const READY_TIMEOUT: Duration = Duration::from_secs(20 * 60);

fn state_dir(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("sovereign-live-{tag}-{}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Polls until Tor is ready, printing each state change with the elapsed time.
fn wait_ready(who: &str, m: &Messenger, since: Instant) -> Duration {
    let mut last = None;
    loop {
        let status = m.tor_status().unwrap();
        let line = format!("{:?} {}%", status.state, status.percent);
        if last.as_deref() != Some(line.as_str()) {
            println!("[{who}] +{:>6.1}s {line}", since.elapsed().as_secs_f64());
            last = Some(line);
        }
        match status.state {
            TorState::Ready => return since.elapsed(),
            TorState::Failed => panic!("{who}: Tor failed after {:?}", since.elapsed()),
            _ => {}
        }
        assert!(since.elapsed() < READY_TIMEOUT, "{who}: not ready in time");
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Pins each side to the other. `b_on_a` is the name `a` uses for `b`, and `a_on_b` the name
/// `b` uses for `a`. (An earlier version of this helper swapped them, so Alice had no
/// contact called "bob" and the first live run failed with `NotPinned`.)
fn pair(a: &Messenger, b_on_a: &str, b: &Messenger, a_on_b: &str) {
    a.scan_pairing(b_on_a.into(), b.own_pairing_payload(String::new()).unwrap())
        .unwrap();
    b.scan_pairing(a_on_b.into(), a.own_pairing_payload(String::new()).unwrap())
        .unwrap();
}

/// Needs no network: guards the helper above, which the live test depends on.
#[test]
fn pair_pins_each_side_under_the_name_the_other_is_dialled_by() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    pair(&alice, "bob", &bob, "alice");
    assert_eq!(alice.pinned_peers().unwrap(), vec!["bob".to_string()]);
    assert_eq!(bob.pinned_peers().unwrap(), vec!["alice".to_string()]);
    assert_eq!(
        alice.pinned_onion_address("bob".into()).unwrap(),
        Some(bob.own_onion_address().unwrap())
    );
}

#[test]
#[ignore = "reaches the Tor network"]
fn two_identities_message_each_other_over_tor() {
    let alice = Messenger::new();
    let bob = Messenger::new();
    pair(&alice, "bob", &bob, "alice");
    println!("alice onion: {}", alice.own_onion_address().unwrap());
    println!("bob   onion: {}", bob.own_onion_address().unwrap());

    let began = Instant::now();
    alice.tor_start(state_dir("alice")).unwrap();
    bob.tor_start(state_dir("bob")).unwrap();
    let a_ready = wait_ready("alice", &alice, began);
    let b_ready = wait_ready("bob", &bob, began);
    println!("RESULT cold start: alice ready {a_ready:?}, bob ready {b_ready:?}");

    // Bob waits for a call; Alice dials Bob's onion address pinned from his QR code.
    let bob_side: Arc<Messenger> = Arc::clone(&bob);
    let listener = std::thread::spawn(move || bob_side.accept_peer_tor(600));
    let dialled = Instant::now();
    alice.connect_peer_tor("bob".into()).unwrap();
    println!(
        "RESULT connect + handshake over Tor: {:?}",
        dialled.elapsed()
    );
    assert_eq!(listener.join().unwrap().unwrap(), "alice");

    alice
        .send_over_transport("bob".into(), "hello over tor".into())
        .unwrap();
    let sent = Instant::now();
    while !bob.receive_from_peer("alice".into()).unwrap() {
        assert!(
            sent.elapsed() < Duration::from_secs(120),
            "message never arrived"
        );
    }
    println!("RESULT first message latency: {:?}", sent.elapsed());
    assert_eq!(bob.history("alice".into()).unwrap(), vec!["hello over tor"]);

    bob.send_over_transport("alice".into(), "hello back".into())
        .unwrap();
    let sent = Instant::now();
    // Bob's delivery notice for the first message arrives before his reply.
    while alice.history("bob".into()).unwrap().len() < 2 {
        alice.receive_from_peer("bob".into()).unwrap();
        assert!(
            sent.elapsed() < Duration::from_secs(120),
            "reply never arrived"
        );
    }
    assert_eq!(
        alice.history("bob".into()).unwrap(),
        vec!["hello over tor", "hello back"]
    );
    alice.tor_stop().unwrap();
    bob.tor_stop().unwrap();
}

#[test]
#[ignore = "reaches the Tor network"]
fn a_warm_restart_with_saved_state_is_measured() {
    let m = Messenger::new();
    let dir = state_dir("warm");

    let cold = Instant::now();
    m.tor_start(dir.clone()).unwrap();
    let cold_ready = wait_ready("cold", &m, cold);
    m.tor_stop().unwrap();
    println!("RESULT cold start to ready: {cold_ready:?}");

    // Same state directory, same identity: Tor's cached directory and guards are reused.
    let warm = Instant::now();
    m.tor_start(dir).unwrap();
    let warm_ready = wait_ready("warm", &m, warm);
    println!("RESULT warm start to ready: {warm_ready:?} (cold was {cold_ready:?})");
    m.tor_stop().unwrap();
}

#[test]
#[ignore = "reaches the Tor network"]
fn a_restored_identity_comes_up_under_the_same_onion_address() {
    // The address is stable across restarts because its seed is in the vault.
    let first = Messenger::create_persistent();
    let address = first.own_onion_address().unwrap();
    let restored =
        Messenger::restore(first.data_key().unwrap(), first.export_vault().unwrap()).unwrap();
    assert_eq!(restored.own_onion_address().unwrap(), address);
    let began = Instant::now();
    restored.tor_start(state_dir("restored")).unwrap();
    wait_ready("restored", &restored, began);
    println!("RESULT service is up under {address}");
    restored.tor_stop().unwrap();
}
