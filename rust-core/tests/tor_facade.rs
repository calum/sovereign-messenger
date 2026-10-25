//! The Tor surface of the facade. These tests need no network. Live tests that really
//! reach the Tor network are in `tor_live.rs` and are ignored by default.

use rust_core::ffi::{FacadeError, Messenger, TorState};

fn paired_with(label: &str) -> (std::sync::Arc<Messenger>, std::sync::Arc<Messenger>) {
    let me = Messenger::new();
    let them = Messenger::new();
    me.scan_pairing(
        label.into(),
        them.own_pairing_payload(String::new()).unwrap(),
    )
    .unwrap();
    (me, them)
}

#[test]
fn connecting_to_an_unpinned_contact_is_refused_before_anything_else() {
    let m = Messenger::new();
    assert_eq!(
        m.connect_peer_tor("nobody".into()),
        Err(FacadeError::NotPinned)
    );
}

#[test]
fn accepting_or_connecting_before_tor_starts_says_tor_is_not_running() {
    let (me, _them) = paired_with("bob");
    assert_eq!(
        me.connect_peer_tor("bob".into()),
        Err(FacadeError::TorUnavailable)
    );
    assert_eq!(me.accept_peer_tor(1), Err(FacadeError::TorUnavailable));
}

#[cfg(not(feature = "tor"))]
mod without_the_feature {
    use super::*;

    #[test]
    fn a_build_without_tor_reports_not_built_and_refuses_to_start() {
        let m = Messenger::new();
        let status = m.tor_status().unwrap();
        assert_eq!(status.state, TorState::NotBuilt);
        assert_eq!(status.percent, 0);
        assert_eq!(
            m.tor_start("/nonexistent".into()),
            Err(FacadeError::TorUnavailable)
        );
        // Stopping something that never started is harmless.
        m.tor_stop().unwrap();
    }
}

#[cfg(feature = "tor")]
mod with_the_feature {
    use super::*;
    use std::time::{Duration, Instant};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sovereign-facade-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_new_messenger_has_tor_stopped() {
        let m = Messenger::new();
        assert_eq!(m.tor_status().unwrap().state, TorState::Stopped);
    }

    #[test]
    fn starting_moves_off_stopped_and_stopping_returns_to_stopped() {
        let m = Messenger::new();
        let dir = temp_dir("start");
        m.tor_start(dir.to_string_lossy().into_owned()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut state = m.tor_status().unwrap().state;
        while state == TorState::Stopped || state == TorState::Starting {
            assert!(Instant::now() < deadline, "never left {state:?}");
            std::thread::sleep(Duration::from_millis(50));
            state = m.tor_status().unwrap().state;
        }
        // Offline or filtered, it can be bootstrapping or already failed, but never ready.
        assert_ne!(state, TorState::Ready);
        m.tor_stop().unwrap();
        assert_eq!(m.tor_status().unwrap().state, TorState::Stopped);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn starting_twice_keeps_one_node() {
        let m = Messenger::new();
        let dir = temp_dir("twice");
        m.tor_start(dir.to_string_lossy().into_owned()).unwrap();
        m.tor_start(dir.to_string_lossy().into_owned()).unwrap();
        m.tor_stop().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_directory_that_cannot_be_created_fails_cleanly() {
        let m = Messenger::new();
        // A path below a regular file can never be a directory.
        let file = temp_dir("afile");
        std::fs::write(&file, b"x").unwrap();
        let bad = file.join("below");
        assert_eq!(
            m.tor_start(bad.to_string_lossy().into_owned()),
            Err(FacadeError::Network)
        );
        assert_eq!(m.tor_status().unwrap().state, TorState::Stopped);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_node_that_is_not_ready_refuses_to_connect_and_accept_times_out() {
        let (me, _them) = paired_with("bob");
        let dir = temp_dir("notready");
        me.tor_start(dir.to_string_lossy().into_owned()).unwrap();
        assert_eq!(me.accept_peer_tor(1), Err(FacadeError::Network));
        assert_eq!(me.connect_peer_tor("bob".into()), Err(FacadeError::Network));
        me.tor_stop().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn exactly_one_side_of_a_pair_dials() {
    // Two phones that both dial would each make a session and the second would replace
    // the first. The rule is fixed by the keys, so both phones reach the same answer.
    for _ in 0..20 {
        let a = Messenger::new();
        let b = Messenger::new();
        a.scan_pairing("b".into(), b.own_pairing_payload(String::new()).unwrap())
            .unwrap();
        b.scan_pairing("a".into(), a.own_pairing_payload(String::new()).unwrap())
            .unwrap();
        let a_role = a.tor_role("b".into()).unwrap();
        let b_role = b.tor_role("a".into()).unwrap();
        assert_ne!(a_role, b_role, "both sides chose {a_role:?}");
    }
}

#[test]
fn the_role_is_stable_for_the_same_pair() {
    let (me, them) = paired_with("them");
    let first = me.tor_role("them".into()).unwrap();
    assert_eq!(me.tor_role("them".into()).unwrap(), first);
    let _ = them;
}

#[test]
fn the_role_for_an_unpinned_contact_is_an_error() {
    assert_eq!(
        Messenger::new().tor_role("nobody".into()),
        Err(FacadeError::NotPinned)
    );
}
