//! How long the handshake helpers wait for a frame is decided by the link, so a slow
//! carrier (an onion circuit) can be given more time than a LAN socket without the
//! helpers changing.

use std::time::{Duration, Instant};

use rust_core::transport::{Transport, TransportError};
use rust_core::wire;

/// A link that never delivers anything and says how long a handshake may wait on it.
struct Silent(Option<Duration>);

impl Transport for Silent {
    fn send(&self, _frame: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn receive(&self) -> Result<Option<Vec<u8>>, TransportError> {
        std::thread::sleep(Duration::from_millis(20));
        Ok(None)
    }

    fn handshake_deadline(&self) -> Duration {
        self.0.unwrap_or_else(|| DefaultOnly.handshake_deadline())
    }
}

/// Uses the trait's default, so a test can read it.
struct DefaultOnly;

impl Transport for DefaultOnly {
    fn send(&self, _frame: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn receive(&self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(None)
    }
}

#[test]
fn the_default_handshake_deadline_is_ten_seconds() {
    assert_eq!(DefaultOnly.handshake_deadline(), Duration::from_secs(10));
}

#[test]
fn the_helpers_give_up_when_the_links_own_deadline_passes() {
    let link = Silent(Some(Duration::from_millis(300)));
    let start = Instant::now();
    assert!(wire::receive_challenge(&link).is_err());
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(250),
        "gave up too early: {took:?}"
    );
    assert!(
        took < Duration::from_secs(5),
        "ignored the link's deadline: {took:?}"
    );
}
