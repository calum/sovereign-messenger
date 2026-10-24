//! A send that fails at the transport must not advance the send counter. If it
//! did, the receiver would wait forever for the counter the sender skipped, and
//! every later frame would be refused. The link here is an in-memory queue that
//! can be told to fail its next sends.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rust_core::double_ratchet::DoubleRatchet;
use rust_core::secret::Key32;
use rust_core::transport::{Transport, TransportError};
use rust_core::wire::{self, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR};
use rust_core::CoreError;

struct Pipe {
    queue: Mutex<VecDeque<Vec<u8>>>,
    fail_sends: AtomicUsize,
}

impl Pipe {
    fn failing(next_sends: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            fail_sends: AtomicUsize::new(next_sends),
        }
    }

    fn queued(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

impl Transport for Pipe {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        if self.fail_sends.load(Ordering::SeqCst) > 0 {
            self.fail_sends.fetch_sub(1, Ordering::SeqCst);
            return Err(TransportError::Io);
        }
        self.queue.lock().unwrap().push_back(frame.to_vec());
        Ok(())
    }

    fn receive(&self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(self.queue.lock().unwrap().pop_front())
    }
}

#[test]
fn failed_write_does_not_advance_the_counter() {
    let root = Key32([7u8; 32]);
    let mut send = DoubleRatchet::new(&root, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR);
    let mut recv = DoubleRatchet::new(&root, RESPONDER_TO_INITIATOR, INITIATOR_TO_RESPONDER);
    let link = Pipe::failing(1);

    assert_eq!(
        wire::send_message(&link, &mut send, b"never arrives"),
        Err(CoreError::Network)
    );
    assert_eq!(link.queued(), 0);

    wire::send_message(&link, &mut send, b"arrives").unwrap();
    assert_eq!(
        wire::receive_message(&link, &mut recv).unwrap(),
        b"arrives".to_vec()
    );
}

#[test]
fn failed_write_in_the_middle_of_a_conversation_keeps_the_chain_in_step() {
    let root = Key32([7u8; 32]);
    let mut send = DoubleRatchet::new(&root, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR);
    let mut recv = DoubleRatchet::new(&root, RESPONDER_TO_INITIATOR, INITIATOR_TO_RESPONDER);
    let link = Pipe::failing(0);

    wire::send_message(&link, &mut send, b"one").unwrap();
    link.fail_sends.store(2, Ordering::SeqCst);
    assert!(wire::send_message(&link, &mut send, b"two").is_err());
    assert!(wire::send_message(&link, &mut send, b"two again").is_err());
    wire::send_message(&link, &mut send, b"three").unwrap();

    assert_eq!(wire::receive_message(&link, &mut recv).unwrap(), b"one");
    assert_eq!(wire::receive_message(&link, &mut recv).unwrap(), b"three");
}
