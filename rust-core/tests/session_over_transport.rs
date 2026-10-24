//! Handshake and ratchet messages carried over a real TCP transport on loopback.
//! The responder runs on its own thread, as a second phone would.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use rust_core::handshake::{self, Identity};
use rust_core::ratchet::Chain;
use rust_core::secret::Key32;
use rust_core::transport::{TcpTransport, Transport};
use rust_core::wire::{self, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR};
use rust_core::CoreError;

const WAIT: Duration = Duration::from_secs(5);

fn pair() -> (TcpTransport, TcpTransport) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let client = std::thread::spawn(move || TcpTransport::connect(&addr, WAIT).unwrap());
    let server = TcpTransport::accept(&listener, WAIT).unwrap();
    (client.join().unwrap(), server)
}

#[test]
fn handshake_then_ratchet_both_directions_over_tcp() {
    let (client, server) = pair();
    let (me, public) = Identity::generate();

    let responder = std::thread::spawn(move || {
        let init = wire::receive_handshake(&server).unwrap();
        let root = handshake::respond(&me, &init).unwrap();
        let mut recv = Chain::new(&root, INITIATOR_TO_RESPONDER);
        let mut send = Chain::new(&root, RESPONDER_TO_INITIATOR);
        let heard = wire::receive_message(&server, &mut recv).unwrap();
        assert_eq!(heard, b"hello bob".to_vec());
        wire::send_message(&server, &mut send, b"hi alice").unwrap();
        server
    });

    let (init, root) = handshake::initiate(&public).unwrap();
    wire::send_handshake(&client, &init).unwrap();
    let mut send = Chain::new(&root, INITIATOR_TO_RESPONDER);
    let mut recv = Chain::new(&root, RESPONDER_TO_INITIATOR);
    wire::send_message(&client, &mut send, b"hello bob").unwrap();
    assert_eq!(
        wire::receive_message(&client, &mut recv).unwrap(),
        b"hi alice".to_vec()
    );
    let _server = responder.join().unwrap();
}

#[test]
fn tampered_frame_is_rejected_after_crossing_the_socket() {
    let (client, server) = pair();
    let root = Key32([5u8; 32]);
    let mut send = Chain::new(&root, INITIATOR_TO_RESPONDER);
    let mut recv = Chain::new(&root, INITIATOR_TO_RESPONDER);

    let sealed = send.seal(b"attack at dawn").unwrap();
    let mut frame = wire::encode_message(&sealed);
    let last = frame.len() - 1;
    frame[last] ^= 0x01; // flip one bit of the ciphertext in transit
    client.send(&frame).unwrap();

    assert_eq!(
        wire::receive_message(&server, &mut recv),
        Err(CoreError::Auth)
    );
}

#[test]
fn shortened_length_prefix_fails_authentication() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let raw = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
    let server = TcpTransport::accept(&listener, WAIT).unwrap();
    let mut raw = raw.join().unwrap();

    let root = Key32([5u8; 32]);
    let mut send = Chain::new(&root, INITIATOR_TO_RESPONDER);
    let mut recv = Chain::new(&root, INITIATOR_TO_RESPONDER);
    let frame = wire::encode_message(&send.seal(b"short").unwrap());

    // The prefix claims one byte less than the frame. The reader takes a
    // truncated body, which must not authenticate.
    raw.write_all(&((frame.len() - 1) as u32).to_be_bytes())
        .unwrap();
    raw.write_all(&frame).unwrap();

    assert_eq!(
        wire::receive_message(&server, &mut recv),
        Err(CoreError::Auth)
    );
}
