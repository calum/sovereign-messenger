//! Handshake and ratchet messages carried over a real TCP transport on loopback.
//! The responder runs on its own thread, as a second phone would.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use rust_core::double_ratchet::{DoubleRatchet, Role};
use rust_core::handshake::{self, Identity};
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
    let (alice, alice_pub) = Identity::generate();

    let responder = std::thread::spawn(move || {
        // The responder speaks first: its challenge must arrive before the handshake.
        let challenge = handshake::new_challenge();
        wire::send_challenge(&server, &challenge.offer()).unwrap();
        let init = wire::receive_handshake(&server).unwrap();
        let root = handshake::respond(&me, &alice_pub.x25519, &init, &challenge).unwrap();
        let mut session = DoubleRatchet::new(
            &root,
            Role::Responder,
            RESPONDER_TO_INITIATOR,
            INITIATOR_TO_RESPONDER,
        );
        let heard = wire::receive_message(&server, &mut session).unwrap();
        assert_eq!(heard, b"hello bob".to_vec());
        wire::send_message(&server, &mut session, b"hi alice").unwrap();
        server
    });

    let challenge = wire::receive_challenge(&client).unwrap();
    let (init, root) = handshake::initiate(&alice, &public, &challenge).unwrap();
    wire::send_handshake(&client, &init).unwrap();
    let mut session = DoubleRatchet::new(
        &root,
        Role::Initiator,
        INITIATOR_TO_RESPONDER,
        RESPONDER_TO_INITIATOR,
    );
    wire::send_message(&client, &mut session, b"hello bob").unwrap();
    assert_eq!(
        wire::receive_message(&client, &mut session).unwrap(),
        b"hi alice".to_vec()
    );
    let _server = responder.join().unwrap();
}

#[test]
fn tampered_frame_is_rejected_after_crossing_the_socket() {
    let (client, server) = pair();
    let root = Key32([5u8; 32]);
    let mut send = DoubleRatchet::new(
        &root,
        Role::Initiator,
        INITIATOR_TO_RESPONDER,
        RESPONDER_TO_INITIATOR,
    );
    let mut recv = DoubleRatchet::new(
        &root,
        Role::Responder,
        RESPONDER_TO_INITIATOR,
        INITIATOR_TO_RESPONDER,
    );

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
    let mut send = DoubleRatchet::new(
        &root,
        Role::Initiator,
        INITIATOR_TO_RESPONDER,
        RESPONDER_TO_INITIATOR,
    );
    let mut recv = DoubleRatchet::new(
        &root,
        Role::Responder,
        RESPONDER_TO_INITIATOR,
        INITIATOR_TO_RESPONDER,
    );
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

#[test]
fn ratchet_steps_both_ways_for_several_rounds_over_tcp() {
    let (client, server) = pair();
    let root = Key32([6u8; 32]);
    let responder_root = Key32(root.0);

    let responder = std::thread::spawn(move || {
        let mut session = DoubleRatchet::new(
            &responder_root,
            Role::Responder,
            RESPONDER_TO_INITIATOR,
            INITIATOR_TO_RESPONDER,
        );
        for round in 0..5 {
            let heard = wire::receive_message(&server, &mut session).unwrap();
            assert_eq!(heard, format!("a{round}").into_bytes());
            wire::send_message(&server, &mut session, format!("b{round}").as_bytes()).unwrap();
        }
        server
    });

    let mut session = DoubleRatchet::new(
        &root,
        Role::Initiator,
        INITIATOR_TO_RESPONDER,
        RESPONDER_TO_INITIATOR,
    );
    for round in 0..5 {
        wire::send_message(&client, &mut session, format!("a{round}").as_bytes()).unwrap();
        assert_eq!(
            wire::receive_message(&client, &mut session).unwrap(),
            format!("b{round}").into_bytes()
        );
    }
    let _server = responder.join().unwrap();
}
