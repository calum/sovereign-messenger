//! Framing tests for the TCP transport over loopback. Two in-process parties
//! stand in for two phones. Malformed frames are written by hand so the
//! failure paths reach the real reader.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use rust_core::transport::{TcpTransport, Transport, TransportError, MAX_FRAME_LEN};

const WAIT: Duration = Duration::from_secs(5);

fn pair() -> (TcpTransport, TcpTransport) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let client = std::thread::spawn(move || TcpTransport::connect(&addr, WAIT).unwrap());
    let server = TcpTransport::accept(&listener, WAIT).unwrap();
    (client.join().unwrap(), server)
}

/// A raw socket that writes whatever bytes the test chooses.
fn raw_pair() -> (TcpStream, TcpTransport) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let raw = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
    let server = TcpTransport::accept(&listener, WAIT).unwrap();
    (raw.join().unwrap(), server)
}

#[test]
fn frames_arrive_intact_in_both_directions() {
    let (client, server) = pair();
    client.send(b"ping").unwrap();
    assert_eq!(server.receive().unwrap(), Some(b"ping".to_vec()));
    server.send(b"pong").unwrap();
    assert_eq!(client.receive().unwrap(), Some(b"pong".to_vec()));
}

#[test]
fn frame_at_the_size_cap_is_accepted() {
    let (client, server) = pair();
    let big = vec![7u8; MAX_FRAME_LEN];
    client.send(&big).unwrap();
    assert_eq!(server.receive().unwrap(), Some(big));
}

#[test]
fn oversize_frame_refused_before_anything_is_written() {
    let (client, server) = pair();
    let too_big = vec![0u8; MAX_FRAME_LEN + 1];
    assert_eq!(client.send(&too_big), Err(TransportError::Oversize));
    // If anything had been written, this frame would arrive garbled or late.
    client.send(b"after").unwrap();
    assert_eq!(server.receive().unwrap(), Some(b"after".to_vec()));
}

#[test]
fn oversize_length_prefix_refused_without_reading_the_body() {
    let (mut raw, server) = raw_pair();
    raw.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert_eq!(server.receive(), Err(TransportError::Oversize));
}

#[test]
fn peer_closed_before_a_frame_is_reported() {
    let (client, server) = pair();
    drop(client);
    assert_eq!(server.receive(), Err(TransportError::Closed));
}

#[test]
fn length_prefix_longer_than_the_data_is_reported_as_truncated() {
    let (mut raw, server) = raw_pair();
    raw.write_all(&100u32.to_be_bytes()).unwrap();
    raw.write_all(&[1u8; 10]).unwrap();
    drop(raw);
    assert_eq!(server.receive(), Err(TransportError::Truncated));
}

#[test]
fn idle_connection_returns_none_instead_of_blocking() {
    let (_client, server) = pair();
    assert_eq!(server.receive(), Ok(None));
}

#[test]
fn accept_gives_up_after_its_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let result = TcpTransport::accept(&listener, Duration::from_millis(100));
    assert!(matches!(result, Err(TransportError::Io)));
}
