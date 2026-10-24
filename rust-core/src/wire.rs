//! Frame layout for handshake and ratchet messages, and helpers that move them
//! over a `Transport`. Each frame starts with a one-byte tag, so a handshake
//! frame can never be parsed as a chat message.
//!
//! Security property: nothing here decides authenticity. A malformed frame is
//! refused by length or tag; a forged or altered chat message is refused by the
//! ratchet's AEAD. The handshake frame carries public values only.

use std::time::{Duration, Instant};

use crate::error::CoreError;
use crate::handshake::HandshakeInit;
use crate::ratchet::{Chain, Message};
use crate::transport::{Transport, TransportError};

/// Direction labels. Both peers derive the same two chains from the root; the
/// initiator sends on `i->r` and the responder on `r->i`, so a message cannot
/// be reflected back to its sender.
pub const INITIATOR_TO_RESPONDER: &[u8] = b"i->r";
pub const RESPONDER_TO_INITIATOR: &[u8] = b"r->i";

pub const TAG_HANDSHAKE: u8 = 0x01;
pub const TAG_MESSAGE: u8 = 0x02;

/// ML-KEM-768 ciphertext length in bytes (FIPS 203). Checked in tests against the library.
pub const MLKEM768_CT_LEN: usize = 1088;
const EPHEMERAL_LEN: usize = 32;
const STATIC_LEN: usize = 32;
const HANDSHAKE_LEN: usize = 1 + EPHEMERAL_LEN + STATIC_LEN + MLKEM768_CT_LEN;
const MESSAGE_HEADER_LEN: usize = 1 + 8;
/// A ChaCha20-Poly1305 ciphertext is at least the 16-byte tag.
const MESSAGE_MIN_LEN: usize = MESSAGE_HEADER_LEN + 16;

/// How long a receive helper waits for a frame before giving up.
const RECEIVE_DEADLINE: Duration = Duration::from_secs(10);

pub fn encode_handshake(init: &HandshakeInit) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_LEN);
    out.push(TAG_HANDSHAKE);
    out.extend_from_slice(&init.ephemeral_x25519);
    out.extend_from_slice(&init.initiator_x25519);
    out.extend_from_slice(&init.mlkem_ct);
    out
}

pub fn decode_handshake(frame: &[u8]) -> Result<HandshakeInit, CoreError> {
    if frame.len() != HANDSHAKE_LEN || frame[0] != TAG_HANDSHAKE {
        return Err(CoreError::Malformed);
    }
    let static_at = 1 + EPHEMERAL_LEN;
    let mut ephemeral_x25519 = [0u8; EPHEMERAL_LEN];
    ephemeral_x25519.copy_from_slice(&frame[1..static_at]);
    let mut initiator_x25519 = [0u8; STATIC_LEN];
    initiator_x25519.copy_from_slice(&frame[static_at..static_at + STATIC_LEN]);
    Ok(HandshakeInit {
        ephemeral_x25519,
        initiator_x25519,
        mlkem_ct: frame[static_at + STATIC_LEN..].to_vec(),
    })
}

pub fn encode_message(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(MESSAGE_HEADER_LEN + msg.ciphertext.len());
    out.push(TAG_MESSAGE);
    out.extend_from_slice(&msg.counter.to_be_bytes());
    out.extend_from_slice(&msg.ciphertext);
    out
}

pub fn decode_message(frame: &[u8]) -> Result<Message, CoreError> {
    if frame.len() < MESSAGE_MIN_LEN || frame[0] != TAG_MESSAGE {
        return Err(CoreError::Malformed);
    }
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&frame[1..MESSAGE_HEADER_LEN]);
    Ok(Message {
        counter: u64::from_be_bytes(counter),
        ciphertext: frame[MESSAGE_HEADER_LEN..].to_vec(),
    })
}

pub fn send_handshake(link: &dyn Transport, init: &HandshakeInit) -> Result<(), CoreError> {
    link.send(&encode_handshake(init)).map_err(map_transport)
}

pub fn receive_handshake(link: &dyn Transport) -> Result<HandshakeInit, CoreError> {
    decode_handshake(&next_frame(link)?)
}

/// Seals `plaintext` on `chain` and sends it. The chain advances only after the
/// transport accepts the frame. A failed write leaves the counter where it was,
/// so the peer's next expected counter still matches our next frame.
pub fn send_message(
    link: &dyn Transport,
    chain: &mut Chain,
    plaintext: &[u8],
) -> Result<(), CoreError> {
    chain.seal_with(plaintext, |sealed| {
        link.send(&encode_message(sealed)).map_err(map_transport)
    })
}

/// Receives one message and opens it on `chain`. A tampered frame returns
/// `CoreError::Auth` and leaves the chain where it was.
pub fn receive_message(link: &dyn Transport, chain: &mut Chain) -> Result<Vec<u8>, CoreError> {
    let msg = decode_message(&next_frame(link)?)?;
    chain.open(&msg)
}

/// One receive attempt. Returns `Ok(None)` if the link was idle for a poll
/// interval, so a caller holding a lock can release it and try again.
pub fn poll_message(link: &dyn Transport, chain: &mut Chain) -> Result<Option<Vec<u8>>, CoreError> {
    match link.receive().map_err(map_transport)? {
        Some(frame) => {
            let msg = decode_message(&frame)?;
            chain.open(&msg).map(Some)
        }
        None => Ok(None),
    }
}

/// Waits for the next frame, looping over idle polls until a deadline.
fn next_frame(link: &dyn Transport) -> Result<Vec<u8>, CoreError> {
    let deadline = Instant::now() + RECEIVE_DEADLINE;
    loop {
        match link.receive().map_err(map_transport)? {
            Some(frame) => return Ok(frame),
            None if Instant::now() >= deadline => return Err(CoreError::Network),
            None => {}
        }
    }
}

/// Oversize frames are a length problem; every other transport failure is a network failure.
fn map_transport(e: TransportError) -> CoreError {
    match e {
        TransportError::Oversize => CoreError::Malformed,
        TransportError::Closed | TransportError::Truncated | TransportError::Io => {
            CoreError::Network
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{initiate, Identity};
    use crate::secret::Key32;

    #[test]
    fn handshake_frame_round_trips() {
        let (me, public) = Identity::generate();
        let (init, _root) = initiate(&me, &public).unwrap();
        let frame = encode_handshake(&init);
        let back = decode_handshake(&frame).unwrap();
        assert_eq!(back.ephemeral_x25519, init.ephemeral_x25519);
        assert_eq!(back.initiator_x25519, init.initiator_x25519);
        assert_eq!(back.mlkem_ct, init.mlkem_ct);
    }

    #[test]
    fn handshake_frame_with_wrong_length_is_refused() {
        let (me, public) = Identity::generate();
        let (init, _root) = initiate(&me, &public).unwrap();
        let mut frame = encode_handshake(&init);
        frame.pop();
        assert!(matches!(
            decode_handshake(&frame),
            Err(CoreError::Malformed)
        ));
        frame.push(0);
        frame.push(0);
        assert!(matches!(
            decode_handshake(&frame),
            Err(CoreError::Malformed)
        ));
    }

    #[test]
    fn frame_with_wrong_tag_is_refused() {
        let (me, public) = Identity::generate();
        let (init, _root) = initiate(&me, &public).unwrap();
        let mut frame = encode_handshake(&init);
        frame[0] = TAG_MESSAGE;
        assert!(matches!(
            decode_handshake(&frame),
            Err(CoreError::Malformed)
        ));
    }

    #[test]
    fn message_frame_round_trips() {
        let root = Key32([3u8; 32]);
        let mut send = Chain::new(&root, INITIATOR_TO_RESPONDER);
        let sealed = send.seal(b"payload").unwrap();
        let back = decode_message(&encode_message(&sealed)).unwrap();
        assert_eq!(back.counter, sealed.counter);
        assert_eq!(back.ciphertext, sealed.ciphertext);
    }

    #[test]
    fn short_message_frame_is_refused() {
        assert!(matches!(
            decode_message(&[TAG_MESSAGE; 10]),
            Err(CoreError::Malformed)
        ));
    }

    #[test]
    fn mlkem_ciphertext_length_matches_the_library() {
        let (me, public) = Identity::generate();
        let (init, _root) = initiate(&me, &public).unwrap();
        assert_eq!(init.mlkem_ct.len(), MLKEM768_CT_LEN);
    }
}
