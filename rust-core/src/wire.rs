//! Frame layout for the challenge, handshake and ratchet messages, and helpers
//! that move them over a `Transport`. Each frame starts with a one-byte tag, so a
//! handshake frame can never be parsed as a chat message. A ratchet frame carries
//! a version byte inside its authenticated header, so a future layout is refused,
//! not misread.
//!
//! Frames, all lengths checked on decode (exact length, or minimum for messages):
//!
//! | tag  | frame      | layout                                                        | length        |
//! |------|------------|---------------------------------------------------------------|---------------|
//! | 0x03 | challenge  | tag, challenge (32), responder ephemeral X25519 public (32)   | 65 bytes      |
//! | 0x01 | handshake  | tag, ephemeral X25519 (32), initiator static X25519 (32), ML-KEM-768 ciphertext (1088), confirmation tag (32) | 1185 bytes |
//! | 0x02 | message    | tag, ratchet header (49), ciphertext (at least 16)            | at least 66 bytes |
//!
//! The ratchet header is version (1 byte, `0x01`), ratchet public key (32), previous
//! chain length (u64 BE), counter (u64 BE). It is authenticated as AEAD associated data.
//!
//! The responder sends the challenge first, once per connection. The handshake carries
//! a confirmation tag over the challenge and the responder's ephemeral key, so a
//! handshake captured earlier fails and the key cannot be swapped in transit.
//!
//! Handshake v2 (2026-10-29) grew the challenge frame from 33 to 65 bytes. The tag byte
//! is unchanged; the exact length check refuses the old 33-byte frame as `Malformed`,
//! and the `v2` labels in the key derivation mean the two versions can never agree on
//! a root. Builds before v2 cannot connect to builds after it.
//!
//! Security property: nothing here decides authenticity. A malformed frame is
//! refused by length or tag; a forged or altered chat message is refused by the
//! ratchet's AEAD. The handshake frame carries public values only.

use std::time::Instant;

use crate::double_ratchet::{header_bytes, header_from_bytes, DoubleRatchet, Message, HEADER_LEN};
use crate::error::CoreError;
use crate::handshake::{ChallengeOffer, HandshakeInit, CHALLENGE_LEN};
use crate::transport::{Transport, TransportError};

/// Direction labels. Both peers derive the same two chains from the root; the
/// initiator sends on `i->r` and the responder on `r->i`, so a message cannot
/// be reflected back to its sender.
pub const INITIATOR_TO_RESPONDER: &[u8] = b"i->r";
pub const RESPONDER_TO_INITIATOR: &[u8] = b"r->i";

pub const TAG_HANDSHAKE: u8 = 0x01;
pub const TAG_MESSAGE: u8 = 0x02;
/// The responder's challenge, sent before the initiator speaks. A handshake
/// built with an old challenge fails its confirmation tag, so a replay is refused.
pub const TAG_CHALLENGE: u8 = 0x03;

/// ML-KEM-768 ciphertext length in bytes (FIPS 203). Checked in tests against the library.
pub const MLKEM768_CT_LEN: usize = 1088;
const EPHEMERAL_LEN: usize = 32;
const STATIC_LEN: usize = 32;
const TAG_LEN: usize = 32;
/// Tag, ephemeral key, initiator static key, ML-KEM ciphertext, confirmation tag: 1185 bytes.
const HANDSHAKE_LEN: usize = 1 + EPHEMERAL_LEN + STATIC_LEN + MLKEM768_CT_LEN + TAG_LEN;
/// Tag, the 32-byte challenge, the responder's ephemeral public key: 65 bytes.
const CHALLENGE_FRAME_LEN: usize = 1 + CHALLENGE_LEN + EPHEMERAL_LEN;
/// Tag, then the ratchet header (49 bytes), then the ciphertext. A ChaCha20-Poly1305
/// ciphertext is at least the 16-byte tag, so a message frame is at least 66 bytes.
const MESSAGE_MIN_LEN: usize = 1 + HEADER_LEN + 16;

/// Layout: `[tag 0x01][ephemeral 32][initiator static 32][ML-KEM ct 1088][confirmation tag 32]`.
pub fn encode_handshake(init: &HandshakeInit) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_LEN);
    out.push(TAG_HANDSHAKE);
    out.extend_from_slice(&init.ephemeral_x25519);
    out.extend_from_slice(&init.initiator_x25519);
    out.extend_from_slice(&init.mlkem_ct);
    out.extend_from_slice(&init.tag);
    out
}

pub fn decode_handshake(frame: &[u8]) -> Result<HandshakeInit, CoreError> {
    if frame.len() != HANDSHAKE_LEN || frame[0] != TAG_HANDSHAKE {
        return Err(CoreError::Malformed);
    }
    let static_at = 1 + EPHEMERAL_LEN;
    let kem_at = static_at + STATIC_LEN;
    let confirm_at = kem_at + MLKEM768_CT_LEN;
    let mut ephemeral_x25519 = [0u8; EPHEMERAL_LEN];
    ephemeral_x25519.copy_from_slice(&frame[1..static_at]);
    let mut initiator_x25519 = [0u8; STATIC_LEN];
    initiator_x25519.copy_from_slice(&frame[static_at..kem_at]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&frame[confirm_at..]);
    Ok(HandshakeInit {
        ephemeral_x25519,
        initiator_x25519,
        mlkem_ct: frame[kem_at..confirm_at].to_vec(),
        tag,
    })
}

/// Layout: `[tag 0x03][challenge 32][responder ephemeral X25519 public 32]`. Only the
/// responder sends it.
pub fn encode_challenge(offer: &ChallengeOffer) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHALLENGE_FRAME_LEN);
    out.push(TAG_CHALLENGE);
    out.extend_from_slice(&offer.nonce);
    out.extend_from_slice(&offer.ephemeral);
    out
}

/// A challenge frame of any other length or tag (including the 33-byte frame of the
/// previous handshake version) is refused as `Malformed`.
pub fn decode_challenge(frame: &[u8]) -> Result<ChallengeOffer, CoreError> {
    if frame.len() != CHALLENGE_FRAME_LEN || frame[0] != TAG_CHALLENGE {
        return Err(CoreError::Malformed);
    }
    let mut nonce = [0u8; CHALLENGE_LEN];
    nonce.copy_from_slice(&frame[1..1 + CHALLENGE_LEN]);
    let mut ephemeral = [0u8; EPHEMERAL_LEN];
    ephemeral.copy_from_slice(&frame[1 + CHALLENGE_LEN..]);
    Ok(ChallengeOffer { nonce, ephemeral })
}

pub fn send_challenge(link: &dyn Transport, offer: &ChallengeOffer) -> Result<(), CoreError> {
    link.send(&encode_challenge(offer)).map_err(map_transport)
}

pub fn receive_challenge(link: &dyn Transport) -> Result<ChallengeOffer, CoreError> {
    decode_challenge(&next_frame(link)?)
}

/// Layout: `[tag 0x02][ratchet header 49][ciphertext]`.
pub fn encode_message(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + HEADER_LEN + msg.ciphertext.len());
    out.push(TAG_MESSAGE);
    out.extend_from_slice(&header_bytes(&msg.header));
    out.extend_from_slice(&msg.ciphertext);
    out
}

pub fn decode_message(frame: &[u8]) -> Result<Message, CoreError> {
    if frame.len() < MESSAGE_MIN_LEN || frame[0] != TAG_MESSAGE {
        return Err(CoreError::Malformed);
    }
    let header = header_from_bytes(&frame[1..1 + HEADER_LEN])?;
    Ok(Message {
        header,
        ciphertext: frame[1 + HEADER_LEN..].to_vec(),
    })
}

pub fn send_handshake(link: &dyn Transport, init: &HandshakeInit) -> Result<(), CoreError> {
    link.send(&encode_handshake(init)).map_err(map_transport)
}

pub fn receive_handshake(link: &dyn Transport) -> Result<HandshakeInit, CoreError> {
    decode_handshake(&next_frame_within(link, link.responder_deadline())?)
}

/// Seals `plaintext` on the session and sends it. The session advances only after
/// the transport accepts the frame. A failed write leaves the counter and the
/// ratchet key where they were, so the peer's next expected counter still matches.
pub fn send_message(
    link: &dyn Transport,
    session: &mut DoubleRatchet,
    plaintext: &[u8],
) -> Result<(), CoreError> {
    session.seal_with(plaintext, |sealed| {
        link.send(&encode_message(sealed)).map_err(map_transport)
    })
}

/// Receives one message and opens it on the session. A tampered frame returns
/// `CoreError::Auth` and leaves the session where it was.
pub fn receive_message(
    link: &dyn Transport,
    session: &mut DoubleRatchet,
) -> Result<Vec<u8>, CoreError> {
    open_frame(session, &next_frame(link)?)
}

/// Reads one frame if one arrives within the poll interval. Holds no session state,
/// so the caller can wait on the socket without holding the session lock.
pub fn receive_frame(link: &dyn Transport) -> Result<Option<Vec<u8>>, CoreError> {
    link.receive().map_err(map_transport)
}

/// Decodes and opens one frame read by `receive_frame`.
pub fn open_frame(session: &mut DoubleRatchet, frame: &[u8]) -> Result<Vec<u8>, CoreError> {
    let msg = decode_message(frame)?;
    session.open(&msg)
}

/// Waits for the next frame, looping over idle polls until a deadline.
fn next_frame(link: &dyn Transport) -> Result<Vec<u8>, CoreError> {
    next_frame_within(link, link.handshake_deadline())
}

/// Like `next_frame` with the wait chosen by the caller.
fn next_frame_within(
    link: &dyn Transport,
    wait: std::time::Duration,
) -> Result<Vec<u8>, CoreError> {
    let deadline = Instant::now() + wait;
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
    use crate::double_ratchet::Role;
    use crate::handshake::{initiate, new_challenge, Identity};
    use crate::secret::Key32;

    #[test]
    fn handshake_frame_round_trips() {
        let (me, public) = Identity::generate();
        let (init, _root) = initiate(&me, &public, &new_challenge().offer()).unwrap();
        let frame = encode_handshake(&init);
        let back = decode_handshake(&frame).unwrap();
        assert_eq!(back.ephemeral_x25519, init.ephemeral_x25519);
        assert_eq!(back.initiator_x25519, init.initiator_x25519);
        assert_eq!(back.mlkem_ct, init.mlkem_ct);
    }

    #[test]
    fn handshake_frame_with_wrong_length_is_refused() {
        let (me, public) = Identity::generate();
        let (init, _root) = initiate(&me, &public, &new_challenge().offer()).unwrap();
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
        let (init, _root) = initiate(&me, &public, &new_challenge().offer()).unwrap();
        let mut frame = encode_handshake(&init);
        frame[0] = TAG_MESSAGE;
        assert!(matches!(
            decode_handshake(&frame),
            Err(CoreError::Malformed)
        ));
    }

    #[test]
    fn handshake_frame_carries_the_confirmation_tag() {
        let (me, public) = Identity::generate();
        let (init, _root) = initiate(&me, &public, &new_challenge().offer()).unwrap();
        let back = decode_handshake(&encode_handshake(&init)).unwrap();
        assert_eq!(back.tag, init.tag);
    }

    fn offer() -> ChallengeOffer {
        ChallengeOffer {
            nonce: [4u8; CHALLENGE_LEN],
            ephemeral: [5u8; 32],
        }
    }

    #[test]
    fn challenge_frame_round_trips() {
        let frame = encode_challenge(&offer());
        assert_eq!(frame.len(), 65);
        assert_eq!(decode_challenge(&frame).unwrap(), offer());
    }

    #[test]
    fn old_33_byte_challenge_frame_is_refused() {
        let mut old = vec![TAG_CHALLENGE];
        old.extend_from_slice(&[4u8; CHALLENGE_LEN]);
        assert_eq!(old.len(), 33);
        assert!(matches!(decode_challenge(&old), Err(CoreError::Malformed)));
    }

    #[test]
    fn challenge_frame_with_wrong_length_is_refused() {
        let mut frame = encode_challenge(&offer());
        frame.pop();
        assert!(matches!(
            decode_challenge(&frame),
            Err(CoreError::Malformed)
        ));
        frame.push(0);
        frame.push(0);
        assert!(matches!(
            decode_challenge(&frame),
            Err(CoreError::Malformed)
        ));
    }

    #[test]
    fn challenge_frame_with_wrong_tag_is_refused() {
        let mut frame = encode_challenge(&offer());
        frame[0] = TAG_HANDSHAKE;
        assert!(matches!(
            decode_challenge(&frame),
            Err(CoreError::Malformed)
        ));
    }

    #[test]
    fn message_frame_round_trips() {
        let root = Key32([3u8; 32]);
        let mut send = DoubleRatchet::new(
            &root,
            Role::Initiator,
            INITIATOR_TO_RESPONDER,
            RESPONDER_TO_INITIATOR,
        );
        let sealed = send.seal(b"payload").unwrap();
        let back = decode_message(&encode_message(&sealed)).unwrap();
        assert_eq!(back.header, sealed.header);
        assert_eq!(back.ciphertext, sealed.ciphertext);
    }

    #[test]
    fn message_frame_with_unknown_version_is_refused() {
        let root = Key32([3u8; 32]);
        let mut send = DoubleRatchet::new(
            &root,
            Role::Initiator,
            INITIATOR_TO_RESPONDER,
            RESPONDER_TO_INITIATOR,
        );
        let mut frame = encode_message(&send.seal(b"payload").unwrap());
        frame[1] = crate::double_ratchet::RATCHET_VERSION + 1;
        assert!(matches!(decode_message(&frame), Err(CoreError::Malformed)));
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
        let (init, _root) = initiate(&me, &public, &new_challenge().offer()).unwrap();
        assert_eq!(init.mlkem_ct.len(), MLKEM768_CT_LEN);
    }
}
