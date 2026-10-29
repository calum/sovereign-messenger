//! Plaintext layout inside every sealed chat message: a kind byte, an 8-byte
//! message id, and for text the UTF-8 body. The envelope is sealed by the ratchet
//! like any plaintext, so a receipt cannot be forged or replayed by the network.
//!
//! Security property: receipts carry an id and nothing else, so a delivered or read
//! notice reveals no message content. An unknown kind or a receipt of the wrong
//! length is refused, never guessed at.
//!
//! | kind | frame     | layout                      |
//! |------|-----------|-----------------------------|
//! | 0x10 | text      | kind, id (u64 BE), text     |
//! | 0x11 | delivered | kind, id (u64 BE)           |
//! | 0x12 | read      | kind, id (u64 BE)           |

use zeroize::Zeroizing;

use crate::error::CoreError;

const KIND_TEXT: u8 = 0x10;
const KIND_DELIVERED: u8 = 0x11;
const KIND_READ: u8 = 0x12;
const ID_END: usize = 1 + 8;

/// One decoded envelope. A text body borrows from the opened plaintext.
#[derive(Debug, PartialEq, Eq)]
pub enum Envelope<'a> {
    Text {
        id: u64,
        body: &'a [u8],
    },
    /// The contact's phone received message `id`.
    Delivered(u64),
    /// The contact has seen message `id` and every earlier one from this phone.
    Read(u64),
}

/// The plaintext is wiped when the returned buffer drops.
pub fn encode_text(id: u64, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(ID_END + body.len()));
    out.push(KIND_TEXT);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn encode_delivered(id: u64) -> Vec<u8> {
    encode_receipt(KIND_DELIVERED, id)
}

pub fn encode_read(id: u64) -> Vec<u8> {
    encode_receipt(KIND_READ, id)
}

fn encode_receipt(kind: u8, id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(ID_END);
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
    out
}

pub fn decode(plaintext: &[u8]) -> Result<Envelope<'_>, CoreError> {
    let (&kind, rest) = plaintext.split_first().ok_or(CoreError::Malformed)?;
    let id_bytes: [u8; 8] = rest
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .ok_or(CoreError::Malformed)?;
    let id = u64::from_be_bytes(id_bytes);
    match kind {
        KIND_TEXT => Ok(Envelope::Text {
            id,
            body: &plaintext[ID_END..],
        }),
        KIND_DELIVERED if plaintext.len() == ID_END => Ok(Envelope::Delivered(id)),
        KIND_READ if plaintext.len() == ID_END => Ok(Envelope::Read(id)),
        _ => Err(CoreError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let bytes = encode_text(7, b"hello");
        assert_eq!(
            decode(&bytes).unwrap(),
            Envelope::Text {
                id: 7,
                body: b"hello"
            }
        );
    }

    #[test]
    fn empty_text_body_is_allowed() {
        let bytes = encode_text(1, b"");
        assert_eq!(decode(&bytes).unwrap(), Envelope::Text { id: 1, body: b"" });
    }

    #[test]
    fn receipts_round_trip() {
        assert_eq!(
            decode(&encode_delivered(9)).unwrap(),
            Envelope::Delivered(9)
        );
        assert_eq!(
            decode(&encode_read(u64::MAX)).unwrap(),
            Envelope::Read(u64::MAX)
        );
    }

    #[test]
    fn refuses_empty_short_unknown_and_padded_receipts() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[KIND_TEXT, 0, 0, 0]).is_err());
        assert!(decode(&[0x99, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
        let mut padded = encode_delivered(1);
        padded.push(0);
        assert!(decode(&padded).is_err());
        let mut padded = encode_read(1);
        padded.push(0);
        assert!(decode(&padded).is_err());
    }

    #[test]
    fn raw_text_without_an_envelope_is_refused() {
        assert!(decode(b"hello").is_err());
    }
}
