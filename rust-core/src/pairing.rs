//! Pairing payload (the QR code body) and identity fingerprints.
//! The payload carries only public keys and a short connection hint. Rust
//! builds and parses the bytes; Kotlin only renders them. Parsing is strict
//! (exact length, magic, version) so a malformed or truncated code is refused
//! before any key is pinned.
//!
//! The payload is sent as two QR codes (`split`, `Assembler`, `reassemble`). Each
//! part is a 10-byte header (index, count `2`, 8-byte payload id) and about half
//! the payload. The id is an integrity check that stops parts from different or
//! tampered payloads being joined; it is not authentication. The fingerprint
//! compared in person is still the trust step.

use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::handshake::IdentityPublic;

const MAGIC: &[u8; 4] = b"SMQR";
const VERSION: u8 = 1;
const MLKEM768_EK_LEN: usize = 1184;
const FINGERPRINT_DOMAIN: &[u8] = b"sovereign-p2p v1 fingerprint";

/// Upper bound on the connection hint, so a QR code stays small and scannable.
pub const MAX_HINT_LEN: usize = 64;

/// Encodes `public` and a connection hint into the payload bytes for the QR code.
/// Fails if the hint is too long, not printable ASCII, or the key has the wrong size.
pub fn encode(public: &IdentityPublic, hint: &str) -> Result<Vec<u8>, CoreError> {
    if public.mlkem_ek.len() != MLKEM768_EK_LEN || !is_valid_hint(hint) {
        return Err(CoreError::Malformed);
    }
    let mut out = Vec::with_capacity(4 + 1 + 32 + MLKEM768_EK_LEN + 1 + hint.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&public.x25519);
    out.extend_from_slice(&public.mlkem_ek);
    out.push(hint.len() as u8);
    out.extend_from_slice(hint.as_bytes());
    Ok(out)
}

/// Parses a scanned payload. Rejects bad magic, unknown version, wrong length,
/// trailing bytes, an all-zero X25519 key (a low-order point), and a bad hint.
pub fn decode(bytes: &[u8]) -> Result<(IdentityPublic, String), CoreError> {
    let fixed = 4 + 1 + 32 + MLKEM768_EK_LEN + 1;
    if bytes.len() < fixed || &bytes[..4] != MAGIC || bytes[4] != VERSION {
        return Err(CoreError::Malformed);
    }
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&bytes[5..37]);
    if x25519 == [0u8; 32] {
        return Err(CoreError::Malformed);
    }
    let mlkem_ek = bytes[37..37 + MLKEM768_EK_LEN].to_vec();

    let hint_len = bytes[fixed - 1] as usize;
    if hint_len > MAX_HINT_LEN || bytes.len() != fixed + hint_len {
        return Err(CoreError::Malformed);
    }
    let hint = std::str::from_utf8(&bytes[fixed..]).map_err(|_| CoreError::Malformed)?;
    if !is_valid_hint(hint) {
        return Err(CoreError::Malformed);
    }
    Ok((IdentityPublic { x25519, mlkem_ek }, hint.to_owned()))
}

/// Short human-checkable label for an identity, shown next to a pinned peer.
/// Hash of the public keys, so it reveals nothing secret. 128 bits, grouped.
pub fn fingerprint(public: &IdentityPublic) -> String {
    let mut h = Sha256::new();
    h.update(FINGERPRINT_DOMAIN);
    h.update(public.x25519);
    h.update(&public.mlkem_ek);
    let digest = h.finalize();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

/// Number of QR codes one pairing payload is split into. A payload of about 1.2 KB
/// as one code is version 27, which fails to decode about 7% of the time (PLAN.md
/// Decisions, 2026-10-24, QR decode). Two codes of about 0.6 KB decode reliably.
pub const PART_COUNT: u8 = 2;

/// Part header: index (1 byte), count (1 byte), payload id (8 bytes), 10 bytes in all.
/// The chunk follows. The id is the first 8 bytes of SHA-256 over `PART_ID_DOMAIN`
/// (`sovereign-p2p v1 pairing part id`) and the whole payload.
pub const PART_HEADER_LEN: usize = 2 + ID_LEN;
const ID_LEN: usize = 8;
const PART_ID_DOMAIN: &[u8] = b"sovereign-p2p v1 pairing part id";

/// Splits an encoded pairing payload into `PART_COUNT` QR parts. Each part carries
/// its index, the total, and an id that is a hash of the whole payload. The id ties
/// the parts to one identity and lets reassembly detect any tampering.
/// The payload must be a valid pairing payload; anything else is refused.
pub fn split(payload: &[u8]) -> Result<Vec<Vec<u8>>, CoreError> {
    decode(payload)?;
    let id = payload_id(payload);
    let chunk_len = payload.len().div_ceil(PART_COUNT as usize);
    Ok(payload
        .chunks(chunk_len)
        .enumerate()
        .map(|(index, chunk)| {
            let mut part = Vec::with_capacity(PART_HEADER_LEN + chunk.len());
            part.push(index as u8);
            part.push(PART_COUNT);
            part.extend_from_slice(&id);
            part.extend_from_slice(chunk);
            part
        })
        .collect())
}

/// Collects scanned parts until the full payload is complete. Parts for another
/// payload, a duplicate, or a bad header are refused and change nothing. A set
/// that completes but does not match its id is discarded, so a tampered part
/// cannot produce a payload that pins.
#[derive(Default)]
pub struct Assembler {
    id: Option<[u8; ID_LEN]>,
    chunks: Vec<Option<Vec<u8>>>,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct parts accepted so far.
    pub fn received(&self) -> u8 {
        self.chunks.iter().filter(|c| c.is_some()).count() as u8
    }

    /// Number of parts in the set, or 0 before the first part.
    pub fn total(&self) -> u8 {
        self.chunks.len() as u8
    }

    /// Adds one scanned part. Returns the full payload once every part is in and
    /// the joined bytes match the id. Returns `Ok(None)` while parts are still missing.
    pub fn add(&mut self, part: &[u8]) -> Result<Option<Vec<u8>>, CoreError> {
        if part.len() <= PART_HEADER_LEN {
            return Err(CoreError::Malformed);
        }
        let index = part[0] as usize;
        let count = part[1];
        if count != PART_COUNT || index >= count as usize {
            return Err(CoreError::Malformed);
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&part[2..PART_HEADER_LEN]);
        match self.id {
            Some(existing) if existing != id => return Err(CoreError::Malformed),
            Some(_) => {}
            None => {
                self.id = Some(id);
                self.chunks = vec![None; count as usize];
            }
        }
        if self.chunks[index].is_some() {
            return Err(CoreError::Malformed);
        }
        self.chunks[index] = Some(part[PART_HEADER_LEN..].to_vec());
        if self.chunks.iter().any(Option::is_none) {
            return Ok(None);
        }
        let payload: Vec<u8> = self.chunks.iter().flatten().flatten().copied().collect();
        if Some(payload_id(&payload)) != self.id || decode(&payload).is_err() {
            *self = Self::default();
            return Err(CoreError::Malformed);
        }
        Ok(Some(payload))
    }
}

/// Reassembles a complete set of parts. Refuses a missing part, a duplicate, and any
/// part from a different payload or with a bad header.
pub fn reassemble(parts: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
    let mut asm = Assembler::new();
    let mut complete = None;
    for part in parts {
        complete = asm.add(part)?;
    }
    complete.ok_or(CoreError::Malformed)
}

fn payload_id(payload: &[u8]) -> [u8; ID_LEN] {
    let mut h = Sha256::new();
    h.update(PART_ID_DOMAIN);
    h.update(payload);
    let digest = h.finalize();
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&digest[..ID_LEN]);
    id
}

fn is_valid_hint(hint: &str) -> bool {
    hint.len() <= MAX_HINT_LEN && hint.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Identity;

    fn sample() -> IdentityPublic {
        Identity::generate().1
    }

    #[test]
    fn payload_round_trips() {
        let public = sample();
        let bytes = encode(&public, "10.0.0.2:7000").unwrap();
        let (parsed, hint) = decode(&bytes).unwrap();
        assert_eq!(parsed, public);
        assert_eq!(hint, "10.0.0.2:7000");
    }

    #[test]
    fn empty_hint_is_allowed() {
        let public = sample();
        let (_, hint) = decode(&encode(&public, "").unwrap()).unwrap();
        assert_eq!(hint, "");
    }

    #[test]
    fn truncated_payload_rejected() {
        let bytes = encode(&sample(), "h").unwrap();
        assert_eq!(decode(&bytes[..bytes.len() - 1]), Err(CoreError::Malformed));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = encode(&sample(), "h").unwrap();
        bytes.push(0);
        assert_eq!(decode(&bytes), Err(CoreError::Malformed));
    }

    #[test]
    fn wrong_magic_and_version_rejected() {
        let good = encode(&sample(), "h").unwrap();
        let mut magic = good.clone();
        magic[0] ^= 1;
        assert_eq!(decode(&magic), Err(CoreError::Malformed));
        let mut version = good;
        version[4] = 2;
        assert_eq!(decode(&version), Err(CoreError::Malformed));
    }

    #[test]
    fn all_zero_x25519_key_rejected() {
        let mut bytes = encode(&sample(), "h").unwrap();
        bytes[5..37].fill(0);
        assert_eq!(decode(&bytes), Err(CoreError::Malformed));
    }

    #[test]
    fn oversized_or_non_ascii_hint_rejected_on_encode() {
        let public = sample();
        assert_eq!(
            encode(&public, &"x".repeat(MAX_HINT_LEN + 1)),
            Err(CoreError::Malformed)
        );
        assert_eq!(encode(&public, "caf\u{e9}"), Err(CoreError::Malformed));
    }

    #[test]
    fn wrong_key_length_rejected_on_encode() {
        let mut public = sample();
        public.mlkem_ek.pop();
        assert_eq!(encode(&public, ""), Err(CoreError::Malformed));
    }

    #[test]
    fn fingerprint_is_stable_and_key_specific() {
        let a = sample();
        let b = sample();
        assert_eq!(fingerprint(&a), fingerprint(&a));
        assert_ne!(fingerprint(&a), fingerprint(&b));
        assert_eq!(fingerprint(&a).len(), 39); // 32 hex digits in 8 groups of 4, joined by '-'
    }

    fn parts_of(public: &IdentityPublic) -> Vec<Vec<u8>> {
        split(&encode(public, "h").unwrap()).unwrap()
    }

    #[test]
    fn split_parts_reassemble_to_the_payload() {
        let payload = encode(&sample(), "10.0.0.2:7000").unwrap();
        let parts = split(&payload).unwrap();
        assert_eq!(parts.len(), PART_COUNT as usize);
        assert_eq!(reassemble(&parts).unwrap(), payload);
    }

    #[test]
    fn parts_arrive_in_any_order() {
        let payload = encode(&sample(), "h").unwrap();
        let mut parts = split(&payload).unwrap();
        parts.reverse();
        assert_eq!(reassemble(&parts).unwrap(), payload);
    }

    #[test]
    fn missing_part_is_refused() {
        let parts = parts_of(&sample());
        assert_eq!(reassemble(&parts[..1]), Err(CoreError::Malformed));
        assert_eq!(reassemble(&parts[1..]), Err(CoreError::Malformed));
    }

    #[test]
    fn duplicated_part_is_refused() {
        let parts = parts_of(&sample());
        assert_eq!(
            reassemble(&[parts[0].clone(), parts[0].clone()]),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn part_from_another_payload_is_refused() {
        let a = parts_of(&sample());
        let b = parts_of(&sample());
        assert_eq!(
            reassemble(&[a[0].clone(), b[1].clone()]),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn mismatched_part_leaves_the_assembler_unchanged() {
        let a = parts_of(&sample());
        let b = parts_of(&sample());
        let mut asm = Assembler::new();
        assert_eq!(asm.add(&a[0]), Ok(None));
        assert_eq!(asm.add(&b[1]), Err(CoreError::Malformed));
        assert_eq!(asm.received(), 1);
        assert!(asm.add(&a[1]).unwrap().is_some());
    }

    #[test]
    fn out_of_range_index_or_count_is_refused() {
        let parts = parts_of(&sample());
        let mut bad_index = parts[0].clone();
        bad_index[0] = PART_COUNT;
        assert_eq!(
            reassemble(&[bad_index, parts[1].clone()]),
            Err(CoreError::Malformed)
        );
        let mut bad_count = parts[0].clone();
        bad_count[1] = PART_COUNT + 1;
        assert_eq!(
            reassemble(&[bad_count, parts[1].clone()]),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn tampered_part_does_not_reassemble_into_a_payload() {
        let public = sample();
        let parts = parts_of(&public);
        // Flip a bit inside the X25519 key. The result still parses, so only the id check catches it.
        let mut tampered = parts[0].clone();
        tampered[PART_HEADER_LEN + 20] ^= 1;
        assert_eq!(
            reassemble(&[tampered, parts[1].clone()]),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn old_single_code_payload_is_refused_not_misread() {
        let payload = encode(&sample(), "h").unwrap();
        assert_eq!(Assembler::new().add(&payload), Err(CoreError::Malformed));
    }
}
