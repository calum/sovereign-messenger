//! Pairing payload (the QR code body) and identity fingerprints.
//! The payload carries only public keys and a short connection hint. Rust
//! builds and parses the bytes; Kotlin only renders them. Parsing is strict
//! (exact length, magic, version) so a malformed or truncated code is refused
//! before any key is pinned.

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
}
