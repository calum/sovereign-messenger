//! Identity vault: the long-term identity and the pinned contacts, sealed under a
//! 32-byte data key with ChaCha20-Poly1305 so they can sit on flash between runs
//! (owner decision 2026-10-25). Security property: the blob alone reveals nothing,
//! and any change to it, or the wrong key, fails authentication and yields no
//! partial state. The data key itself is wrapped by the Android Keystore in Kotlin
//! and never stored in the clear. Messages, sessions and ratchet state are never
//! put in the vault.
//!
//! Format: `version (1) || nonce (12) || ciphertext+tag`. The version and a fixed
//! label are authenticated as associated data. Every seal draws a fresh random
//! 96-bit nonce; the vault is sealed only when a pin changes, so the number of
//! seals under one key stays far below the point where random nonces could collide.

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CoreError;
use crate::handshake::{Identity, IdentityPublic, MLKEM_SEED_LEN, ONION_SEED_LEN};
use crate::secret::{Key32, SecretBytes};

/// Format version of a sealed vault. An unknown version is refused, not guessed at.
pub const VERSION: u8 = 1;
const AAD: &[u8] = b"sovereign-vault v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MLKEM768_EK_LEN: usize = 1184;

/// A fresh random data key. Rust makes it and hands it to Kotlin once, to be
/// wrapped by the Keystore (Decisions, 2026-10-25, identity key wrap).
pub fn new_data_key() -> Key32 {
    let mut k = Key32([0u8; 32]);
    getrandom::fill(&mut k.0).expect("OS randomness unavailable");
    k
}

/// Seals `plaintext` under `key`. The output is safe to write to app-private storage.
pub fn seal(key: &Key32, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("OS randomness unavailable");
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CoreError::Malformed)?;
    let ct = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| CoreError::Auth)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens a sealed blob. A wrong key or any modified byte is `CoreError::Auth`;
/// a blob too short to hold a version, nonce and tag, or of an unknown version,
/// is `CoreError::Malformed`. Neither message carries content.
pub fn open(key: &Key32, blob: &[u8]) -> Result<SecretBytes, CoreError> {
    if blob.len() < 1 + NONCE_LEN + TAG_LEN || blob[0] != VERSION {
        return Err(CoreError::Malformed);
    }
    let nonce: [u8; NONCE_LEN] = blob[1..1 + NONCE_LEN]
        .try_into()
        .map_err(|_| CoreError::Malformed)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| CoreError::Malformed)?;
    let mut plain = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &blob[1 + NONCE_LEN..],
                aad: AAD,
            },
        )
        .map_err(|_| CoreError::Auth)?;
    let out = SecretBytes::new(&plain);
    plain.zeroize();
    Ok(out)
}

/// Serialises the identity secrets and the pins. Pins are sorted by label so the
/// layout is deterministic. The buffer holds secrets, so it zeroizes on drop.
pub(crate) fn encode_contents(
    identity: &Identity,
    pins: &HashMap<String, IdentityPublic>,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(&identity.x25519_secret().0);
    out.extend_from_slice(identity.mlkem_seed());
    out.extend_from_slice(identity.onion_seed());
    let count = u16::try_from(pins.len()).map_err(|_| CoreError::Malformed)?;
    out.extend_from_slice(&count.to_be_bytes());
    let mut labels: Vec<&String> = pins.keys().collect();
    labels.sort();
    for label in labels {
        let public = &pins[label];
        let id_len = u16::try_from(label.len()).map_err(|_| CoreError::Malformed)?;
        out.extend_from_slice(&id_len.to_be_bytes());
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&public.x25519);
        out.extend_from_slice(&public.onion);
        let ek_len = u16::try_from(public.mlkem_ek.len()).map_err(|_| CoreError::Malformed)?;
        out.extend_from_slice(&ek_len.to_be_bytes());
        out.extend_from_slice(&public.mlkem_ek);
    }
    Ok(out)
}

/// The identity, its public half, and the pins read back from a vault.
pub(crate) type Contents = (Identity, IdentityPublic, HashMap<String, IdentityPublic>);

/// Parses what `encode_contents` wrote. Strict: trailing bytes, a duplicate label,
/// a wrong-sized ML-KEM key or non-UTF-8 label is `Malformed`.
pub(crate) fn decode_contents(bytes: &[u8]) -> Result<Contents, CoreError> {
    let mut r = Reader { bytes, at: 0 };
    let mut x25519 = Key32(r.take(32)?.try_into().map_err(|_| CoreError::Malformed)?);
    let mut seed = [0u8; MLKEM_SEED_LEN];
    seed.copy_from_slice(r.take(MLKEM_SEED_LEN)?);
    let mut onion_seed = [0u8; ONION_SEED_LEN];
    onion_seed.copy_from_slice(r.take(ONION_SEED_LEN)?);
    let (identity, public) = Identity::from_secrets(&x25519.0, &seed, &onion_seed);
    x25519.zeroize();
    seed.zeroize();
    onion_seed.zeroize();

    let count = r.u16()?;
    let mut pins = HashMap::new();
    for _ in 0..count {
        let id_len = r.u16()? as usize;
        let label = std::str::from_utf8(r.take(id_len)?)
            .map_err(|_| CoreError::Malformed)?
            .to_owned();
        let x25519: [u8; 32] = r.take(32)?.try_into().map_err(|_| CoreError::Malformed)?;
        let onion: [u8; 32] = r.take(32)?.try_into().map_err(|_| CoreError::Malformed)?;
        let ek_len = r.u16()? as usize;
        if ek_len != MLKEM768_EK_LEN {
            return Err(CoreError::Malformed);
        }
        let mlkem_ek = r.take(ek_len)?.to_vec();
        if pins
            .insert(
                label,
                IdentityPublic {
                    x25519,
                    mlkem_ek,
                    onion,
                },
            )
            .is_some()
        {
            return Err(CoreError::Malformed);
        }
    }
    if r.at != bytes.len() {
        return Err(CoreError::Malformed);
    }
    Ok((identity, public, pins))
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CoreError> {
        let end = self.at.checked_add(n).ok_or(CoreError::Malformed)?;
        let slice = self.bytes.get(self.at..end).ok_or(CoreError::Malformed)?;
        self.at = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, CoreError> {
        let b: [u8; 2] = self.take(2)?.try_into().map_err(|_| CoreError::Malformed)?;
        Ok(u16::from_be_bytes(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::probe::{NoClone, NoDebug, Probe};

    #[test]
    fn contents_round_trip_keeps_identity_and_pins() {
        let (identity, public) = Identity::generate();
        let (_other, other_pub) = Identity::generate();
        let mut pins = HashMap::new();
        pins.insert("bob".to_string(), other_pub.clone());
        let bytes = encode_contents(&identity, &pins).unwrap();
        let (_restored, restored_pub, restored_pins) = decode_contents(&bytes).unwrap();
        assert_eq!(restored_pub, public);
        assert_eq!(restored_pins, pins);
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let (identity, _) = Identity::generate();
        let mut bytes = encode_contents(&identity, &HashMap::new())
            .unwrap()
            .to_vec();
        bytes.push(0);
        assert_eq!(decode_contents(&bytes).err(), Some(CoreError::Malformed));
    }

    #[test]
    fn a_wrong_sized_pinned_kem_key_is_refused() {
        let (identity, _) = Identity::generate();
        let mut pins = HashMap::new();
        pins.insert(
            "bob".to_string(),
            IdentityPublic {
                x25519: [1u8; 32],
                mlkem_ek: vec![0u8; 10],
                onion: [2u8; 32],
            },
        );
        let bytes = encode_contents(&identity, &pins).unwrap();
        assert_eq!(decode_contents(&bytes).err(), Some(CoreError::Malformed));
    }

    #[test]
    fn every_prefix_of_the_contents_is_refused() {
        let (identity, _) = Identity::generate();
        let (_o, other_pub) = Identity::generate();
        let mut pins = HashMap::new();
        pins.insert("bob".to_string(), other_pub);
        let bytes = encode_contents(&identity, &pins).unwrap();
        for len in 0..bytes.len() {
            assert!(decode_contents(&bytes[..len]).is_err(), "prefix {len}");
        }
    }

    #[test]
    fn data_key_has_no_clone_or_debug() {
        // Key32 is the type that carries the data key; this vault must not give it a Debug or Clone.
        {
            let value = Probe::<Key32>::CLONE;
            assert!(!value);
        }
        {
            let value = Probe::<Key32>::DEBUG;
            assert!(!value);
        }
    }
}
