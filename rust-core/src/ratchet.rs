//! Symmetric-key ratchet over ChaCha20-Poly1305. Each message gets a fresh key
//! and the chain key is advanced irreversibly, so earlier messages stay sealed
//! even if a later chain key leaks (forward secrecy within a chain).
//!
//! Not yet implemented: the DH ratchet step (fresh X25519/ML-KEM material on
//! each reply, for post-compromise security). The message format leaves room
//! for it.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::secret::Key32;

pub struct Chain {
    chain_key: Key32,
    counter: u64,
}

pub struct Message {
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

impl Chain {
    /// One direction of traffic. Both peers call this with the same root and
    /// label: the sender seals with it, the receiver opens with it.
    pub fn new(root: &Key32, label: &[u8]) -> Chain {
        let hk = Hkdf::<Sha256>::from_prk(&root.0).expect("32-byte PRK");
        let mut ck = [0u8; 32];
        hk.expand(label, &mut ck).expect("len ok");
        let chain = Chain {
            chain_key: Key32(ck),
            counter: 0,
        };
        ck.zeroize();
        chain
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Message, CoreError> {
        let counter = self.counter;
        let (mut mk, next) = self.step();
        let cipher = ChaCha20Poly1305::new_from_slice(&mk.0).map_err(|_| CoreError::Malformed)?;
        mk.zeroize();
        let ciphertext = cipher
            .encrypt(
                &nonce_for(counter),
                Payload {
                    msg: plaintext,
                    aad: &counter.to_be_bytes(),
                },
            )
            .map_err(|_| CoreError::Auth)?;
        self.chain_key = next;
        self.counter += 1;
        Ok(Message {
            counter,
            ciphertext,
        })
    }

    /// Messages must arrive in order. Out-of-order support comes later.
    pub fn open(&mut self, msg: &Message) -> Result<Vec<u8>, CoreError> {
        if msg.counter != self.counter {
            return Err(CoreError::Malformed);
        }
        let (mut mk, next) = self.step();
        let cipher = ChaCha20Poly1305::new_from_slice(&mk.0).map_err(|_| CoreError::Malformed)?;
        mk.zeroize();
        let plaintext = cipher
            .decrypt(
                &nonce_for(msg.counter),
                Payload {
                    msg: &msg.ciphertext,
                    aad: &msg.counter.to_be_bytes(),
                },
            )
            .map_err(|_| CoreError::Auth)?;
        self.chain_key = next;
        self.counter += 1;
        Ok(plaintext)
    }

    /// Returns (message key, next chain key).
    fn step(&self) -> (Key32, Key32) {
        let hk = Hkdf::<Sha256>::from_prk(&self.chain_key.0).expect("32-byte PRK");
        let mut mk = [0u8; 32];
        let mut ck = [0u8; 32];
        hk.expand(b"message key", &mut mk).expect("len ok");
        hk.expand(b"next chain", &mut ck).expect("len ok");
        let out = (Key32(mk), Key32(ck));
        mk.zeroize();
        ck.zeroize();
        out
    }
}

fn nonce_for(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_in_order() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        for text in [&b"hi"[..], b"second", b""] {
            let m = a.seal(text).unwrap();
            assert_eq!(b.open(&m).unwrap(), text);
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        let mut m = a.seal(b"attack at dawn").unwrap();
        m.ciphertext[0] ^= 1;
        assert_eq!(b.open(&m), Err(CoreError::Auth));
    }

    #[test]
    fn replay_rejected() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        let m = a.seal(b"once").unwrap();
        assert!(b.open(&m).is_ok());
        assert_eq!(b.open(&m), Err(CoreError::Malformed));
    }
}
