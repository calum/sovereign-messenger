//! Symmetric-key ratchet over ChaCha20-Poly1305. Each message gets a fresh key
//! and the chain key is advanced irreversibly, so earlier messages stay sealed
//! even if a later chain key leaks (forward secrecy within a chain).
//!
//! Out-of-order delivery: when a message arrives ahead of the counter, the
//! message keys for the counters in between are kept in a bounded cache. Each
//! cached key is used once and zeroized on use, eviction or drop, so a later
//! copy of a skipped message can still be read, and a replay cannot be.
//!
//! The DH step that gives post-compromise security is in `double_ratchet.rs`.
//! `Chain` is one direction with no DH step.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::secret::Key32;

/// Largest number of counters one receive may skip, so a forged large counter
/// cannot make the receiver derive an unbounded number of keys. Chosen to fit a
/// burst of messages lost on a LAN link. Documented in PLAN.md (2026-10-24).
pub const MAX_SKIP: u64 = 100;

/// Most skipped message keys held at once, per cache. When full, the oldest key
/// is evicted and zeroized. Equal to `MAX_SKIP`, so one full skip fits.
pub const MAX_CACHED_KEYS: usize = 100;

/// Skipped message keys, each tagged with its chain (`K`) and counter. The keys
/// are wiped on eviction, on removal after use, and on drop.
pub(crate) struct SkipCache<K> {
    entries: Vec<(K, u64, Key32)>,
}

impl<K: PartialEq + Copy> SkipCache<K> {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn get(&self, chain: &K, n: u64) -> Option<&Key32> {
        self.entries
            .iter()
            .find(|(c, m, _)| c == chain && *m == n)
            .map(|(_, _, mk)| mk)
    }

    /// Removes the key for `(chain, n)`. The removed key is zeroized when dropped.
    pub(crate) fn remove(&mut self, chain: &K, n: u64) {
        if let Some(i) = self
            .entries
            .iter()
            .position(|(c, m, _)| c == chain && *m == n)
        {
            drop(self.entries.remove(i));
        }
    }

    pub(crate) fn insert(&mut self, chain: K, n: u64, mk: Key32) {
        if self.entries.len() >= MAX_CACHED_KEYS {
            let (_, _, mut oldest) = self.entries.remove(0);
            oldest.zeroize();
        }
        self.entries.push((chain, n, mk));
    }

    pub(crate) fn insert_all(&mut self, chain: K, keys: Vec<(u64, Key32)>) {
        for (n, mk) in keys {
            self.insert(chain, n, mk);
        }
    }

    #[cfg(test)]
    pub(crate) fn all_zero(&self) -> bool {
        self.entries.iter().all(|(_, _, mk)| mk.0 == [0u8; 32])
    }
}

impl<K> SkipCache<K> {
    /// Overwrites every cached key with zeros in place. Run on drop; the entries
    /// are then freed with the vector.
    pub(crate) fn zeroize_in_place(&mut self) {
        for (_, _, mk) in self.entries.iter_mut() {
            mk.zeroize();
        }
    }
}

impl<K> Drop for SkipCache<K> {
    fn drop(&mut self) {
        self.zeroize_in_place();
    }
}

/// A position in one KDF chain: the chain key for message `n`.
pub(crate) struct Position {
    pub(crate) ck: Key32,
    pub(crate) n: u64,
}

pub struct Chain {
    pos: Position,
    skipped: SkipCache<()>,
}

pub struct Message {
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

impl Chain {
    /// One direction of traffic. Both peers call this with the same root and
    /// label: the sender seals with it, the receiver opens with it.
    pub fn new(root: &Key32, label: &[u8]) -> Chain {
        Chain {
            pos: Position {
                ck: derive_chain(root, label),
                n: 0,
            },
            skipped: SkipCache::new(),
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Message, CoreError> {
        let counter = self.pos.n;
        let next_n = counter.checked_add(1).ok_or(CoreError::Malformed)?;
        let (mk, next) = step(&self.pos.ck);
        let ciphertext = aead_seal(&mk, &counter.to_be_bytes(), counter, plaintext)?;
        self.pos = Position {
            ck: next,
            n: next_n,
        };
        Ok(Message {
            counter,
            ciphertext,
        })
    }

    /// Opens a message. A counter behind the chain is read from the skipped-key
    /// cache and the key is consumed on success. A counter ahead of the chain
    /// caches the keys in between, up to `MAX_SKIP`. A failed open changes nothing.
    pub fn open(&mut self, msg: &Message) -> Result<Vec<u8>, CoreError> {
        let aad = msg.counter.to_be_bytes();
        if msg.counter < self.pos.n {
            let mk = self
                .skipped
                .get(&(), msg.counter)
                .ok_or(CoreError::Malformed)?;
            let plaintext = aead_open(mk, &aad, msg.counter, &msg.ciphertext)?;
            self.skipped.remove(&(), msg.counter);
            return Ok(plaintext);
        }
        let (skipped, at) = advance(&self.pos, msg.counter)?;
        let (mk, next) = step(&at.ck);
        let plaintext = aead_open(&mk, &aad, msg.counter, &msg.ciphertext)?;
        self.pos = Position {
            ck: next,
            n: msg.counter.checked_add(1).ok_or(CoreError::Malformed)?,
        };
        self.skipped.insert_all((), skipped);
        Ok(plaintext)
    }
}

/// Derives the chain key for one direction from the root key.
pub(crate) fn derive_chain(root: &Key32, label: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::from_prk(&root.0).expect("32-byte PRK");
    let mut ck = [0u8; 32];
    hk.expand(label, &mut ck).expect("len ok");
    let out = Key32(ck);
    ck.zeroize();
    out
}

/// Derives (message key, next chain key) from a chain key. The caller wipes both
/// after use; the `Key32` values zeroize on drop.
pub(crate) fn step(ck: &Key32) -> (Key32, Key32) {
    let hk = Hkdf::<Sha256>::from_prk(&ck.0).expect("32-byte PRK");
    let mut mk = [0u8; 32];
    let mut next = [0u8; 32];
    hk.expand(b"message key", &mut mk).expect("len ok");
    hk.expand(b"next chain", &mut next).expect("len ok");
    let out = (Key32(mk), Key32(next));
    mk.zeroize();
    next.zeroize();
    out
}

/// Keys for counters `[pos.n, target)`, and the position at `target`. Refuses a
/// target behind the chain, or a gap larger than `MAX_SKIP`, before deriving anything.
pub(crate) fn advance(
    pos: &Position,
    target: u64,
) -> Result<(Vec<(u64, Key32)>, Position), CoreError> {
    if target < pos.n || target - pos.n > MAX_SKIP {
        return Err(CoreError::Malformed);
    }
    let mut ck = Key32(pos.ck.0);
    let mut n = pos.n;
    let mut skipped = Vec::new();
    while n < target {
        let (mk, next) = step(&ck);
        skipped.push((n, mk));
        ck = next;
        n += 1;
    }
    Ok((skipped, Position { ck, n }))
}

/// Seals with a message key. The associated data binds the frame header, so the
/// header cannot be changed without failing authentication.
pub(crate) fn aead_seal(
    mk: &Key32,
    aad: &[u8],
    n: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&mk.0).map_err(|_| CoreError::Malformed)?;
    cipher
        .encrypt(
            &nonce_for(n),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::Auth)
}

/// Opens with a message key. Any failure is `CoreError::Auth` and carries no content.
pub(crate) fn aead_open(
    mk: &Key32,
    aad: &[u8],
    n: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&mk.0).map_err(|_| CoreError::Malformed)?;
    cipher
        .decrypt(
            &nonce_for(n),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::Auth)
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

    fn seal_n(a: &mut Chain, n: usize) -> Vec<Message> {
        (0..n).map(|i| a.seal(&[i as u8; 4]).unwrap()).collect()
    }

    #[test]
    fn out_of_order_delivery_decrypts() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        let msgs = seal_n(&mut a, 3);
        assert_eq!(b.open(&msgs[2]).unwrap(), vec![2u8; 4]);
        assert_eq!(b.open(&msgs[0]).unwrap(), vec![0u8; 4]);
        assert_eq!(b.open(&msgs[1]).unwrap(), vec![1u8; 4]);
        // The chain itself moved on: the next in-order message still works.
        let next = a.seal(b"after").unwrap();
        assert_eq!(b.open(&next).unwrap(), b"after".to_vec());
    }

    #[test]
    fn replayed_out_of_order_message_is_rejected() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        let msgs = seal_n(&mut a, 3);
        assert!(b.open(&msgs[2]).is_ok());
        assert_eq!(b.open(&msgs[2]), Err(CoreError::Malformed));
        assert!(b.open(&msgs[0]).is_ok());
        // Used once: the skipped key was consumed by the first decryption.
        assert_eq!(b.open(&msgs[0]), Err(CoreError::Malformed));
    }

    #[test]
    fn skipping_beyond_the_cap_is_rejected() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        let msgs = seal_n(&mut a, MAX_SKIP as usize + 2);
        // Counter 101 would skip 101 keys (0..=100): over the cap of 100.
        assert_eq!(
            b.open(&msgs[MAX_SKIP as usize + 1]),
            Err(CoreError::Malformed)
        );
        // Refusing it must not advance the chain, so exactly 100 skips still work.
        assert!(b.open(&msgs[MAX_SKIP as usize]).is_ok());
    }

    #[test]
    fn tampered_out_of_order_message_is_rejected_and_does_not_burn_its_key() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        let msgs = seal_n(&mut a, 2);
        assert!(b.open(&msgs[1]).is_ok());
        let mut forged = Message {
            counter: msgs[0].counter,
            ciphertext: msgs[0].ciphertext.clone(),
        };
        forged.ciphertext[0] ^= 1;
        assert_eq!(b.open(&forged), Err(CoreError::Auth));
        // The attacker's failed attempt must not consume the genuine key.
        assert!(b.open(&msgs[0]).is_ok());
    }

    #[test]
    fn cache_is_bounded_and_evicts_the_oldest_key() {
        let root = Key32([9u8; 32]);
        let mut a = Chain::new(&root, b"i->r");
        let mut b = Chain::new(&root, b"i->r");
        let msgs = seal_n(&mut a, 151);
        // Skip 0..=99 (cache full at 100 keys), then skip 100..=148 (49 more).
        assert!(b.open(&msgs[100]).is_ok());
        assert!(b.open(&msgs[149]).is_ok());
        // Key 0 was the oldest and has been evicted.
        assert_eq!(b.open(&msgs[0]), Err(CoreError::Malformed));
        // A recent skipped key survived eviction.
        assert!(b.open(&msgs[49]).is_ok());
    }

    #[test]
    fn skip_cache_wipe_zeroizes_every_stored_key() {
        let mut cache = SkipCache::<()>::new();
        cache.insert((), 0, Key32([0xAA; 32]));
        cache.insert((), 1, Key32([0xBB; 32]));
        cache.zeroize_in_place();
        assert!(cache.all_zero());
    }
}
