//! Double Ratchet: a DH ratchet on top of the symmetric chains in `ratchet.rs`.
//! A side that receives a new X25519 key from its peer generates a fresh key on
//! its next send and mixes the DH output into the root key. A chain key that
//! leaks is then useless once the peer has replied, so later messages recover
//! (post-compromise security). This is the standard Double Ratchet construction,
//! with one difference: the first messages use chains derived from the handshake
//! root, because there is no prekey, so a side can send before it has a peer key.
//! NOT independently reviewed.
//!
//! Security property: every header field is authenticated as AEAD associated
//! data, so a tampered header fails authentication and leaves the state
//! unchanged. A failed open or a failed write changes nothing. Message keys are
//! used once and zeroized on use, eviction and drop.
//!
//! Known limit: if both sides take a DH step before either sees the other's new
//! key, the two chains diverge. The receiver then refuses with `Auth`, and the
//! session must be re-handshaken.

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::ratchet::{advance, aead_open, aead_seal, derive_chain, step, Position, SkipCache};
use crate::secret::Key32;

/// Version of the ratchet frame. Bumped when the header layout changes.
pub const RATCHET_VERSION: u8 = 1;
/// Version, ratchet public key, previous chain length and counter, in that order.
pub const HEADER_LEN: usize = 1 + 32 + 8 + 8;

const RATCHET_INFO: &[u8] = b"sovereign-p2p v1 dh ratchet";

/// Header of one ratchet message. Every field is authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The sender's current ratchet public key.
    pub dh: [u8; 32],
    /// Length of the sender's previous sending chain. Lets the receiver keep
    /// the old chain's messages that were still in flight.
    pub pn: u64,
    /// Position of this message in the sending chain.
    pub n: u64,
}

pub struct Message {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

/// Canonical header bytes: version, key, pn, n. Used as associated data.
pub fn header_bytes(h: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = RATCHET_VERSION;
    out[1..33].copy_from_slice(&h.dh);
    out[33..41].copy_from_slice(&h.pn.to_be_bytes());
    out[41..49].copy_from_slice(&h.n.to_be_bytes());
    out
}

/// Parses header bytes. Refuses an unknown version or a wrong length.
pub fn header_from_bytes(bytes: &[u8]) -> Result<Header, CoreError> {
    if bytes.len() != HEADER_LEN || bytes[0] != RATCHET_VERSION {
        return Err(CoreError::Malformed);
    }
    let mut dh = [0u8; 32];
    dh.copy_from_slice(&bytes[1..33]);
    let mut pn = [0u8; 8];
    pn.copy_from_slice(&bytes[33..41]);
    let mut n = [0u8; 8];
    n.copy_from_slice(&bytes[41..49]);
    Ok(Header {
        dh,
        pn: u64::from_be_bytes(pn),
        n: u64::from_be_bytes(n),
    })
}

/// One peer's view of a conversation. Both directions share this state, because
/// a DH step on one direction changes the keys used by the other.
pub struct DoubleRatchet {
    root: Key32,
    /// Our current ratchet secret. Replaced on our next send after a peer key arrives.
    dh_self: StaticSecret,
    /// The peer's most recent ratchet public key, if one has arrived.
    dh_peer: Option<[u8; 32]>,
    /// True when a new peer key arrived since our last DH step, so our next send steps.
    pending: bool,
    send: Position,
    recv: Position,
    /// Length of our previous sending chain, sent in every header until the next step.
    pn_out: u64,
    /// Keys for skipped positions. Keyed by the peer key of the chain they belong to.
    skipped: SkipCache<[u8; 32]>,
}

/// State that a send produces. Applied only after the frame is written.
struct Staged {
    dh: Option<StaticSecret>,
    root: Option<Key32>,
    send: Position,
    pn_out: u64,
}

impl DoubleRatchet {
    /// `send_label` and `recv_label` name the two directions, so each side sends on
    /// the chain the other receives on.
    pub fn new(root: &Key32, send_label: &[u8], recv_label: &[u8]) -> Self {
        Self {
            root: Key32(root.0),
            dh_self: StaticSecret::random_from_rng(OsRng),
            dh_peer: None,
            pending: false,
            send: Position {
                ck: derive_chain(root, send_label),
                n: 0,
            },
            recv: Position {
                ck: derive_chain(root, recv_label),
                n: 0,
            },
            pn_out: 0,
            skipped: SkipCache::new(),
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Message, CoreError> {
        let (msg, staged) = self.prepare(plaintext)?;
        self.commit(staged);
        Ok(msg)
    }

    /// Seals and hands the frame to `emit`. State advances only if `emit` returns
    /// `Ok`, so a failed write leaves the peer's expected counter and key unchanged.
    pub fn seal_with<F>(&mut self, plaintext: &[u8], emit: F) -> Result<(), CoreError>
    where
        F: FnOnce(&Message) -> Result<(), CoreError>,
    {
        let (msg, staged) = self.prepare(plaintext)?;
        emit(&msg)?;
        self.commit(staged);
        Ok(())
    }

    fn prepare(&self, plaintext: &[u8]) -> Result<(Message, Staged), CoreError> {
        let stepping = self.pending;
        let fresh = if stepping {
            let peer = self.dh_peer.ok_or(CoreError::Malformed)?;
            let secret = StaticSecret::random_from_rng(OsRng);
            let mut shared = secret.diffie_hellman(&PublicKey::from(peer));
            let (root, ck) = kdf_root(&self.root, shared.as_bytes());
            shared.zeroize();
            Some((secret, root, Position { ck, n: 0 }))
        } else {
            None
        };

        let pn = if stepping { self.send.n } else { self.pn_out };
        let (dh_secret, root, pos) = match fresh {
            Some((secret, root, pos)) => (Some(secret), Some(root), pos),
            None => (
                None,
                None,
                Position {
                    ck: Key32(self.send.ck.0),
                    n: self.send.n,
                },
            ),
        };
        let dh = match &dh_secret {
            Some(secret) => PublicKey::from(secret).to_bytes(),
            None => PublicKey::from(&self.dh_self).to_bytes(),
        };

        let header = Header { dh, pn, n: pos.n };
        let (mk, next) = step(&pos.ck);
        let ciphertext = aead_seal(&mk, &header_bytes(&header), header.n, plaintext)?;
        let staged = Staged {
            dh: dh_secret,
            root,
            send: Position {
                ck: next,
                n: pos.n.checked_add(1).ok_or(CoreError::Malformed)?,
            },
            pn_out: pn,
        };
        Ok((Message { header, ciphertext }, staged))
    }

    fn commit(&mut self, staged: Staged) {
        if let (Some(secret), Some(root)) = (staged.dh, staged.root) {
            self.dh_self = secret;
            self.root = root;
            self.pending = false;
        }
        self.send = staged.send;
        self.pn_out = staged.pn_out;
    }

    /// Opens a message. Nothing changes unless the message authenticates.
    pub fn open(&mut self, msg: &Message) -> Result<Vec<u8>, CoreError> {
        let h = msg.header;

        // A key cached from an earlier position. It is used once; a failed open keeps it.
        if let Some(mk) = self.skipped.get(&h.dh, h.n) {
            let plaintext = aead_open(mk, &header_bytes(&h), h.n, &msg.ciphertext)?;
            self.skipped.remove(&h.dh, h.n);
            return Ok(plaintext);
        }

        if self.dh_peer == Some(h.dh) {
            return self.open_same_epoch(msg);
        }
        match self.dh_peer {
            Some(_) => self.open_new_epoch(msg),
            // No peer key yet. The message is either one the peer sent on the
            // handshake chain before it had our key, or the peer's first DH step.
            // Both are tried; each is authenticated, and state changes only on success.
            None => match self.open_same_epoch(msg) {
                Err(CoreError::Auth) => self.open_new_epoch(msg),
                other => other,
            },
        }
    }

    /// The peer's current key, or the first key seen from the handshake chain.
    fn open_same_epoch(&mut self, msg: &Message) -> Result<Vec<u8>, CoreError> {
        let h = msg.header;
        let (skipped, at) = advance(&self.recv, h.n)?;
        let (mk, next) = step(&at.ck);
        let plaintext = aead_open(&mk, &header_bytes(&h), h.n, &msg.ciphertext)?;
        self.recv = Position {
            ck: next,
            n: h.n.checked_add(1).ok_or(CoreError::Malformed)?,
        };
        if self.dh_peer.is_none() {
            self.dh_peer = Some(h.dh);
            self.pending = true;
        }
        self.skipped.insert_all(h.dh, skipped);
        Ok(plaintext)
    }

    /// A new peer key: a DH receive step. The old chain may still have messages in
    /// flight up to the peer's pn, so their keys are kept first. With no earlier
    /// peer key the old chain has no known key, so nothing is kept from it.
    fn open_new_epoch(&mut self, msg: &Message) -> Result<Vec<u8>, CoreError> {
        let h = msg.header;
        let aad = header_bytes(&h);
        let old = self.dh_peer;
        let old_skipped = match old {
            Some(_) if h.pn > self.recv.n => advance(&self.recv, h.pn)?.0,
            _ => Vec::new(),
        };
        let mut shared = self.dh_self.diffie_hellman(&PublicKey::from(h.dh));
        let (root, ck) = kdf_root(&self.root, shared.as_bytes());
        shared.zeroize();
        let fresh = Position { ck, n: 0 };
        let (skipped, at) = advance(&fresh, h.n)?;
        let (mk, next) = step(&at.ck);
        let plaintext = aead_open(&mk, &aad, h.n, &msg.ciphertext)?;

        self.root = root;
        self.recv = Position {
            ck: next,
            n: h.n.checked_add(1).ok_or(CoreError::Malformed)?,
        };
        self.dh_peer = Some(h.dh);
        self.pending = true;
        if let Some(old) = old {
            self.skipped.insert_all(old, old_skipped);
        }
        self.skipped.insert_all(h.dh, skipped);
        Ok(plaintext)
    }

    /// Test-only copy of the sending chain key, to model a leaked key.
    #[cfg(test)]
    pub(crate) fn send_chain_key_for_test(&self) -> [u8; 32] {
        self.send.ck.0
    }
}

/// Root KDF: HKDF-SHA256 with the root key as salt and the DH output as input.
/// Returns (new root key, new chain key). The label keeps it apart from the
/// handshake's root derivation.
fn kdf_root(root: &Key32, dh: &[u8]) -> (Key32, Key32) {
    let hk = Hkdf::<Sha256>::new(Some(&root.0), dh);
    let mut out = [0u8; 64];
    hk.expand(RATCHET_INFO, &mut out)
        .expect("64 bytes is a valid HKDF length");
    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    new_root.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..]);
    out.zeroize();
    let pair = (Key32(new_root), Key32(chain));
    new_root.zeroize();
    chain.zeroize();
    pair
}

#[cfg(test)]
mod tests {
    use super::*;

    const I2R: &[u8] = b"i->r";
    const R2I: &[u8] = b"r->i";

    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = Key32([4u8; 32]);
        (
            DoubleRatchet::new(&root, I2R, R2I),
            DoubleRatchet::new(&root, R2I, I2R),
        )
    }

    fn open_message_key(mk: &Key32, msg: &Message) -> Result<Vec<u8>, CoreError> {
        aead_open(
            mk,
            &header_bytes(&msg.header),
            msg.header.n,
            &msg.ciphertext,
        )
    }

    /// What an attacker holding `ck` can do: derive message keys forward and try
    /// each one on `msg`. Returns true if any opens it.
    fn stolen_key_opens(ck: [u8; 32], msg: &Message) -> bool {
        let mut ck = Key32(ck);
        for _ in 0..=50 {
            let (mk, next) = step(&ck);
            if open_message_key(&mk, msg).is_ok() {
                return true;
            }
            ck = next;
        }
        false
    }

    #[test]
    fn both_directions_alternate_and_decrypt() {
        let (mut a, mut b) = pair();
        for round in 0..3 {
            let text = format!("a{round}");
            let m = a.seal(text.as_bytes()).unwrap();
            assert_eq!(b.open(&m).unwrap(), text.into_bytes());
            let text = format!("b{round}");
            let m = b.seal(text.as_bytes()).unwrap();
            assert_eq!(a.open(&m).unwrap(), text.into_bytes());
        }
        let first = a.seal(b"x").unwrap();
        let second = a.seal(b"y").unwrap();
        assert_eq!(b.open(&second).unwrap(), b"y".to_vec());
        assert_eq!(b.open(&first).unwrap(), b"x".to_vec());
    }

    #[test]
    fn reply_after_receiving_carries_a_new_ratchet_key() {
        let (mut a, mut b) = pair();
        let m1 = a.seal(b"1").unwrap();
        b.open(&m1).unwrap();
        let m2 = b.seal(b"2").unwrap();
        a.open(&m2).unwrap();
        let m3 = a.seal(b"3").unwrap();
        assert_ne!(m3.header.dh, m1.header.dh);
        assert_eq!(m3.header.n, 0);
        assert_eq!(b.open(&m3).unwrap(), b"3".to_vec());
    }

    #[test]
    fn chain_key_copied_before_a_dh_step_cannot_open_later_messages() {
        let (mut a, mut b) = pair();
        let m1 = a.seal(b"a1").unwrap();
        b.open(&m1).unwrap();
        let m2 = b.seal(b"b1").unwrap();
        a.open(&m2).unwrap();
        let m3 = b.seal(b"b2").unwrap();
        a.open(&m3).unwrap();

        // The attacker copies Bob's sending chain key while it is still in the
        // epoch that Alice has already seen.
        let stolen = b.send_chain_key_for_test();
        let old_epoch = b.seal(b"b3").unwrap();
        // Control: the copied key does open a message from that same epoch.
        assert!(stolen_key_opens(stolen, &old_epoch));
        a.open(&old_epoch).unwrap();

        // Alice replies with a new ratchet key, and Bob steps again on his reply.
        let reply = a.seal(b"a2").unwrap();
        b.open(&reply).unwrap();
        let after_step = b.seal(b"b4").unwrap();
        assert_eq!(a.open(&after_step).unwrap(), b"b4".to_vec());

        assert!(!stolen_key_opens(stolen, &after_step));
    }

    #[test]
    fn tampered_header_is_rejected_and_state_is_unchanged() {
        let (mut a, mut b) = pair();
        let m1 = a.seal(b"1").unwrap();
        b.open(&m1).unwrap();
        let m2 = b.seal(b"2").unwrap();
        a.open(&m2).unwrap();
        let good = a.seal(b"3").unwrap();

        let mut dh_bit = Message {
            header: good.header,
            ciphertext: good.ciphertext.clone(),
        };
        dh_bit.header.dh[0] ^= 1;
        let mut pn_bit = Message {
            header: good.header,
            ciphertext: good.ciphertext.clone(),
        };
        pn_bit.header.pn ^= 1;
        let mut n_bit = Message {
            header: good.header,
            ciphertext: good.ciphertext.clone(),
        };
        n_bit.header.n ^= 1;

        assert_eq!(b.open(&dh_bit), Err(CoreError::Auth));
        assert_eq!(b.open(&pn_bit), Err(CoreError::Auth));
        assert_eq!(b.open(&n_bit), Err(CoreError::Auth));
        // The genuine message still opens: the failed attempts changed nothing.
        assert_eq!(b.open(&good).unwrap(), b"3".to_vec());
    }

    #[test]
    fn replayed_message_is_rejected() {
        let (mut a, mut b) = pair();
        let m1 = a.seal(b"once").unwrap();
        assert!(b.open(&m1).is_ok());
        assert_eq!(b.open(&m1), Err(CoreError::Malformed));

        let m2 = b.seal(b"reply").unwrap();
        a.open(&m2).unwrap();
        let m3 = a.seal(b"step").unwrap();
        b.open(&m3).unwrap();
        // m1 belongs to a finished epoch and its counter is used.
        assert!(b.open(&m1).is_err());
        assert_eq!(b.open(&m3), Err(CoreError::Malformed));
    }

    #[test]
    fn old_epoch_message_delivered_late_still_opens() {
        let (mut a, mut b) = pair();
        let m1 = a.seal(b"1").unwrap();
        let m2 = a.seal(b"2").unwrap();
        assert_eq!(b.open(&m2).unwrap(), b"2".to_vec());
        let r = b.seal(b"r").unwrap();
        a.open(&r).unwrap();
        let m3 = a.seal(b"3").unwrap();
        assert_eq!(b.open(&m3).unwrap(), b"3".to_vec());
        // m1 arrives after the DH step; its key was cached when m2 skipped it.
        assert_eq!(b.open(&m1).unwrap(), b"1".to_vec());
    }

    #[test]
    fn header_round_trips_and_wrong_version_is_refused() {
        let h = Header {
            dh: [3u8; 32],
            pn: 7,
            n: 9,
        };
        let mut bytes = header_bytes(&h).to_vec();
        assert_eq!(header_from_bytes(&bytes).unwrap(), h);
        bytes[0] = RATCHET_VERSION + 1;
        assert_eq!(header_from_bytes(&bytes), Err(CoreError::Malformed));
    }

    #[test]
    fn wrong_root_key_fails_authentication_on_the_first_message() {
        let mut a = DoubleRatchet::new(&Key32([1u8; 32]), I2R, R2I);
        let mut b = DoubleRatchet::new(&Key32([2u8; 32]), R2I, I2R);
        let m = a.seal(b"hello").unwrap();
        assert_eq!(b.open(&m), Err(CoreError::Auth));
    }
}
