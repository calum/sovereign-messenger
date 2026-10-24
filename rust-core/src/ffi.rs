//! UniFFI facade: the only surface Kotlin can call. Keys, chain state and
//! plaintext history stay in Rust. Kotlin gets public identity bytes, handshake
//! bytes, sealed wire bytes, and plaintext strings for display. It never gets a
//! private key, a chain key or a message key. Errors carry no content.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroize;

use crate::error::CoreError;
use crate::handshake::{self, HandshakeInit, Identity, IdentityPublic};
use crate::pairing;
use crate::ratchet::{Chain, Message};
use crate::secret::{Key32, SecretBytes};
use crate::store::Store;

/// Public identity, safe to show in a QR code. Holds no secret material.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PublicIdentity {
    pub x25519: Vec<u8>,
    pub mlkem_ek: Vec<u8>,
}

/// First handshake message, sent by the initiator. Public values only.
#[derive(Clone, Debug, uniffi::Record)]
pub struct HandshakeMessage {
    pub ephemeral_x25519: Vec<u8>,
    pub mlkem_ct: Vec<u8>,
}

/// A peer whose identity was just pinned from a scanned QR code.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ScannedPeer {
    /// Shown to the user so they can compare it with the other phone.
    pub fingerprint: String,
    /// Local connection info from the QR code. Empty until a transport exists.
    pub connection_hint: String,
}

/// One sealed chat message as it goes over the wire.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WireMessage {
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

/// Whether memory locking took effect. Counts and a boolean only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LockReport {
    /// True if a fresh 32-byte buffer could be `mlock`ed right now.
    pub probe_locked: bool,
    pub stored_total: u64,
    pub stored_locked: u64,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FacadeError {
    #[error("malformed input")]
    Malformed,
    #[error("authentication failed")]
    AuthFailed,
    #[error("no session with this peer")]
    NoSession,
    /// The peer's pinned key differs from the one offered. The new key is refused.
    /// The message names no key; the user must unpin the peer to accept a new one.
    #[error("pinned key changed; new key refused")]
    PinChanged,
    /// The same identity was scanned again for an already-pinned peer.
    #[error("identity already pinned")]
    DuplicatePin,
    #[error("internal state unavailable")]
    Internal,
}

impl From<CoreError> for FacadeError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Malformed => FacadeError::Malformed,
            CoreError::Auth | CoreError::BadSignature => FacadeError::AuthFailed,
            CoreError::PinMismatch => FacadeError::PinChanged,
            CoreError::DuplicatePin => FacadeError::DuplicatePin,
            CoreError::Lock => FacadeError::Internal,
        }
    }
}

/// Directional labels. Both peers derive the same two chains from the root;
/// the initiator sends on "i->r" and the responder sends on "r->i", so a
/// message can never be reflected back to its sender.
const INITIATOR_TO_RESPONDER: &[u8] = b"i->r";
const RESPONDER_TO_INITIATOR: &[u8] = b"r->i";

struct Session {
    send: Chain,
    recv: Chain,
}

struct State {
    identity: Identity,
    public: IdentityPublic,
    sessions: HashMap<String, Session>,
    /// Trust-on-first-use pins, keyed by the caller's peer label. RAM only.
    /// Survives `forget` and `wipe_all` so a later QR cannot replace a key.
    pins: HashMap<String, IdentityPublic>,
    store: Store,
}

/// One local user. Dropping it wipes every key and message it holds.
#[derive(uniffi::Object)]
pub struct Messenger {
    state: Mutex<State>,
}

#[uniffi::export]
impl Messenger {
    /// Generates a fresh identity in RAM. Nothing is persisted.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let (identity, public) = Identity::generate();
        Arc::new(Self {
            state: Mutex::new(State {
                identity,
                public,
                sessions: HashMap::new(),
                pins: HashMap::new(),
                store: Store::new(),
            }),
        })
    }

    pub fn own_identity(&self) -> Result<PublicIdentity, FacadeError> {
        let st = self.lock()?;
        Ok(PublicIdentity {
            x25519: st.public.x25519.to_vec(),
            mlkem_ek: st.public.mlkem_ek.clone(),
        })
    }

    /// Payload bytes for this identity's QR code. Rust builds the bytes; Kotlin only renders them.
    pub fn own_pairing_payload(&self, connection_hint: String) -> Result<Vec<u8>, FacadeError> {
        let st = self.lock()?;
        Ok(pairing::encode(&st.public, &connection_hint)?)
    }

    /// Fingerprint of this identity, shown so the two users can compare it in person.
    pub fn own_fingerprint(&self) -> Result<String, FacadeError> {
        let st = self.lock()?;
        Ok(pairing::fingerprint(&st.public))
    }

    /// Pins the identity in a scanned QR code for `peer_id` (trust on first use).
    /// Refuses a malformed payload, a different key for a pinned peer
    /// (`PinChanged`), and a second scan of the same key (`DuplicatePin`).
    pub fn scan_pairing(
        &self,
        peer_id: String,
        payload: Vec<u8>,
    ) -> Result<ScannedPeer, FacadeError> {
        let (public, connection_hint) = pairing::decode(&payload)?;
        let mut st = self.lock()?;
        match st.pins.get(&peer_id) {
            Some(pinned) if *pinned == public => Err(FacadeError::DuplicatePin),
            Some(_) => Err(FacadeError::PinChanged),
            None => {
                let fingerprint = pairing::fingerprint(&public);
                st.pins.insert(peer_id, public);
                Ok(ScannedPeer {
                    fingerprint,
                    connection_hint,
                })
            }
        }
    }

    /// Fingerprint of the identity pinned for `peer_id`, if any.
    pub fn pin_fingerprint(&self, peer_id: String) -> Result<Option<String>, FacadeError> {
        let st = self.lock()?;
        Ok(st.pins.get(&peer_id).map(pairing::fingerprint))
    }

    /// Peer labels with a pinned identity, sorted.
    pub fn pinned_peers(&self) -> Result<Vec<String>, FacadeError> {
        let st = self.lock()?;
        let mut peers: Vec<String> = st.pins.keys().cloned().collect();
        peers.sort();
        Ok(peers)
    }

    /// The user has checked the new key in person and accepts it. Drops the pin
    /// and any session for `peer_id`; the next scan or handshake pins again.
    pub fn unpin(&self, peer_id: String) -> Result<(), FacadeError> {
        let mut st = self.lock()?;
        st.pins.remove(&peer_id);
        st.sessions.remove(&peer_id);
        Ok(())
    }

    /// Initiator side: encapsulate to the peer's identity and open a session.
    /// Pins the identity on first use; refuses a different key for a pinned peer.
    pub fn start_session(
        &self,
        peer_id: String,
        peer: PublicIdentity,
    ) -> Result<HandshakeMessage, FacadeError> {
        let peer = to_core_public(peer)?;
        let (init, root) = handshake::initiate(&peer)?;
        let mut st = self.lock()?;
        match st.pins.get(&peer_id) {
            Some(pinned) if *pinned != peer => return Err(FacadeError::PinChanged),
            Some(_) => {}
            None => {
                st.pins.insert(peer_id.clone(), peer);
            }
        }
        st.sessions.insert(
            peer_id,
            session_for(&root, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR),
        );
        Ok(HandshakeMessage {
            ephemeral_x25519: init.ephemeral_x25519.to_vec(),
            mlkem_ct: init.mlkem_ct,
        })
    }

    /// Responder side: derive the same root from the initiator's handshake message.
    pub fn accept_session(
        &self,
        peer_id: String,
        init: HandshakeMessage,
    ) -> Result<(), FacadeError> {
        let init = HandshakeInit {
            ephemeral_x25519: to_array32(&init.ephemeral_x25519)?,
            mlkem_ct: init.mlkem_ct,
        };
        let mut st = self.lock()?;
        let root = handshake::respond(&st.identity, &init)?;
        st.sessions.insert(
            peer_id,
            session_for(&root, RESPONDER_TO_INITIATOR, INITIATOR_TO_RESPONDER),
        );
        Ok(())
    }

    /// Seals the text for the peer and records it locally. The returned wire
    /// message is what a transport would carry (no transport exists yet).
    pub fn send(&self, peer_id: String, text: String) -> Result<WireMessage, FacadeError> {
        let mut guard = self.lock()?;
        let st = &mut *guard;
        let session = st
            .sessions
            .get_mut(&peer_id)
            .ok_or(FacadeError::NoSession)?;
        let sealed = session.send.seal(text.as_bytes())?;
        st.store.push(&peer_id, text.as_bytes());
        Ok(WireMessage {
            counter: sealed.counter,
            ciphertext: sealed.ciphertext,
        })
    }

    /// Opens a message from the peer. A tampered, replayed or out-of-order
    /// message is rejected and leaves the chain where it was.
    pub fn receive(&self, peer_id: String, msg: WireMessage) -> Result<(), FacadeError> {
        let mut guard = self.lock()?;
        let st = &mut *guard;
        let session = st
            .sessions
            .get_mut(&peer_id)
            .ok_or(FacadeError::NoSession)?;
        let mut plaintext = session.recv.open(&Message {
            counter: msg.counter,
            ciphertext: msg.ciphertext,
        })?;
        st.store.push(&peer_id, &plaintext);
        plaintext.zeroize();
        Ok(())
    }

    /// Plaintext history for display, oldest first. Each string is a copy that
    /// Kotlin owns; the Rust copies are zeroized when the store drops them.
    pub fn history(&self, peer_id: String) -> Result<Vec<String>, FacadeError> {
        let st = self.lock()?;
        Ok(st
            .store
            .history(&peer_id)
            .into_iter()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect())
    }

    /// Peer ids with an open session, sorted.
    pub fn peers(&self) -> Result<Vec<String>, FacadeError> {
        let st = self.lock()?;
        let mut peers: Vec<String> = st.sessions.keys().cloned().collect();
        peers.sort();
        Ok(peers)
    }

    /// Ends one conversation and its ratchet state. The pin stays (see `unpin`).
    pub fn forget(&self, peer_id: String) -> Result<(), FacadeError> {
        let mut st = self.lock()?;
        st.store.forget(&peer_id);
        st.sessions.remove(&peer_id);
        Ok(())
    }

    /// Wipes all sessions and history. The app calls this when it leaves the foreground.
    /// Pins are kept on purpose: a wiped pin would let a new QR code replace a trusted key.
    pub fn wipe_all(&self) -> Result<(), FacadeError> {
        let mut st = self.lock()?;
        st.store.wipe_all();
        st.sessions.clear();
        Ok(())
    }

    /// Reports whether `mlock` took effect. The core cannot stop the OS from
    /// swapping unlocked pages, so the app needs this to tell the user.
    pub fn lock_report(&self) -> Result<LockReport, FacadeError> {
        let st = self.lock()?;
        let count = st.store.lock_count();
        let probe = SecretBytes::new(&[0u8; 32]);
        Ok(LockReport {
            probe_locked: probe.is_locked(),
            stored_total: count.total as u64,
            stored_locked: count.locked as u64,
        })
    }
}

impl Messenger {
    fn lock(&self) -> Result<MutexGuard<'_, State>, FacadeError> {
        // A poisoned lock means a panic happened mid-update. Refuse to continue
        // rather than read half-updated ratchet state.
        self.state.lock().map_err(|_| FacadeError::Internal)
    }
}

fn session_for(root: &Key32, send_label: &[u8], recv_label: &[u8]) -> Session {
    Session {
        send: Chain::new(root, send_label),
        recv: Chain::new(root, recv_label),
    }
}

fn to_core_public(p: PublicIdentity) -> Result<IdentityPublic, FacadeError> {
    Ok(IdentityPublic {
        x25519: to_array32(&p.x25519)?,
        mlkem_ek: p.mlkem_ek,
    })
}

fn to_array32(bytes: &[u8]) -> Result<[u8; 32], FacadeError> {
    bytes.try_into().map_err(|_| FacadeError::Malformed)
}
