//! UniFFI facade: the only surface Kotlin can call. Keys, chain state and
//! plaintext history stay in Rust. Kotlin gets public identity bytes, handshake
//! bytes, sealed wire bytes, and plaintext strings for display. It never gets a
//! private identity key, a chain key or a message key. Errors carry no content.
//!
//! One exception, by owner decision (2026-10-25): `data_key` hands Kotlin the
//! 32-byte vault key once, so the Android Keystore can wrap it, and `restore`
//! takes it back after a restart. While Kotlin holds it, the plaintext key sits on
//! the Java heap. The vault blob and the wrapped key are the only things Kotlin stores.
//!
//! Lock order: a session's send or receive lock may be held while taking the
//! state lock, never the reverse. A receive blocked on the socket holds only its
//! session's receive lock, so it cannot stall a send.

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use zeroize::Zeroize;

use crate::apk_transfer;
use crate::double_ratchet::{DoubleRatchet, Header, Message};
use crate::error::CoreError;
use crate::handshake::{self, Identity, IdentityPublic, CHALLENGE_LEN};
use crate::onion;
use crate::pairing;
use crate::secret::{Key32, SecretBytes};
use crate::store::Store;
use crate::transport::{TcpTransport, Transport};
use crate::update;
use crate::vault;
use crate::wire::{self, INITIATOR_TO_RESPONDER, RESPONDER_TO_INITIATOR};

/// Public identity, safe to show in a QR code. Holds no secret material.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PublicIdentity {
    pub x25519: Vec<u8>,
    pub mlkem_ek: Vec<u8>,
    /// Ed25519 public key of the onion service (32 bytes).
    pub onion: Vec<u8>,
}

/// First handshake message, sent by the initiator. Public values only.
#[derive(Clone, Debug, uniffi::Record)]
pub struct HandshakeMessage {
    pub ephemeral_x25519: Vec<u8>,
    /// The initiator's long-term X25519 public key. The responder checks it against its pin.
    pub initiator_x25519: Vec<u8>,
    pub mlkem_ct: Vec<u8>,
    /// Key-confirmation tag over the responder's challenge (32 bytes). Public.
    pub tag: Vec<u8>,
}

/// A peer whose identity was just pinned from a scanned QR code.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ScannedPeer {
    /// Shown to the user so they can compare it with the other phone.
    pub fingerprint: String,
    /// Local connection info from the QR code. Empty until a transport exists.
    pub connection_hint: String,
}

/// One sealed chat message as it goes over the wire. The first three fields are the
/// ratchet header; they are authenticated with the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct WireMessage {
    /// The sender's current ratchet public key (32 bytes).
    pub ratchet_public: Vec<u8>,
    /// Length of the sender's previous sending chain.
    pub previous_count: u64,
    /// Position of this message in the sending chain.
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

/// An update whose signature has checked out. Only this type reaches the install step.
#[derive(Clone, Debug, uniffi::Record)]
pub struct VerifiedUpdate {
    pub apk: Vec<u8>,
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
    /// The update is validly signed but not newer than the installed build. It is refused.
    #[error("update is older than or the same as the installed version")]
    Downgraded,
    #[error("no session with this peer")]
    NoSession,
    /// The peer's pinned key differs from the one offered. The new key is refused.
    /// The message names no key; the user must unpin the peer to accept a new one.
    #[error("pinned key changed; new key refused")]
    PinChanged,
    /// The same identity was scanned again for an already-pinned peer.
    #[error("identity already pinned")]
    DuplicatePin,
    /// Connecting needs the peer's identity from a scanned QR code first.
    #[error("no pinned identity for this peer")]
    NotPinned,
    /// The session exists but no network connection is open for it.
    #[error("no open connection to this peer")]
    NoLink,
    #[error("network error")]
    Network,
    #[error("internal state unavailable")]
    Internal,
}

impl From<CoreError> for FacadeError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Malformed => FacadeError::Malformed,
            CoreError::Auth | CoreError::BadSignature => FacadeError::AuthFailed,
            CoreError::Downgrade => FacadeError::Downgraded,
            CoreError::PinMismatch => FacadeError::PinChanged,
            CoreError::DuplicatePin => FacadeError::DuplicatePin,
            CoreError::Network => FacadeError::Network,
            CoreError::Lock => FacadeError::Internal,
        }
    }
}

/// How long `connect_peer` waits for the TCP connection to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct Session {
    /// Both directions and the DH ratchet state. Held only for the state change,
    /// never across a socket read.
    ratchet: Mutex<DoubleRatchet>,
    /// `None` for an in-process session with no network connection.
    link: Option<Arc<dyn Transport>>,
}

struct State {
    identity: Identity,
    public: IdentityPublic,
    sessions: HashMap<String, Arc<Session>>,
    /// Trust-on-first-use pins, keyed by the caller's peer label. Sealed into the
    /// vault by `export_vault`, never written in the clear.
    /// Survives `forget` and `wipe_all` so a later QR cannot replace a key.
    pins: HashMap<String, IdentityPublic>,
    store: Store,
    /// The peer a `listen_for_peer` call is waiting for, set only while it runs.
    /// Lets the UI show that a listener is up without a second source of truth.
    listening: Option<String>,
    /// The challenge last issued by `responder_challenge`. Spent by the next
    /// `accept_session`, whatever its outcome, so it cannot authenticate a second handshake.
    pending_challenge: Option<[u8; CHALLENGE_LEN]>,
    /// Key that seals the identity vault. `None` for a `new()` messenger, which
    /// has no vault. Zeroized on drop.
    data_key: Option<Key32>,
}

/// Collects the scanned QR parts of one pairing. Holds only public bytes.
/// Make a new one for each scan; a finished or abandoned set is never reused.
#[derive(uniffi::Object)]
pub struct PairingAssembler {
    inner: Mutex<pairing::Assembler>,
}

#[uniffi::export]
impl PairingAssembler {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(pairing::Assembler::new()),
        })
    }

    /// Adds one scanned part. Returns the full payload once every part is in;
    /// pass that to `Messenger::scan_pairing`. A refused part changes nothing.
    pub fn add_part(&self, part: Vec<u8>) -> Result<Option<Vec<u8>>, FacadeError> {
        let mut asm = self.inner.lock().map_err(|_| FacadeError::Internal)?;
        Ok(asm.add(&part)?)
    }

    /// Distinct parts accepted so far.
    pub fn received(&self) -> Result<u8, FacadeError> {
        let asm = self.inner.lock().map_err(|_| FacadeError::Internal)?;
        Ok(asm.received())
    }

    /// Parts in the set, or 0 before the first part.
    pub fn total(&self) -> Result<u8, FacadeError> {
        let asm = self.inner.lock().map_err(|_| FacadeError::Internal)?;
        Ok(asm.total())
    }
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
        Self::from_parts(identity, public, HashMap::new(), None)
    }

    /// A fresh identity with a fresh data key, for a first launch. The caller takes
    /// `data_key` once to have it wrapped, then stores `export_vault` after every pin change.
    #[uniffi::constructor]
    pub fn create_persistent() -> Arc<Self> {
        let (identity, public) = Identity::generate();
        Self::from_parts(
            identity,
            public,
            HashMap::new(),
            Some(vault::new_data_key()),
        )
    }

    /// Rebuilds the identity and pins from a stored vault. `AuthFailed` for a wrong
    /// key or any changed byte, `Malformed` for a short blob or a key that is not
    /// 32 bytes. Nothing is partly restored on a refusal. Sessions and messages
    /// are not in the vault, so the restored messenger starts with none.
    #[uniffi::constructor]
    pub fn restore(data_key: Vec<u8>, vault_blob: Vec<u8>) -> Result<Arc<Self>, FacadeError> {
        let key = Key32(to_array32(&data_key)?);
        let plain = vault::open(&key, &vault_blob)?;
        let (identity, public, pins) = vault::decode_contents(plain.expose())?;
        Ok(Self::from_parts(identity, public, pins, Some(key)))
    }

    /// The vault key, handed out once so Kotlin can wrap it with the Keystore.
    /// `Internal` for a messenger made with `new()`, which has no vault.
    pub fn data_key(&self) -> Result<Vec<u8>, FacadeError> {
        let st = self.lock()?;
        let key = st.data_key.as_ref().ok_or(FacadeError::Internal)?;
        Ok(key.0.to_vec())
    }

    /// The identity and pins sealed under the data key, fresh nonce each call.
    /// Call it after `scan_pairing`, `unpin` or any handshake that pins a new peer,
    /// and write the result to app-private storage excluded from backup.
    pub fn export_vault(&self) -> Result<Vec<u8>, FacadeError> {
        let st = self.lock()?;
        let key = st.data_key.as_ref().ok_or(FacadeError::Internal)?;
        let contents = vault::encode_contents(&st.identity, &st.pins)?;
        Ok(vault::seal(key, &contents)?)
    }

    pub fn own_identity(&self) -> Result<PublicIdentity, FacadeError> {
        let st = self.lock()?;
        Ok(PublicIdentity {
            x25519: st.public.x25519.to_vec(),
            mlkem_ek: st.public.mlkem_ek.clone(),
            onion: st.public.onion.to_vec(),
        })
    }

    /// This identity's v3 onion address, `<56 characters>.onion`. Stable across restarts
    /// because its key is part of the vault. Public: it is also in the QR code.
    pub fn own_onion_address(&self) -> Result<String, FacadeError> {
        let st = self.lock()?;
        Ok(onion::address(&st.public.onion))
    }

    /// The onion address pinned for `peer_id` from their scanned QR code, if any.
    pub fn pinned_onion_address(&self, peer_id: String) -> Result<Option<String>, FacadeError> {
        let st = self.lock()?;
        Ok(st.pins.get(&peer_id).map(|p| onion::address(&p.onion)))
    }

    /// Payload bytes for this identity's QR code. Rust builds the bytes; Kotlin only renders them.
    pub fn own_pairing_payload(&self, connection_hint: String) -> Result<Vec<u8>, FacadeError> {
        let st = self.lock()?;
        Ok(pairing::encode(&st.public, &connection_hint)?)
    }

    /// The QR parts for this identity, in order. Each part is one QR code; the
    /// scanner must collect all of them (see `PairingAssembler`) before pinning.
    pub fn own_pairing_parts(&self, connection_hint: String) -> Result<Vec<Vec<u8>>, FacadeError> {
        let st = self.lock()?;
        let payload = pairing::encode(&st.public, &connection_hint)?;
        Ok(pairing::split(&payload)?)
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

    /// Responder side, first step: issues a fresh challenge and remembers it as the
    /// one the next `accept_session` must answer. The caller sends these bytes to the
    /// initiator, who passes them to `start_session`. A new call replaces the old challenge.
    pub fn responder_challenge(&self) -> Result<Vec<u8>, FacadeError> {
        let challenge = handshake::new_challenge();
        self.lock()?.pending_challenge = Some(challenge);
        Ok(challenge.to_vec())
    }

    /// Initiator side: encapsulate to the peer's identity and open a session, bound to
    /// the responder's `challenge`. Pins the identity on first use; refuses a different
    /// key for a pinned peer.
    pub fn start_session(
        &self,
        peer_id: String,
        peer: PublicIdentity,
        challenge: Vec<u8>,
    ) -> Result<HandshakeMessage, FacadeError> {
        let peer = to_core_public(peer)?;
        let challenge = to_array32(&challenge)?;
        let mut st = self.lock()?;
        let (init, root) = handshake::initiate(&st.identity, &peer, &challenge)?;
        pin_or_check(&mut st, &peer_id, &peer)?;
        st.sessions.insert(
            peer_id,
            Arc::new(session_for(
                &root,
                INITIATOR_TO_RESPONDER,
                RESPONDER_TO_INITIATOR,
                None,
            )),
        );
        Ok(HandshakeMessage {
            ephemeral_x25519: init.ephemeral_x25519.to_vec(),
            initiator_x25519: init.initiator_x25519.to_vec(),
            mlkem_ct: init.mlkem_ct,
            tag: init.tag.to_vec(),
        })
    }

    /// Responder side: derive the same root from the initiator's handshake message.
    /// `challenge` must be the one `responder_challenge` issued, and it is spent by
    /// this call whatever the outcome. Refuses with `NotPinned` if `peer_id` has no
    /// pin, and with `AuthFailed` if the initiator's static key is not the pinned one,
    /// if the challenge is not the pending one, or if the confirmation tag does not
    /// verify. No session is stored on any refusal, so a replay leaves a live session alone.
    pub fn accept_session(
        &self,
        peer_id: String,
        init: HandshakeMessage,
        challenge: Vec<u8>,
    ) -> Result<(), FacadeError> {
        let challenge = to_array32(&challenge)?;
        let init = handshake::HandshakeInit {
            ephemeral_x25519: to_array32(&init.ephemeral_x25519)?,
            initiator_x25519: to_array32(&init.initiator_x25519)?,
            mlkem_ct: init.mlkem_ct,
            tag: to_array32(&init.tag)?,
        };
        let mut st = self.lock()?;
        let pinned = st.pins.get(&peer_id).ok_or(FacadeError::NotPinned)?.x25519;
        let issued = st.pending_challenge.take().ok_or(FacadeError::AuthFailed)?;
        if issued != challenge {
            return Err(FacadeError::AuthFailed);
        }
        let root = handshake::respond(&st.identity, &pinned, &init, &issued)?;
        st.sessions.insert(
            peer_id,
            Arc::new(session_for(
                &root,
                RESPONDER_TO_INITIATOR,
                INITIATOR_TO_RESPONDER,
                None,
            )),
        );
        Ok(())
    }

    /// Seals the text for the peer and records it locally, without a network send.
    /// `send_over_transport` is the path that transmits.
    pub fn send(&self, peer_id: String, text: String) -> Result<WireMessage, FacadeError> {
        let session = self.session(&peer_id)?;
        let sealed = lock_ratchet(&session.ratchet)?.seal(text.as_bytes())?;
        self.lock()?.store.push(&peer_id, text.as_bytes());
        Ok(wire_from_message(sealed))
    }

    /// Opens a message from the peer without a network receive. A tampered,
    /// replayed or out-of-order message is rejected and leaves the chain where it was.
    pub fn receive(&self, peer_id: String, msg: WireMessage) -> Result<(), FacadeError> {
        let session = self.session(&peer_id)?;
        let header = Header {
            dh: to_array32(&msg.ratchet_public)?,
            pn: msg.previous_count,
            n: msg.counter,
        };
        let mut plaintext = lock_ratchet(&session.ratchet)?.open(&Message {
            header,
            ciphertext: msg.ciphertext,
        })?;
        self.lock()?.store.push(&peer_id, &plaintext);
        plaintext.zeroize();
        Ok(())
    }

    /// Dials `addr` (for example `192.168.1.20:47001`) and runs the handshake
    /// with the identity pinned for `peer_id`. The socket stays open for the session.
    pub fn connect_peer(&self, peer_id: String, addr: String) -> Result<(), FacadeError> {
        // Refuse before dialing: an unpinned peer cannot be authenticated.
        self.lock()?
            .pins
            .get(&peer_id)
            .ok_or(FacadeError::NotPinned)?;
        let link: Arc<dyn Transport> = Arc::new(
            TcpTransport::connect(&addr, CONNECT_TIMEOUT).map_err(|_| FacadeError::Network)?,
        );
        self.initiate_on_link(peer_id, link)
    }

    /// Binds `bind_addr` and waits up to `timeout_secs` for one connection from any
    /// pinned contact. Returns the label of the contact whose long-term key the caller
    /// proved in the handshake; a caller whose key is not pinned is refused with
    /// `NotPinned` and no session is made. Blocks the calling thread.
    pub fn listen_for_any_peer(
        &self,
        bind_addr: String,
        timeout_secs: u32,
    ) -> Result<String, FacadeError> {
        let listener = TcpListener::bind(&bind_addr).map_err(|_| FacadeError::Network)?;
        let link: Arc<dyn Transport> = Arc::new(
            TcpTransport::accept(&listener, Duration::from_secs(u64::from(timeout_secs)))
                .map_err(|_| FacadeError::Network)?,
        );
        drop(listener); // one peer per listen call
        self.respond_on_link(link, None)
    }

    /// Binds `bind_addr` and waits up to `timeout_secs` for one peer to connect.
    /// Blocks the calling thread; the app runs it off the UI thread.
    pub fn listen_for_peer(
        &self,
        peer_id: String,
        bind_addr: String,
        timeout_secs: u32,
    ) -> Result<(), FacadeError> {
        // Refuse before binding: a peer with no pin cannot be authenticated.
        self.lock()?
            .pins
            .get(&peer_id)
            .ok_or(FacadeError::NotPinned)?;
        self.lock()?.listening = Some(peer_id.clone());
        let result = self.accept_one(peer_id, &bind_addr, timeout_secs);
        // Cleared on every exit, so a failed or timed-out listen never reads as "listening".
        if let Ok(mut st) = self.lock() {
            st.listening = None;
        }
        result
    }

    /// Peers whose session holds a live connection, sorted. An in-process session
    /// has no socket and is left out, so it never reads as connected.
    pub fn linked_peers(&self) -> Result<Vec<String>, FacadeError> {
        let st = self.lock()?;
        let mut peers: Vec<String> = st
            .sessions
            .iter()
            .filter(|(_, session)| session.link.is_some())
            .map(|(peer, _)| peer.clone())
            .collect();
        peers.sort();
        Ok(peers)
    }

    /// The peer a listener is waiting for, or `None` when no listener is up.
    pub fn listening_peer(&self) -> Result<Option<String>, FacadeError> {
        Ok(self.lock()?.listening.clone())
    }

    /// Seals `text` and sends it over the peer's open connection. Records it
    /// locally only after the frame has been handed to the socket.
    pub fn send_over_transport(&self, peer_id: String, text: String) -> Result<(), FacadeError> {
        let session = self.session(&peer_id)?;
        let link = session.link.clone().ok_or(FacadeError::NoLink)?;
        {
            let mut ratchet = lock_ratchet(&session.ratchet)?;
            wire::send_message(link.as_ref(), &mut ratchet, text.as_bytes())?;
        }
        self.lock()?.store.push(&peer_id, text.as_bytes());
        Ok(())
    }

    /// Waits for one message from the peer over its open connection. Returns
    /// `Ok(false)` if nothing arrived within the poll interval, so the caller can
    /// stop its loop; `Ok(true)` when a message was opened and stored.
    pub fn receive_from_peer(&self, peer_id: String) -> Result<bool, FacadeError> {
        let session = self.session(&peer_id)?;
        let link = session.link.clone().ok_or(FacadeError::NoLink)?;
        // The socket wait happens without the ratchet lock, so a send is not stalled.
        let Some(frame) = wire::receive_frame(link.as_ref())? else {
            return Ok(false);
        };
        let mut plaintext = {
            let mut ratchet = lock_ratchet(&session.ratchet)?;
            wire::open_frame(&mut ratchet, &frame)?
        };
        self.lock()?.store.push(&peer_id, &plaintext);
        plaintext.zeroize();
        Ok(true)
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

    /// Wipes all sessions and history, and closes their connections. The app
    /// calls this when it leaves the foreground. Pins are kept on purpose: a
    /// wiped pin would let a new QR code replace a trusted key.
    pub fn wipe_all(&self) -> Result<(), FacadeError> {
        let mut st = self.lock()?;
        st.store.wipe_all();
        st.sessions.clear();
        Ok(())
    }

    /// Fingerprint of the developer key compiled into this build, for the update
    /// screen. `None` when no key is pinned, in which case every update is refused.
    pub fn developer_key_fingerprint(&self) -> Option<String> {
        update::DEVELOPER_PUBLIC_KEY.map(|key| update::developer_key_fingerprint(&key))
    }

    /// Checks an APK's detached Ed25519 signature over `version` and `apk`, against the
    /// compiled-in developer key, and refuses a `version` not newer than
    /// `installed_version`. Refuses a signature that is not 64 bytes (`Malformed`),
    /// a bad one (`AuthFailed`), and an equal or older version (`Downgraded`).
    /// `installed_version` comes from the app's installed version code.
    pub fn verify_update(
        &self,
        apk: Vec<u8>,
        version: u64,
        signature: Vec<u8>,
        installed_version: u64,
    ) -> Result<(), FacadeError> {
        Ok(update::verify_update(
            &apk,
            version,
            &signature,
            installed_version,
        )?)
    }

    /// Listens on `bind_addr` (the update port is 47002) for one sender, reads one
    /// APK, and returns it only if its signature verifies over the version it
    /// carries and that version is newer than `installed_version`. Blocks; the app
    /// runs it off the UI thread. Nothing is written to disk here.
    pub fn receive_update(
        &self,
        bind_addr: String,
        timeout_secs: u32,
        installed_version: u64,
    ) -> Result<VerifiedUpdate, FacadeError> {
        let mut apk = Vec::new();
        let (version, signature) = apk_transfer::receive_update_on(
            &bind_addr,
            Duration::from_secs(u64::from(timeout_secs)),
            &mut apk,
        )?;
        update::verify_update(&apk, version, &signature, installed_version)?;
        Ok(VerifiedUpdate { apk })
    }

    /// Dials `addr` (the receiver's update port, 47002) and forwards one bundle:
    /// the APK, the developer's 64-byte Ed25519 signature over it, and the version.
    /// The phone never signs; the signature comes from the developer's PC. A
    /// signature that is not 64 bytes, or an APK that is empty or over
    /// `MAX_APK_LEN`, is refused as `Malformed` before any connection is opened.
    /// The receiver verifies the bundle itself, so a bad bundle is refused there.
    /// Nothing is written to disk and no APK byte appears in an error.
    pub fn send_update(
        &self,
        addr: String,
        timeout_secs: u32,
        apk: Vec<u8>,
        version: u64,
        signature: Vec<u8>,
    ) -> Result<(), FacadeError> {
        let sig: [u8; apk_transfer::SIGNATURE_LEN] = signature
            .as_slice()
            .try_into()
            .map_err(|_| FacadeError::Malformed)?;
        // The cap is the APK cap, not the 64 KiB control-frame cap: a real APK is far larger.
        if apk.is_empty() || apk.len() > apk_transfer::MAX_APK_LEN {
            return Err(FacadeError::Malformed);
        }
        Ok(apk_transfer::send_update_to(
            &addr,
            Duration::from_secs(u64::from(timeout_secs)),
            version,
            &sig,
            &apk,
        )?)
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
    fn from_parts(
        identity: Identity,
        public: IdentityPublic,
        pins: HashMap<String, IdentityPublic>,
        data_key: Option<Key32>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                identity,
                public,
                sessions: HashMap::new(),
                pins,
                store: Store::new(),
                listening: None,
                pending_challenge: None,
                data_key,
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, FacadeError> {
        // A poisoned lock means a panic happened mid-update. Refuse to continue
        // rather than read half-updated ratchet state.
        self.state.lock().map_err(|_| FacadeError::Internal)
    }

    fn session(&self, peer_id: &str) -> Result<Arc<Session>, FacadeError> {
        self.lock()?
            .sessions
            .get(peer_id)
            .cloned()
            .ok_or(FacadeError::NoSession)
    }

    /// Binds `bind_addr`, accepts one connection and runs the responder side of
    /// the handshake. Called only from `listen_for_peer`, which tracks the listener.
    fn accept_one(
        &self,
        peer_id: String,
        bind_addr: &str,
        timeout_secs: u32,
    ) -> Result<(), FacadeError> {
        let listener = TcpListener::bind(bind_addr).map_err(|_| FacadeError::Network)?;
        let link: Arc<dyn Transport> = Arc::new(
            TcpTransport::accept(&listener, Duration::from_secs(u64::from(timeout_secs)))
                .map_err(|_| FacadeError::Network)?,
        );
        drop(listener); // one peer per listen call
        self.respond_on_link(link, Some(&peer_id)).map(|_| ())
    }

    /// Initiator side of the handshake over an open link to the contact pinned as
    /// `peer_id`. The link stays open for the session. Shared by every carrier.
    pub(crate) fn initiate_on_link(
        &self,
        peer_id: String,
        link: Arc<dyn Transport>,
    ) -> Result<(), FacadeError> {
        // The responder speaks first with its challenge; the handshake is built on it.
        let challenge = wire::receive_challenge(link.as_ref())?;
        let (init, root) = {
            let st = self.lock()?;
            let peer = st.pins.get(&peer_id).ok_or(FacadeError::NotPinned)?;
            handshake::initiate(&st.identity, peer, &challenge)?
        };
        wire::send_handshake(link.as_ref(), &init)?;
        let session = session_for(
            &root,
            INITIATOR_TO_RESPONDER,
            RESPONDER_TO_INITIATOR,
            Some(link),
        );
        self.lock()?.sessions.insert(peer_id, Arc::new(session));
        Ok(())
    }

    /// Responder side of the handshake over an open link. With `expected` set, the
    /// caller must be that pinned contact. With `None`, the caller is whichever pinned
    /// contact owns the long-term key in its handshake, and an unknown key is `NotPinned`.
    /// Returns the contact's label. Shared by every carrier.
    pub(crate) fn respond_on_link(
        &self,
        link: Arc<dyn Transport>,
        expected: Option<&str>,
    ) -> Result<String, FacadeError> {
        // A fresh challenge per connection, sent before the initiator's handshake.
        // The handshake must answer this one, so a captured handshake from an earlier
        // connection fails its tag here and the live session is not replaced.
        let challenge = handshake::new_challenge();
        wire::send_challenge(link.as_ref(), &challenge)?;
        let init = wire::receive_handshake(link.as_ref())?;
        let mut st = self.lock()?;
        let peer_id = match expected {
            Some(label) => label.to_owned(),
            None => st
                .pins
                .iter()
                .find(|(_, pinned)| pinned.x25519 == init.initiator_x25519)
                .map(|(label, _)| label.clone())
                .ok_or(FacadeError::NotPinned)?,
        };
        let pinned = st.pins.get(&peer_id).ok_or(FacadeError::NotPinned)?.x25519;
        let root = handshake::respond(&st.identity, &pinned, &init, &challenge)?;
        let session = session_for(
            &root,
            RESPONDER_TO_INITIATOR,
            INITIATOR_TO_RESPONDER,
            Some(link),
        );
        st.sessions.insert(peer_id.clone(), Arc::new(session));
        Ok(peer_id)
    }
}

/// Pins `peer` under `peer_id` on first use; refuses a different key for a pinned peer.
fn pin_or_check(st: &mut State, peer_id: &str, peer: &IdentityPublic) -> Result<(), FacadeError> {
    match st.pins.get(peer_id) {
        Some(pinned) if pinned != peer => Err(FacadeError::PinChanged),
        Some(_) => Ok(()),
        None => {
            st.pins.insert(peer_id.to_owned(), peer.clone());
            Ok(())
        }
    }
}

fn lock_ratchet(
    ratchet: &Mutex<DoubleRatchet>,
) -> Result<MutexGuard<'_, DoubleRatchet>, FacadeError> {
    ratchet.lock().map_err(|_| FacadeError::Internal)
}

fn wire_from_message(msg: Message) -> WireMessage {
    WireMessage {
        ratchet_public: msg.header.dh.to_vec(),
        previous_count: msg.header.pn,
        counter: msg.header.n,
        ciphertext: msg.ciphertext,
    }
}

fn session_for(
    root: &Key32,
    send_label: &[u8],
    recv_label: &[u8],
    link: Option<Arc<dyn Transport>>,
) -> Session {
    Session {
        ratchet: Mutex::new(DoubleRatchet::new(root, send_label, recv_label)),
        link,
    }
}

fn to_core_public(p: PublicIdentity) -> Result<IdentityPublic, FacadeError> {
    Ok(IdentityPublic {
        x25519: to_array32(&p.x25519)?,
        mlkem_ek: p.mlkem_ek,
        onion: to_array32(&p.onion)?,
    })
}

fn to_array32(bytes: &[u8]) -> Result<[u8; 32], FacadeError> {
    bytes.try_into().map_err(|_| FacadeError::Malformed)
}

#[cfg(test)]
mod update_facade_tests {
    use super::*;
    use crate::secret::probe::{NoClone, NoDebug, Probe};

    #[test]
    fn messenger_has_no_debug_or_clone() {
        // Dropping the Messenger wipes every key and message, and a Debug print
        // would expose the state. Neither the object nor the Arc handed to Kotlin may print.
        {
            let value = Probe::<Messenger>::DEBUG;
            assert!(!value);
        }
        {
            let value = Probe::<Messenger>::CLONE;
            assert!(!value);
        }
    }

    #[test]
    fn facade_refuses_every_update_while_no_key_is_compiled_in() {
        let m = Messenger::new();
        assert_eq!(m.developer_key_fingerprint(), None);
        assert_eq!(
            m.verify_update(b"apk".to_vec(), 2, vec![0u8; 64], 1),
            Err(FacadeError::AuthFailed)
        );
    }
}
