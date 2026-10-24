//! Hybrid key agreement: X25519 + ML-KEM-768 (FIPS 203), with static-static DH
//! between the two long-term X25519 identity keys.
//! Three secrets feed one HKDF: the ephemeral DH, the ML-KEM secret, and the
//! static DH. The ML-KEM part defeats store-now-decrypt-later. The static DH
//! authenticates the initiator: only the holder of the initiator's identity key
//! can compute it, so a responder that checks the initiator's static key against
//! its pin refuses everyone else.
//!
//! Freshness: the responder first sends a random challenge. The initiator binds
//! it into the root and into a key-confirmation tag (HMAC-SHA256 keyed with the
//! root). A captured handshake replayed later carries an old challenge, so its
//! tag fails here and no session is stored. The tag adds no authentication beyond
//! the static DH: it proves only that the initiator derived the same root.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, FromSeed, Kem, KeyExport, TryKeyInit};
use ml_kem::{MlKem768, B32};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::secret::Key32;

type DecapKey = <MlKem768 as Kem>::DecapsulationKey;
type EncapKey = <MlKem768 as Kem>::EncapsulationKey;
type HmacSha256 = Hmac<Sha256>;

const ROOT_INFO: &[u8] = b"sovereign-p2p v1 root";
/// Labels the static-static DH input inside the HKDF input keying material, so
/// it cannot be confused with the ephemeral DH or the ML-KEM secret.
const STATIC_DH_LABEL: &[u8] = b"sovereign-p2p v1 static dh";
/// Labels the responder's challenge inside the HKDF input, so a root derived with
/// one challenge cannot be confused with a root derived with another.
const CHALLENGE_LABEL: &[u8] = b"sovereign-p2p v1 challenge";
/// Domain label for the key-confirmation tag, so the MAC is not valid for any other input.
const CONFIRM_LABEL: &[u8] = b"sovereign-p2p v1 key confirmation";

/// Length of the responder's challenge, in bytes.
pub const CHALLENGE_LEN: usize = 32;
/// Length of the key-confirmation tag, in bytes (HMAC-SHA256 output).
pub const TAG_LEN: usize = 32;

/// Public identity carried inside the QR code. Pinned on first contact (TOFU).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityPublic {
    pub x25519: [u8; 32],
    pub mlkem_ek: Vec<u8>,
}

/// Long-term identity secret. Lives only in RAM.
pub struct Identity {
    x25519: StaticSecret,
    mlkem_dk: DecapKey,
}

impl Identity {
    pub fn generate() -> (Self, IdentityPublic) {
        let x25519 = StaticSecret::random_from_rng(OsRng);
        let mut seed = [0u8; 64];
        random_fill(&mut seed);
        let (dk, ek) = MlKem768::from_seed(&seed.into());
        seed.zeroize();
        let public = IdentityPublic {
            x25519: PublicKey::from(&x25519).to_bytes(),
            mlkem_ek: ek.to_bytes().to_vec(),
        };
        (
            Self {
                x25519,
                mlkem_dk: dk,
            },
            public,
        )
    }
}

/// Sent by the initiator: ephemeral X25519 key, the initiator's long-term X25519
/// public key, the ML-KEM ciphertext, and the key-confirmation tag. All public values.
#[derive(Clone, Debug)]
pub struct HandshakeInit {
    pub ephemeral_x25519: [u8; 32],
    pub initiator_x25519: [u8; 32],
    pub mlkem_ct: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

/// A fresh random challenge for one handshake. The responder issues it before the
/// initiator speaks, and it is never reused.
pub fn new_challenge() -> [u8; CHALLENGE_LEN] {
    let mut c = [0u8; CHALLENGE_LEN];
    random_fill(&mut c);
    c
}

/// Initiator side. Takes the responder's challenge for this handshake. Returns the
/// message to send and the derived root key.
pub fn initiate(
    me: &Identity,
    peer: &IdentityPublic,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<(HandshakeInit, Key32), CoreError> {
    let eph = StaticSecret::random_from_rng(OsRng);
    let mut m: B32 = [0u8; 32].into();
    random_fill(&mut m);
    let out = initiate_with(&me.x25519, peer, &eph, &m, challenge);
    m.zeroize();
    out
}

/// The initiator's steps with the randomness supplied, so a test can hold the
/// ephemeral key and the ML-KEM coins fixed and vary only the static key.
fn initiate_with(
    me_static: &StaticSecret,
    peer: &IdentityPublic,
    eph: &StaticSecret,
    m: &B32,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<(HandshakeInit, Key32), CoreError> {
    let ek = EncapKey::new_from_slice(&peer.mlkem_ek).map_err(|_| CoreError::Malformed)?;
    let (ct, mut ss) = ek.encapsulate_deterministic(m);

    let mut eph_dh = eph.diffie_hellman(&PublicKey::from(peer.x25519));
    let mut static_dh = me_static.diffie_hellman(&PublicKey::from(peer.x25519));

    let root = derive_root(
        eph_dh.as_bytes(),
        ss.as_slice(),
        static_dh.as_bytes(),
        challenge,
    );
    eph_dh.zeroize();
    static_dh.zeroize();
    ss.zeroize();

    let ephemeral_x25519 = PublicKey::from(eph).to_bytes();
    let initiator_x25519 = PublicKey::from(me_static).to_bytes();
    let mlkem_ct = ct.as_slice().to_vec();
    let tag = confirmation_mac(
        &root,
        &ephemeral_x25519,
        &initiator_x25519,
        &mlkem_ct,
        challenge,
    )
    .finalize()
    .into_bytes();
    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(&tag);

    let init = HandshakeInit {
        ephemeral_x25519,
        initiator_x25519,
        mlkem_ct,
        tag: tag_bytes,
    };
    Ok((init, root))
}

/// Responder side. The caller passes the X25519 key pinned for this peer and the
/// challenge it issued for this handshake. The handshake is refused with
/// `CoreError::Auth` unless the initiator's static key equals that pin, and unless
/// the confirmation tag verifies under the root derived with that challenge. A
/// replayed handshake fails the tag, so no root is returned for it.
pub fn respond(
    me: &Identity,
    pinned_initiator: &[u8; 32],
    init: &HandshakeInit,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<Key32, CoreError> {
    // Checked before any decapsulation: a stranger is refused at the pin, and the
    // ML-KEM and DH work is never done for it.
    if init.initiator_x25519 != *pinned_initiator {
        return Err(CoreError::Auth);
    }
    let mut ss = me
        .mlkem_dk
        .decapsulate_slice(&init.mlkem_ct)
        .map_err(|_| CoreError::Malformed)?;

    let mut eph_dh = me
        .x25519
        .diffie_hellman(&PublicKey::from(init.ephemeral_x25519));
    let mut static_dh = me
        .x25519
        .diffie_hellman(&PublicKey::from(init.initiator_x25519));

    let root = derive_root(
        eph_dh.as_bytes(),
        ss.as_slice(),
        static_dh.as_bytes(),
        challenge,
    );
    eph_dh.zeroize();
    static_dh.zeroize();
    ss.zeroize();

    // Constant-time comparison (hmac's verify_slice). Checked before the root is returned,
    // so a replayed or altered handshake never yields a root the caller can store.
    confirmation_mac(
        &root,
        &init.ephemeral_x25519,
        &init.initiator_x25519,
        &init.mlkem_ct,
        challenge,
    )
    .verify_slice(&init.tag)
    .map_err(|_| CoreError::Auth)?;
    Ok(root)
}

/// The keyed MAC over the public handshake values and the challenge. Keyed with the
/// root, so only a party that derived the same root can produce the tag.
fn confirmation_mac(
    root: &Key32,
    ephemeral: &[u8; 32],
    initiator: &[u8; 32],
    mlkem_ct: &[u8],
    challenge: &[u8; CHALLENGE_LEN],
) -> HmacSha256 {
    // HMAC accepts a key of any length, so this cannot fail for a 32-byte root.
    let mut mac = HmacSha256::new_from_slice(&root.0).expect("HMAC takes any key length");
    mac.update(CONFIRM_LABEL);
    mac.update(ephemeral);
    mac.update(initiator);
    mac.update(mlkem_ct);
    mac.update(challenge);
    mac
}

fn random_fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS randomness unavailable");
}

/// Concatenates the DH and KEM outputs and the challenge in a fixed order and runs
/// HKDF. The static DH and the challenge are each preceded by their label so they
/// are tagged inputs. Every input has a fixed length, so the concatenation is
/// unambiguous. The challenge makes the root depend on this handshake only.
fn derive_root(eph_dh: &[u8], ss: &[u8], static_dh: &[u8], challenge: &[u8]) -> Key32 {
    let mut ikm = Vec::with_capacity(
        eph_dh.len()
            + ss.len()
            + STATIC_DH_LABEL.len()
            + static_dh.len()
            + CHALLENGE_LABEL.len()
            + challenge.len(),
    );
    ikm.extend_from_slice(eph_dh);
    ikm.extend_from_slice(ss);
    ikm.extend_from_slice(STATIC_DH_LABEL);
    ikm.extend_from_slice(static_dh);
    ikm.extend_from_slice(CHALLENGE_LABEL);
    ikm.extend_from_slice(challenge);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(ROOT_INFO, &mut out)
        .expect("32 bytes is a valid HKDF length");
    ikm.zeroize();
    let key = Key32(out);
    out.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::probe::{NoClone, NoDebug, Probe};

    #[test]
    fn identity_secrets_have_no_debug_or_clone() {
        // A derived Debug would print the X25519 secret and the ML-KEM seed.
        {
            let value = Probe::<Identity>::DEBUG;
            assert!(!value);
        }
        {
            let value = Probe::<Identity>::CLONE;
            assert!(!value);
        }
    }

    #[test]
    fn both_sides_derive_same_root() {
        let (bob, bob_pub) = Identity::generate();
        let (alice, alice_pub) = Identity::generate();
        let c = new_challenge();
        let (init, root_a) = initiate(&alice, &bob_pub, &c).unwrap();
        let root_b = respond(&bob, &alice_pub.x25519, &init, &c).unwrap();
        assert_eq!(root_a.0, root_b.0);
    }

    #[test]
    fn wrong_responder_identity_is_refused_by_the_confirmation_tag() {
        let (_real, public) = Identity::generate();
        let (alice, alice_pub) = Identity::generate();
        let (impostor, _) = Identity::generate();
        let c = new_challenge();
        let (init, _root_a) = initiate(&alice, &public, &c).unwrap();
        // The impostor derives a different root, so the tag fails and no root is returned.
        assert_eq!(
            respond(&impostor, &alice_pub.x25519, &init, &c).err(),
            Some(CoreError::Auth)
        );
    }

    #[test]
    fn same_ephemeral_and_kem_coins_with_other_static_key_derive_other_root() {
        let (_bob, bob_pub) = Identity::generate();
        let (alice, _) = Identity::generate();
        let (mallory, _) = Identity::generate();
        let eph = StaticSecret::random_from_rng(OsRng);
        let m: B32 = [7u8; 32].into();
        let c = [1u8; CHALLENGE_LEN];

        let (init_a, root_a) = initiate_with(&alice.x25519, &bob_pub, &eph, &m, &c).unwrap();
        let (init_m, root_m) = initiate_with(&mallory.x25519, &bob_pub, &eph, &m, &c).unwrap();
        assert_eq!(init_a.ephemeral_x25519, init_m.ephemeral_x25519);
        assert_eq!(init_a.mlkem_ct, init_m.mlkem_ct);
        assert_ne!(init_a.initiator_x25519, init_m.initiator_x25519);
        assert_ne!(root_a.0, root_m.0);
    }

    #[test]
    fn responder_with_real_kem_key_but_other_static_key_derives_other_root() {
        let (real, public) = Identity::generate();
        let (alice, alice_pub) = Identity::generate();
        let c = new_challenge();
        let (init, _root_a) = initiate(&alice, &public, &c).unwrap();
        // Same ML-KEM decapsulation key, different X25519 static key: only the
        // static DH can tell these two responders apart, and the tag catches it.
        let half_wrong = Identity {
            x25519: StaticSecret::random_from_rng(OsRng),
            mlkem_dk: real.mlkem_dk,
        };
        assert_eq!(
            respond(&half_wrong, &alice_pub.x25519, &init, &c).err(),
            Some(CoreError::Auth)
        );
    }
}
