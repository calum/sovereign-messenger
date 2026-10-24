//! Hybrid key agreement: X25519 + ML-KEM-768 (FIPS 203).
//! Both shared secrets feed one HKDF, so the session stays secret if either
//! primitive is broken. The ML-KEM part is what defeats store-now-decrypt-later.

use hkdf::Hkdf;
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

const ROOT_INFO: &[u8] = b"sovereign-p2p v1 root";

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

/// Sent by the initiator: ephemeral X25519 key plus the ML-KEM ciphertext.
#[derive(Clone, Debug)]
pub struct HandshakeInit {
    pub ephemeral_x25519: [u8; 32],
    pub mlkem_ct: Vec<u8>,
}

/// Initiator side. Returns the message to send and the derived root key.
pub fn initiate(peer: &IdentityPublic) -> Result<(HandshakeInit, Key32), CoreError> {
    let ek = EncapKey::new_from_slice(&peer.mlkem_ek).map_err(|_| CoreError::Malformed)?;
    let mut m: B32 = [0u8; 32].into();
    random_fill(&mut m);
    let (ct, mut ss) = ek.encapsulate_deterministic(&m);
    m.zeroize();

    let eph = StaticSecret::random_from_rng(OsRng);
    let mut dh = eph.diffie_hellman(&PublicKey::from(peer.x25519));

    let root = derive_root(dh.as_bytes(), ss.as_slice());
    dh.zeroize();
    ss.zeroize();

    let init = HandshakeInit {
        ephemeral_x25519: PublicKey::from(&eph).to_bytes(),
        mlkem_ct: ct.as_slice().to_vec(),
    };
    Ok((init, root))
}

/// Responder side. Derives the same root key from the initiator's message.
pub fn respond(me: &Identity, init: &HandshakeInit) -> Result<Key32, CoreError> {
    let mut ss = me
        .mlkem_dk
        .decapsulate_slice(&init.mlkem_ct)
        .map_err(|_| CoreError::Malformed)?;

    let mut dh = me
        .x25519
        .diffie_hellman(&PublicKey::from(init.ephemeral_x25519));

    let root = derive_root(dh.as_bytes(), ss.as_slice());
    dh.zeroize();
    ss.zeroize();
    Ok(root)
}

fn random_fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS randomness unavailable");
}

fn derive_root(dh: &[u8], ss: &[u8]) -> Key32 {
    let mut ikm = Vec::with_capacity(dh.len() + ss.len());
    ikm.extend_from_slice(dh);
    ikm.extend_from_slice(ss);

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

    #[test]
    fn both_sides_derive_same_root() {
        let (me, public) = Identity::generate();
        let (init, root_a) = initiate(&public).unwrap();
        let root_b = respond(&me, &init).unwrap();
        assert_eq!(root_a.0, root_b.0);
    }

    #[test]
    fn wrong_identity_derives_different_root() {
        let (_real, public) = Identity::generate();
        let (impostor, _) = Identity::generate();
        let (init, root_a) = initiate(&public).unwrap();
        let root_b = respond(&impostor, &init).unwrap();
        assert_ne!(root_a.0, root_b.0);
    }
}
