//! Low-order X25519 points. A peer key of small order makes a Diffie-Hellman output
//! the same for every secret, so it would add nothing to the root. The QR decode and
//! both handshake sides must refuse such a key before any root is derived, with
//! `CoreError::Malformed` (the error carries no key material).

use rust_core::handshake::{self, Identity};
use rust_core::pairing;
use rust_core::CoreError;

const CH: [u8; 32] = [7u8; 32];

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Every encoding of a point of order dividing 8 that X25519 accepts: the five
/// canonical u-coordinates, their non-canonical forms below 2^255 (p, p+1), and each
/// of those with the unused top bit set (X25519 ignores bit 255).
fn low_order_points() -> Vec<[u8; 32]> {
    let mut base = vec![
        hex32("0000000000000000000000000000000000000000000000000000000000000000"),
        hex32("0100000000000000000000000000000000000000000000000000000000000000"),
        hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];
    let with_top_bit: Vec<[u8; 32]> = base
        .iter()
        .map(|p| {
            let mut q = *p;
            q[31] |= 0x80;
            q
        })
        .collect();
    base.extend(with_top_bit);
    base
}

#[test]
fn the_list_really_is_low_order() {
    // Guards the test data: each point gives an all-zero DH output.
    let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    for p in low_order_points() {
        let dh = secret.diffie_hellman(&x25519_dalek::PublicKey::from(p));
        assert!(!dh.was_contributory(), "{p:02x?} is not low order");
    }
}

#[test]
fn qr_decode_refuses_every_low_order_key() {
    let (_id, public) = Identity::generate();
    for p in low_order_points() {
        let mut bad = public.clone();
        bad.x25519 = p;
        let payload = pairing::encode(&bad, "hint").unwrap();
        assert_eq!(pairing::decode(&payload).err(), Some(CoreError::Malformed));
    }
}

#[test]
fn qr_decode_still_accepts_a_real_key() {
    let (_id, public) = Identity::generate();
    let payload = pairing::encode(&public, "hint").unwrap();
    assert!(pairing::decode(&payload).is_ok());
}

#[test]
fn initiate_refuses_a_low_order_responder_static_key() {
    let (alice, _) = Identity::generate();
    let (_bob, bob_pub) = Identity::generate();
    for p in low_order_points() {
        let mut bad = bob_pub.clone();
        bad.x25519 = p;
        assert_eq!(
            handshake::initiate(&alice, &bad, &CH).err(),
            Some(CoreError::Malformed)
        );
    }
}

#[test]
fn respond_refuses_a_low_order_ephemeral_key() {
    let (alice, alice_pub) = Identity::generate();
    let (bob, bob_pub) = Identity::generate();
    let (good, _) = handshake::initiate(&alice, &bob_pub, &CH).unwrap();
    for p in low_order_points() {
        let mut init = good.clone();
        init.ephemeral_x25519 = p;
        assert_eq!(
            handshake::respond(&bob, &alice_pub.x25519, &init, &CH).err(),
            Some(CoreError::Malformed)
        );
    }
}

#[test]
fn respond_refuses_a_low_order_initiator_static_key() {
    let (alice, _) = Identity::generate();
    let (bob, bob_pub) = Identity::generate();
    let (good, _) = handshake::initiate(&alice, &bob_pub, &CH).unwrap();
    for p in low_order_points() {
        let mut init = good.clone();
        init.initiator_x25519 = p;
        // Pinned to the same bad key, so the pin check passes and the DH check is reached.
        assert_eq!(
            handshake::respond(&bob, &p, &init, &CH).err(),
            Some(CoreError::Malformed)
        );
    }
}
