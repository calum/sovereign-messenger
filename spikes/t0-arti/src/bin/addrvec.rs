//! Prints arti's own onion address for fixed Ed25519 seeds, so rust-core's address
//! code and key derivation can be checked against arti with no network. Spike only.
use safelog::DisplayRedacted;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};

fn main() {
    for seed in [[0u8; 32], [1u8; 32], [0x42u8; 32], std::array::from_fn(|i| i as u8)] {
        let kp = Keypair::from(&seed);
        let hsid_kp = HsIdKeypair::from(ExpandedKeypair::from(&kp));
        let hsid = HsIdKey::from(&hsid_kp).id();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        println!("{} {}", hex(&seed), hsid.display_unredacted());
    }
}
