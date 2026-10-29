//! Both sides sending at once must not desynchronise the ratchet.
//! Security property: a DH step needs the peer's newest key, so steps strictly
//! alternate and the two chains cannot diverge (no permanent `Auth` failures).

use std::collections::VecDeque;

use rust_core::double_ratchet::{DoubleRatchet, Message, Role};
use rust_core::secret::Key32;

const I2R: &[u8] = b"i->r";
const R2I: &[u8] = b"r->i";

fn pair() -> (DoubleRatchet, DoubleRatchet) {
    let root = Key32([9u8; 32]);
    (
        DoubleRatchet::new(&root, Role::Initiator, I2R, R2I),
        DoubleRatchet::new(&root, Role::Responder, R2I, I2R),
    )
}

#[test]
fn crossing_first_texts_then_crossing_acks_stay_in_sync() {
    let (mut a, mut b) = pair();
    let t1 = a.seal(b"t1").unwrap();
    let u1 = b.seal(b"u1").unwrap();
    assert_eq!(a.open(&u1).unwrap(), b"u1");
    assert_eq!(b.open(&t1).unwrap(), b"t1");
    // Both send again before either has seen the other's reply.
    let da = a.seal(b"da").unwrap();
    let db = b.seal(b"db").unwrap();
    assert_eq!(b.open(&da).unwrap(), b"da");
    assert_eq!(a.open(&db).unwrap(), b"db");

    for i in 0..10 {
        let m = a.seal(format!("a{i}").as_bytes()).unwrap();
        assert_eq!(b.open(&m).unwrap(), format!("a{i}").into_bytes());
    }
    for i in 0..10 {
        let m = b.seal(format!("b{i}").as_bytes()).unwrap();
        assert_eq!(a.open(&m).unwrap(), format!("b{i}").into_bytes());
    }
    for i in 0..10 {
        let m = b.seal(format!("B{i}").as_bytes()).unwrap();
        assert_eq!(a.open(&m).unwrap(), format!("B{i}").into_bytes());
        let m = a.seal(format!("A{i}").as_bytes()).unwrap();
        assert_eq!(b.open(&m).unwrap(), format!("A{i}").into_bytes());
    }
}

/// Small seeded generator so a failing interleaving can be replayed from its seed.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

type InFlight = VecDeque<(Message, Vec<u8>)>;

fn deliver(to: &mut DoubleRatchet, queue: &mut InFlight, seed: u64) {
    if let Some((m, text)) = queue.pop_front() {
        assert_eq!(to.open(&m).unwrap(), text, "seed {seed}");
    }
}

#[test]
fn random_interleavings_never_fail_authentication() {
    for seed in 1..=300u64 {
        let mut rng = Xorshift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (mut a, mut b) = pair();
        // In flight toward each side: order is kept per direction, delay is arbitrary.
        let mut to_a = InFlight::new();
        let mut to_b = InFlight::new();
        for step in 0..200u32 {
            match rng.next() % 4 {
                0 => {
                    let text = format!("a{step}").into_bytes();
                    to_b.push_back((a.seal(&text).unwrap(), text));
                }
                1 => {
                    let text = format!("b{step}").into_bytes();
                    to_a.push_back((b.seal(&text).unwrap(), text));
                }
                2 => deliver(&mut a, &mut to_a, seed),
                _ => deliver(&mut b, &mut to_b, seed),
            }
        }
        while !to_a.is_empty() {
            deliver(&mut a, &mut to_a, seed);
        }
        while !to_b.is_empty() {
            deliver(&mut b, &mut to_b, seed);
        }
        // Still in step afterwards, in both directions.
        let m = a.seal(b"end-a").unwrap();
        assert_eq!(b.open(&m).unwrap(), b"end-a", "seed {seed}");
        let m = b.seal(b"end-b").unwrap();
        assert_eq!(a.open(&m).unwrap(), b"end-b", "seed {seed}");
    }
}
