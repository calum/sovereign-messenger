//! Linux only. `munlock` is not reference counted per page: unlocking one
//! secret can unlock a live secret that shares its page. This test runs in its
//! own process so that `VmLck` in /proc/self/status counts only what it locks.
//! Written first; it could not be run on the Windows host it was written on.
#![cfg(target_os = "linux")]

use rust_core::secret::SecretBytes;

const PAGE: usize = 4096;

/// Locked bytes for this process, from the kernel's own count.
fn vm_lck_bytes() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let line = status
        .lines()
        .find(|l| l.starts_with("VmLck:"))
        .expect("VmLck line present");
    let kib: usize = line
        .split_whitespace()
        .nth(1)
        .expect("VmLck value")
        .parse()
        .expect("VmLck is a number");
    kib * 1024
}

fn page_of(s: &SecretBytes) -> usize {
    s.expose().as_ptr() as usize / PAGE
}

#[test]
fn dropping_one_secret_keeps_a_live_neighbour_on_its_page_locked() {
    let first = SecretBytes::new(&[1u8; 16]);
    assert!(first.is_locked(), "first secret must lock for the test to mean anything");

    // Find a second secret on the same page as the first.
    let mut kept = Vec::new();
    let neighbour = loop {
        let candidate = SecretBytes::new(&[2u8; 16]);
        assert!(candidate.is_locked());
        if page_of(&candidate) == page_of(&first) {
            break candidate;
        }
        kept.push(candidate);
        assert!(kept.len() < 10_000, "no shared page found; allocator behaviour changed");
    };

    let before = vm_lck_bytes();
    assert!(before >= PAGE);

    drop(first);

    // The neighbour is still alive and its page must still be locked.
    assert_eq!(neighbour.expose(), &[2u8; 16]);
    assert!(
        vm_lck_bytes() >= PAGE,
        "dropping one secret unlocked the page that a live neighbour uses"
    );
    drop(kept);
}
