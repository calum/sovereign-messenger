//! Linux only. `munlock` is not reference counted per page: unlocking one
//! secret can unlock a live secret that shares its page. This test runs in its
//! own process so that `VmLck` in /proc/self/status counts only what it locks.
//!
//! It allocates a batch of small secrets, so that some must share a page whatever the
//! allocator does, then drops one and checks that the page of a surviving neighbour is
//! still locked. An earlier version waited for a second secret to land on the page of
//! the first, which depended on the allocator and failed on glibc.
#![cfg(target_os = "linux")]

use std::collections::HashMap;

use rust_core::secret::SecretBytes;

const PAGE: usize = 4096;

/// Enough 16-byte secrets that two must share a page under any allocator that packs small
/// allocations (1000 of them need at least 16 KB, which is 4 pages).
const BATCH: usize = 1000;

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

/// Whether the kernel reports the mapping that contains `address` as locked, from `smaps`.
fn mapping_is_locked(address: usize) -> bool {
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("read /proc/self/smaps");
    let mut in_mapping = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ') {
            if let Some((lo, hi)) = range.split_once('-') {
                if let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                {
                    in_mapping = lo <= address && address < hi;
                    continue;
                }
            }
        }
        if in_mapping && line.starts_with("Locked:") {
            let kib: usize = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            return kib > 0;
        }
    }
    false
}

#[test]
fn dropping_one_secret_keeps_a_live_neighbour_on_its_page_locked() {
    let secrets: Vec<SecretBytes> = (0..BATCH)
        .map(|i| SecretBytes::new(&[(i % 250) as u8 + 1; 16]))
        .collect();
    assert!(
        secrets.iter().all(|s| s.is_locked()),
        "every secret must lock for the test to mean anything"
    );

    // Two secrets on the same page: the first is dropped, the second is the live neighbour.
    let mut by_page: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, s) in secrets.iter().enumerate() {
        by_page.entry(page_of(s)).or_default().push(i);
    }
    let shared = by_page
        .values()
        .find(|indexes| indexes.len() >= 2)
        .expect("a batch this large must put two secrets on one page");
    let (victim_index, neighbour_index) = (shared[0], shared[1]);
    let neighbour_page = page_of(&secrets[neighbour_index]);
    let neighbour_bytes = secrets[neighbour_index].expose().to_vec();
    assert!(vm_lck_bytes() >= PAGE);
    assert!(mapping_is_locked(neighbour_page * PAGE));

    // Drop only the victim; every other secret, including the neighbour, stays alive.
    // `Option` slots keep the indexes stable.
    let mut slots: Vec<Option<SecretBytes>> = secrets.into_iter().map(Some).collect();
    drop(slots[victim_index].take());

    let neighbour = slots[neighbour_index]
        .as_ref()
        .expect("neighbour still alive");
    assert_eq!(neighbour.expose(), neighbour_bytes.as_slice());
    assert_eq!(page_of(neighbour), neighbour_page);
    assert!(
        vm_lck_bytes() >= PAGE,
        "dropping one secret unlocked the page that a live neighbour uses"
    );
    assert!(
        mapping_is_locked(neighbour_page * PAGE),
        "dropping one secret unlocked the page that a live neighbour uses"
    );
}
