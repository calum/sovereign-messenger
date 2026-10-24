//! RAM-only chat store. There is no persistence API by design: nothing here
//! can write to disk. Dropping the store wipes every secret it holds.

use std::collections::HashMap;

use crate::secret::SecretBytes;

pub type PeerId = String;

#[derive(Default)]
pub struct Store {
    messages: HashMap<PeerId, Vec<SecretBytes>>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, peer: &str, plaintext: &[u8]) {
        self.messages
            .entry(peer.to_owned())
            .or_default()
            .push(SecretBytes::new(plaintext));
    }

    pub fn history(&self, peer: &str) -> Vec<&[u8]> {
        self.messages
            .get(peer)
            .map(|v| v.iter().map(|m| m.expose()).collect())
            .unwrap_or_default()
    }

    /// Wipe a single conversation immediately.
    pub fn forget(&mut self, peer: &str) {
        self.messages.remove(peer);
    }

    /// Wipe everything. Also runs on drop.
    pub fn wipe_all(&mut self) {
        self.messages.clear();
    }

    /// Counts how many stored messages are `mlock`ed. Reports counts only, never
    /// content, so the UI can show whether the OS honoured the lock.
    pub fn lock_count(&self) -> LockCount {
        let mut count = LockCount::default();
        for msg in self.messages.values().flatten() {
            count.total += 1;
            if msg.is_locked() {
                count.locked += 1;
            }
        }
        count
    }
}

/// Result of [`Store::lock_count`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LockCount {
    pub total: usize,
    pub locked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_history_forget() {
        let mut s = Store::new();
        s.push("alice", b"hello");
        assert_eq!(s.history("alice"), vec![&b"hello"[..]]);
        s.forget("alice");
        assert!(s.history("alice").is_empty());
    }

    #[test]
    fn lock_report_counts_every_stored_message() {
        let mut s = Store::new();
        s.push("alice", b"one");
        s.push("bob", b"two");
        let r = s.lock_count();
        assert_eq!(r.total, 2);
        assert!(r.locked <= r.total);
    }
}
