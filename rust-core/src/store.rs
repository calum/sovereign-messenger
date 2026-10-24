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
}
