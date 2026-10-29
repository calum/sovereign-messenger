//! RAM-only chat store. There is no persistence API by design: nothing here
//! can write to disk. Dropping the store wipes every secret it holds.
//!
//! Message text lives in `SecretBytes` (locked, zeroized on drop). The id, time,
//! direction and delivery state beside it are metadata about this phone's own
//! conversation and are never written anywhere either.

use std::collections::HashMap;

use crate::secret::SecretBytes;

pub type PeerId = String;

/// How far an outgoing message has got. Only moves forward; a late or repeated
/// receipt never takes a message back a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Delivery {
    /// Queued here; the contact was not reachable yet.
    Pending,
    /// Handed to the link.
    Sent,
    /// The contact's phone confirmed it received it.
    Delivered,
    /// The contact opened the chat after it arrived.
    Read,
}

pub struct Record {
    pub id: u64,
    pub outgoing: bool,
    pub at_ms: u64,
    pub delivery: Delivery,
    /// Incoming only: the user has had the chat open since it arrived.
    pub seen: bool,
    text: SecretBytes,
}

impl Record {
    pub fn text(&self) -> &[u8] {
        self.text.expose()
    }
}

#[derive(Default)]
pub struct Store {
    messages: HashMap<PeerId, Vec<Record>>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_outgoing(
        &mut self,
        peer: &str,
        id: u64,
        at_ms: u64,
        delivery: Delivery,
        text: &[u8],
    ) {
        self.messages
            .entry(peer.to_owned())
            .or_default()
            .push(Record {
                id,
                outgoing: true,
                at_ms,
                delivery,
                seen: true,
                text: SecretBytes::new(text),
            });
    }

    /// Returns false, storing nothing, if the contact already used this id.
    pub fn push_incoming(&mut self, peer: &str, id: u64, at_ms: u64, text: &[u8]) -> bool {
        let list = self.messages.entry(peer.to_owned()).or_default();
        if list.iter().any(|r| !r.outgoing && r.id == id) {
            return false;
        }
        list.push(Record {
            id,
            outgoing: false,
            at_ms,
            delivery: Delivery::Delivered,
            seen: false,
            text: SecretBytes::new(text),
        });
        true
    }

    /// Message texts only, oldest first.
    pub fn history(&self, peer: &str) -> Vec<&[u8]> {
        self.records(peer).iter().map(Record::text).collect()
    }

    pub fn records(&self, peer: &str) -> &[Record] {
        self.messages.get(peer).map_or(&[], Vec::as_slice)
    }

    /// Ids of queued outgoing messages, oldest first.
    pub fn pending_ids(&self, peer: &str) -> Vec<u64> {
        self.records(peer)
            .iter()
            .filter(|r| r.outgoing && r.delivery == Delivery::Pending)
            .map(|r| r.id)
            .collect()
    }

    pub fn text_of_outgoing(&self, peer: &str, id: u64) -> Option<&[u8]> {
        self.records(peer)
            .iter()
            .find(|r| r.outgoing && r.id == id)
            .map(Record::text)
    }

    /// Moves outgoing message `id` forward to `to`. Never backward.
    pub fn advance(&mut self, peer: &str, id: u64, to: Delivery) {
        if let Some(r) = self
            .messages
            .get_mut(peer)
            .and_then(|l| l.iter_mut().find(|r| r.outgoing && r.id == id))
        {
            r.delivery = r.delivery.max(to);
        }
    }

    /// The contact read message `id`: it and every earlier sent message become `Read`.
    /// A queued message is untouched, since the contact cannot have seen it.
    pub fn mark_read_through(&mut self, peer: &str, id: u64) {
        let Some(list) = self.messages.get_mut(peer) else {
            return;
        };
        let Some(pos) = list.iter().position(|r| r.outgoing && r.id == id) else {
            return;
        };
        for r in list[..=pos].iter_mut().filter(|r| r.outgoing) {
            if r.delivery > Delivery::Pending {
                r.delivery = Delivery::Read;
            }
        }
    }

    pub fn unread(&self, peer: &str) -> usize {
        self.records(peer)
            .iter()
            .filter(|r| !r.outgoing && !r.seen)
            .count()
    }

    /// Marks every incoming message seen. Returns how many were new and the id of the newest.
    pub fn mark_seen(&mut self, peer: &str) -> (usize, Option<u64>) {
        let Some(list) = self.messages.get_mut(peer) else {
            return (0, None);
        };
        let mut count = 0;
        for r in list.iter_mut().filter(|r| !r.outgoing && !r.seen) {
            r.seen = true;
            count += 1;
        }
        let newest = list.iter().rev().find(|r| !r.outgoing).map(|r| r.id);
        (count, newest)
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
        for rec in self.messages.values().flatten() {
            count.total += 1;
            if rec.text.is_locked() {
                count.locked += 1;
            }
        }
        count
    }
}

/// Result of [`Store::lock_count`].
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
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
        s.push_outgoing("alice", 1, 10, Delivery::Sent, b"hello");
        assert_eq!(s.history("alice"), vec![&b"hello"[..]]);
        s.forget("alice");
        assert!(s.history("alice").is_empty());
    }

    #[test]
    fn lock_report_counts_every_stored_message() {
        let mut s = Store::new();
        s.push_outgoing("alice", 1, 0, Delivery::Sent, b"one");
        assert!(s.push_incoming("bob", 2, 0, b"two"));
        let r = s.lock_count();
        assert_eq!(r.total, 2);
        assert!(r.locked <= r.total);
    }

    #[test]
    fn a_repeated_incoming_id_is_stored_once() {
        let mut s = Store::new();
        assert!(s.push_incoming("bob", 5, 0, b"hi"));
        assert!(!s.push_incoming("bob", 5, 1, b"hi again"));
        assert_eq!(s.history("bob").len(), 1);
    }

    #[test]
    fn delivery_only_moves_forward() {
        let mut s = Store::new();
        s.push_outgoing("bob", 1, 0, Delivery::Sent, b"x");
        s.advance("bob", 1, Delivery::Read);
        s.advance("bob", 1, Delivery::Delivered);
        assert_eq!(s.records("bob")[0].delivery, Delivery::Read);
    }

    #[test]
    fn read_covers_earlier_sent_messages_but_not_queued_ones() {
        let mut s = Store::new();
        s.push_outgoing("bob", 1, 0, Delivery::Delivered, b"a");
        s.push_outgoing("bob", 2, 0, Delivery::Pending, b"queued");
        s.push_outgoing("bob", 3, 0, Delivery::Sent, b"c");
        s.push_outgoing("bob", 4, 0, Delivery::Sent, b"d");
        s.mark_read_through("bob", 3);
        let states: Vec<_> = s.records("bob").iter().map(|r| r.delivery).collect();
        assert_eq!(
            states,
            vec![
                Delivery::Read,
                Delivery::Pending,
                Delivery::Read,
                Delivery::Sent
            ]
        );
    }

    #[test]
    fn unread_counts_incoming_until_seen() {
        let mut s = Store::new();
        s.push_incoming("bob", 1, 0, b"a");
        s.push_outgoing("bob", 2, 0, Delivery::Sent, b"mine");
        s.push_incoming("bob", 3, 0, b"b");
        assert_eq!(s.unread("bob"), 2);
        assert_eq!(s.mark_seen("bob"), (2, Some(3)));
        assert_eq!(s.unread("bob"), 0);
        assert_eq!(s.mark_seen("bob"), (0, Some(3)));
    }

    #[test]
    fn pending_ids_keep_send_order() {
        let mut s = Store::new();
        s.push_outgoing("bob", 9, 0, Delivery::Pending, b"a");
        s.push_outgoing("bob", 4, 0, Delivery::Sent, b"b");
        s.push_outgoing("bob", 2, 0, Delivery::Pending, b"c");
        assert_eq!(s.pending_ids("bob"), vec![9, 2]);
    }
}
