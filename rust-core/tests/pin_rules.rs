//! Who may be pinned. A contact's key is pinned under one label, and your own key is
//! never a contact. Otherwise a caller identified by its key could match two labels,
//! and a phone could be paired with itself.

use rust_core::ffi::{FacadeError, Messenger};

#[test]
fn your_own_identity_cannot_be_pinned_as_a_contact() {
    let me = Messenger::new();
    let own = me.own_pairing_payload(String::new()).unwrap();
    assert_eq!(
        me.scan_pairing("me".into(), own).map(|_| ()),
        Err(FacadeError::Malformed)
    );
    assert!(me.pinned_peers().unwrap().is_empty());
}

#[test]
fn the_same_identity_cannot_be_pinned_under_two_labels() {
    let me = Messenger::new();
    let them = Messenger::new();
    let payload = them.own_pairing_payload(String::new()).unwrap();
    me.scan_pairing("first".into(), payload.clone()).unwrap();
    assert_eq!(
        me.scan_pairing("second".into(), payload).map(|_| ()),
        Err(FacadeError::DuplicatePin)
    );
    assert_eq!(me.pinned_peers().unwrap(), vec!["first".to_string()]);
}

#[test]
fn two_different_contacts_can_each_be_pinned() {
    let me = Messenger::new();
    let a = Messenger::new();
    let b = Messenger::new();
    me.scan_pairing("a".into(), a.own_pairing_payload(String::new()).unwrap())
        .unwrap();
    me.scan_pairing("b".into(), b.own_pairing_payload(String::new()).unwrap())
        .unwrap();
    assert_eq!(me.pinned_peers().unwrap().len(), 2);
}

#[test]
fn unpinning_frees_the_identity_for_a_new_label() {
    let me = Messenger::new();
    let them = Messenger::new();
    let payload = them.own_pairing_payload(String::new()).unwrap();
    me.scan_pairing("old".into(), payload.clone()).unwrap();
    me.unpin("old".into()).unwrap();
    me.scan_pairing("new".into(), payload).unwrap();
    assert_eq!(me.pinned_peers().unwrap(), vec!["new".to_string()]);
}
