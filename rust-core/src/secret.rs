//! Locked, zeroized byte buffers. Secrets never move to swap and are wiped on drop.

use zeroize::Zeroize;

/// Heap buffer whose pages are `mlock`ed so the OS cannot swap them out.
pub struct SecretBytes {
    buf: Vec<u8>,
    locked: bool,
}

impl SecretBytes {
    pub fn new(data: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(data.len().max(1));
        buf.extend_from_slice(data);
        let locked = lock(&buf);
        Self { buf, locked }
    }

    pub fn expose(&self) -> &[u8] {
        &self.buf
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            unlock(&self.buf);
        }
    }
}

/// Fixed-size secret key material, zeroized on drop.
/// No `Clone`: a copy of a key is a second place it can leak, and nothing in the core needs one.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key32(pub [u8; 32]);

#[cfg(unix)]
fn lock(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    // SAFETY: pointer and length describe a live allocation owned by the caller.
    unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0 }
}

#[cfg(unix)]
fn unlock(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: same region that was locked in `lock`.
    unsafe {
        libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
    }
}

#[cfg(not(unix))]
fn lock(_buf: &[u8]) -> bool {
    false
}

#[cfg(not(unix))]
fn unlock(_buf: &[u8]) {}

/// Test-only probes that report whether a type implements `Clone` or `Debug`.
/// Inherent associated consts are selected only when their bound holds, so
/// `Probe::<T>::CLONE` is `true` exactly when `T: Clone`, and the trait fallback
/// gives `false` otherwise. A secret type that gains a derive fails its test.
#[cfg(test)]
pub(crate) mod probe {
    use std::marker::PhantomData;

    pub(crate) struct Probe<T>(PhantomData<T>);

    pub(crate) trait NoClone {
        const CLONE: bool = false;
    }
    impl<T> NoClone for Probe<T> {}
    impl<T: Clone> Probe<T> {
        pub(crate) const CLONE: bool = true;
    }

    pub(crate) trait NoDebug {
        const DEBUG: bool = false;
    }
    impl<T> NoDebug for Probe<T> {}
    impl<T: std::fmt::Debug> Probe<T> {
        pub(crate) const DEBUG: bool = true;
    }
}

#[cfg(test)]
mod tests {
    use super::probe::{NoClone, NoDebug, Probe};
    use super::*;

    #[test]
    fn probe_reports_true_for_a_type_that_has_both_traits() {
        // Positive control: without it, a probe that always answers false would pass.
        {
            let value = Probe::<u8>::CLONE;
            assert!(value);
        }
        {
            let value = Probe::<u8>::DEBUG;
            assert!(value);
        }
    }

    #[test]
    fn key_material_types_do_not_implement_clone() {
        // CLAUDE.md rule 2: do not Clone secret types casually. Nothing in the
        // core needs a copy of a key, so the type must not offer one.
        {
            let value = Probe::<Key32>::CLONE;
            assert!(!value);
        }
        {
            let value = Probe::<SecretBytes>::CLONE;
            assert!(!value);
        }
    }

    #[test]
    fn key_material_types_do_not_implement_debug() {
        // A derived Debug would print key bytes into any `{:?}` or panic message.
        {
            let value = Probe::<Key32>::DEBUG;
            assert!(!value);
        }
        {
            let value = Probe::<SecretBytes>::DEBUG;
            assert!(!value);
        }
    }

    #[test]
    fn secret_bytes_round_trip() {
        let s = SecretBytes::new(b"hunter2");
        assert_eq!(s.expose(), b"hunter2");
    }

    #[test]
    fn key32_zeroizes_on_explicit_wipe() {
        let mut k = Key32([7u8; 32]);
        k.zeroize();
        assert_eq!(k.0, [0u8; 32]);
    }
}
