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
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
