//! Peer-to-peer APK transfer over the local network. The sender dials the
//! receiver's update port; the receiver checks the signature (see `update.rs`)
//! before the bytes are offered for install.
//!
//! Wire format, in order: a 64-byte detached Ed25519 signature, a 4-byte
//! big-endian APK length, then the APK bytes. Nothing else is sent.
//!
//! Security property: the announced length is checked against `MAX_APK_LEN`
//! before any buffer is reserved or any body is read, so a peer cannot make the
//! receiver allocate more than the cap. The transfer layer does not trust the
//! bytes; the signature check decides whether they may be installed. This module
//! never writes to disk.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::error::CoreError;

/// Port the receiving phone listens on during the in-person meeting.
pub const UPDATE_PORT: u16 = 47002;

/// Largest APK accepted. Set above the current release size with room to grow;
/// raising it raises the memory one peer can make the receiver allocate.
pub const MAX_APK_LEN: usize = 64 * 1024 * 1024;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// A 64 MiB APK over a slow Wi-Fi link can take a minute or more, so the sender
/// allows a long write before giving up.
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

/// Longest the receiver waits on a stalled sender mid-transfer.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Writes one update. Refuses an empty or oversize APK before writing anything.
pub fn write_update<W: Write>(
    w: &mut W,
    signature: &[u8; SIGNATURE_LEN],
    apk: &[u8],
) -> Result<(), CoreError> {
    // Refuse before writing a byte: the receiver would refuse the length anyway.
    if apk.is_empty() || apk.len() > MAX_APK_LEN {
        return Err(CoreError::Malformed);
    }
    let mut head = [0u8; SIGNATURE_LEN + 4];
    head[..SIGNATURE_LEN].copy_from_slice(signature);
    head[SIGNATURE_LEN..].copy_from_slice(&(apk.len() as u32).to_be_bytes());
    w.write_all(&head).map_err(|_| CoreError::Network)?;
    w.write_all(apk).map_err(|_| CoreError::Network)?;
    w.flush().map_err(|_| CoreError::Network)
}

/// Reads one update into `apk`, replacing its contents, and returns the signature.
/// The announced length is checked against `MAX_APK_LEN` and before `apk` grows.
pub fn read_update<R: Read>(
    r: &mut R,
    apk: &mut Vec<u8>,
) -> Result<[u8; SIGNATURE_LEN], CoreError> {
    apk.clear();
    let mut signature = [0u8; SIGNATURE_LEN];
    r.read_exact(&mut signature)
        .map_err(|_| CoreError::Network)?;
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)
        .map_err(|_| CoreError::Network)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    // The cap and the empty check come before any reservation or body read.
    if len == 0 || len > MAX_APK_LEN {
        return Err(CoreError::Malformed);
    }
    apk.try_reserve_exact(len).map_err(|_| CoreError::Network)?;
    apk.resize(len, 0);
    r.read_exact(apk).map_err(|_| CoreError::Network)?;
    Ok(signature)
}

/// Sender side: dials `addr` and sends one update.
pub fn send_update_to(
    addr: &str,
    timeout: Duration,
    signature: &[u8; SIGNATURE_LEN],
    apk: &[u8],
) -> Result<(), CoreError> {
    let target = addr
        .to_socket_addrs()
        .map_err(|_| CoreError::Network)?
        .next()
        .ok_or(CoreError::Network)?;
    let mut stream =
        TcpStream::connect_timeout(&target, timeout).map_err(|_| CoreError::Network)?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|_| CoreError::Network)?;
    write_update(&mut stream, signature, apk)
}

/// Receiver side: binds `bind_addr`, waits up to `timeout` for one sender, and reads one update.
pub fn receive_update_on(
    bind_addr: &str,
    timeout: Duration,
    apk: &mut Vec<u8>,
) -> Result<[u8; SIGNATURE_LEN], CoreError> {
    let listener = TcpListener::bind(bind_addr).map_err(|_| CoreError::Network)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| CoreError::Network)?;
    let deadline = Instant::now() + timeout;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(CoreError::Network);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return Err(CoreError::Network),
        }
    };
    // One sender per listen. Accepted sockets can inherit non-blocking mode.
    drop(listener);
    stream
        .set_nonblocking(false)
        .map_err(|_| CoreError::Network)?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|_| CoreError::Network)?;
    let mut stream = stream;
    read_update(&mut stream, apk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SIG: [u8; SIGNATURE_LEN] = [7u8; SIGNATURE_LEN];

    fn header(len: u32) -> Vec<u8> {
        let mut v = SIG.to_vec();
        v.extend_from_slice(&len.to_be_bytes());
        v
    }

    #[test]
    fn round_trip_over_loopback_tcp() {
        let apk: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let sent = apk.clone();
        let sender = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(&addr).unwrap();
            write_update(&mut stream, &SIG, &sent).unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        let mut got = Vec::new();
        let sig = read_update(&mut stream, &mut got).unwrap();
        sender.join().unwrap();
        assert_eq!(sig, SIG);
        assert_eq!(got, apk);
    }

    #[test]
    fn round_trip_through_listener_helpers() {
        let apk = b"tiny-apk".to_vec();
        let port = {
            // Find a free port, then release it for the helper to bind.
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let bind = format!("127.0.0.1:{port}");
        let dial = bind.clone();
        let sent = apk.clone();
        let sender = std::thread::spawn(move || {
            // The receiver may not be listening yet; retry briefly.
            for _ in 0..200 {
                if send_update_to(&dial, Duration::from_secs(1), &SIG, &sent).is_ok() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("sender never connected");
        });
        let mut got = Vec::new();
        let sig = receive_update_on(&bind, Duration::from_secs(5), &mut got).unwrap();
        sender.join().unwrap();
        assert_eq!(sig, SIG);
        assert_eq!(got, apk);
    }

    #[test]
    fn oversize_announced_length_refused_before_body_read() {
        // Only the header is present. If the receiver read a body it would see
        // end-of-stream; the error must come from the length check instead.
        let wire = header((MAX_APK_LEN + 1) as u32);
        let mut apk = Vec::new();
        let err = read_update(&mut Cursor::new(wire), &mut apk).unwrap_err();
        assert_eq!(err, CoreError::Malformed);
        assert_eq!(
            apk.capacity(),
            0,
            "no buffer may be reserved for a refused length"
        );
    }

    #[test]
    fn truncated_stream_refused() {
        // Announces 10 bytes, delivers 5, then the stream ends.
        let mut wire = header(10);
        wire.extend_from_slice(&[1, 2, 3, 4, 5]);
        let mut apk = Vec::new();
        assert_eq!(
            read_update(&mut Cursor::new(wire), &mut apk),
            Err(CoreError::Network)
        );
    }

    #[test]
    fn wrong_length_refused() {
        // A zero-length APK is not an installable package, and must not be offered.
        let wire = header(0);
        let mut apk = Vec::new();
        assert_eq!(
            read_update(&mut Cursor::new(wire), &mut apk),
            Err(CoreError::Malformed)
        );
    }

    #[test]
    fn sender_refuses_oversize_apk_before_writing() {
        let big = vec![0u8; MAX_APK_LEN + 1];
        let mut wire = Vec::new();
        assert_eq!(
            write_update(&mut wire, &SIG, &big),
            Err(CoreError::Malformed)
        );
        assert!(wire.is_empty(), "nothing may be written for a refused APK");
    }
}
