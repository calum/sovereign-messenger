//! Peer-to-peer APK transfer over the local network. The sender dials the
//! receiver's update port; the receiver checks the signature and version (see
//! `update.rs`) before the bytes are offered for install.
//!
//! Wire format v2, in order. The header is 77 bytes (1 + 8 + 64 + 4), then the APK:
//!
//! | field          | size        | meaning                                        |
//! |----------------|-------------|------------------------------------------------|
//! | frame version  | 1 byte      | `0x02`. Any other value is refused.            |
//! | version        | 8 bytes     | update version, u64 big-endian. Signed.        |
//! | signature      | 64 bytes    | detached Ed25519 over the signed message below |
//! | APK length     | 4 bytes     | u32 big-endian. Refused if 0 or over `MAX_APK_LEN` |
//! | APK            | length bytes| the update package                             |
//!
//! The signed message is the ASCII label `sovereign-p2p update v2`, then the
//! version as u64 big-endian, then the APK bytes. It is built by
//! `update::signed_message`. The APK length is not signed; the signature covers
//! the APK bytes, and a wrong length fails the body read or the signature check.
//!
//! Security property: the announced length is checked against `MAX_APK_LEN`
//! before any buffer is reserved or any body is read, so a peer cannot make the
//! receiver allocate more than the cap. The version is part of the signed
//! message, so a version edited in transit fails the signature check. The
//! transfer layer does not trust the bytes; the signature check decides whether
//! they may be installed. This module never writes to disk.

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

/// Version of the transfer frame. The first byte of every frame. A frame in the
/// old layout (no version field) starts with a signature byte, so it is refused
/// here rather than misread as a v2 frame.
pub const FRAME_VERSION: u8 = 0x02;

/// Bytes before the APK: frame version, update version, signature, APK length.
const HEADER_LEN: usize = 1 + 8 + SIGNATURE_LEN + 4;

/// A 64 MiB APK over a slow Wi-Fi link can take a minute or more, so the sender
/// allows a long write before giving up.
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

/// Longest the receiver waits on one read from a stalled sender.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// One overall limit on a transfer, from accept to the last body byte. Without
/// it a peer sending a byte just inside each read timeout holds the receiver
/// for hours. Ten minutes carries 64 MiB at about 0.9 Mbit/s.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(600);

/// The body buffer grows by at most this much per step, as bytes arrive, so a
/// peer that announces a large length and sends nothing costs one chunk.
const BODY_CHUNK: usize = 1024 * 1024;

/// Writes one update. Refuses an empty or oversize APK before writing anything.
pub fn write_update<W: Write>(
    w: &mut W,
    version: u64,
    signature: &[u8; SIGNATURE_LEN],
    apk: &[u8],
) -> Result<(), CoreError> {
    // Refuse before writing a byte: the receiver would refuse the length anyway.
    if apk.is_empty() || apk.len() > MAX_APK_LEN {
        return Err(CoreError::Malformed);
    }
    let mut head = [0u8; HEADER_LEN];
    head[0] = FRAME_VERSION;
    head[1..9].copy_from_slice(&version.to_be_bytes());
    head[9..9 + SIGNATURE_LEN].copy_from_slice(signature);
    head[HEADER_LEN - 4..].copy_from_slice(&(apk.len() as u32).to_be_bytes());
    w.write_all(&head).map_err(|_| CoreError::Network)?;
    w.write_all(apk).map_err(|_| CoreError::Network)?;
    w.flush().map_err(|_| CoreError::Network)
}

/// Reads one update into `apk`, replacing its contents, and returns the announced
/// version and the signature. The frame version and the announced length are
/// checked before `apk` grows.
pub fn read_update<R: Read>(
    r: &mut R,
    apk: &mut Vec<u8>,
) -> Result<(u64, [u8; SIGNATURE_LEN]), CoreError> {
    apk.clear();
    let mut frame_version = [0u8; 1];
    r.read_exact(&mut frame_version)
        .map_err(|_| CoreError::Network)?;
    if frame_version[0] != FRAME_VERSION {
        return Err(CoreError::Malformed);
    }
    let mut version_bytes = [0u8; 8];
    r.read_exact(&mut version_bytes)
        .map_err(|_| CoreError::Network)?;
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
    // Grow in bounded steps as data arrives; the announced length is unsigned
    // and unproven, so it must not decide how much memory is reserved.
    while apk.len() < len {
        let start = apk.len();
        let step = BODY_CHUNK.min(len - start);
        let grown = apk
            .try_reserve_exact(step)
            .map_err(|_| CoreError::Network)
            .and_then(|()| {
                apk.resize(start + step, 0);
                r.read_exact(&mut apk[start..])
                    .map_err(|_| CoreError::Network)
            });
        if let Err(e) = grown {
            apk.clear();
            return Err(e);
        }
    }
    Ok((u64::from_be_bytes(version_bytes), signature))
}

/// Sender side: dials `addr` and sends one update.
pub fn send_update_to(
    addr: &str,
    timeout: Duration,
    version: u64,
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
    write_update(&mut stream, version, signature, apk)
}

/// Receiver side: binds `bind_addr`, waits up to `timeout` for one sender, and reads one update.
pub fn receive_update_on(
    bind_addr: &str,
    timeout: Duration,
    apk: &mut Vec<u8>,
) -> Result<(u64, [u8; SIGNATURE_LEN]), CoreError> {
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
    read_update_with_deadline(stream, TRANSFER_DEADLINE, apk)
}

/// Reads one update from `stream`, giving up once `limit` has passed in total.
fn read_update_with_deadline(
    stream: TcpStream,
    limit: Duration,
    apk: &mut Vec<u8>,
) -> Result<(u64, [u8; SIGNATURE_LEN]), CoreError> {
    let mut reader = DeadlineStream {
        stream,
        deadline: Instant::now() + limit,
    };
    read_update(&mut reader, apk)
}

/// A socket whose every read is bounded by one fixed deadline, so slow
/// trickling cannot extend the transfer past it.
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left.min(READ_TIMEOUT)))?;
        self.stream.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SIG: [u8; SIGNATURE_LEN] = [7u8; SIGNATURE_LEN];
    const VERSION: u64 = 9;

    fn header(len: u32) -> Vec<u8> {
        let mut v = vec![FRAME_VERSION];
        v.extend_from_slice(&VERSION.to_be_bytes());
        v.extend_from_slice(&SIG);
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
            write_update(&mut stream, VERSION, &SIG, &sent).unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        let mut got = Vec::new();
        let (version, sig) = read_update(&mut stream, &mut got).unwrap();
        sender.join().unwrap();
        assert_eq!(version, VERSION);
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
                if send_update_to(&dial, Duration::from_secs(1), VERSION, &SIG, &sent).is_ok() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("sender never connected");
        });
        let mut got = Vec::new();
        let (version, sig) = receive_update_on(&bind, Duration::from_secs(5), &mut got).unwrap();
        sender.join().unwrap();
        assert_eq!(version, VERSION);
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
    fn trickling_sender_cut_off_at_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let mut wire = header(1000);
            wire.extend_from_slice(&[0u8; 1000]);
            for b in wire {
                if s.write_all(&[b]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let (stream, _) = listener.accept().unwrap();
        let start = Instant::now();
        let mut apk = Vec::new();
        let r = read_update_with_deadline(stream, Duration::from_millis(400), &mut apk);
        assert_eq!(r, Err(CoreError::Network));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "deadline not enforced"
        );
        sender.join().unwrap();
    }

    #[test]
    fn large_transfer_round_trips_in_chunks() {
        let apk: Vec<u8> = (0..(2 * BODY_CHUNK + 12_345) as u32)
            .map(|i| (i % 253) as u8)
            .collect();
        let mut wire = header(apk.len() as u32);
        wire.extend_from_slice(&apk);
        let mut got = Vec::new();
        read_update(&mut Cursor::new(wire), &mut got).unwrap();
        assert_eq!(got, apk);
    }

    #[test]
    fn announced_length_without_data_does_not_reserve_it() {
        let wire = header(MAX_APK_LEN as u32);
        let mut apk = Vec::new();
        assert_eq!(
            read_update(&mut Cursor::new(wire), &mut apk),
            Err(CoreError::Network)
        );
        assert!(
            apk.capacity() <= 2 * BODY_CHUNK,
            "reserved {}",
            apk.capacity()
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
    fn unknown_frame_version_refused() {
        // A frame in another layout, or any other version, is refused, not misread.
        let mut wire = header(4);
        wire[0] = FRAME_VERSION.wrapping_add(1);
        wire.extend_from_slice(b"apk!");
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
            write_update(&mut wire, VERSION, &SIG, &big),
            Err(CoreError::Malformed)
        );
        assert!(wire.is_empty(), "nothing may be written for a refused APK");
    }
}
