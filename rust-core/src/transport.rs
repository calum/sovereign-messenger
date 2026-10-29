//! Framed byte transport. The rest of the core talks to a `Transport`, never to
//! a socket, so Tor (or another carrier) can replace TCP later without touching
//! the handshake or the ratchet.
//!
//! Security property: a peer cannot make this layer allocate more than
//! `MAX_FRAME_LEN` bytes. The length is checked before any body is read, so an
//! oversize prefix is refused without allocation. Frames are opaque here; the
//! authenticity of their contents is decided by the ratchet, not by this layer.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Largest frame accepted in either direction. Handshake messages are about
/// 1.1 KB; a chat message is capped by this as well. Larger frames are refused.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// How long a single read waits before returning `Ok(None)`, so a receive
/// loop can notice that it should stop.
const IDLE_POLL: Duration = Duration::from_millis(500);

/// Upper bound on how long a frame may take to arrive once its first byte has.
const FRAME_DEADLINE: Duration = Duration::from_secs(10);

const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("peer closed the connection")]
    Closed,
    #[error("frame exceeds the size cap")]
    Oversize,
    #[error("connection ended inside a frame")]
    Truncated,
    #[error("network I/O failed")]
    Io,
}

/// A link that carries whole frames. Both methods take `&self` so one thread
/// can receive while another sends. Implementations must keep sends whole:
/// two concurrent `send` calls must not interleave their bytes.
pub trait Transport: Send + Sync {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError>;

    /// Returns `Ok(None)` if nothing arrived within the poll interval. Returns
    /// an error, never a partial frame, when the link is gone.
    fn receive(&self) -> Result<Option<Vec<u8>>, TransportError>;

    /// How long the handshake helpers wait for each frame on this link before giving up.
    /// A carrier with more latency than a LAN socket (Tor) overrides this.
    fn handshake_deadline(&self) -> Duration {
        Duration::from_secs(10)
    }

    /// How long the responder waits for the initiator's handshake after sending its challenge.
    /// A caller who connects and says nothing costs a worker this long, so a carrier that
    /// anyone can reach (an onion service) sets it shorter than the general deadline.
    fn responder_deadline(&self) -> Duration {
        self.handshake_deadline()
    }

    /// True for a link carried over Tor. Ending Tor ends the sessions on such links.
    fn is_onion(&self) -> bool {
        false
    }

    /// Ends the connection so the peer sees it drop. Used when the session is declared dead
    /// while the carrier is still up; without it the peer would keep writing into a socket
    /// nobody reads. Best effort, never fails.
    fn close(&self) {}
}

/// One TCP connection. Each frame is a 4-byte big-endian length, then the body.
pub struct TcpTransport {
    stream: TcpStream,
    write_lock: Mutex<()>,
    read_lock: Mutex<()>,
}

impl TcpTransport {
    /// Connects to `addr` (for example `192.168.1.20:47001`), giving up after `timeout`.
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self, TransportError> {
        let target = addr
            .to_socket_addrs()
            .map_err(|_| TransportError::Io)?
            .next()
            .ok_or(TransportError::Io)?;
        let stream =
            TcpStream::connect_timeout(&target, timeout).map_err(|_| TransportError::Io)?;
        Self::from_stream(stream)
    }

    /// Waits up to `timeout` for one inbound connection on `listener`.
    pub fn accept(listener: &TcpListener, timeout: Duration) -> Result<Self, TransportError> {
        listener
            .set_nonblocking(true)
            .map_err(|_| TransportError::Io)?;
        let deadline = Instant::now() + timeout;
        let accepted = loop {
            match listener.accept() {
                Ok((stream, _)) => break Ok(stream),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break Err(TransportError::Io);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break Err(TransportError::Io),
            }
        };
        listener
            .set_nonblocking(false)
            .map_err(|_| TransportError::Io)?;
        let stream = accepted?;
        // Accepted sockets can inherit non-blocking mode on some platforms.
        stream
            .set_nonblocking(false)
            .map_err(|_| TransportError::Io)?;
        Self::from_stream(stream)
    }

    fn from_stream(stream: TcpStream) -> Result<Self, TransportError> {
        stream
            .set_read_timeout(Some(IDLE_POLL))
            .map_err(|_| TransportError::Io)?;
        stream
            .set_write_timeout(Some(WRITE_TIMEOUT))
            .map_err(|_| TransportError::Io)?;
        stream.set_nodelay(true).map_err(|_| TransportError::Io)?;
        Ok(Self {
            stream,
            write_lock: Mutex::new(()),
            read_lock: Mutex::new(()),
        })
    }
}

impl Transport for TcpTransport {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > MAX_FRAME_LEN {
            return Err(TransportError::Oversize);
        }
        let mut wire = Vec::with_capacity(4 + frame.len());
        wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        wire.extend_from_slice(frame);

        let _guard = self.write_lock.lock().map_err(|_| TransportError::Io)?;
        let mut stream = &self.stream;
        stream.write_all(&wire).map_err(map_write_error)?;
        stream.flush().map_err(map_write_error)
    }

    fn receive(&self) -> Result<Option<Vec<u8>>, TransportError> {
        let _guard = self.read_lock.lock().map_err(|_| TransportError::Io)?;
        let mut stream = &self.stream;

        let mut prefix = [0u8; 4];
        // Nothing has arrived yet: report idle, not an error.
        match stream.read(&mut prefix[..1]) {
            Ok(0) => return Err(TransportError::Closed),
            Ok(_) => {}
            Err(e) if is_timeout(&e) => return Ok(None),
            Err(e) => return Err(map_read_error(&e)),
        }
        let deadline = Instant::now() + FRAME_DEADLINE;
        read_exact_by(&mut stream, &mut prefix[1..], deadline)?;

        let len = u32::from_be_bytes(prefix) as usize;
        if len > MAX_FRAME_LEN {
            return Err(TransportError::Oversize);
        }
        let mut body = vec![0u8; len];
        read_exact_by(&mut stream, &mut body, deadline)?;
        Ok(Some(body))
    }

    fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Reads exactly `buf.len()` bytes, waiting through poll timeouts until `deadline`.
/// Once a frame has started, the link is expected to finish it.
fn read_exact_by(
    stream: &mut &TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), TransportError> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(TransportError::Truncated),
            Ok(n) => filled += n,
            Err(e) if is_timeout(&e) => {
                if Instant::now() >= deadline {
                    return Err(TransportError::Io);
                }
            }
            Err(e) => return Err(map_read_error(&e)),
        }
    }
    Ok(())
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn map_read_error(e: &io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => TransportError::Truncated,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => TransportError::Closed,
        _ => TransportError::Io,
    }
}

fn map_write_error(e: io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => TransportError::Closed,
        _ => TransportError::Io,
    }
}
