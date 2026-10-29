//! Tor carrier for the `Transport` trait (feature `tor`). Security property: the same
//! frame rules as the TCP carrier hold over an onion stream: a frame larger than
//! `MAX_FRAME_LEN` is refused from its length prefix alone, before any body is read or
//! allocated, and a frame cut short is reported, never delivered. Authenticity is still
//! decided above this layer by the handshake and the ratchet, not here.

use std::any::Any;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use crate::transport::{Transport, TransportError, MAX_FRAME_LEN};

/// How long one `receive` waits for the first byte before reporting idle, so a receive
/// loop can notice that it should stop.
const IDLE_POLL: Duration = Duration::from_millis(500);

/// How long a frame may take to arrive once its first byte has. Longer than on a LAN:
/// an onion circuit adds seconds of latency and jitter.
const FRAME_DEADLINE: Duration = Duration::from_secs(60);

/// How long `close` waits for a send in progress before giving up on a clean shutdown.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the handshake helpers wait for each frame on an onion link.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(60);

/// How long the responder waits for the initiator's handshake after its challenge.
const RESPONDER_DEADLINE: Duration = Duration::from_secs(20);

const READ_CHUNK: usize = 16 * 1024;

/// Frames over any byte stream: a 4-byte big-endian length, then the body. The Tor
/// carrier uses an arti `DataStream`; the tests use an in-memory pipe.
///
/// The reader keeps its own buffer instead of using `read_exact`, so a poll that times
/// out with half a frame buffered keeps those bytes for the next call. The reader and
/// the writer have separate locks: a receive that is waiting never stalls a send.
pub struct StreamTransport<S> {
    handle: Handle,
    reader: Mutex<Reader<ReadHalf<S>>>,
    writer: Mutex<WriteHalf<S>>,
    /// Keeps the runtime that drives this stream alive for as long as the link exists.
    /// Calling `block_on` with a timer on a handle whose runtime was dropped panics, and
    /// a panic aborts the app (`panic = "abort"`).
    _keepalive: Option<Arc<dyn Any + Send + Sync>>,
}

struct Reader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> StreamTransport<S> {
    /// `handle` is the runtime that drives the stream; calls block the calling thread on
    /// it, so they must not be made from one of that runtime's own threads.
    pub fn new(handle: Handle, stream: S) -> Self {
        let (read, write) = stream.split();
        Self {
            handle,
            reader: Mutex::new(Reader {
                inner: read,
                buf: Vec::new(),
            }),
            writer: Mutex::new(write),
            _keepalive: None,
        }
    }

    /// Ties the lifetime of `owner` (the runtime) to this link.
    pub fn keep_alive(mut self, owner: Arc<dyn Any + Send + Sync>) -> Self {
        self._keepalive = Some(owner);
        self
    }
}

/// Owns a tokio runtime and never blocks when dropped. A plain `Runtime` panics if it is
/// dropped inside async code, and the last holder of a link can be a worker thread; this
/// shuts down in the background instead, so it is safe to drop from anywhere.
pub struct OwnedRuntime {
    runtime: Option<tokio::runtime::Runtime>,
}

impl OwnedRuntime {
    pub fn new(runtime: tokio::runtime::Runtime) -> Self {
        Self {
            runtime: Some(runtime),
        }
    }

    pub fn handle(&self) -> Handle {
        self.runtime
            .as_ref()
            .map(|r| r.handle().clone())
            .expect("runtime present until drop")
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for StreamTransport<S> {
    fn send(&self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > MAX_FRAME_LEN {
            return Err(TransportError::Oversize);
        }
        let mut wire = Vec::with_capacity(4 + frame.len());
        wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        wire.extend_from_slice(frame);
        self.handle.block_on(async {
            // The lock is held for the whole write, so two sends never interleave.
            let mut writer = self.writer.lock().await;
            let write = async {
                writer.write_all(&wire).await?;
                writer.flush().await
            };
            match tokio::time::timeout(WRITE_TIMEOUT, write).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(map_write_error(&e)),
                Err(_) => Err(TransportError::Io),
            }
        })
    }

    fn receive(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.handle.block_on(async {
            let mut reader = self.reader.lock().await;
            reader.receive().await
        })
    }

    /// An onion circuit is slow to answer, so each handshake frame gets longer than on a LAN.
    fn handshake_deadline(&self) -> Duration {
        HANDSHAKE_DEADLINE
    }

    /// A stranger can open a stream to an onion service and say nothing. A real contact answers
    /// the challenge within a round trip or two, so the responder waits far less than for the
    /// initiator's side.
    fn responder_deadline(&self) -> Duration {
        RESPONDER_DEADLINE
    }

    fn is_onion(&self) -> bool {
        true
    }

    /// Shuts the write half so the peer's next read ends. Waits briefly for a send in
    /// progress; if one is stuck the stream is dropped with the session instead.
    fn close(&self) {
        self.handle.block_on(async {
            if let Ok(mut writer) = tokio::time::timeout(CLOSE_WAIT, self.writer.lock()).await {
                let _ = writer.close().await;
            }
        });
    }
}

impl<R: AsyncRead + Unpin> Reader<R> {
    async fn receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        // Bytes left over from an earlier read mean a frame is already under way.
        let mut started = (!self.buf.is_empty()).then(Instant::now);
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            if let Some(frame) = self.take_frame()? {
                return Ok(Some(frame));
            }
            let wait = match started {
                None => IDLE_POLL,
                Some(at) => FRAME_DEADLINE.saturating_sub(at.elapsed()),
            };
            if wait.is_zero() {
                return Err(TransportError::Io);
            }
            // `read` is cancel-safe: a timeout drops the future without consuming bytes.
            match tokio::time::timeout(wait, self.inner.read(&mut chunk)).await {
                Err(_) if started.is_none() => return Ok(None),
                Err(_) => return Err(TransportError::Io),
                Ok(Ok(0)) if self.buf.is_empty() => return Err(TransportError::Closed),
                Ok(Ok(0)) => return Err(TransportError::Truncated),
                Ok(Ok(n)) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    started.get_or_insert_with(Instant::now);
                }
                Ok(Err(e)) => return Err(map_read_error(&e)),
            }
        }
    }

    /// Removes one whole frame from the buffer, if there is one. The length is checked
    /// as soon as its four bytes are in, so an oversize claim is refused before the
    /// body is waited for or allocated.
    fn take_frame(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        let Some(prefix) = self.buf.first_chunk::<4>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*prefix) as usize;
        if len > MAX_FRAME_LEN {
            return Err(TransportError::Oversize);
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let frame = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(frame))
    }
}

fn map_read_error(e: &io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => TransportError::Truncated,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => TransportError::Closed,
        _ => TransportError::Io,
    }
}

fn map_write_error(e: &io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => TransportError::Closed,
        _ => TransportError::Io,
    }
}

// ---------------------------------------------------------------------------------
// The node: a Tor client plus this identity's onion service.
// ---------------------------------------------------------------------------------

use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Mutex as StdMutex;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient};
use futures::StreamExt;
use tor_cell::relaycell::msg::Connected;
use tor_config::{BoolOrAuto, ExplicitOrAuto};
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, status::State};
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;
use zeroize::Zeroizing;

use crate::onion;

/// The virtual port the onion service listens on. Not secret; every identity uses it.
pub const ONION_PORT: u16 = 47001;

/// Longest a connect to a peer's onion service may take. Reaching an onion service
/// builds several circuits and can take minutes on a first contact (PLAN.md, T0 results).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

/// Incoming streams held for the core to pick up. More than this are dropped, so a
/// flood of connections cannot grow memory without bound.
const MAX_PENDING_INCOMING: usize = 8;

/// Service nickname inside arti. Local only; it is never published.
const NICKNAME: &str = "sovereignmesh";

/// Where the node is in coming up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Bootstrapping,
    Publishing,
    Ready,
    Failed,
}

/// What the UI may show: a phase and, while bootstrapping, how far along (0 to 100).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub percent: u8,
}

struct Shared {
    phase: StdMutex<Phase>,
    percent: AtomicU8,
}

impl Shared {
    /// Sets the phase even from `Failed`; used when the node is shut down.
    fn force(&self, phase: Phase) {
        if let Ok(mut p) = self.phase.lock() {
            *p = phase;
        }
    }

    fn set(&self, phase: Phase) {
        if let Ok(mut p) = self.phase.lock() {
            // Failed is final: a late status event must not turn it back into progress.
            if *p != Phase::Failed {
                *p = phase;
            }
        }
    }
}

/// A running Tor client and onion service. Dropping it stops both. The service key is
/// built from the identity's onion seed in memory and never written to disk: arti's
/// primary keystore is the in-memory one, so only public directory data and guard
/// state go to `state_dir`.
pub struct TorNode {
    runtime: Arc<OwnedRuntime>,
    shared: Arc<Shared>,
    client: Arc<StdMutex<Option<Arc<TorClient<PreferredRuntime>>>>>,
    incoming: StdMutex<Receiver<Incoming>>,
    /// Every task the node spawned, so `shutdown` can stop them all.
    tasks: Arc<StdMutex<Vec<tokio::task::AbortHandle>>>,
}

/// A stream waiting to be picked up, with when it arrived.
type Incoming = (Instant, StreamTransport<DataStream>);

/// A queued stream older than this is dropped unread: a stranger who opened one and went
/// quiet must not keep a place in the queue.
const MAX_QUEUE_AGE: Duration = Duration::from_secs(45);

impl TorNode {
    /// Starts bootstrapping in the background and returns at once; read `status` to see
    /// progress. `state_dir` must be app-private storage. `onion_seed` is the identity's
    /// onion service seed and `expected_onion` its public key: if the service that comes up
    /// does not have that address, the node fails rather than run under another one.
    pub fn start(
        state_dir: &Path,
        onion_seed: &[u8; 32],
        expected_onion: [u8; 32],
    ) -> Result<Arc<Self>, TransportError> {
        prepare_dir(state_dir)?;
        install_crypto_provider();
        let runtime = Arc::new(OwnedRuntime::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("tor")
                .enable_all()
                .build()
                .map_err(|_| TransportError::Io)?,
        ));
        let shared = Arc::new(Shared {
            phase: StdMutex::new(Phase::Starting),
            percent: AtomicU8::new(0),
        });
        let client = Arc::new(StdMutex::new(None));
        let (tx, rx) = sync_channel(MAX_PENDING_INCOMING);
        // Wiped when the task ends or is dropped, whichever happens first.
        let seed = Zeroizing::new(*onion_seed);
        let tasks = Arc::new(StdMutex::new(Vec::new()));
        let task_shared = Arc::clone(&shared);
        let task_client = Arc::clone(&client);
        let task_runtime = Arc::clone(&runtime);
        let task_list = Arc::clone(&tasks);
        let state_dir = state_dir.to_path_buf();
        let main = runtime.handle().spawn(async move {
            let ctx = RunContext {
                shared: Arc::clone(&task_shared),
                client_slot: task_client,
                incoming: tx,
                runtime: task_runtime,
                tasks: task_list,
            };
            let result = run(&state_dir, &seed, expected_onion, ctx).await;
            if result.is_err() {
                task_shared.set(Phase::Failed);
            }
        });
        if let Ok(mut list) = tasks.lock() {
            list.push(main.abort_handle());
        }
        Ok(Arc::new(Self {
            runtime,
            shared,
            client,
            incoming: StdMutex::new(rx),
            tasks,
        }))
    }

    /// Stops the Tor client and the onion service, and makes every waiting `accept` return
    /// at once. Safe to call more than once. Links already handed out keep the runtime alive
    /// until they are dropped, but nothing new is accepted and no new circuit is built.
    pub fn shutdown(&self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        if let Ok(mut slot) = self.client.lock() {
            *slot = None;
        }
        self.shared.force(Phase::Failed);
    }

    pub fn status(&self) -> Status {
        Status {
            phase: self
                .shared
                .phase
                .lock()
                .map(|p| *p)
                .unwrap_or(Phase::Failed),
            percent: self.shared.percent.load(Ordering::Relaxed),
        }
    }

    /// Dials a peer's onion service and returns the open link. Blocks, up to
    /// `CONNECT_TIMEOUT`; the caller runs it off the UI thread. `NotReady` until Tor has
    /// bootstrapped.
    pub fn connect(
        &self,
        onion_address: &str,
    ) -> Result<StreamTransport<DataStream>, TransportError> {
        // Refuse a malformed address here, before it reaches Tor.
        onion::parse(onion_address).map_err(|_| TransportError::Io)?;
        let client = self
            .client
            .lock()
            .map_err(|_| TransportError::Io)?
            .clone()
            .ok_or(TransportError::Io)?;
        let target = (onion_address.to_owned(), ONION_PORT);
        let handle = self.runtime.handle();
        let stream = handle.block_on(async {
            tokio::time::timeout(CONNECT_TIMEOUT, client.connect(target)).await
        });
        match stream {
            Ok(Ok(stream)) => Ok(StreamTransport::new(handle, stream)
                .keep_alive(Arc::clone(&self.runtime) as Arc<dyn Any + Send + Sync>)),
            _ => Err(TransportError::Io),
        }
    }

    /// Waits up to `timeout` for the next inbound stream to the onion service.
    pub fn accept(&self, timeout: Duration) -> Result<StreamTransport<DataStream>, TransportError> {
        let deadline = Instant::now() + timeout;
        let rx = self.incoming.lock().map_err(|_| TransportError::Io)?;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                // A stale stream is dropped and the next one is tried.
                Ok((arrived, _)) if arrived.elapsed() > MAX_QUEUE_AGE => continue,
                Ok((_, link)) => return Ok(link),
                Err(RecvTimeoutError::Timeout) => return Err(TransportError::Io),
                Err(RecvTimeoutError::Disconnected) => return Err(TransportError::Closed),
            }
        }
    }
}

impl Drop for TorNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// arti's TLS needs a process-wide crypto provider when more than one could be linked.
/// Installing twice is not an error worth stopping for, so the result is ignored.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Creates `dir` readable by this user only. arti refuses a state directory that other
/// users could read, and it holds guard choices and a directory cache.
fn prepare_dir(dir: &Path) -> Result<(), TransportError> {
    std::fs::create_dir_all(dir).map_err(|_| TransportError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| TransportError::Io)?;
    }
    Ok(())
}

fn client_config(state_dir: &Path) -> Result<arti_client::TorClientConfig, TransportError> {
    client_config_with(state_dir, ArtiKeystoreKind::Ephemeral)
}

/// `client_config` with the keystore kind chosen, so a test can compare against the
/// on-disk default. The product always uses the in-memory kind.
fn client_config_with(
    state_dir: &Path,
    kind: ArtiKeystoreKind,
) -> Result<arti_client::TorClientConfig, TransportError> {
    let mut builder =
        TorClientConfigBuilder::from_directories(state_dir.join("state"), state_dir.join("cache"));
    // The in-memory keystore: the onion service key is inserted at launch and gone at exit.
    builder
        .storage()
        .keystore()
        .enabled(BoolOrAuto::Explicit(true))
        .primary()
        .kind(ExplicitOrAuto::Explicit(kind));
    builder.build().map_err(|_| TransportError::Io)
}

/// What the background task shares with the node that started it.
struct RunContext {
    shared: Arc<Shared>,
    client_slot: Arc<StdMutex<Option<Arc<TorClient<PreferredRuntime>>>>>,
    incoming: SyncSender<Incoming>,
    runtime: Arc<OwnedRuntime>,
    tasks: Arc<StdMutex<Vec<tokio::task::AbortHandle>>>,
}

async fn run(
    state_dir: &Path,
    seed: &[u8; 32],
    expected_onion: [u8; 32],
    ctx: RunContext,
) -> Result<(), TransportError> {
    let RunContext {
        shared,
        client_slot,
        incoming,
        runtime,
        tasks,
    } = ctx;
    let shared = &shared;
    let handle = runtime.handle();
    let register = |task: tokio::task::AbortHandle| {
        if let Ok(mut list) = tasks.lock() {
            list.push(task);
        }
    };
    shared.set(Phase::Bootstrapping);
    let config = client_config(state_dir)?;
    let client = Arc::new(
        TorClient::builder()
            .config(config)
            .create_unbootstrapped_async()
            .await
            .map_err(|_| TransportError::Io)?,
    );

    let mut events = client.bootstrap_events();
    let progress = Arc::clone(shared);
    register(
        tokio::spawn(async move {
            while let Some(status) = events.next().await {
                let pct = (status.as_frac() * 100.0).clamp(0.0, 100.0) as u8;
                progress.percent.store(pct, Ordering::Relaxed);
            }
        })
        .abort_handle(),
    );
    client.bootstrap().await.map_err(|_| TransportError::Io)?;
    if let Ok(mut slot) = client_slot.lock() {
        *slot = Some(Arc::clone(&client));
    }

    shared.set(Phase::Publishing);
    let service_config = OnionServiceConfigBuilder::default()
        .nickname(NICKNAME.parse().map_err(|_| TransportError::Io)?)
        .build()
        .map_err(|_| TransportError::Io)?;
    let keypair = HsIdKeypair::from(ExpandedKeypair::from(&Keypair::from(seed)));
    if HsIdKey::from(&keypair).id().as_ref() != expected_onion.as_slice() {
        return Err(TransportError::Io);
    }
    let (service, requests) = client
        .launch_onion_service_with_hsid(service_config, keypair)
        .map_err(|_| TransportError::Io)?
        .ok_or(TransportError::Io)?;

    let status_shared = Arc::clone(shared);
    let mut status_events = service.status_events();
    register(
        tokio::spawn(async move {
            let _keep_alive = service; // the service stops when its last handle drops
            while let Some(status) = status_events.next().await {
                match status.state() {
                    State::DegradedReachable | State::Running => status_shared.set(Phase::Ready),
                    State::Broken => status_shared.set(Phase::Failed),
                    _ => {}
                }
            }
        })
        .abort_handle(),
    );

    let streams = handle_rend_requests(requests);
    futures::pin_mut!(streams);
    while let Some(request) = streams.next().await {
        let wanted =
            matches!(request.request(), IncomingStreamRequest::Begin(b) if b.port() == ONION_PORT);
        if !wanted {
            continue; // dropping the request refuses it
        }
        let Ok(stream) = request.accept(Connected::new_empty()).await else {
            continue;
        };
        // A full queue drops the new stream: bounded memory beats serving a flood.
        let link = StreamTransport::new(handle.clone(), stream)
            .keep_alive(Arc::clone(&runtime) as Arc<dyn Any + Send + Sync>);
        let _ = incoming.try_send((Instant::now(), link));
    }
    Ok(())
}

#[cfg(test)]
mod frame_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

    use crate::transport::{Transport, TransportError, MAX_FRAME_LEN};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    type Link = StreamTransport<Compat<DuplexStream>>;

    fn pair(rt: &tokio::runtime::Runtime) -> (Link, Link) {
        let (a, b) = tokio::io::duplex(4 * 1024 * 1024);
        (
            StreamTransport::new(rt.handle().clone(), a.compat()),
            StreamTransport::new(rt.handle().clone(), b.compat()),
        )
    }

    /// One framed side and one raw tokio end, for writing bytes a well-behaved peer would not.
    fn raw_pair(rt: &tokio::runtime::Runtime) -> (DuplexStream, Link) {
        let (raw, framed) = tokio::io::duplex(4 * 1024 * 1024);
        (
            raw,
            StreamTransport::new(rt.handle().clone(), framed.compat()),
        )
    }

    #[test]
    fn frames_arrive_intact_in_both_directions() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        a.send(b"ping").unwrap();
        assert_eq!(b.receive().unwrap().unwrap(), b"ping");
        b.send(b"pong").unwrap();
        assert_eq!(a.receive().unwrap().unwrap(), b"pong");
    }

    #[test]
    fn an_empty_frame_is_delivered_as_an_empty_frame() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        a.send(b"").unwrap();
        assert_eq!(b.receive().unwrap().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn a_frame_at_the_size_cap_is_accepted() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        let frame = vec![0xAB; MAX_FRAME_LEN];
        a.send(&frame).unwrap();
        assert_eq!(b.receive().unwrap().unwrap(), frame);
    }

    #[test]
    fn an_oversize_frame_is_refused_before_anything_is_written() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        assert_eq!(
            a.send(&vec![0u8; MAX_FRAME_LEN + 1]),
            Err(TransportError::Oversize)
        );
        // Nothing reached the peer, so it is idle and a normal frame still works.
        assert_eq!(b.receive().unwrap(), None);
        a.send(b"ok").unwrap();
        assert_eq!(b.receive().unwrap().unwrap(), b"ok");
    }

    #[test]
    fn an_oversize_length_prefix_is_refused_without_reading_the_body() {
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        rt.block_on(async {
            // A prefix claiming 4 GiB, and only a few bytes after it.
            raw.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
            raw.write_all(b"xyz").await.unwrap();
        });
        assert_eq!(framed.receive(), Err(TransportError::Oversize));
    }

    #[test]
    fn a_prefix_one_over_the_cap_is_refused() {
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        rt.block_on(async {
            raw.write_all(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes())
                .await
                .unwrap();
        });
        assert_eq!(framed.receive(), Err(TransportError::Oversize));
    }

    #[test]
    fn a_peer_that_closed_before_a_frame_is_reported_as_closed() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        drop(a);
        assert_eq!(b.receive(), Err(TransportError::Closed));
    }

    #[test]
    fn a_connection_cut_inside_a_frame_is_reported_as_truncated() {
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        rt.block_on(async {
            raw.write_all(&10u32.to_be_bytes()).await.unwrap();
            raw.write_all(b"abc").await.unwrap(); // 3 of the promised 10 bytes
            raw.shutdown().await.unwrap();
        });
        drop(raw);
        assert_eq!(framed.receive(), Err(TransportError::Truncated));
    }

    #[test]
    fn a_connection_cut_inside_the_length_prefix_is_reported_as_truncated() {
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        rt.block_on(async {
            raw.write_all(&[0, 0]).await.unwrap(); // half a prefix
            raw.shutdown().await.unwrap();
        });
        drop(raw);
        assert_eq!(framed.receive(), Err(TransportError::Truncated));
    }

    #[test]
    fn an_idle_link_returns_none_instead_of_blocking() {
        let rt = runtime();
        let (_a, b) = pair(&rt);
        let start = Instant::now();
        assert_eq!(b.receive().unwrap(), None);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_frame_split_across_many_small_writes_is_reassembled() {
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        let body = vec![7u8; 300];
        let mut wire = (body.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&body);
        let writer = rt.spawn(async move {
            for chunk in wire.chunks(7) {
                raw.write_all(chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            raw // keep the stream open until the frame has been read
        });
        // The first poll may time out on an idle link; keep polling until the frame is whole.
        let got = loop {
            if let Some(frame) = framed.receive().unwrap() {
                break frame;
            }
        };
        assert_eq!(got, body);
        drop(rt.block_on(writer).unwrap());
    }

    #[test]
    fn two_frames_sent_back_to_back_stay_separate() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        a.send(b"first").unwrap();
        a.send(b"second").unwrap();
        assert_eq!(b.receive().unwrap().unwrap(), b"first");
        assert_eq!(b.receive().unwrap().unwrap(), b"second");
    }

    #[test]
    fn concurrent_sends_do_not_interleave_their_bytes() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        let a = Arc::new(a);
        let mut senders = Vec::new();
        for id in 1u8..=4 {
            let a = Arc::clone(&a);
            senders.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    a.send(&vec![id; 3000]).unwrap();
                }
            }));
        }
        for _ in 0..100 {
            let frame = loop {
                if let Some(f) = b.receive().unwrap() {
                    break f;
                }
            };
            assert_eq!(frame.len(), 3000);
            assert!(
                frame.iter().all(|&byte| byte == frame[0]),
                "interleaved frame"
            );
        }
        for s in senders {
            s.join().unwrap();
        }
    }

    #[test]
    fn a_reader_blocked_on_receive_does_not_stall_a_send() {
        let rt = runtime();
        let (a, b) = pair(&rt);
        let a = Arc::new(a);
        let reader = {
            let a = Arc::clone(&a);
            std::thread::spawn(move || {
                // Nothing is coming for a while: this poll must not hold the send path.
                let _ = a.receive();
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        a.send(b"hello").unwrap();
        assert!(start.elapsed() < Duration::from_millis(400));
        assert_eq!(b.receive().unwrap().unwrap(), b"hello");
        reader.join().unwrap();
    }

    #[test]
    fn bytes_that_arrive_with_the_first_read_are_not_lost_between_polls() {
        // Two frames land in one read. The first receive returns the first; the second must
        // come out of the buffer on the next call, not be dropped.
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        let mut wire = Vec::new();
        for body in [&b"one"[..], &b"two"[..]] {
            wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
            wire.extend_from_slice(body);
        }
        rt.block_on(async { raw.write_all(&wire).await.unwrap() });
        assert_eq!(framed.receive().unwrap().unwrap(), b"one");
        assert_eq!(framed.receive().unwrap().unwrap(), b"two");
        drop(raw);
    }

    #[test]
    fn read_exact_reads_are_not_used_so_a_cancelled_poll_cannot_drop_bytes() {
        // A poll that times out with half a frame buffered must keep those bytes.
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        rt.block_on(async {
            raw.write_all(&6u32.to_be_bytes()).await.unwrap();
            raw.write_all(b"ab").await.unwrap();
        });
        let polled = std::thread::scope(|s| {
            let t = s.spawn(|| framed.receive());
            std::thread::sleep(Duration::from_millis(100));
            rt.block_on(async { raw.write_all(b"cdef").await.unwrap() });
            t.join().unwrap()
        });
        // Either the first poll already saw the whole frame, or it timed out: in both
        // cases the next call must produce the complete frame without losing "ab".
        let frame = match polled.unwrap() {
            Some(f) => f,
            None => loop {
                if let Some(f) = framed.receive().unwrap() {
                    break f;
                }
            },
        };
        assert_eq!(frame, b"abcdef");
        drop(raw);
    }

    #[test]
    fn an_onion_link_allows_the_handshake_more_time_than_a_lan_link() {
        let rt = runtime();
        let (a, _b) = pair(&rt);
        assert_eq!(a.handshake_deadline(), Duration::from_secs(60));
    }

    #[test]
    fn a_link_keeps_working_after_the_node_that_made_it_lets_go_of_its_runtime() {
        // The link holds the runtime alive. Without that, dropping the node's runtime
        // while a session is open made the next poll panic, and a panic aborts the app.
        let owned = Arc::new(OwnedRuntime::new(runtime()));
        let (a, b) = tokio::io::duplex(1024 * 1024);
        let keep: Arc<dyn std::any::Any + Send + Sync> = owned.clone();
        let a_link = StreamTransport::new(owned.handle(), a.compat()).keep_alive(Arc::clone(&keep));
        let b_link = StreamTransport::new(owned.handle(), b.compat()).keep_alive(keep);
        drop(owned); // the node lets go; the links still hold it
        a_link.send(b"still alive").unwrap();
        assert_eq!(b_link.receive().unwrap().unwrap(), b"still alive");
    }

    #[test]
    fn dropping_the_last_runtime_reference_inside_async_code_does_not_panic() {
        // Tokio panics if a runtime is dropped from inside a runtime. A link can be the last
        // holder and be dropped from a worker thread, so the owner must not block.
        let owned = Arc::new(OwnedRuntime::new(runtime()));
        let other = runtime();
        let moved = Arc::clone(&owned);
        drop(owned);
        other.block_on(async move {
            drop(moved);
        });
    }

    // Reads on the raw end to check what the framed side actually put on the wire.
    #[test]
    fn the_wire_format_is_a_four_byte_big_endian_length_then_the_body() {
        let rt = runtime();
        let (mut raw, framed) = raw_pair(&rt);
        framed.send(b"hey").unwrap();
        let mut got = [0u8; 7];
        rt.block_on(async { raw.read_exact(&mut got).await.unwrap() });
        assert_eq!(&got, &[0, 0, 0, 3, b'h', b'e', b'y']);
    }
}

#[cfg(test)]
mod node_tests {
    use super::*;

    fn temp_state_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sovereign-tor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Every regular file under `dir`, so a test can look at what Tor wrote.
    fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    #[test]
    fn the_node_config_builds_with_the_in_memory_keystore() {
        let dir = temp_state_dir("config");
        prepare_dir(&dir).unwrap();
        assert!(client_config(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Creates a client over `kind`, inserts the identity key for `seed`, and returns the
    /// outcome of the launch plus the files Tor left under `dir`.
    fn launch_offline(
        dir: &Path,
        kind: ArtiKeystoreKind,
        seed: &[u8; 32],
    ) -> (Result<(), String>, Vec<std::path::PathBuf>) {
        prepare_dir(dir).unwrap();
        install_crypto_provider();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let outcome = rt.block_on(async {
            let client = TorClient::builder()
                .config(client_config_with(dir, kind).unwrap())
                .create_unbootstrapped_async()
                .await
                .map_err(|e| format!("create client: {e}"))?;
            let keypair = HsIdKeypair::from(ExpandedKeypair::from(&Keypair::from(seed)));
            let svc_cfg = OnionServiceConfigBuilder::default()
                .nickname(NICKNAME.parse().unwrap())
                .build()
                .map_err(|e| format!("svc config: {e}"))?;
            client
                .launch_onion_service_with_hsid(svc_cfg, keypair)
                .map(|_| ())
                .map_err(|e| format!("launch: {e}"))
        });
        drop(rt);
        (outcome, files_under(dir))
    }

    fn looks_like_a_key_file(file: &Path) -> bool {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        name.contains("ed25519") || name.contains("hs_id")
    }

    #[test]
    fn the_onion_service_key_is_inserted_in_memory_and_never_written_to_disk() {
        let dir = temp_state_dir("nokey");
        let seed = [0x5Au8; 32];
        let (outcome, files) = launch_offline(&dir, ArtiKeystoreKind::Ephemeral, &seed);
        // The insert and launch must work offline; this is the claim under test.
        assert_eq!(
            outcome,
            Ok(()),
            "offline launch with the in-memory keystore"
        );
        let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        for file in &files {
            let bytes = std::fs::read(file).unwrap_or_default();
            assert!(
                !bytes.windows(seed.len()).any(|w| w == seed),
                "seed bytes found in {file:?}"
            );
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&seed_hex),
                "seed hex found in {file:?}"
            );
            assert!(
                !looks_like_a_key_file(file),
                "a key file was written: {file:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn control_the_default_on_disk_keystore_does_write_a_key_file() {
        // Without this, the test above could pass for the wrong reason (for example if
        // the file names it looks for never occur). The native keystore must trip it.
        let dir = temp_state_dir("control");
        let (outcome, files) = launch_offline(&dir, ArtiKeystoreKind::Native, &[0x5Au8; 32]);
        assert_eq!(outcome, Ok(()), "offline launch with the native keystore");
        assert!(
            files.iter().any(|f| looks_like_a_key_file(f)),
            "expected a key file among {files:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn shutting_a_node_down_makes_a_waiting_accept_return_at_once() {
        // Stopping Tor must not leave accept workers blocked for their full timeout while
        // they keep the old node alive.
        let dir = temp_state_dir("shutdown");
        let node = TorNode::start(&dir, &[0x11u8; 32], expected_onion(&[0x11u8; 32])).unwrap();
        let waiter = {
            let node = Arc::clone(&node);
            std::thread::spawn(move || {
                let began = Instant::now();
                let result = node.accept(Duration::from_secs(30)).map(|_| ());
                (result, began.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        node.shutdown();
        let (result, waited) = waiter.join().unwrap();
        assert_eq!(result, Err(TransportError::Closed));
        assert!(
            waited < Duration::from_secs(5),
            "accept kept waiting: {waited:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stopped_node_refuses_to_connect() {
        let dir = temp_state_dir("stopped");
        let node = TorNode::start(&dir, &[0x12u8; 32], expected_onion(&[0x12u8; 32])).unwrap();
        node.shutdown();
        let address = onion::address(&expected_onion(&[0x13u8; 32]));
        assert!(node.connect(&address).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn expected_onion(seed: &[u8; 32]) -> [u8; 32] {
        crate::handshake::Identity::from_secrets(&[1u8; 32], &[2u8; 64], seed)
            .1
            .onion
    }
}
