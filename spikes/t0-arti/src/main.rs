//! T0 spike: can arti host a v3 onion service and reach it from a second process?
//! Scratch-only. Not product code. Payloads are fixed test strings.
use std::{path::PathBuf, time::Instant};

use anyhow::{anyhow, bail, Context, Result};
use arti_client::{config::TorClientConfigBuilder, TorClient, TorClientConfig};
use futures::{io::{AsyncReadExt, AsyncWriteExt}, StreamExt};
use tor_cell::relaycell::msg::Connected;
use safelog::DisplayRedacted;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, status::State};
use tor_proto::stream::IncomingStreamRequest;

const PORT: u16 = 7777;

fn config(state: PathBuf) -> TorClientConfig {
    let cache = state.join("cache");
    TorClientConfigBuilder::from_directories(state, cache).build().expect("config")
}

async fn bootstrap(state: PathBuf) -> Result<std::sync::Arc<TorClient<tor_rtcompat::PreferredRuntime>>> {
    let tor = TorClient::builder().config(config(state)).create_unbootstrapped_async().await.context("create client")?;
    let mut events = tor.bootstrap_events();
    let t0 = Instant::now();
    tokio::spawn(async move {
        while let Some(st) = events.next().await {
            eprintln!("bootstrap_event t={:.1}s {}", t0.elapsed().as_secs_f64(), st);
        }
    });
    tor.bootstrap().await.context("bootstrap")?;
    Ok(tor)
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, body: &[u8]) -> Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > 64 * 1024 { bail!("frame too large: {n}"); }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[tokio::main]
async fn main() -> Result<()> {
    // arti's TLS needs an explicit process-level provider when more than one could be linked.
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Diagnostics only: RUST_LOG controls arti's tracing output to stderr.
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).try_init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => server(PathBuf::from(&args[2])).await,
        Some("client") => client(PathBuf::from(&args[2]), &args[3]).await,
        _ => bail!("usage: t0-arti server <state_dir> | client <state_dir> <onion>"),
    }
}

async fn server(state: PathBuf) -> Result<()> {
    let t_boot = Instant::now();
    let tor = bootstrap(state).await?;
    println!("server: bootstrap_secs={:.2}", t_boot.elapsed().as_secs_f64());

    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("t0spike".parse().map_err(|e| anyhow!("nickname: {e:?}"))?)
        .build()
        .map_err(|e| anyhow!("svc config: {e:?}"))?;
    let t_launch = Instant::now();
    let (svc, rend) = tor
        .launch_onion_service(svc_cfg)?
        .ok_or_else(|| anyhow!("onion service disabled in config"))?;
    println!("server: onion_address={}", svc.onion_address().ok_or_else(|| anyhow!("no onion address"))?.display_unredacted());

    // Publish time: first state that is reachable (descriptor published, intro points up).
    let mut status = svc.status_events();
    let mut reachable_secs = None;
    while let Some(st) = status.next().await {
        let s = st.state();
        if matches!(s, State::DegradedReachable | State::Running) && reachable_secs.is_none() {
            reachable_secs = Some(t_launch.elapsed().as_secs_f64());
            println!("server: state={s:?} publish_secs={:.2} fully_reachable={}", t_launch.elapsed().as_secs_f64(), s.is_fully_reachable());
            break;
        }
        if matches!(s, State::Broken) { bail!("onion service broke: state={s:?}"); }
    }
    if reachable_secs.is_none() { bail!("status stream ended before reachable"); }
    println!("server: waiting for one client connection (port {PORT})");

    let streams = handle_rend_requests(rend);
    futures::pin_mut!(streams);
    let stream_req = streams.next().await.ok_or_else(|| anyhow!("no stream request"))?;
    let port_ok = matches!(stream_req.request(), IncomingStreamRequest::Begin(b) if b.port() == PORT);
    if !port_ok { bail!("unexpected stream request (not BEGIN on port {PORT})"); }
    let mut data = stream_req.accept(Connected::new_empty()).await.context("accept stream")?;
    let t_rt = Instant::now();
    let got = read_frame(&mut data).await.context("read frame")?;
    println!("server: received_bytes={} ok", got.len());
    write_frame(&mut data, b"t0 pong from server").await.context("write reply")?;
    data.flush().await?;
    println!("server: round_trip_side_secs={:.2} ROUND_TRIP_SERVER_OK", t_rt.elapsed().as_secs_f64());
    // Keep the service alive until the client has read the reply.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    drop(svc);
    Ok(())
}

async fn client(state: PathBuf, onion: &str) -> Result<()> {
    let t_boot = Instant::now();
    let tor = bootstrap(state).await?;
    println!("client: bootstrap_secs={:.2}", t_boot.elapsed().as_secs_f64());

    let t_conn = Instant::now();
    let mut data = tor.connect((onion, PORT)).await.context("connect to onion")?;
    println!("client: connect_secs={:.2}", t_conn.elapsed().as_secs_f64());
    write_frame(&mut data, b"t0 ping from client").await.context("write")?;
    let reply = read_frame(&mut data).await.context("read reply")?;
    println!("client: received_bytes={} reply={:?} ROUND_TRIP_CLIENT_OK", reply.len(), String::from_utf8_lossy(&reply));
    Ok(())
}
