// SPDX-License-Identifier: Apache-2.0

//! # `furcate-mesh` CLI
//!
//! Noun-verb shape, consistent with `furcate-inference` and the
//! `kubectl` / `docker` / `gh` family:
//!
//! ```text
//! furcate-mesh peer up                   # join the LAN mesh
//! furcate-mesh peers                     # list discovered peers
//! furcate-mesh model push   <name>       # advertise a loaded model
//! furcate-mesh model pull   <peer> <hex> # fetch a model from a peer
//! furcate-mesh route inspect             # show the routing table
//! ```
//!
//! ## Status
//!
//! `peer id`, `peer up`, and `peers` are wired through to the real
//! identity / discovery / transport stack. `model push` advertises a
//! local artefact and serves it over Zenoh queries; `model pull`
//! fetches a digest from a peer. Routing-table inspection still needs
//! a persistent state store to land before it can show anything
//! useful; today it surfaces the in-memory router's view.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use furcate_mesh_core::{HybridLogicalClock, MeshEvent, PeerId};
use furcate_mesh_discovery::{Discovery, DiscoveryConfig};
use furcate_mesh_identity::PeerIdentity;
use furcate_mesh_transfer::{TransferService, root_hash};
use furcate_mesh_transport::{SUB_ALL_HEARTBEATS, Transport, TransportConfig};
use tokio_stream::StreamExt;
use tracing::{info, warn};

/// `furcate-mesh` — LAN peer fabric for Pi-class boxes.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Override the config directory (where the Ed25519 identity
    /// lives). Defaults to `~/.config/furcate-mesh`.
    #[arg(long, env = "FURCATE_MESH_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Manage the local peer.
    Peer {
        #[command(subcommand)]
        sub: PeerCmd,
    },
    /// List peers seen on the mesh (one snapshot, then exit).
    Peers {
        /// How long to observe heartbeats before printing.
        #[arg(long, default_value_t = 5)]
        for_secs: u64,
    },
    /// Manage model distribution over the mesh.
    Model {
        #[command(subcommand)]
        sub: ModelCmd,
    },
    /// Inspect routing state.
    Route {
        #[command(subcommand)]
        sub: RouteCmd,
    },
}

#[derive(Debug, Subcommand)]
enum PeerCmd {
    /// Bring the local peer up and stay attached to the mesh.
    Up {
        /// Optional static seed peers (`<peer-hex>@<host>:<port>`).
        /// Repeat for multiple. Used when mDNS is unavailable.
        #[arg(long = "seed")]
        seeds: Vec<String>,
        /// Skip mDNS entirely. Implies the seed list is authoritative.
        #[arg(long)]
        seeds_only: bool,
        /// Zenoh listen port. Default 7447 (Zenoh's documented port).
        #[arg(long, default_value_t = 7447)]
        port: u16,
        /// Heartbeat interval (seconds).
        #[arg(long, default_value_t = 5)]
        heartbeat_secs: u64,
    },
    /// Print this peer's stable address (Ed25519 public key, hex).
    Id,
}

#[derive(Debug, Subcommand)]
enum ModelCmd {
    /// Advertise a local file as a model artefact on the mesh.
    Push {
        /// Logical model name (matches `furcate-inference` `LoadedModel.name`).
        name: String,
        /// Local path to the model artefact.
        path: PathBuf,
        /// On-disk format tag (e.g. `gguf`, `onnx`, `safetensors`).
        #[arg(long, default_value = "gguf")]
        format: String,
        /// Zenoh listen port to ride. Default 7447.
        #[arg(long, default_value_t = 7447)]
        port: u16,
        /// Static seed peers, same shape as `peer up --seed`.
        #[arg(long = "seed")]
        seeds: Vec<String>,
        /// Skip mDNS.
        #[arg(long)]
        seeds_only: bool,
    },
    /// Pull a model from a peer by its BLAKE3 digest.
    Pull {
        /// Source peer's hex address. Informational today — the actual
        /// transfer rides Zenoh's query routing.
        peer: String,
        /// BLAKE3 digest of the model, hex.
        digest: String,
        /// Local cache dir. Defaults to `<config_dir>/cache`.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        /// Zenoh listen port to ride. Default 7447.
        #[arg(long, default_value_t = 7447)]
        port: u16,
        /// Static seed peers.
        #[arg(long = "seed")]
        seeds: Vec<String>,
        /// Skip mDNS.
        #[arg(long)]
        seeds_only: bool,
    },
    /// List models currently advertised on the mesh.
    List {
        /// How long to observe model announcements before printing.
        #[arg(long, default_value_t = 5)]
        for_secs: u64,
    },
}

#[derive(Debug, Subcommand)]
enum RouteCmd {
    /// Show the current routing table.
    Inspect,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,furcate_mesh=info,furcate_mesh_cli=info")
            }),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config_dir = cli
        .config_dir
        .unwrap_or_else(PeerIdentity::default_config_dir);

    match cli.cmd {
        Cmd::Peer { sub } => match sub {
            PeerCmd::Up {
                seeds,
                seeds_only,
                port,
                heartbeat_secs,
            } => peer_up(config_dir, seeds, seeds_only, port, heartbeat_secs).await,
            PeerCmd::Id => peer_id(&config_dir),
        },
        Cmd::Peers { for_secs } => peers_list(&config_dir, for_secs).await,
        Cmd::Model { sub } => match sub {
            ModelCmd::Push {
                name,
                path,
                format,
                port,
                seeds,
                seeds_only,
            } => model_push(&config_dir, &name, &path, &format, port, &seeds, seeds_only).await,
            ModelCmd::Pull {
                peer,
                digest,
                cache_dir,
                port,
                seeds,
                seeds_only,
            } => {
                model_pull(
                    &config_dir,
                    &peer,
                    &digest,
                    cache_dir,
                    port,
                    &seeds,
                    seeds_only,
                )
                .await
            }
            ModelCmd::List { for_secs } => model_list(&config_dir, for_secs).await,
        },
        Cmd::Route { sub } => match sub {
            RouteCmd::Inspect => route_inspect().await,
        },
    }
}

fn peer_id(config_dir: &std::path::Path) -> Result<()> {
    let id = PeerIdentity::load_or_generate(config_dir)?;
    println!("{}", id.peer_id());
    Ok(())
}

/// Bring up the local peer: identity → transport → discovery →
/// heartbeat loop. Blocks until Ctrl-C.
async fn peer_up(
    config_dir: PathBuf,
    seeds: Vec<String>,
    seeds_only: bool,
    port: u16,
    heartbeat_secs: u64,
) -> Result<()> {
    let id = PeerIdentity::load_or_generate(&config_dir)?;
    let peer = id.peer_id();
    let listen_url = format!("tcp/0.0.0.0:{port}");
    info!(peer = %peer, listen = %listen_url, "starting mesh peer");

    let transport = Transport::new(TransportConfig {
        listen: Some(listen_url.clone()),
        connect: vec![],
    })
    .await
    .context("opening zenoh session")?;
    let transport = Arc::new(transport);

    let (discovery, mut discovered_rx) = Discovery::new(DiscoveryConfig {
        local_peer: Some(peer),
        local_zenoh_url: Some(listen_url.clone()),
        port,
        seeds,
        seeds_only,
    });
    let discovery_handle = tokio::spawn(async move {
        if let Err(e) = discovery.run().await {
            warn!(error = %e, "discovery loop exited with error");
        }
    });

    // Discovery forwarder: log discoveries as they arrive. The real
    // routing crate is in-process today; once it has a persistent
    // store we'll wire announcements to it here.
    tokio::spawn(async move {
        while let Some(found) = discovered_rx.recv().await {
            info!(
                peer = %found.peer,
                addr = %found.addr,
                zenoh = %found.zenoh_url,
                via_mdns = found.via_mdns,
                "discovered peer"
            );
        }
    });

    // Heartbeat loop: publish a Heartbeat MeshEvent on a fixed cadence.
    let hb_transport = transport.clone();
    let hb_peer = peer;
    let hb_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(heartbeat_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let ev = MeshEvent::Heartbeat {
                peer: hb_peer,
                clock: HybridLogicalClock::now(),
                // Load is a placeholder until the routing crate
                // exposes its current local load.
                load: 0.0,
            };
            if let Err(e) = hb_transport.publish(&ev).await {
                warn!(error = %e, "heartbeat publish failed");
            }
        }
    });

    info!(peer = %peer, "mesh peer up; waiting for Ctrl-C");
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    info!("shutting down");
    hb_handle.abort();
    discovery_handle.abort();
    Ok(())
}

/// Listen for heartbeats for a fixed window, then print one snapshot
/// of who we saw.
async fn peers_list(config_dir: &std::path::Path, for_secs: u64) -> Result<()> {
    // We don't advertise here — just open a passive listener.
    let port = pick_free_port()?;
    let listen_url = format!("tcp/0.0.0.0:{port}");
    let _id = PeerIdentity::load_or_generate(config_dir)?;
    let transport = Transport::new(TransportConfig {
        listen: Some(listen_url),
        connect: vec![],
    })
    .await
    .context("opening zenoh session")?;

    let mut sub = transport
        .subscribe(SUB_ALL_HEARTBEATS)
        .await
        .context("subscribing to heartbeats")?;

    let mut seen: std::collections::BTreeMap<PeerId, (f64, u64)> =
        std::collections::BTreeMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(for_secs);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sub.next()).await {
            Ok(Some(Ok(MeshEvent::Heartbeat { peer, load, .. }))) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                seen.insert(peer, (load, now));
            }
            Ok(Some(Ok(_) | Err(_))) => {}
            Ok(None) | Err(_) => break,
        }
    }

    if seen.is_empty() {
        println!("(no peers seen in {for_secs}s)");
    } else {
        println!(
            "PEER                                                             LOAD  LAST_SEEN"
        );
        for (p, (load, ts)) in &seen {
            println!("{p}  {load:>4.2}  {ts}");
        }
    }
    Ok(())
}

/// Push: bring up transport, register the file under its BLAKE3 digest
/// with the transfer service, advertise a `ModelAnnounce` on the mesh,
/// and stay alive serving pulls.
async fn model_push(
    config_dir: &std::path::Path,
    name: &str,
    path: &std::path::Path,
    format: &str,
    port: u16,
    seeds: &[String],
    seeds_only: bool,
) -> Result<()> {
    let id = PeerIdentity::load_or_generate(config_dir)?;
    let peer = id.peer_id();
    let digest = root_hash(path)
        .await
        .with_context(|| format!("hashing {}", path.display()))?;
    info!(peer = %peer, model = name, digest = %digest, "pushing model");

    let listen_url = format!("tcp/0.0.0.0:{port}");
    let transport = Transport::new(TransportConfig {
        listen: Some(listen_url.clone()),
        connect: vec![],
    })
    .await
    .context("opening zenoh session")?;
    let transport = Arc::new(transport);

    let cache_dir = config_dir.join("cache");
    tokio::fs::create_dir_all(&cache_dir).await.ok();
    let transfer = TransferService::new(cache_dir, transport.session());
    transfer.register(digest.clone(), path.to_path_buf()).await;
    let _serve_handle = transfer
        .serve()
        .await
        .context("declaring transfer queryable")?;

    let (discovery, _discovered_rx) = Discovery::new(DiscoveryConfig {
        local_peer: Some(peer),
        local_zenoh_url: Some(listen_url),
        port,
        seeds: seeds.to_vec(),
        seeds_only,
    });
    let _discovery_handle = tokio::spawn(discovery.run());

    let announce = MeshEvent::ModelAnnounce {
        peer,
        clock: HybridLogicalClock::now(),
        model_name: name.into(),
        digest_blake3: digest.clone(),
        format: format.into(),
    };
    transport
        .publish(&announce)
        .await
        .context("publishing ModelAnnounce")?;

    println!("pushed {name} ({format}) digest={digest}\nlistening for pulls — Ctrl-C to stop");
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    Ok(())
}

/// Pull: bring up transport, listen for the advertising peer (briefly
/// — Zenoh peer discovery on a fresh session), then fetch the digest.
async fn model_pull(
    config_dir: &std::path::Path,
    peer_hex: &str,
    digest: &str,
    cache_dir: Option<PathBuf>,
    port: u16,
    seeds: &[String],
    seeds_only: bool,
) -> Result<()> {
    let _id = PeerIdentity::load_or_generate(config_dir)?;
    let listen_url = format!("tcp/0.0.0.0:{port}");
    let transport = Transport::new(TransportConfig {
        listen: Some(listen_url.clone()),
        connect: vec![],
    })
    .await
    .context("opening zenoh session")?;
    let transport = Arc::new(transport);

    let (discovery, _discovered_rx) = Discovery::new(DiscoveryConfig {
        local_peer: None,
        local_zenoh_url: None,
        port,
        seeds: seeds.to_vec(),
        seeds_only,
    });
    let _discovery_handle = tokio::spawn(discovery.run());

    // Brief settle for peer discovery + Zenoh handshake.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let cache_dir = cache_dir.unwrap_or_else(|| config_dir.join("cache"));
    let transfer = TransferService::new(cache_dir.clone(), transport.session());
    let peer =
        PeerId::from_hex(peer_hex).with_context(|| format!("parsing peer-hex {peer_hex}"))?;
    let path = transfer
        .pull(peer, digest)
        .await
        .with_context(|| format!("pulling digest {digest}"))?;
    println!(
        "pulled {} bytes into {}",
        tokio::fs::metadata(&path).await?.len(),
        path.display()
    );
    Ok(())
}

/// Listen for ModelAnnounce events for a window, then print a one-shot
/// table.
async fn model_list(config_dir: &std::path::Path, for_secs: u64) -> Result<()> {
    let _id = PeerIdentity::load_or_generate(config_dir)?;
    let port = pick_free_port()?;
    let listen_url = format!("tcp/0.0.0.0:{port}");
    let transport = Transport::new(TransportConfig {
        listen: Some(listen_url),
        connect: vec![],
    })
    .await
    .context("opening zenoh session")?;

    let mut sub = transport
        .subscribe(furcate_mesh_transport::SUB_ALL_MODELS)
        .await
        .context("subscribing to model announcements")?;

    let mut seen: std::collections::BTreeMap<(PeerId, String), (String, String)> =
        std::collections::BTreeMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(for_secs);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sub.next()).await {
            Ok(Some(Ok(MeshEvent::ModelAnnounce {
                peer,
                model_name,
                digest_blake3,
                format,
                ..
            }))) => {
                seen.insert((peer, model_name), (digest_blake3, format));
            }
            Ok(Some(Ok(_) | Err(_))) => {}
            Ok(None) | Err(_) => break,
        }
    }

    if seen.is_empty() {
        println!("(no model announcements in {for_secs}s)");
    } else {
        println!("PEER  MODEL  FORMAT  DIGEST");
        for ((peer, name), (digest, format)) in &seen {
            println!("{peer}  {name}  {format}  {digest}");
        }
    }
    Ok(())
}

#[allow(clippy::unused_async)] // body lands when routing has a persistent store
async fn route_inspect() -> Result<()> {
    eprintln!("route inspect: in-memory router has no persistent state yet");
    Ok(())
}

/// Helper: bind to :0 to discover a free TCP port, release it.
fn pick_free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").context("bind ephemeral")?;
    let p = l.local_addr().context("local_addr")?.port();
    drop(l);
    Ok(p)
}
