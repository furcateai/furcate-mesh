// SPDX-License-Identifier: Apache-2.0

//! # `furcate-mesh-discovery`
//!
//! mDNS-based peer discovery. The service type is
//! `_furcate-mesh._tcp.local.` and the TXT records carry the peer's
//! Ed25519 public key (`peer=<hex>`) plus the Zenoh listen URL
//! (`zenoh=<uri>`).
//!
//! ## What this crate does
//!
//! - Advertises the local peer on mDNS so other peers can find it.
//! - Browses for `_furcate-mesh._tcp.local.` and surfaces each
//!   discovery as a [`DiscoveredPeer`] event.
//! - Accepts a static seed list for environments where mDNS is
//!   filtered (some enterprise WLANs).
//!
//! ## What this crate explicitly does *not* do
//!
//! - **DHT / NAT traversal.** This is a LAN fabric.
//! - **Liveness.** Peer-down detection is the transport crate's job
//!   (it watches [`MeshEvent::Heartbeat`] in the gossip stream); we
//!   only deliver "I saw this peer on the network" events.
//! - **Authentication.** Discovery says *who's there*, not *who's
//!   allowed*. The identity crate enforces the latter at TLS handshake.
//!
//! ## Status
//!
//! Real mDNS advertise + browse, with a manual seed-list fallback.
//! The `Discovery::run` task owns one `ServiceDaemon`; each
//! `ServiceResolved` event becomes a [`DiscoveredPeer`] forwarded on
//! the channel.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

use std::net::SocketAddr;

use furcate_mesh_core::PeerId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Discovery service type. Constant — this is part of the wire
/// contract, on the same level as the Zenoh topic names.
pub const SERVICE_TYPE: &str = "_furcate-mesh._tcp.local.";

/// Discovery errors.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// mDNS daemon creation or service registration failed.
    #[error("mdns: {0}")]
    Mdns(String),
    /// IO error binding sockets or reading interface lists.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A seed-list entry could not be parsed.
    #[error("bad seed entry {entry:?}: {reason}")]
    BadSeed {
        /// The offending entry as the operator wrote it.
        entry: String,
        /// Why it didn't parse.
        reason: String,
    },
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, DiscoveryError>;

/// One peer the discovery layer has observed on the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    /// The peer's stable address.
    pub peer: PeerId,
    /// Where to dial it. Always populated even for mDNS finds — the
    /// browse callback gives us `SocketAddr`s directly.
    pub addr: SocketAddr,
    /// The Zenoh listen URL the peer advertised (e.g. `tcp/<ip>:7447`).
    pub zenoh_url: String,
    /// `true` if found via mDNS, `false` if from the static seed list.
    pub via_mdns: bool,
}

/// Configuration for the discovery layer.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryConfig {
    /// The local peer's public key, advertised in the mDNS TXT record.
    pub local_peer: Option<PeerId>,
    /// The Zenoh listen URL of the local peer, advertised in the TXT
    /// record so remote peers know where to dial.
    pub local_zenoh_url: Option<String>,
    /// TCP port to advertise in the mDNS A/AAAA record. This is the
    /// Zenoh listen port — `mdns-sd` requires it as a `u16`.
    pub port: u16,
    /// Static seed peers. Each entry is `peer-hex@host:port[/zenoh-url]`.
    /// Used when mDNS is unavailable.
    pub seeds: Vec<String>,
    /// If `true`, only use the seed list and skip mDNS entirely.
    pub seeds_only: bool,
}

/// The discovery service. Construct with [`Discovery::new`], spawn
/// [`Discovery::run`] on a Tokio task, and consume the
/// [`mpsc::Receiver<DiscoveredPeer>`] handed back.
pub struct Discovery {
    cfg: DiscoveryConfig,
    sink: mpsc::Sender<DiscoveredPeer>,
}

impl Discovery {
    /// Construct a new discovery service. The returned tuple is
    /// `(service, receiver)`; spawn `service.run()` and read from
    /// `receiver` for [`DiscoveredPeer`] events.
    #[must_use]
    pub fn new(cfg: DiscoveryConfig) -> (Self, mpsc::Receiver<DiscoveredPeer>) {
        // 32 is enough headroom for a Pi-class mesh; the consumer is
        // expected to keep up.
        let (tx, rx) = mpsc::channel(32);
        (Self { cfg, sink: tx }, rx)
    }

    /// Run the discovery service until the receiver is dropped.
    ///
    /// On entry the service:
    ///   1. Emits every parsed static seed as a [`DiscoveredPeer`]
    ///      with `via_mdns = false`. This happens before any mDNS work
    ///      so callers in seed-only mode get peers immediately.
    ///   2. If `seeds_only` is `false`, opens a `ServiceDaemon`,
    ///      optionally registers the local peer (when
    ///      `local_peer` + `local_zenoh_url` are set), and browses
    ///      for [`SERVICE_TYPE`]. Each `ServiceResolved` whose TXT
    ///      records carry a `peer=<hex>` and `zenoh=<url>` becomes a
    ///      [`DiscoveredPeer`] on the sink.
    ///
    /// The loop exits when the consumer drops the receiver — the
    /// `sink.send` returns an error and we tear down the daemon
    /// cleanly.
    ///
    /// # Errors
    /// [`DiscoveryError::Mdns`] on initial daemon construction or
    /// service registration; [`DiscoveryError::BadSeed`] on a
    /// malformed seed entry.
    pub async fn run(self) -> Result<()> {
        // Seeds first — even if mDNS fails, the operator gets peers.
        for entry in &self.cfg.seeds {
            let peer = parse_seed(entry)?;
            if self.sink.send(peer).await.is_err() {
                // Consumer dropped; nothing more to do.
                debug!("discovery: receiver dropped while flushing seeds");
                return Ok(());
            }
        }

        if self.cfg.seeds_only {
            // Stay alive so the caller's `tokio::spawn` handle remains
            // joinable on a long-lived shape, but with nothing to do.
            // We just wait for the consumer to drop.
            self.sink.closed().await;
            return Ok(());
        }

        let daemon =
            ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(format!("daemon: {e}")))?;

        // Register our own service so peers can find us — only when we
        // were given the bits to advertise.
        if let (Some(local_peer), Some(zenoh_url)) =
            (self.cfg.local_peer, self.cfg.local_zenoh_url.as_deref())
        {
            register_local(&daemon, local_peer, zenoh_url, self.cfg.port)?;
        } else {
            debug!("discovery: no local advertise bits, browsing only");
        }

        let rx = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| DiscoveryError::Mdns(format!("browse: {e}")))?;

        // The flume receiver is executor-agnostic; recv_async() works
        // inside this tokio task.
        loop {
            match rx.recv_async().await {
                Ok(ServiceEvent::ServiceResolved(svc)) => {
                    let Some(peer) = resolve_to_peer(&svc) else {
                        continue;
                    };
                    if Some(peer.peer) == self.cfg.local_peer {
                        // Don't surface ourselves to the routing layer.
                        continue;
                    }
                    if self.sink.send(peer).await.is_err() {
                        debug!("discovery: receiver dropped, shutting down");
                        break;
                    }
                }
                Ok(_) => {
                    // Other variants (ServiceFound/Removed/Search*) —
                    // we only emit on Resolved, which is the only one
                    // that carries both address + TXT in one event.
                }
                Err(e) => {
                    warn!(error = %e, "mDNS browse channel closed; exiting");
                    break;
                }
            }
        }

        // Best-effort shutdown. We don't care about the result —
        // the daemon's drop will tear down the OS sockets anyway.
        let _ = daemon.shutdown();
        Ok(())
    }
}

/// Register the local peer on mDNS. Best-effort: failures here are
/// surfaced as [`DiscoveryError::Mdns`] but do not abort the rest of
/// the discovery loop (the caller can decide).
fn register_local(
    daemon: &ServiceDaemon,
    local_peer: PeerId,
    zenoh_url: &str,
    port: u16,
) -> Result<()> {
    let peer_hex = local_peer.to_hex();
    let props = [("peer", peer_hex.as_str()), ("zenoh", zenoh_url)];

    // Service type, instance name, and host name MUST end with `.`.
    // Use the peer's short hex as the instance label so it's stable
    // and unique across reboots.
    let instance = format!("furcate-{}", local_peer.short());
    let host = format!("{instance}.local.");

    let info = ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", port, &props[..])
        .map_err(|e| DiscoveryError::Mdns(format!("ServiceInfo: {e}")))?
        .enable_addr_auto();

    daemon
        .register(info)
        .map_err(|e| DiscoveryError::Mdns(format!("register: {e}")))?;
    debug!(instance, host, port, "mDNS local registered");
    Ok(())
}

/// Convert a resolved mDNS service into a [`DiscoveredPeer`] iff its
/// TXT records carry the expected `peer=<hex>` and `zenoh=<url>` keys
/// and at least one address is present.
fn resolve_to_peer(svc: &mdns_sd::ResolvedService) -> Option<DiscoveredPeer> {
    let mut peer_hex: Option<String> = None;
    let mut zenoh_url: Option<String> = None;
    for p in svc.txt_properties.iter() {
        match p.key().to_ascii_lowercase().as_str() {
            "peer" => peer_hex = Some(p.val_str().to_string()),
            "zenoh" => zenoh_url = Some(p.val_str().to_string()),
            _ => {}
        }
    }
    let peer_hex = peer_hex?;
    let zenoh_url = zenoh_url?;
    let peer = PeerId::from_hex(&peer_hex).ok()?;

    // Pick any address — peers on a LAN usually only have one
    // routable one. The routing crate can use any of them.
    let scoped = svc.addresses.iter().next()?;
    let addr = SocketAddr::new(scoped.to_ip_addr(), svc.port);

    Some(DiscoveredPeer {
        peer,
        addr,
        zenoh_url,
        via_mdns: true,
    })
}

/// Parse a single seed-list entry. Format:
/// `<peer-hex>@<host>:<port>[/<zenoh-url>]`.
///
/// `zenoh-url` defaults to `tcp/<host>:<port>` if omitted.
///
/// # Errors
/// [`DiscoveryError::BadSeed`] if any segment fails to parse.
pub fn parse_seed(entry: &str) -> Result<DiscoveredPeer> {
    let (peer_part, rest) = entry
        .split_once('@')
        .ok_or_else(|| DiscoveryError::BadSeed {
            entry: entry.into(),
            reason: "expected '<peer-hex>@<host:port>[/<zenoh-url>]'".into(),
        })?;
    let peer = PeerId::from_hex(peer_part).map_err(|e| DiscoveryError::BadSeed {
        entry: entry.into(),
        reason: format!("{e}"),
    })?;
    let (host_port, zenoh_url_opt) = rest
        .split_once('/')
        .map_or((rest, None), |(hp, zu)| (hp, Some(zu.to_string())));
    let addr: SocketAddr = host_port.parse().map_err(|e| DiscoveryError::BadSeed {
        entry: entry.into(),
        reason: format!("not a socket addr: {e}"),
    })?;
    let zenoh_url = zenoh_url_opt.unwrap_or_else(|| format!("tcp/{host_port}"));
    Ok(DiscoveredPeer {
        peer,
        addr,
        zenoh_url,
        via_mdns: false,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_seed_with_explicit_zenoh_url() {
        let hex = "ab".repeat(32);
        let seed = format!("{hex}@10.0.0.5:7447/tcp/10.0.0.5:7447");
        let peer = parse_seed(&seed).expect("parse ok");
        assert_eq!(peer.zenoh_url, "tcp/10.0.0.5:7447");
        assert_eq!(peer.addr.to_string(), "10.0.0.5:7447");
        assert!(!peer.via_mdns);
    }

    #[test]
    fn parse_seed_defaults_zenoh_url_when_missing() {
        let hex = "cd".repeat(32);
        let seed = format!("{hex}@192.168.1.10:7447");
        let peer = parse_seed(&seed).expect("parse ok");
        assert_eq!(peer.zenoh_url, "tcp/192.168.1.10:7447");
    }

    #[test]
    fn parse_seed_rejects_bad_peer_hex() {
        let seed = "not-hex@10.0.0.1:7447";
        assert!(matches!(
            parse_seed(seed),
            Err(DiscoveryError::BadSeed { .. })
        ));
    }

    #[test]
    fn parse_seed_rejects_missing_at_sign() {
        assert!(matches!(
            parse_seed("10.0.0.1:7447"),
            Err(DiscoveryError::BadSeed { .. })
        ));
    }

    #[tokio::test]
    async fn seeds_only_flushes_then_idles_until_receiver_drops() {
        // With seeds_only=true we skip the mdns daemon entirely, so this
        // test runs reliably on every CI runner (mDNS is sometimes
        // sandboxed out — looking at you, GitHub Actions).
        let hex_a = "ab".repeat(32);
        let hex_b = "cd".repeat(32);
        let (svc, mut rx) = Discovery::new(DiscoveryConfig {
            seeds: vec![
                format!("{hex_a}@10.0.0.5:7447"),
                format!("{hex_b}@10.0.0.6:7447"),
            ],
            seeds_only: true,
            ..DiscoveryConfig::default()
        });
        let task = tokio::spawn(svc.run());

        let first = rx.recv().await.expect("first seed");
        assert_eq!(first.addr.to_string(), "10.0.0.5:7447");
        let second = rx.recv().await.expect("second seed");
        assert_eq!(second.addr.to_string(), "10.0.0.6:7447");

        // Drop the receiver — the task should exit cleanly.
        drop(rx);
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("task exits within 2s")
            .expect("no panic");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn seeds_only_with_bad_seed_returns_bad_seed_error() {
        let (svc, _rx) = Discovery::new(DiscoveryConfig {
            seeds: vec!["this-is-not-a-seed".into()],
            seeds_only: true,
            ..DiscoveryConfig::default()
        });
        let err = svc.run().await.expect_err("must reject");
        assert!(matches!(err, DiscoveryError::BadSeed { .. }));
    }
}
