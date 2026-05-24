// SPDX-License-Identifier: Apache-2.0

//! # `furcate-mesh-transport`
//!
//! Zenoh session wrapper + canonical key expressions.
//!
//! The Zenoh wire is doing the heavy lifting here; this crate's job is
//! to keep the topic naming and payload framing consistent across every
//! consumer (the CLI, Furcate Studio, the proprietary fleet plane).
//!
//! ## Topic conventions
//!
//! Every key starts with `furcate/mesh/` to namespace away from any
//! other Zenoh deployment on the same LAN. The next segment scopes by
//! event class:
//!
//! | Pattern                                     | Event variant            |
//! |---------------------------------------------|--------------------------|
//! | `furcate/mesh/<peer>/heartbeat`             | [`Heartbeat`][hb]        |
//! | `furcate/mesh/<peer>/model/<name>`          | [`ModelAnnounce`][ma]    |
//! | `furcate/mesh/<to>/work-offer/<request-id>` | [`WorkOffer`][wo]        |
//! | `furcate/mesh/<to>/work-result/<request-id>`| [`WorkResult`][wr]       |
//! | `furcate/mesh/<peer>/agent/<agent-id>`      | [`AgentState`][as]       |
//!
//! [hb]: furcate_mesh_core::MeshEvent::Heartbeat
//! [ma]: furcate_mesh_core::MeshEvent::ModelAnnounce
//! [wo]: furcate_mesh_core::MeshEvent::WorkOffer
//! [wr]: furcate_mesh_core::MeshEvent::WorkResult
//! [as]: furcate_mesh_core::MeshEvent::AgentState
//!
//! Subscribers wildcard over `<peer>` to listen to the whole mesh.
//!
//! ## Payload framing
//!
//! Payloads are JSON-encoded [`MeshEvent`] values. JSON is wasteful
//! versus a tagged binary codec, but at mesh-event scale (heartbeats,
//! announcements, small offers) the tradeoff buys easy interop with
//! Furcate Studio and the proprietary fleet plane without a shared
//! schema-registry. We can swap to CBOR or postcard behind the same
//! API later — callers never see the wire bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

use std::sync::Arc;

use furcate_mesh_core::{MeshEvent, PeerId};
use futures::stream::{BoxStream, StreamExt};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};
use zenoh::{Config, Session, bytes::Encoding};

// ---------------------------------------------------------------------------
// Key-expression helpers
// ---------------------------------------------------------------------------

/// Root namespace for every mesh key.
pub const ROOT: &str = "furcate/mesh";

/// Build the canonical Zenoh key expression for a [`MeshEvent`].
///
/// This is the publisher side. For subscriber side, see the wildcard
/// helpers below.
#[must_use]
pub fn key_for(event: &MeshEvent) -> String {
    match event {
        MeshEvent::Heartbeat { peer, .. } => format!("{ROOT}/{peer}/heartbeat"),
        MeshEvent::ModelAnnounce {
            peer, model_name, ..
        } => format!("{ROOT}/{peer}/model/{model_name}"),
        MeshEvent::WorkOffer { to, .. } => {
            // Request IDs are out of scope of MeshEvent; callers
            // typically format the key as `key_work_offer(to, &uuid)`.
            // We hand back the prefix so the simple case still works.
            format!("{ROOT}/{to}/work-offer")
        }
        MeshEvent::WorkResult { to, .. } => format!("{ROOT}/{to}/work-result"),
        MeshEvent::AgentState { peer, agent_id, .. } => {
            format!("{ROOT}/{peer}/agent/{agent_id}")
        }
    }
}

/// Full work-offer key including a request id.
#[must_use]
pub fn key_work_offer(to: &PeerId, request_id: &str) -> String {
    format!("{ROOT}/{to}/work-offer/{request_id}")
}

/// Full work-result key including a request id.
#[must_use]
pub fn key_work_result(to: &PeerId, request_id: &str) -> String {
    format!("{ROOT}/{to}/work-result/{request_id}")
}

/// Wildcard for "all heartbeats from any peer". Use this in
/// subscribers that want to track liveness.
pub const SUB_ALL_HEARTBEATS: &str = "furcate/mesh/*/heartbeat";

/// Wildcard for "all model announcements". Used by the routing crate
/// to maintain the peer→model index.
pub const SUB_ALL_MODELS: &str = "furcate/mesh/*/model/**";

/// Wildcard for "any agent-state event". Used by Furcate Studio.
pub const SUB_ALL_AGENT_STATE: &str = "furcate/mesh/*/agent/**";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Zenoh session open / publish / subscribe failed.
    #[error("zenoh: {0}")]
    Zenoh(String),
    /// Payload encode/decode failure.
    #[error("encoding: {0}")]
    Encoding(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Mesh transport configuration. Most operators leave this at default.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// `tcp/<ip>:<port>` listen URL. `None` means "let Zenoh pick" —
    /// useful in tests, terrible in production.
    pub listen: Option<String>,
    /// Static peer URLs to dial on top of mDNS discovery. Each entry
    /// must parse as a Zenoh `EndPoint` (e.g. `"tcp/192.168.1.50:7447"`).
    pub connect: Vec<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            // 7447 is Zenoh's documented default.
            listen: Some("tcp/0.0.0.0:7447".into()),
            connect: vec![],
        }
    }
}

/// The mesh transport. One per process; expensive to construct (opens a
/// Zenoh session, binds the listener, dials seed peers) but cheap to
/// clone — the [`Session`] inside is reference-counted.
#[derive(Clone)]
pub struct Transport {
    session: Arc<Session>,
}

impl Transport {
    /// Open a Zenoh session bound to `cfg.listen` and pre-connected to
    /// every endpoint in `cfg.connect`.
    ///
    /// Zenoh's own scouting/gossip will reach late-discovered peers
    /// once at least one connect endpoint is live, so callers don't
    /// need to call [`Transport::new`] every time mDNS surfaces a new
    /// neighbour — typically only once at process startup with the
    /// initially-known peer set.
    ///
    /// # Errors
    /// [`TransportError::Zenoh`] on config parse failure or session
    /// open failure (port already bound, malformed endpoint, etc.).
    pub async fn new(cfg: TransportConfig) -> Result<Self> {
        debug!(?cfg, "opening zenoh session");

        let mut config = Config::default();
        // Mode: "peer" — full-mesh dataflow with no central router.
        config
            .insert_json5("mode", r#""peer""#)
            .map_err(|e| TransportError::Zenoh(format!("mode: {e}")))?;

        if let Some(listen) = &cfg.listen {
            let listen_json = serde_json::to_string(&[listen])
                .map_err(|e| TransportError::Encoding(format!("listen endpoints: {e}")))?;
            config
                .insert_json5("listen/endpoints", &listen_json)
                .map_err(|e| TransportError::Zenoh(format!("listen/endpoints: {e}")))?;
        }

        if !cfg.connect.is_empty() {
            let connect_json = serde_json::to_string(&cfg.connect)
                .map_err(|e| TransportError::Encoding(format!("connect endpoints: {e}")))?;
            config
                .insert_json5("connect/endpoints", &connect_json)
                .map_err(|e| TransportError::Zenoh(format!("connect/endpoints: {e}")))?;
        }

        let session = zenoh::open(config)
            .await
            .map_err(|e| TransportError::Zenoh(format!("open: {e}")))?;

        Ok(Self {
            session: Arc::new(session),
        })
    }

    /// Publish one [`MeshEvent`] on its canonical key, JSON-encoded.
    ///
    /// # Errors
    /// [`TransportError::Encoding`] on JSON encode failure;
    /// [`TransportError::Zenoh`] on Zenoh put failure.
    pub async fn publish(&self, event: &MeshEvent) -> Result<()> {
        let key = key_for(event);
        let bytes = serde_json::to_vec(event)
            .map_err(|e| TransportError::Encoding(format!("encoding event: {e}")))?;
        self.session
            .put(&key, bytes)
            .encoding(Encoding::APPLICATION_JSON)
            .await
            .map_err(|e| TransportError::Zenoh(format!("put {key}: {e}")))?;
        Ok(())
    }

    /// Subscribe to a key expression (wildcards allowed). Returns a
    /// stream of decoded [`MeshEvent`] values.
    ///
    /// Decode failures yield `Err(TransportError::Encoding)` items —
    /// the stream stays open so one malformed publisher cannot poison
    /// the whole mesh view.
    ///
    /// # Errors
    /// [`TransportError::Zenoh`] if Zenoh refuses the subscription
    /// (e.g. a malformed key expression). Per-sample decode errors are
    /// surfaced *inside* the stream, not at this call.
    pub async fn subscribe(&self, key_expr: &str) -> Result<BoxStream<'static, Result<MeshEvent>>> {
        let subscriber = self
            .session
            .declare_subscriber(key_expr.to_string())
            .await
            .map_err(|e| TransportError::Zenoh(format!("declare_subscriber {key_expr}: {e}")))?;

        // We forward Zenoh samples through a tokio mpsc into a
        // `'static` stream. Going via a channel keeps the subscriber
        // owned by a dedicated task and frees the caller to await the
        // stream without lifetime headaches. The channel doubles as
        // backpressure: a slow consumer slows the forwarder, which
        // slows Zenoh's own buffer drain.
        let (tx, rx) = mpsc::channel::<Result<MeshEvent>>(256);
        let key_owned = key_expr.to_owned();
        tokio::spawn(async move {
            loop {
                let Ok(sample) = subscriber.recv_async().await else {
                    // Subscriber channel closed (session shutting
                    // down). Exit the forwarder.
                    debug!(key_expr = %key_owned, "subscriber channel closed");
                    break;
                };
                let key = sample.key_expr().as_str().to_owned();
                let bytes = sample.payload().to_bytes().into_owned();
                let decoded = serde_json::from_slice::<MeshEvent>(&bytes).map_err(|e| {
                    warn!(key = %key, error = %e, "mesh event decode failed");
                    TransportError::Encoding(format!("decoding event on {key}: {e}"))
                });
                if tx.send(decoded).await.is_err() {
                    // Consumer dropped the stream — exit cleanly so
                    // the subscriber is dropped and Zenoh undeclares
                    // it.
                    break;
                }
            }
        });

        Ok(ReceiverStream::new(rx).boxed())
    }

    /// Borrow the underlying Zenoh session — useful for crates (like
    /// `furcate-mesh-transfer`) that want to declare queryables or do
    /// chunked pulls without re-implementing the session-open dance.
    #[must_use]
    pub fn session(&self) -> Arc<Session> {
        self.session.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_mesh_core::HybridLogicalClock;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }

    #[test]
    fn heartbeat_key_uses_peer_hex() {
        let ev = MeshEvent::Heartbeat {
            peer: pid(0xaa),
            clock: HybridLogicalClock::now(),
            load: 0.0,
        };
        let key = key_for(&ev);
        assert!(key.starts_with("furcate/mesh/"));
        assert!(key.ends_with("/heartbeat"));
    }

    #[test]
    fn model_announce_key_includes_model_name() {
        let ev = MeshEvent::ModelAnnounce {
            peer: pid(0xbb),
            clock: HybridLogicalClock::now(),
            model_name: "llama-3-8b-q4".into(),
            digest_blake3: "0".repeat(64),
            format: "gguf".into(),
        };
        let key = key_for(&ev);
        assert!(key.ends_with("/model/llama-3-8b-q4"));
    }

    #[test]
    fn work_offer_key_with_request_id() {
        let key = key_work_offer(&pid(0xcc), "req-123");
        assert!(key.ends_with("/work-offer/req-123"));
    }

    /// End-to-end pub/sub against a real (loopback) Zenoh session.
    ///
    /// Two transports on `tcp/127.0.0.1:0` — the OS hands each an
    /// ephemeral port — connected to each other. One publishes a
    /// heartbeat, the other subscribes via the wildcard and decodes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pub_sub_roundtrip_on_loopback() {
        // Pick two ephemeral ports up-front so both peers know each
        // other's listen URL. `tcp/127.0.0.1:0` would work for listen
        // but we need a concrete connect URL on the other side.
        let port_a = pick_free_tcp_port();
        let port_b = pick_free_tcp_port();

        let a = Transport::new(TransportConfig {
            listen: Some(format!("tcp/127.0.0.1:{port_a}")),
            connect: vec![format!("tcp/127.0.0.1:{port_b}")],
        })
        .await
        .expect("open transport a");

        let b = Transport::new(TransportConfig {
            listen: Some(format!("tcp/127.0.0.1:{port_b}")),
            connect: vec![format!("tcp/127.0.0.1:{port_a}")],
        })
        .await
        .expect("open transport b");

        let mut sub = b
            .subscribe(SUB_ALL_HEARTBEATS)
            .await
            .expect("subscribe on b");

        // Let the session-to-session handshake settle. Zenoh peer
        // discovery on loopback is fast but not instantaneous.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let ev = MeshEvent::Heartbeat {
            peer: pid(0x01),
            clock: HybridLogicalClock::now(),
            load: 0.25,
        };
        a.publish(&ev).await.expect("publish on a");

        let received = tokio::time::timeout(std::time::Duration::from_secs(3), sub.next())
            .await
            .expect("subscribe timed out");
        let decoded = received.expect("stream closed").expect("decode ok");
        match decoded {
            MeshEvent::Heartbeat { peer, load, .. } => {
                assert_eq!(peer, pid(0x01));
                assert!((load - 0.25).abs() < f64::EPSILON);
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    /// Pick a free TCP port by binding to :0 and releasing. There is a
    /// tiny race between release and Zenoh re-binding the same port,
    /// but on a developer box / CI runner it is good enough.
    fn pick_free_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = listener.local_addr().expect("local_addr").port();
        drop(listener);
        port
    }
}
