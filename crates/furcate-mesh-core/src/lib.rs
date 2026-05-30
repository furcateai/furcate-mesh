// SPDX-License-Identifier: Apache-2.0

//! # `furcate-mesh-core`
//!
//! Data types for the LAN peer fabric. **No** Zenoh, **no** rustls,
//! **no** mDNS — those live in sibling crates. Importing this crate is
//! cheap; importing the transport crate pulls in a small protocol stack.
//!
//! ## What lives here
//!
//! - [`PeerId`] — 32-byte Ed25519 public key, the only stable peer
//!   address in the mesh. Display form is the lower-cased hex.
//! - [`MeshEvent`] — the tagged enum every peer publishes to and
//!   subscribes to. Wire-stable and `serde`-serialisable.
//! - [`HybridLogicalClock`] — minimal HLC for last-writer-wins
//!   reconciliation on conflicting gossip writes.
//! - Error types every higher-level crate composes with `#[from]`.
//!
//! The point of factoring these out is that downstream code (Furcate
//! Studio, the proprietary fleet plane) can talk *about* the mesh
//! without depending on Zenoh.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod extensions;
pub mod wire;

pub use extensions::{
    AnnouncementStream, DiscoveryBackend, DiscoveryError, PeerAnnouncement, WorkBroker,
    WorkBrokerError, WorkOffer, WorkOutcome,
};

// ---------------------------------------------------------------------------
// Peer identity
// ---------------------------------------------------------------------------

/// 32-byte Ed25519 public key. The canonical peer address in the mesh.
///
/// Constructed once at first boot by `furcate-mesh-identity`; persisted
/// alongside the private key on disk. The mesh never carries a
/// peer's name — humans use whatever short label the operator
/// configures locally.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(#[serde(with = "crate::wire::hex_array")] pub [u8; 32]);

impl PeerId {
    /// Construct from raw key bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// The 32 raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-cased hex of the full 32 bytes.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short form: first 6 hex chars, suitable for logs.
    #[must_use]
    pub fn short(&self) -> String {
        hex::encode(&self.0[..3])
    }

    /// Parse from hex. Accepts upper or lower case; must be exactly 64
    /// hex chars (32 bytes).
    ///
    /// # Errors
    /// [`PeerIdError`] when the input is the wrong length or not hex.
    pub fn from_hex(s: &str) -> std::result::Result<Self, PeerIdError> {
        let bytes = hex::decode(s).map_err(|_| PeerIdError::Malformed)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| PeerIdError::WrongLength)?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form in Debug — full 32 bytes is unreadable in logs and
        // we always have `to_hex()` when you actually need it.
        write!(f, "PeerId({})", self.short())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Errors parsing a [`PeerId`].
#[derive(Debug, Error)]
pub enum PeerIdError {
    /// Wrong number of bytes after hex-decoding.
    #[error("peer id must be 32 bytes (64 hex chars)")]
    WrongLength,
    /// Not valid hex.
    #[error("peer id is not valid hex")]
    Malformed,
}

// ---------------------------------------------------------------------------
// Mesh events — the wire-stable enum every peer publishes & subscribes to
// ---------------------------------------------------------------------------

/// One mesh event, addressed by a Zenoh key expression like
/// `furcate/mesh/<peer-hex>/<event-kind>`. Wire-stable: variants only
/// ever get added, never reordered or removed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MeshEvent {
    /// Heartbeat. Every peer publishes one of these every
    /// [`MeshConfig::heartbeat_interval_secs`] so the routing layer
    /// can prune dead peers without waiting on mDNS TTLs.
    Heartbeat {
        /// Sender.
        peer: PeerId,
        /// When the sender produced this event.
        clock: HybridLogicalClock,
        /// Coarse current load: 0.0 idle, 1.0 saturated. Routing uses
        /// this to bias work-stealing; not load-bearing on correctness.
        ///
        /// `f64` because JSON numbers are IEEE 754 doubles; using `f32`
        /// here would lose precision on round-trip against the
        /// `furcate-protocol` test vectors.
        load: f64,
    },
    /// Peer is announcing a model it has loaded and can serve.
    ModelAnnounce {
        /// Sender.
        peer: PeerId,
        /// When the sender produced this event.
        clock: HybridLogicalClock,
        /// Logical model name (matches `furcate-inference` `LoadedModel.name`).
        model_name: String,
        /// BLAKE3 digest of the on-disk artefact. Hex.
        digest_blake3: String,
        /// Format hint (`gguf`, `onnx`, …).
        format: String,
    },
    /// Peer is forwarding an inference request to the recipient because
    /// it can't serve it locally.
    WorkOffer {
        /// Forwarding peer.
        from: PeerId,
        /// Intended servicer.
        to: PeerId,
        /// Opaque request body, serialised by the inference crate.
        #[serde(with = "crate::wire::base64url_bytes_bytes")]
        request: bytes::Bytes,
        /// Hops the request has already taken. Increment on forward.
        hops: u8,
    },
    /// Reply to a [`MeshEvent::WorkOffer`].
    WorkResult {
        /// Original servicer.
        from: PeerId,
        /// Original requester (the peer that issued the `WorkOffer`).
        to: PeerId,
        /// Opaque response body.
        #[serde(with = "crate::wire::base64url_bytes_bytes")]
        response: bytes::Bytes,
    },
    /// Agent-state transition gossiped between peers. Optional — only
    /// emitted when the operator runs `furcate-inference agent`.
    AgentState {
        /// Sender.
        peer: PeerId,
        /// When the sender produced this event.
        clock: HybridLogicalClock,
        /// Agent identifier (TOML file name minus extension, typically).
        agent_id: String,
        /// Opaque state body — agent crate decides the shape.
        #[serde(with = "crate::wire::base64url_bytes_bytes")]
        state: bytes::Bytes,
    },

    // -- Sensor / edge-node frames (Sensor-class `furcate-node` firmware) ----
    //
    // These carry the two-way link between MCU-class nodes and a Field-class
    // aggregator. They are wire-stable additions — see the CDDL schema in the
    // `furcate-node` repo's `wire/` directory, which the C firmware codec is
    // validated against.
    /// A sensor sample published by an edge node (uplink).
    SensorReading {
        /// Originating node.
        peer: PeerId,
        /// When the node sampled.
        clock: HybridLogicalClock,
        /// Stable sensor id within the node, e.g. `bme280-0`.
        sensor_id: String,
        /// Metric name, e.g. `temperature_c`, `humidity_pct`.
        metric: String,
        /// Numeric value. `f64` for the same IEEE-754 round-trip reason as
        /// [`MeshEvent::Heartbeat`]'s `load`.
        value: f64,
        /// Unit label, e.g. `C`, `%`, `Pa`. Empty when dimensionless.
        unit: String,
        /// Optional opaque payload for non-scalar sensors (image crop, raw
        /// frame). Absent for plain scalar readings.
        #[serde(
            with = "crate::wire::base64url_bytes_opt",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        raw: Option<bytes::Bytes>,
    },
    /// A command addressed to an edge node (downlink). The node interprets
    /// `verb` + `params`; unknown verbs are ignored (forward-compatible).
    Command {
        /// Target node.
        to: PeerId,
        /// Issuer's clock.
        clock: HybridLogicalClock,
        /// Verb, e.g. `set-interval`, `actuate`, `identify`, `reboot`.
        verb: String,
        /// Opaque parameter blob (CBOR/JSON), interpreted per `verb`.
        #[serde(with = "crate::wire::base64url_bytes_bytes")]
        params: bytes::Bytes,
    },
    /// Device attestation evidence forwarded by the node; the aggregator
    /// relays it northbound to the verifier (RATS).
    Attestation {
        /// Attesting node.
        peer: PeerId,
        /// Node's clock.
        clock: HybridLogicalClock,
        /// Evidence format, e.g. `esp-secure-boot-v2`, `psa-token`.
        format: String,
        /// Opaque evidence blob (COSE/CBOR).
        #[serde(with = "crate::wire::base64url_bytes_bytes")]
        evidence: bytes::Bytes,
    },
    /// An OTA image offered to a node (downlink). Delivery is either a `url`
    /// the node fetches, or out-of-band chunking keyed by `image_id`.
    OtaOffer {
        /// Target node.
        to: PeerId,
        /// Issuer's clock.
        clock: HybridLogicalClock,
        /// Image identifier (also the chunk-transfer key).
        image_id: String,
        /// Monotonic secure version (anti-rollback).
        version: u32,
        /// Fetch URL (mqtt/https). Empty when delivered out-of-band.
        url: String,
        /// Lowercase-hex SHA-256 of the image.
        sha256: String,
        /// Image size in bytes.
        size: u64,
    },
    /// A node's OTA progress/outcome (uplink) for an [`MeshEvent::OtaOffer`].
    OtaStatus {
        /// Reporting node.
        peer: PeerId,
        /// Node's clock.
        clock: HybridLogicalClock,
        /// Image this status refers to.
        image_id: String,
        /// State: `downloading`, `applied`, `valid`, `rolled-back`, `failed`.
        state: String,
        /// Free-form detail (error text, percent).
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// Hybrid logical clock
// ---------------------------------------------------------------------------

/// Hybrid logical clock — wall-clock millis with a counter to break ties.
///
/// Used as the tie-break for last-writer-wins gossip reconciliation:
/// given two conflicting [`MeshEvent::AgentState`] writes, the one with
/// the larger HLC wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HybridLogicalClock {
    /// Milliseconds since UNIX epoch.
    pub wall_ms: u64,
    /// Monotonic counter incremented on each event the producing peer
    /// emits in the same millisecond.
    pub counter: u32,
}

impl HybridLogicalClock {
    /// Construct an HLC for "now".
    ///
    /// On a Pi with broken NTP this may go backwards relative to the
    /// last call; the calling code is responsible for not regressing
    /// — typically by storing the previous HLC and `bumping` it past
    /// the wall clock when necessary.
    #[must_use]
    pub fn now() -> Self {
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            wall_ms,
            counter: 0,
        }
    }

    /// Bump this clock past `other`, preserving monotonicity.
    ///
    /// Use case: peer A receives an event with HLC=X. Before producing
    /// its own next event, peer A's local HLC must be > X so the new
    /// event sorts after the one it observed.
    pub fn bump_past(&mut self, other: Self) {
        if other > *self {
            *self = other;
        }
        self.counter = self.counter.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Mesh-wide configuration
// ---------------------------------------------------------------------------

/// Configuration shared between the transport, discovery, and routing
/// crates. Each crate consumes only the fields it cares about.
#[derive(Clone, Debug)]
pub struct MeshConfig {
    /// How often each peer publishes a [`MeshEvent::Heartbeat`].
    /// Default 5 seconds.
    pub heartbeat_interval_secs: u64,
    /// How long after a missing heartbeat we consider a peer dead.
    /// Default 30 seconds.
    pub peer_dead_after_secs: u64,
    /// Maximum hops a [`MeshEvent::WorkOffer`] can take before the
    /// receiver refuses to forward it again. Default 1 (one redirect).
    pub max_hops: u8,
    /// mDNS service domain. Default `local.`.
    pub mdns_domain: String,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 5,
            peer_dead_after_secs: 30,
            max_hops: 1,
            mdns_domain: "local.".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors that bubble up the whole stack
// ---------------------------------------------------------------------------

/// Errors common to every mesh crate.
#[derive(Debug, Error)]
pub enum MeshError {
    /// Identity material is missing, malformed, or unreadable.
    #[error("identity: {0}")]
    Identity(String),
    /// Discovery layer failure (mDNS bind, browse loop crash).
    #[error("discovery: {0}")]
    Discovery(String),
    /// Transport layer failure (Zenoh session open, publish, subscribe).
    #[error("transport: {0}")]
    Transport(String),
    /// Transfer layer failure (chunk fetch, BLAKE3 verify).
    #[error("transfer: {0}")]
    Transfer(String),
    /// Configuration error — most often a malformed seed-list URL.
    #[error("config: {0}")]
    Config(String),
    /// IO error while reading/writing local state.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON (de)serialisation error on a mesh event payload.
    #[error("encoding: {0}")]
    Encoding(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, MeshError>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_hex_roundtrip() {
        let id = PeerId::from_bytes([7u8; 32]);
        let parsed = PeerId::from_hex(&id.to_hex()).expect("parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn peer_id_short_is_six_chars() {
        let id = PeerId::from_bytes([0xab; 32]);
        assert_eq!(id.short().len(), 6);
    }

    #[test]
    fn peer_id_rejects_wrong_length() {
        assert!(matches!(
            PeerId::from_hex("deadbeef"),
            Err(PeerIdError::WrongLength)
        ));
    }

    #[test]
    fn peer_id_rejects_bad_hex() {
        assert!(matches!(
            PeerId::from_hex("zz".repeat(32).as_str()),
            Err(PeerIdError::Malformed)
        ));
    }

    #[test]
    fn hlc_bump_past_advances() {
        let mut a = HybridLogicalClock {
            wall_ms: 100,
            counter: 0,
        };
        let b = HybridLogicalClock {
            wall_ms: 200,
            counter: 0,
        };
        a.bump_past(b);
        assert_eq!(a.wall_ms, 200);
        assert_eq!(a.counter, 1);
    }

    #[test]
    fn mesh_event_roundtrips_via_json() {
        let ev = MeshEvent::Heartbeat {
            peer: PeerId::from_bytes([1; 32]),
            clock: HybridLogicalClock::now(),
            load: 0.42,
        };
        let s = serde_json::to_string(&ev).expect("encode");
        let _back: MeshEvent = serde_json::from_str(&s).expect("decode");
    }

    #[test]
    fn peer_id_wire_form_is_lowercase_hex_string() {
        // Guards against accidental regression to the default
        // `[u8; 32]` JSON-array encoding. The wire form is a 64-char
        // lowercase hex string — see `wire::hex_array`.
        let id = PeerId::from_bytes([0xab; 32]);
        let s = serde_json::to_string(&id).expect("encode");
        assert_eq!(s, format!("\"{}\"", "ab".repeat(32)));
    }

    #[test]
    fn sensor_reading_roundtrips_via_json_without_raw() {
        let ev = MeshEvent::SensorReading {
            peer: PeerId::from_bytes([3; 32]),
            clock: HybridLogicalClock::now(),
            sensor_id: "bme280-0".into(),
            metric: "temperature_c".into(),
            value: 21.5,
            unit: "C".into(),
            raw: None,
        };
        let s = serde_json::to_string(&ev).expect("encode");
        // `raw: None` must be skipped on the wire.
        assert!(!s.contains("raw"), "raw should be omitted when None: {s}");
        assert!(s.contains(r#""kind":"sensor-reading""#), "got: {s}");
        let _back: MeshEvent = serde_json::from_str(&s).expect("decode");
    }

    #[test]
    fn command_and_attestation_roundtrip_via_json() {
        let cmd = MeshEvent::Command {
            to: PeerId::from_bytes([4; 32]),
            clock: HybridLogicalClock::now(),
            verb: "set-interval".into(),
            params: bytes::Bytes::from_static(b"{\"secs\":30}"),
        };
        let s = serde_json::to_string(&cmd).expect("encode");
        let _back: MeshEvent = serde_json::from_str(&s).expect("decode");

        let att = MeshEvent::Attestation {
            peer: PeerId::from_bytes([5; 32]),
            clock: HybridLogicalClock::now(),
            format: "esp-secure-boot-v2".into(),
            evidence: bytes::Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
        };
        let s = serde_json::to_string(&att).expect("encode");
        let _back: MeshEvent = serde_json::from_str(&s).expect("decode");
    }

    #[cfg(feature = "cbor")]
    #[test]
    fn mesh_event_roundtrips_via_cbor() {
        use crate::wire::cbor;
        let cases = [
            MeshEvent::Heartbeat {
                peer: PeerId::from_bytes([1; 32]),
                clock: HybridLogicalClock { wall_ms: 42, counter: 7 },
                load: 0.5,
            },
            MeshEvent::SensorReading {
                peer: PeerId::from_bytes([2; 32]),
                clock: HybridLogicalClock { wall_ms: 99, counter: 0 },
                sensor_id: "sht41".into(),
                metric: "humidity_pct".into(),
                value: 47.25,
                unit: "%".into(),
                raw: Some(bytes::Bytes::from_static(&[1, 2, 3])),
            },
            MeshEvent::OtaStatus {
                peer: PeerId::from_bytes([6; 32]),
                clock: HybridLogicalClock { wall_ms: 1, counter: 1 },
                image_id: "fw-1.2.3".into(),
                state: "valid".into(),
                detail: String::new(),
            },
        ];
        for ev in cases {
            let bytes = cbor::to_vec(&ev).expect("cbor encode");
            let back = cbor::from_slice(&bytes).expect("cbor decode");
            // Re-encode to JSON on both sides to compare structurally without
            // requiring PartialEq on MeshEvent.
            let a = serde_json::to_string(&ev).unwrap();
            let b = serde_json::to_string(&back).unwrap();
            assert_eq!(a, b, "cbor round-trip changed the event");
        }
    }

    #[test]
    fn work_offer_payload_is_base64url_string() {
        // Guards against accidental regression to the default
        // `bytes::Bytes` JSON-array encoding. The wire form is an
        // unpadded base64url string — see `wire::base64url_bytes_bytes`.
        let ev = MeshEvent::WorkOffer {
            from: PeerId::from_bytes([1; 32]),
            to: PeerId::from_bytes([2; 32]),
            request: bytes::Bytes::from_static(&[0x01, 0x02, 0x03, 0x04, 0x05]),
            hops: 0,
        };
        let s = serde_json::to_string(&ev).expect("encode");
        assert!(s.contains(r#""request":"AQIDBAU""#), "got: {s}");
    }
}
