// SPDX-License-Identifier: Apache-2.0

//! Trait surface for mesh extensions — discovery + work brokerage.
//!
//! Reference impls live in sibling crates:
//! - `furcate-mesh-discovery` — mDNS reference impl of [`DiscoveryBackend`]
//! - `tenzro-edge` — Tenzro impl of [`DiscoveryBackend`] + [`WorkBroker`]
//!
//! See the inference repo's `docs/architecture/extension-model.md` (§4)
//! for the canonical contract.

use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::PeerId;

// ---------------------------------------------------------------------------
// DiscoveryBackend
// ---------------------------------------------------------------------------

/// One peer announcement from a discovery backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// Discovered peer.
    pub peer: PeerId,
    /// Optional reachable endpoint (e.g. `"tcp://10.0.0.5:7447"`).
    pub endpoint: Option<String>,
    /// Free-form labels — used by the routing layer to bias selection
    /// (e.g. `"region=eu-west"`, `"npu=hailo"`).
    #[serde(default)]
    pub labels: Vec<String>,
}

/// `DiscoveryBackend` errors.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Setup error — backend could not start (mDNS bind, RPC auth).
    #[error("setup: {0}")]
    Setup(String),
    /// Stream terminated and cannot be resumed.
    #[error("terminated: {0}")]
    Terminated(String),
}

/// An async stream of [`PeerAnnouncement`]s.
pub type AnnouncementStream =
    Pin<Box<dyn Stream<Item = std::result::Result<PeerAnnouncement, DiscoveryError>> + Send>>;

/// Discovers peers and yields announcements.
///
/// Reference impl: mDNS via `mdns-sd 0.19`. Plugin examples: Tenzro
/// `list_providers`, DHT, centralised HTTP registry.
#[async_trait]
pub trait DiscoveryBackend: Send + Sync + 'static {
    /// Start the backend and return a stream of peer announcements.
    /// Implementations MUST clean up on stream drop.
    async fn start(&self) -> std::result::Result<AnnouncementStream, DiscoveryError>;
}

// ---------------------------------------------------------------------------
// WorkBroker
// ---------------------------------------------------------------------------

/// One offer of work to be executed somewhere on the mesh.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkOffer {
    /// Logical work type — e.g. `"inference:text-completion"`,
    /// `"inference:tensor"`. Brokers use this to filter executors.
    pub work_type: String,
    /// Opaque request body, serialised by the inference crate.
    #[serde(with = "crate::wire::base64url_bytes_bytes")]
    pub request: Bytes,
    /// Maximum price the offerer is willing to pay (impl-specific
    /// asset/units). `None` = no limit / not for sale.
    pub max_price: Option<u128>,
    /// Per-offer deadline in seconds. `None` = broker default.
    pub deadline_secs: Option<u32>,
}

/// Outcome of a [`WorkBroker::offer`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkOutcome {
    /// Work was executed and produced this response.
    Completed {
        /// Opaque response bytes.
        #[serde(with = "crate::wire::base64url_bytes_bytes")]
        response: Bytes,
        /// Executor that completed the work.
        executor: PeerId,
    },
    /// Broker accepted the offer but executor failed or timed out.
    Failed {
        /// Reason from the broker.
        reason: String,
    },
    /// Broker refused the offer (no matching executor, price too low,
    /// policy block).
    Refused {
        /// Reason from the broker.
        reason: String,
    },
}

/// `WorkBroker` errors.
#[derive(Debug, Error)]
pub enum WorkBrokerError {
    /// Broker is unreachable.
    #[error("unreachable: {0}")]
    Unreachable(String),
    /// Transient error — caller may retry.
    #[error("transient: {0}")]
    Transient(String),
    /// Broker reported a fatal error.
    #[error("broker failed: {0}")]
    Failed(String),
}

/// Routes a work offer to an executor (locally or globally) and returns
/// the outcome.
///
/// Reference impl: local + LAN-mesh work-stealing. Plugin examples:
/// Tenzro task marketplace, K8s job submission, Slurm.
#[async_trait]
pub trait WorkBroker: Send + Sync + 'static {
    /// Offer work to the broker. Returns when the work completes, fails,
    /// or is refused.
    async fn offer(&self, offer: WorkOffer) -> std::result::Result<WorkOutcome, WorkBrokerError>;
}
