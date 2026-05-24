// SPDX-License-Identifier: Apache-2.0

//! # `furcate-mesh-routing`
//!
//! Local-only work-stealing decisions. *No scheduler-of-schedulers*:
//! every peer decides for itself, on every inference request, whether
//! to serve locally or forward to a peer that has the same model loaded
//! and is less busy.
//!
//! ## The decision
//!
//! For each incoming inference request the router asks, in order:
//!
//! 1. **Do I have the model loaded?** If yes, serve locally — even at
//!    high load, local is almost always faster than a network hop on a
//!    Pi-class box.
//! 2. **If no, who has it?** Consult the peer→model index built from
//!    [`MeshEvent::ModelAnnounce`] gossip.
//! 3. **Of those peers, who is least loaded?** Use the [`MeshEvent::Heartbeat`]
//!    `load` field as a coarse signal; ties broken by [`PeerId`] order
//!    for determinism (so two peers facing the same decision pick the
//!    same target and we don't double-fan-out).
//! 4. **Hop budget?** If the request has hopped >= `max_hops` times,
//!    refuse the forward and return a clear "no capacity" response.
//!
//! ## Status
//!
//! [`Router::record_announce`] and [`Router::route`] are implemented
//! and tested. The hook from the transport's incoming-request stream
//! to `Router::route` is wired in the CLI/binary, not here.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use furcate_mesh_core::{MeshConfig, PeerId};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::debug;

/// Routing errors.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// No peer in the mesh has this model.
    #[error("no peer advertises model {model_name}")]
    NoSuchModel {
        /// Model name the caller asked for.
        model_name: String,
    },
    /// The request has already hit the hop budget.
    #[error("hop budget exhausted (max_hops={max_hops})")]
    HopBudget {
        /// The configured maximum.
        max_hops: u8,
    },
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, RoutingError>;

/// What the router decided for one incoming request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Serve locally. Either the model is loaded here, or no peer has
    /// it (the operator-visible error path for the latter is
    /// [`RoutingError::NoSuchModel`]).
    Local,
    /// Forward to a peer that has the model loaded.
    Forward {
        /// Target peer.
        to: PeerId,
    },
}

/// Snapshot of one peer's gossiped state.
#[derive(Clone, Debug)]
struct PeerState {
    /// Most recent `load` from a heartbeat. `f64::MAX` means "unknown".
    load: f64,
    /// When the most recent heartbeat arrived.
    last_seen: Instant,
    /// Models this peer has advertised.
    models: Vec<String>,
}

/// The router. Cheap to clone; the model index is behind an `RwLock`.
#[derive(Clone)]
pub struct Router {
    cfg: MeshConfig,
    local: PeerId,
    state: Arc<RwLock<HashMap<PeerId, PeerState>>>,
}

impl Router {
    /// Construct a new router. `local` is *this* peer's [`PeerId`] — the
    /// router will never route a request back to its own peer.
    #[must_use]
    pub fn new(local: PeerId, cfg: MeshConfig) -> Self {
        Self {
            cfg,
            local,
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record an incoming [`MeshEvent::ModelAnnounce`].
    #[allow(clippy::significant_drop_tightening)] // guard scope is intentional
    pub async fn record_announce(&self, peer: PeerId, model_name: String) {
        if peer == self.local {
            return;
        }
        let mut state = self.state.write().await;
        let entry = state.entry(peer).or_insert_with(|| PeerState {
            load: f64::MAX,
            last_seen: Instant::now(),
            models: Vec::new(),
        });
        if !entry.models.iter().any(|m| m == &model_name) {
            entry.models.push(model_name);
        }
        entry.last_seen = Instant::now();
    }

    /// Record an incoming [`MeshEvent::Heartbeat`]. Updates `load` and
    /// the last-seen timestamp; does not change the model list.
    #[allow(clippy::significant_drop_tightening)] // guard scope is intentional
    pub async fn record_heartbeat(&self, peer: PeerId, load: f64) {
        if peer == self.local {
            return;
        }
        let mut state = self.state.write().await;
        let entry = state.entry(peer).or_insert_with(|| PeerState {
            load,
            last_seen: Instant::now(),
            models: Vec::new(),
        });
        entry.load = load;
        entry.last_seen = Instant::now();
    }

    /// Decide where to route a request for `model_name`. `local_has`
    /// is whether the caller's own engine has the model loaded;
    /// `hops_so_far` is how many forwards the request has already
    /// taken (0 for first-touch requests).
    ///
    /// # Errors
    /// [`RoutingError::NoSuchModel`] if no live peer advertises the
    /// model and `local_has` is false;
    /// [`RoutingError::HopBudget`] if `hops_so_far >= cfg.max_hops`.
    #[allow(clippy::significant_drop_tightening)] // guard scope is intentional
    pub async fn route(
        &self,
        model_name: &str,
        local_has: bool,
        hops_so_far: u8,
    ) -> Result<Decision> {
        if local_has {
            return Ok(Decision::Local);
        }
        if hops_so_far >= self.cfg.max_hops {
            return Err(RoutingError::HopBudget {
                max_hops: self.cfg.max_hops,
            });
        }

        let state = self.state.read().await;
        let dead_after = Duration::from_secs(self.cfg.peer_dead_after_secs);
        let now = Instant::now();

        let mut candidates: Vec<(PeerId, f64)> = state
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_seen) < dead_after)
            .filter(|(_, s)| s.models.iter().any(|m| m == model_name))
            .map(|(p, s)| (*p, s.load))
            .collect();

        if candidates.is_empty() {
            return Err(RoutingError::NoSuchModel {
                model_name: model_name.into(),
            });
        }

        // Sort by (load ascending, PeerId ascending) so two peers
        // making the same decision pick the same target.
        candidates.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        let to = candidates[0].0;
        debug!(model = model_name, %to, "routing forward");
        Ok(Decision::Forward { to })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }

    #[tokio::test]
    async fn local_has_short_circuits() {
        let r = Router::new(pid(0), MeshConfig::default());
        let d = r.route("any", true, 0).await.expect("ok");
        assert_eq!(d, Decision::Local);
    }

    #[tokio::test]
    async fn no_peers_yields_no_such_model() {
        let r = Router::new(pid(0), MeshConfig::default());
        let err = r.route("llama", false, 0).await.expect_err("no model");
        assert!(matches!(err, RoutingError::NoSuchModel { .. }));
    }

    #[tokio::test]
    async fn picks_least_loaded_peer() {
        let r = Router::new(pid(0), MeshConfig::default());
        r.record_announce(pid(1), "llama".into()).await;
        r.record_announce(pid(2), "llama".into()).await;
        r.record_heartbeat(pid(1), 0.9).await;
        r.record_heartbeat(pid(2), 0.1).await;
        let d = r.route("llama", false, 0).await.expect("ok");
        assert_eq!(d, Decision::Forward { to: pid(2) });
    }

    #[tokio::test]
    async fn hop_budget_blocks_further_forwards() {
        let cfg = MeshConfig {
            max_hops: 1,
            ..MeshConfig::default()
        };
        let r = Router::new(pid(0), cfg);
        r.record_announce(pid(1), "llama".into()).await;
        // hops_so_far = 1, max_hops = 1 → refuse forward.
        let err = r.route("llama", false, 1).await.expect_err("budget");
        assert!(matches!(err, RoutingError::HopBudget { .. }));
    }

    #[tokio::test]
    async fn self_announcements_are_ignored() {
        let r = Router::new(pid(0), MeshConfig::default());
        r.record_announce(pid(0), "llama".into()).await;
        let err = r.route("llama", false, 0).await.expect_err("ignored");
        assert!(matches!(err, RoutingError::NoSuchModel { .. }));
    }
}
