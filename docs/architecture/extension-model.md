# Extension model (mesh)

`furcate-mesh` extends the bundle's overall extension model with two mesh-
specific traits. The canonical extension model — trait-core + impl-shell +
plugin-orbit — is documented in the `furcate-inference` repo:

> [furcate-inference/docs/architecture/extension-model.md](https://github.com/furcateai/furcate-inference/blob/main/docs/architecture/extension-model.md)

Read that first. This document only covers the mesh-specific surface.

---

## Mesh traits (`furcate-mesh-core`)

### `DiscoveryBackend`

Yields peer announcements as a stream of `MeshEvent::PeerAnnounced` events.
Multiple backends compose: today's mDNS finds LAN peers, a future Tenzro
backend bootstraps cross-site seeds. The mesh layer merges all configured
backends into a single discovery stream.

**Reference impls:**
- `furcate-mesh-discovery` (Tier 1) — `mdns-sd 0.19` browsing
  `_furcate-mesh._tcp.local.` (the default everywhere).
- `TenzroDiscovery` in `tenzro-edge-core` (Tier 2) — polled
  `tenzro.provider().list_providers()` for cross-site seeds.

**Plugin examples:** DHT (libp2p / Kademlia), central HTTP registry, custom
gossipsub, AWS Cloud Map, Tailscale magic-DNS.

### `WorkBroker`

Accepts a `MeshEvent::WorkOffer` and returns a routing decision: execute
locally, forward to a specific peer, or reject. Multiple brokers compose in
priority order: try LAN first, then escalate to a remote marketplace.

**Reference impls:**
- `furcate-mesh-broker` (Tier 1) — LAN work-stealing with least-loaded
  tie-breaking by `PeerId`.
- `TenzroBroker` in `tenzro-edge-core` (Tier 2) — `client.task().post_task()`
  + poll; posts offers LAN can't absorb to the Tenzro task marketplace.

**Plugin examples:** K8s job submission, Slurm, Nomad, custom internal queue.

## Wire stability

The `MeshEvent` enum is **wire-stable**:

```rust
pub enum MeshEvent {
    Heartbeat(Heartbeat),
    PeerAnnounced(PeerAnnouncement),
    ModelAnnounce(ModelAnnounce),
    WorkOffer(WorkOffer),
    WorkResult(WorkResult),
    AgentState(AgentState),
    // v0.2+: Extension(String /*type*/, Vec<u8> /*payload*/) for plugins
}
```

Rules:
- Adding a variant: **minor** version bump.
- Removing or renaming a variant: **major** version bump.
- Adding fields to a variant struct: minor, with `serde(default)`.
- Removing or renaming fields: major.

The planned `MeshEvent::Extension` variant lets plugins introduce new event
kinds without touching `MeshEvent` itself.

## Composition

Mesh-side `furcate.toml`:

```toml
[mesh]
peer_id_file = "/etc/furcate/peer.pem"

[discovery.mdns]
type = "mdns"
service = "_furcate-mesh._tcp.local."

[discovery.tenzro]
type = "tenzro-providers"
filter = "model-overlap"

[broker.local]
type = "mesh-local"

[broker.tenzro]
type = "tenzro-task-marketplace"
```

The mesh CLI loads this config and constructs the registry the same way the
inference CLI does.

## Relationship to inference-side traits

A `ReceiptSink` or `Attester` plugin written for `furcate-inference` does not
need a mesh equivalent — those traits live in `furcate-inference-core`. The
mesh layer consumes those traits when needed (e.g., a `WorkResult` event
carries a receipt that the receiving peer routes through its own
`PolicyRouter` and `ReceiptSink`s).

Cross-cutting traits (auth, identity, transport encryption) live in
`furcate-mesh-identity` and are not currently a plugin extension surface —
the raw-PK TLS posture is opinionated by design. If a deployment needs a
different transport security model, the right path is a new repo, not a
plugin.
