# Integration: Tenzro Network (mesh)

**Role in the mesh layer:** Reference impls of `DiscoveryBackend` and
`WorkBroker`. Bootstraps peers from Tenzro Provider, posts unservable work
offers to the Tenzro task marketplace, and settles results via Tenzro
Settlement.

**Operating modes:** Mode 3 (see [`../operating-modes.md`](../operating-modes.md)).

**Crate:** [`tenzro-edge`](https://github.com/furcateai/tenzro-edge) Tier 2
participation runtime — specifically `tenzro-edge-core`, which consumes
[`tenzro-sdk-rust`](https://github.com/tenzro/tenzro-sdk-rust) pinned to rev
`536363b`. Mesh-side composition pulls `tenzro-edge-core` directly from the
composition root; there is no `tenzro` Cargo feature on the mesh crates.

The inference-side Tenzro integration is documented in
[`furcate-inference/docs/architecture/integrations/tenzro.md`](https://github.com/furcateai/furcate-inference/blob/main/docs/architecture/integrations/tenzro.md).
That document is the canonical reference for the *why*; this document
focuses on the mesh-specific impls.

---

## What the mesh-side uses

| Trait impl (`tenzro-edge-core`) | Tenzro SDK call | Purpose |
|---------------------------------|-----------------|---------|
| `TenzroDiscovery` (`DiscoveryBackend`) | polled `client.provider().list_providers()` | Bootstrap peers beyond LAN range |
| `TenzroBroker` (`WorkBroker`) | `client.task().post_task()` + poll | Post `WorkOffer`s LAN can't absorb |

The mesh layer does **not** consume Tenzro identity, wallets, or other SDK
surface directly. Peer identity remains Ed25519 raw-PK TLS at the mesh layer;
Tenzro DIDs are an inference-side concern (the `Attester` trait).

## Discovery composition

When `[discovery.tenzro]` is configured *in addition to* `[discovery.mdns]`,
the two streams are merged. mDNS continues to return LAN peers in
milliseconds; Tenzro provider listings arrive over the network on a longer
cadence. The merged stream feeds the same peer-table the LAN-only mode uses.

Filters available on `[discovery.tenzro]`:

| Filter | Meaning |
|--------|---------|
| `"all"` | All providers reachable through the configured Tenzro endpoint |
| `"model-overlap"` | Only providers serving at least one model this peer also serves |
| `"shard:<id>"` | Only providers in a named shard |
| `"region:<tag>"` | Only providers in a region tag |

Filter is evaluated by the Tenzro side (RPC parameter), not locally.

## Work-broker composition

The broker stack is **priority-ordered**:

1. Try local execution.
2. Try LAN mesh (`broker.local`, `"mesh-local"`).
3. Try Tenzro task marketplace (`broker.tenzro`, `"tenzro-task-marketplace"`).
4. Reject.

If Tenzro is unreachable, step 3 fails immediately and the offer is rejected.
The mesh layer does not queue rejected offers; queuing is an application-
level concern (out of bundle).

## Fail-soft behaviour

- Tenzro discovery is **additive**. If it fails, the merged peer stream still
  contains mDNS results.
- Tenzro broker is **strictly downstream**. If LAN absorbs the offer, Tenzro
  is never consulted.
- A `WorkOffer` posted to Tenzro and not picked up within the broker's
  timeout returns a `MeshEvent::WorkResult` carrying an error — the offering
  peer can decide to retry locally, alert the operator, or surface the error
  to the calling agent loop.

## Status

- `DiscoveryBackend` and `WorkBroker` traits live in `furcate-mesh-core`.
- `TenzroDiscovery` and `TenzroBroker` impls live in `tenzro-edge-core`
  (Tier 2). No separate `furcate-discovery-tenzro` / `furcate-broker-tenzro`
  crates — the mesh impls ship from the same Tier 2 crate as the
  inference-side Tenzro impls.
- Known TLS gap: the SDK currently pulls `reqwest` with `native-tls`,
  conflicting with `furcate-mesh`'s `rustls` + `aws-lc-rs` posture.
- ⏳ Composition wiring in `furcate-mesh-cli` (`--tenzro-rpc` flag).

## Reference

- Inference-side Tenzro integration: link above.
- Tenzro SDK Rust: https://github.com/tenzro/tenzro-sdk-rust
