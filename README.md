# furcate-mesh

**A LAN peer fabric for edge nodes — Pi-class first, designed to grow into other edge hardware classes.**

A LAN peer fabric for 2–32 edge boxes. Discover peers over mDNS, share models
over a content-addressed transfer, and route inference work to peers that
already have the model loaded.

The protocol and trait surface are hardware-agnostic. Pi-class (aarch64 Linux,
1 GB RAM, intermittent network) is the primary target today because that's
where the binary-size budget (~20 MB AArch64 musl static) and operational
defaults are tuned — see [Hardware scope](#hardware-scope) below.

```
furcate-mesh peer up                       # join the LAN mesh
furcate-mesh peers                         # list discovered peers
furcate-mesh model push   <model-name>     # advertise a loaded model
furcate-mesh model pull   <peer> <model>   # fetch a model from a peer
furcate-mesh route inspect                 # show recent routing decisions
```

Independent. Runs without Tenzro, without any external network. Air-gapped LAN
operation is the default.

## Protocol

The mesh wire formats (`MeshEvent` variants: `Heartbeat`, `ModelAnnounce`, `WorkOffer`, `WorkResult`, `AgentState`; `PeerId`; `HybridLogicalClock`) are specified in [`furcate-protocol`](https://github.com/furcateai/furcate-protocol). This release tracks **`furcate-protocol 0.1.x`**. Other mesh implementations targeting the same protocol tag interoperate with this one — events serialised by either side validate against the JSON Schemas published in that repo.

## What it is

- **Peer discovery** — mDNS over IPv4/IPv6 (`_furcate-mesh._tcp.local`), with a manual seed-list fallback. No DHT, no NAT traversal — designed for networks you own.
- **Identity** — every peer is its Ed25519 public key. Mutual peer auth uses [raw public-key TLS](https://datatracker.ietf.org/doc/html/rfc7250) via rustls + aws-lc-rs (FIPS-eligible). No central CA.
- **Model distribution** — content-addressed BLAKE3 chunked pull. Signatures re-verified on the receiver; the mesh is a *transport* optimisation, not a *trust* optimisation.
- **Work-stealing** — when a peer can't serve a request locally, it forwards to a peer that can. Routing is local; hop budget is operator-configured (default max-one-hop).
- **Agent-state gossip** — optional Zenoh pub/sub on `furcate/mesh/agent-state` so multi-peer agent loops observe each other.

## What it is *not*

- **WAN.** Mesh is LAN-only by design. WAN reach comes from `tenzro-edge`.
- **Multi-tenant.** One mesh per LAN.
- **A scheduler.** Routing is local-first; nothing here makes cluster-wide decisions.
- **A quorum / consensus protocol.** State is eventually consistent; conflicting writes are last-writer-wins on hybrid logical clocks.

## Hardware scope

The wire formats and the `DiscoveryBackend` / `WorkBroker` trait surface are hardware-agnostic. Status by class:

| Class | Status |
|---|---|
| **Raspberry Pi 4 / Pi 5** (aarch64 Linux, 1–8 GB RAM) | **Primary target.** ~20 MB AArch64 musl static budget, curated Tokio features, mDNS + Zenoh + BLAKE3 chunk sizes tuned for this class. Validated on aarch64 Linux. |
| **NVIDIA Jetson family** (Orin Nano / Nano Super / Orin NX / AGX Orin) | Trait surface and protocol work today on JetPack 6 aarch64. Operational defaults (chunk size, retry windows) not yet tuned for the higher memory + bandwidth budget. |
| **x86_64 edge boxes** (Intel N100 / NUC-class) | Works today as a build/dev target. Mixed-architecture meshes (some Pis + some x86) are supported by design — `PeerId` and `MeshEvent` are architecture-neutral. |
| **Microcontroller-class** (Cortex-M, RISC-V MCU, no std) | Out of scope. The MCU mesh story belongs in a separate, lighter-weight kernel. |

"Pi-class first" is a deliberate sequencing decision, not a permanent boundary. Adding a class means tuning the binary-size / chunk-size / retry defaults — the protocol stays the same. Issues with a target board + the constraints you need are welcome.

## The trait surface

In `furcate-mesh-core`:

- `DiscoveryBackend` — yields peer announcements as a stream (mDNS, Tenzro providers, DHT, …)
- `WorkBroker` — accepts a `WorkOffer` and finds an executor (LAN mesh, Tenzro task marketplace, K8s, …)

Plus wire-stable types: `PeerId`, `MeshEvent` (`Heartbeat`, `ModelAnnounce`, `WorkOffer`, `WorkResult`, `AgentState`).

2 traits. Locked v0.1.

## Quick start

```bash
cargo build --workspace

# Join the LAN mesh
cargo run -p furcate-mesh-cli -- peer up

# In another terminal, list discovered peers
cargo run -p furcate-mesh-cli -- peers
```

## Crate layout

```
crates/
├── furcate-mesh-core         # Trait kernel + wire-stable types
├── furcate-mesh-identity     # Ed25519 identity + raw-PK TLS via rustls aws-lc-rs
├── furcate-mesh-discovery    # mDNS reference DiscoveryBackend impl
├── furcate-mesh-transport    # Zenoh transport for MeshEvent pub/sub
├── furcate-mesh-transfer     # BLAKE3 chunked model transfer over Zenoh queries
├── furcate-mesh-routing      # LAN work-stealing reference WorkBroker impl
└── furcate-mesh-cli          # The `furcate-mesh` binary
```

## Operating modes

| Mode | Composition |
|---|---|
| **1 — Standalone LAN** | mDNS discovery + LAN work-stealing only. Air-gapped. |
| **3 — + Tenzro Network** | + `DiscoveryBackend=tenzro` (cross-site seeds) + `WorkBroker=tenzro` (task marketplace) via `tenzro-edge` |

The mesh layer skips Mode 2 — Minima anchoring is an inference-side concern (the mesh just transports `WorkResult` events that may carry receipts).

## Binary size

Target: **< 20 MB AArch64 musl static**. Zenoh + BLAKE3 + rustls (aws-lc-rs) + redb is deliberately a tight set; please don't add heavyweight crates without checking the `strip --strip-all` size on Pi.

## Architecture

Full docs live in [`docs/architecture/`](./docs/architecture/):

- [`extension-model.md`](./docs/architecture/extension-model.md) — mesh-specific extension surface
- [`operating-modes.md`](./docs/architecture/operating-modes.md) — mesh modes
- [`integrations/tenzro.md`](./docs/architecture/integrations/tenzro.md) — Tenzro mesh integration (DiscoveryBackend + WorkBroker)

The canonical extension-model design (trait-core + impl-shell + plugin-orbit) lives in [`furcate-inference/docs/architecture/extension-model.md`](https://github.com/furcateai/furcate-inference/blob/main/docs/architecture/extension-model.md) — read that first.

## Status

- Version: **0.1.0**
- 7-crate workspace
- 33 tests pass (30 unit + 3 TLS handshake integration); clippy `-Dwarnings` clean; `#![forbid(unsafe_code)]`
- Real rustls 0.23 + aws-lc-rs raw-PK TLS wired
- Real Zenoh 1.9 transport wired
- Real BLAKE3 chunked transfer wired
- mDNS browse loop wired
- Validated on aarch64 Linux (GCP T2A, Ampere Altra) — matches Pi-class architecture

## Versioning

- The kernel crates in this repo release in **lockstep** (same workspace version). Participation repos that consume the kernel release independently and pin a major version.
- Wire types (`MeshEvent`, `PeerId`): adding fields with `serde(default)` is minor; renames/removals are major.

MSRV, 1.0 timing, and deprecation windows are roadmap decisions and are not set here.

## Sibling repos

- [`furcate-protocol`](https://github.com/furcateai/furcate-protocol) — wire-format specs + schemas + test vectors
- [`furcate-inference`](https://github.com/furcateai/furcate-inference) — edge inference kernel
- [`minima-attest`](https://github.com/furcateai/minima-attest) — Rust client for anchoring hashes on a local Minima node
- [`tenzro-edge`](https://github.com/furcateai/tenzro-edge) — runtime for participating in the Tenzro Network (provides `DiscoveryBackend` + `WorkBroker` impls)
- [`prvnz-edge`](https://github.com/furcateai/prvnz-edge) — runtime for issuing PRVNZ Digital Product Passports
- [`furcate-pi-hat`](https://github.com/furcateai/furcate-pi-hat) — Pi 5 HAT hardware support
- [`furcate-pi-minima`](https://github.com/furcateai/furcate-pi-minima) — supervisor for running a Minima full node on a Pi

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
