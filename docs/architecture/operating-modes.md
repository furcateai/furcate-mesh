# Operating modes (mesh)

`furcate-mesh` follows the same three operating modes as `furcate-inference`.
The canonical mode definitions are in the inference repo:

> [furcate-inference/docs/architecture/operating-modes.md](https://github.com/furcateai/furcate-inference/blob/main/docs/architecture/operating-modes.md)

This page covers the mesh-specific composition for each mode.

---

## Mode 1: Standalone LAN mesh

- **Discovery:** mDNS (`furcate-mesh-discovery`) + static seeds.
- **Transport:** Zenoh TCP, peer-to-peer, no central server.
- **Broker:** LAN work-stealing (`furcate-mesh-broker`).
- **Identity:** Ed25519 raw-PK TLS, mutual auth, no CA.
- **Topology:** 2–32 Pis on the same LAN.

Air-gapped. Works with no internet, no DNS server, no nothing — mDNS plus
direct Zenoh links.

## Mode 2: + Minima-anchored work results

Same mesh wire as Mode 1. Work results returned over the mesh carry receipts
that the receiving peer routes through its inference-side `ReceiptSink`s.
If the peer has Minima configured, the receipt is anchored there. The mesh
layer is unchanged — Minima anchoring is an inference-side concern. Mesh
participates only as the transport of `WorkResult` events.

## Mode 3: + Tenzro-backed discovery and work-broker

- **Discovery:** mDNS + `TenzroDiscovery` (from `tenzro-edge-core`, network
  seeds).
- **Broker:** LAN work-stealing first, then Tenzro task marketplace via
  `TenzroBroker` (from `tenzro-edge-core`).
- **Topology:** unbounded — peers may live on different LANs, connected only
  through Tenzro-provided seeds and the Tenzro task marketplace.

LAN mDNS continues to find local peers as before; Tenzro merely adds remote
peers to the same discovery stream. If Tenzro is unreachable, the mesh
degrades to Mode 1 / 2 behaviour with no restart.

## Embedded edge profile

For PRVNZ-edge or other constrained appliances:

- Discovery: mDNS only (no Tenzro discovery client compiled in).
- Broker: local only (no Tenzro broker compiled in).
- Transport: Zenoh with `transport_tcp` + `transport_compression`, no QUIC,
  no shared-memory.
- No `furcate-mesh-transfer` chunked-fetch capability (a passive receiver
  only; cannot serve large artefacts).

Binary size target inherited from `furcate-inference` embedded profile.
