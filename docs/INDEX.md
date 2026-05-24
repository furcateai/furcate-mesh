# `furcate-mesh` documentation

`furcate-mesh` is the LAN-to-network mesh layer of the Furcate OSS edge
bundle. Its architecture follows the same extension model as
`furcate-inference` — most of the design is shared and documented there.

## Architecture

- [Extension model](architecture/extension-model.md) — mesh-specific extension
  surface. Companion to `furcate-inference`'s
  [extension model](https://github.com/furcateai/furcate-inference/blob/main/docs/architecture/extension-model.md).
- [Operating modes](architecture/operating-modes.md) — how the bundle's
  Mode 1 / 2 / 3 / embedded profiles apply to the mesh layer.

## Integrations

- [Tenzro Network mesh integration](architecture/integrations/tenzro.md) —
  Tenzro as `DiscoveryBackend` (network-wide peer seeds) and `WorkBroker`
  (task marketplace fallback for offers LAN can't absorb).

## Plugins

Plugin authoring follows the same pattern as `furcate-inference`. See the
[authoring guide](https://github.com/furcateai/furcate-inference/blob/main/docs/plugins/authoring.md)
in the inference repo for the canonical reference. Mesh-specific traits live
in `furcate-mesh-core`.

---

## What's in `furcate-mesh`

| Crate | Role |
|-------|------|
| `furcate-mesh-core` | Trait core: `DiscoveryBackend`, `WorkBroker`, wire-stable `PeerId` + `MeshEvent` |
| `furcate-mesh-identity` | Ed25519 identity + raw-PK rustls TLS for peer authentication |
| `furcate-mesh-discovery` | First-party mDNS impl of `DiscoveryBackend` |
| `furcate-mesh-transport` | Zenoh-based transport: pub/sub of `MeshEvent` between peers |
| `furcate-mesh-transfer` | Chunked, BLAKE3-verified artefact transfer over Zenoh queryables |
| `furcate-mesh-routing` | First-party LAN impl of `WorkBroker` (work-stealing) |
| `furcate-mesh-cli` | `furcate-mesh peer up`, `model push`, `model pull`, etc. |
