// SPDX-License-Identifier: Apache-2.0

//! Roundtrip the `furcate-protocol` mesh-event test vectors through
//! this crate's [`MeshEvent`] type. The vectors live in the sibling
//! `furcate-protocol` repo; when this crate is consumed in isolation
//! (no sibling checkout) the test gracefully skips.
//!
//! Each vector is loaded, deserialised into [`MeshEvent`], re-serialised,
//! and compared structurally (as `serde_json::Value`) to the original.
//! Field-order differences fail loudly — they would break interoperability.
//!
//! The wire-format codecs (`crate::wire::hex_array` /
//! `crate::wire::base64url_bytes_bytes`) are what this test guards: if
//! `PeerId` ever drifts back to a JSON array of integers, or `Bytes`
//! fields back to integer arrays, the structural comparison fails.

use std::path::{Path, PathBuf};

use furcate_mesh_core::MeshEvent;

/// Locate the `furcate-protocol/test-vectors/mesh-event/` directory
/// relative to this crate. Returns `None` when the sibling repo is
/// not present.
fn mesh_event_vectors() -> Option<PathBuf> {
    // `CARGO_MANIFEST_DIR` is `.../furcate-mesh/crates/furcate-mesh-core`.
    // The sibling specs repo lives at `.../furcate-protocol`.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest
        .parent()? // crates/
        .parent()? // furcate-mesh/
        .parent()? // furcate-github/
        .join("furcate-protocol")
        .join("test-vectors")
        .join("mesh-event");
    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
    }
}

fn read_value(path: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

#[test]
fn mesh_event_vectors_roundtrip() {
    let Some(dir) = mesh_event_vectors() else {
        eprintln!("skipping: furcate-protocol/test-vectors/mesh-event not present");
        return;
    };
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("read mesh-event dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let original = read_value(&path);
        let body = std::fs::read_to_string(&path).expect("re-read");
        let parsed: MeshEvent = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("deserialise {}: {e}", path.display()));
        let reencoded: serde_json::Value = serde_json::to_value(&parsed)
            .unwrap_or_else(|e| panic!("re-serialise {}: {e}", path.display()));
        assert_eq!(
            original,
            reencoded,
            "structural mismatch on {}: input={original} reencoded={reencoded}",
            path.display()
        );
        checked += 1;
    }
    assert!(checked >= 5, "expected ≥5 mesh-event vectors, got {checked}");
}
