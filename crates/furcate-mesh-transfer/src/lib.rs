// SPDX-License-Identifier: Apache-2.0

//! # `furcate-mesh-transfer`
//!
//! Content-addressed BLAKE3 chunked file transfer between peers, riding
//! on Zenoh queries.
//!
//! ## Protocol shape
//!
//! - Sender declares a queryable at `furcate/mesh/transfer/<digest-hex>`.
//! - Receiver issues `session.get("furcate/mesh/transfer/<digest-hex>")`.
//! - Sender streams the file in [`CHUNK_SIZE`]-byte chunks, one reply
//!   per chunk. Each reply key is
//!   `furcate/mesh/transfer/<digest>/<offset>` and the payload is the
//!   raw chunk bytes; the per-chunk BLAKE3 hash is JSON-encoded into
//!   the reply's *attachment* slot so the receiver can verify on
//!   arrival without re-parsing the payload.
//! - Receiver writes verified chunks to a temp file, re-hashes the
//!   whole reconstructed file against the requested root digest, then
//!   atomic-renames into the cache directory.
//!
//! The cache is a transport, not a trust, optimisation — even with all
//! chunk hashes valid, the root hash must match before the file is
//! renamed into place. The downstream `furcate-inference-registry` is
//! responsible for sigstore/AIBOM re-verification *after* the transfer;
//! we only guarantee bytes.
//!
//! ## What lives here
//!
//! - [`CHUNK_SIZE`] — the on-wire chunk size constant. Wire-stable.
//! - [`ChunkVerifier`] — synchronous BLAKE3 verifier used both
//!   server-side (to label outgoing chunks) and client-side (to reject
//!   corrupt chunks).
//! - [`TransferService`] — the public façade. `serve` declares the
//!   sender-side queryable; `pull` is the receiver-side entry point.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use furcate_mesh_core::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{debug, warn};
use zenoh::Session;

/// On-wire chunk size: 1 MiB. Chosen so that a 4 GB model is ~4096
/// chunks — large enough that per-chunk overhead is negligible, small
/// enough that resuming after a network blip doesn't redo too much
/// work.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Root key-expression prefix for transfer queryables.
pub const TRANSFER_ROOT: &str = "furcate/mesh/transfer";

/// Default per-pull deadline. Configurable per call via [`PullOptions`].
pub const DEFAULT_PULL_TIMEOUT: Duration = Duration::from_mins(5);

/// Transfer errors.
#[derive(Debug, Error)]
pub enum TransferError {
    /// IO error reading or writing the on-disk cache.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A chunk's BLAKE3 hash didn't match what the sender claimed.
    #[error("chunk verify failed at offset {offset}")]
    ChunkVerify {
        /// Byte offset where the mismatch was detected.
        offset: u64,
    },
    /// The reconstructed file's root hash didn't match the manifest.
    #[error("root verify failed: expected {expected}, got {actual}")]
    RootVerify {
        /// Hex of the expected root hash.
        expected: String,
        /// Hex of the hash we actually computed.
        actual: String,
    },
    /// The peer claimed not to have this digest.
    #[error("peer {peer} does not have digest {digest}")]
    PeerMissing {
        /// Which peer was asked.
        peer: PeerId,
        /// What hex digest we asked for.
        digest: String,
    },
    /// Transport-layer error wrapping the underlying transfer.
    #[error("transport: {0}")]
    Transport(String),
    /// Reply was malformed (missing chunk header, bad offset, etc).
    #[error("malformed reply: {0}")]
    MalformedReply(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, TransferError>;

/// One chunk in transit. Wire-stable; carried in each Zenoh reply's
/// attachment slot so the payload stays exact-bytes raw.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkHeader {
    /// Byte offset of this chunk in the file. Always a multiple of
    /// [`CHUNK_SIZE`], except possibly the last chunk.
    pub offset: u64,
    /// BLAKE3 of the chunk's bytes, hex.
    pub chunk_hash: String,
    /// Length of the chunk's payload. Equal to [`CHUNK_SIZE`] for all
    /// but the last chunk.
    pub len: u32,
    /// True if this is the last chunk of the file. The receiver uses
    /// this to know when to start the root-hash verification step.
    pub last: bool,
}

/// Streaming BLAKE3 verifier — sender hashes chunks before emitting
/// them, receiver hashes incoming chunks and compares.
pub struct ChunkVerifier;

impl ChunkVerifier {
    /// Hash a chunk's bytes. The hex encoding goes into the matching
    /// [`ChunkHeader::chunk_hash`].
    #[must_use]
    pub fn hash(bytes: &[u8]) -> String {
        let h = blake3::hash(bytes);
        hex::encode(h.as_bytes())
    }

    /// Verify a received chunk against a header.
    ///
    /// # Errors
    /// [`TransferError::ChunkVerify`] on mismatch.
    pub fn verify(header: &ChunkHeader, bytes: &[u8]) -> Result<()> {
        let actual = Self::hash(bytes);
        if actual == header.chunk_hash {
            Ok(())
        } else {
            Err(TransferError::ChunkVerify {
                offset: header.offset,
            })
        }
    }
}

/// Compute the BLAKE3 root hash of a file on disk. Hex.
///
/// # Errors
/// [`TransferError::Io`] on read failure.
pub async fn root_hash(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

/// Per-pull tunables. `Default` is fine for normal model sizes.
#[derive(Clone, Debug)]
pub struct PullOptions {
    /// Total deadline for the pull. Default [`DEFAULT_PULL_TIMEOUT`].
    pub timeout: Duration,
}

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_PULL_TIMEOUT,
        }
    }
}

/// The sender-side artefact table — maps digest-hex to a file path on
/// local disk. Held behind an `RwLock` so operators can hot-add files
/// while a queryable is running.
type ArtefactIndex = Arc<RwLock<HashMap<String, PathBuf>>>;

/// The transfer service. One per process.
///
/// `cache_dir` is where pulled artefacts land — typically the same
/// directory `furcate-inference-registry` uses, so a model fetched
/// over the mesh is immediately available to the local inference
/// engine.
#[derive(Clone)]
pub struct TransferService {
    cache_dir: PathBuf,
    session: Arc<Session>,
    artefacts: ArtefactIndex,
}

impl TransferService {
    /// Construct a transfer service rooted at `cache_dir`, riding the
    /// given Zenoh session. Get the session via
    /// `Transport::session()` (in `furcate-mesh-transport`).
    #[must_use]
    pub fn new(cache_dir: PathBuf, session: Arc<Session>) -> Self {
        Self {
            cache_dir,
            session,
            artefacts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Where pulled artefacts land.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Register an artefact (digest-hex → file path) for the sender
    /// side to serve.
    pub async fn register(&self, digest_hex: String, path: PathBuf) {
        self.artefacts.write().await.insert(digest_hex, path);
    }

    /// Start the sender-side queryable. Spawns a background task that
    /// owns the queryable and stays alive until the returned task
    /// handle is dropped.
    ///
    /// # Errors
    /// [`TransferError::Transport`] if Zenoh refuses the queryable
    /// declaration (rare; typically only happens on a closed session).
    pub async fn serve(&self) -> Result<tokio::task::JoinHandle<()>> {
        // Wildcard so one queryable serves every digest we host.
        let key_expr = format!("{TRANSFER_ROOT}/*");
        let queryable = self
            .session
            .declare_queryable(&key_expr)
            .await
            .map_err(|e| TransferError::Transport(format!("declare_queryable {key_expr}: {e}")))?;

        let artefacts = self.artefacts.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok(query) = queryable.recv_async().await else {
                    debug!("transfer queryable channel closed");
                    break;
                };
                let selector_key = query.key_expr().as_str().to_owned();
                // Selector is `furcate/mesh/transfer/<digest>`; strip
                // the prefix to recover the digest.
                let Some(digest) = selector_key
                    .strip_prefix(&format!("{TRANSFER_ROOT}/"))
                    .map(str::to_owned)
                else {
                    warn!(key = %selector_key, "transfer query with no digest segment");
                    continue;
                };
                let path = artefacts.read().await.get(&digest).cloned();
                match path {
                    Some(p) => {
                        if let Err(e) = stream_file_chunks(&query, &digest, &p).await {
                            warn!(error = %e, digest, "transfer stream failed");
                        }
                    }
                    None => {
                        debug!(digest, "queryable: digest not hosted; ignoring");
                        // Sending no reply is fine — the receiver's
                        // get() simply sees zero replies for this
                        // selector against this peer.
                    }
                }
            }
        });
        Ok(handle)
    }

    /// Pull a digest from any peer that advertises it on the mesh.
    ///
    /// `peer` is informational today (recorded in error variants for
    /// observability). The actual peer selection is delegated to
    /// Zenoh's query routing — whichever peer's queryable replies
    /// first wins. If you need strict peer-pinning, filter the replies
    /// in a future revision via source-info.
    ///
    /// # Errors
    /// [`TransferError`] per failure mode. Common cases:
    /// - [`TransferError::PeerMissing`] — no peer replied within the
    ///   timeout.
    /// - [`TransferError::ChunkVerify`] — a chunk's BLAKE3 didn't
    ///   match its attached header.
    /// - [`TransferError::RootVerify`] — chunks all verified but the
    ///   reconstructed file's BLAKE3 didn't match the requested digest.
    pub async fn pull(&self, peer: PeerId, digest_hex: &str) -> Result<PathBuf> {
        self.pull_with_options(peer, digest_hex, PullOptions::default())
            .await
    }

    /// Pull with caller-supplied options (timeout, etc).
    ///
    /// # Errors
    /// As for [`TransferService::pull`].
    pub async fn pull_with_options(
        &self,
        peer: PeerId,
        digest_hex: &str,
        opts: PullOptions,
    ) -> Result<PathBuf> {
        debug!(%peer, digest = digest_hex, cache = %self.cache_dir.display(), "pull");

        tokio::fs::create_dir_all(&self.cache_dir).await?;
        let final_path = self.cache_dir.join(digest_hex);
        if final_path.exists() {
            debug!(path = %final_path.display(), "digest already cached");
            return Ok(final_path);
        }
        // Temp file gets the chunks; atomic rename only after root
        // hash verifies. Suffix with `.partial` so a crashed pull
        // leaves a visibly-incomplete file rather than masquerading
        // as a real cache entry.
        let tmp_path = self.cache_dir.join(format!("{digest_hex}.partial"));
        let mut tmp_file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&tmp_path)
            .await?;

        let selector = format!("{TRANSFER_ROOT}/{digest_hex}");
        let replies = self
            .session
            .get(&selector)
            .target(zenoh::query::QueryTarget::All)
            .consolidation(zenoh::query::ConsolidationMode::None)
            .timeout(opts.timeout)
            .await
            .map_err(|e| TransferError::Transport(format!("get {selector}: {e}")))?;

        let mut got_last = false;
        let mut got_any = false;
        loop {
            let Ok(reply) = replies.recv_async().await else {
                break;
            };
            got_any = true;
            let result = reply.into_result().map_err(|e| {
                TransferError::Transport(format!(
                    "reply error: {}",
                    e.payload()
                        .try_to_string()
                        .map(std::borrow::Cow::into_owned)
                        .unwrap_or_default()
                ))
            })?;
            let attachment = result.attachment().ok_or_else(|| {
                TransferError::MalformedReply("reply missing chunk-header attachment".into())
            })?;
            let header_bytes = attachment.to_bytes();
            let header: ChunkHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
                TransferError::MalformedReply(format!("decoding chunk header: {e}"))
            })?;
            let chunk_bytes = result.payload().to_bytes();
            ChunkVerifier::verify(&header, &chunk_bytes)?;
            tmp_file
                .seek(std::io::SeekFrom::Start(header.offset))
                .await?;
            tmp_file.write_all(&chunk_bytes).await?;
            if header.last {
                got_last = true;
            }
        }

        if !got_any {
            // No peer answered within the timeout.
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(TransferError::PeerMissing {
                peer,
                digest: digest_hex.into(),
            });
        }
        if !got_last {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(TransferError::MalformedReply(
                "stream ended without a final chunk".into(),
            ));
        }

        tmp_file.flush().await?;
        drop(tmp_file);

        let actual_root = root_hash(&tmp_path).await?;
        if actual_root != digest_hex {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(TransferError::RootVerify {
                expected: digest_hex.into(),
                actual: actual_root,
            });
        }
        tokio::fs::rename(&tmp_path, &final_path).await?;
        Ok(final_path)
    }
}

/// Stream every chunk of `path` back to the querying peer. One
/// `query.reply(...)` per chunk; the chunk header rides in the reply
/// attachment slot.
///
/// Each reply is sent on the *same* key expression as the query so it
/// passes Zenoh's "reply must intersect query" check — the chunk
/// ordering is recovered from the header's `offset` field, not from
/// the key.
async fn stream_file_chunks(query: &zenoh::query::Query, _digest: &str, path: &Path) -> Result<()> {
    let mut file = tokio::fs::File::open(path).await?;
    let total_len = file.metadata().await?.len();
    let reply_key = query.key_expr().clone();
    let mut offset: u64 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let payload = &buf[..n];
        let last = offset + (n as u64) >= total_len;
        let header = ChunkHeader {
            offset,
            chunk_hash: ChunkVerifier::hash(payload),
            len: u32::try_from(n).map_err(|_| {
                TransferError::Transport("chunk length exceeds u32 (impossible at 1 MiB)".into())
            })?,
            last,
        };
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| TransferError::Transport(format!("encoding chunk header: {e}")))?;
        query
            .reply(reply_key.clone(), payload.to_vec())
            .attachment(header_json)
            .await
            .map_err(|e| TransferError::Transport(format!("reply: {e}")))?;
        offset += n as u64;
        if last {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zenoh::Config;

    #[tokio::test]
    async fn chunk_verifier_accepts_valid_chunk() {
        let bytes = b"hello mesh";
        let hdr = ChunkHeader {
            offset: 0,
            chunk_hash: ChunkVerifier::hash(bytes),
            len: u32::try_from(bytes.len()).expect("fits"),
            last: true,
        };
        ChunkVerifier::verify(&hdr, bytes).expect("ok");
    }

    #[tokio::test]
    async fn chunk_verifier_rejects_corrupt_chunk() {
        let hdr = ChunkHeader {
            offset: 1024,
            chunk_hash: ChunkVerifier::hash(b"original"),
            len: 8,
            last: false,
        };
        let err = ChunkVerifier::verify(&hdr, b"tampered").expect_err("should fail");
        match err {
            TransferError::ChunkVerify { offset } => assert_eq!(offset, 1024),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn root_hash_matches_blake3_of_file_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blob.bin");
        let mut f = tokio::fs::File::create(&path).await.expect("create");
        let payload = vec![0xab; 3 * CHUNK_SIZE + 17];
        f.write_all(&payload).await.expect("write");
        f.flush().await.expect("flush");
        let actual = root_hash(&path).await.expect("hash");
        let expected = hex::encode(blake3::hash(&payload).as_bytes());
        assert_eq!(actual, expected);
    }

    /// Spin up two Zenoh peers on loopback, register a small file on
    /// the sender, pull it from the receiver. End-to-end exercise of
    /// serve + pull + chunk verify + root verify + atomic rename.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_and_pull_roundtrip_on_loopback() {
        let port_a = pick_free_tcp_port();
        let port_b = pick_free_tcp_port();
        let session_a = open_session(port_a, port_b).await;
        let session_b = open_session(port_b, port_a).await;

        let sender_dir = tempfile::tempdir().expect("sender tempdir");
        let recv_dir = tempfile::tempdir().expect("receiver tempdir");

        // Write a 2.5-chunk payload so we exercise the multi-chunk
        // path (not just a single-chunk fast case).
        let payload: Vec<u8> = (0..(2 * CHUNK_SIZE + 4096))
            .map(|i| u8::try_from(i % 251).expect("modulo fits"))
            .collect();
        let src_path = sender_dir.path().join("model.bin");
        tokio::fs::write(&src_path, &payload)
            .await
            .expect("write src");
        let digest = root_hash(&src_path).await.expect("hash src");

        let sender = TransferService::new(sender_dir.path().to_path_buf(), session_a);
        sender.register(digest.clone(), src_path.clone()).await;
        let _serve_handle = sender.serve().await.expect("serve");

        // Let the peer-to-peer handshake and queryable declaration
        // propagate. On a fresh tokio runtime this is rarely instant.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let receiver = TransferService::new(recv_dir.path().to_path_buf(), session_b);
        let pulled = receiver
            .pull_with_options(
                PeerId::from_bytes([0; 32]),
                &digest,
                PullOptions {
                    timeout: Duration::from_secs(10),
                },
            )
            .await
            .expect("pull ok");

        let pulled_bytes = tokio::fs::read(&pulled).await.expect("read pulled");
        assert_eq!(pulled_bytes, payload);
        assert_eq!(
            pulled,
            recv_dir.path().join(&digest),
            "should rename into cache_dir/<digest>"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pull_missing_digest_returns_peer_missing() {
        let port = pick_free_tcp_port();
        let session = open_solo_session(port).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let receiver = TransferService::new(dir.path().to_path_buf(), session);
        let err = receiver
            .pull_with_options(
                PeerId::from_bytes([0; 32]),
                &"a".repeat(64),
                PullOptions {
                    timeout: Duration::from_millis(500),
                },
            )
            .await
            .expect_err("should fail with no peer hosting");
        assert!(matches!(err, TransferError::PeerMissing { .. }), "{err:?}");
    }

    // --- helpers ----------------------------------------------------------

    async fn open_session(listen_port: u16, peer_port: u16) -> Arc<Session> {
        let mut config = Config::default();
        config.insert_json5("mode", r#""peer""#).expect("mode");
        config
            .insert_json5(
                "listen/endpoints",
                &format!(r#"["tcp/127.0.0.1:{listen_port}"]"#),
            )
            .expect("listen");
        config
            .insert_json5(
                "connect/endpoints",
                &format!(r#"["tcp/127.0.0.1:{peer_port}"]"#),
            )
            .expect("connect");
        Arc::new(zenoh::open(config).await.expect("open zenoh"))
    }

    async fn open_solo_session(listen_port: u16) -> Arc<Session> {
        let mut config = Config::default();
        config.insert_json5("mode", r#""peer""#).expect("mode");
        config
            .insert_json5(
                "listen/endpoints",
                &format!(r#"["tcp/127.0.0.1:{listen_port}"]"#),
            )
            .expect("listen");
        Arc::new(zenoh::open(config).await.expect("open zenoh"))
    }

    fn pick_free_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = listener.local_addr().expect("local_addr").port();
        drop(listener);
        port
    }
}
