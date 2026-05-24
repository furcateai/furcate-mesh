// SPDX-License-Identifier: Apache-2.0

//! # `furcate-mesh-identity`
//!
//! Each peer is identified by an Ed25519 keypair. The public key *is*
//! the peer's address ([`PeerId`]); there is no separate name service.
//!
//! ## Persistence
//!
//! The private key is stored as a PKCS#8 v1 PEM file at
//! `<config_dir>/identity.pem` and read-only to the user that runs the
//! daemon (mode 0o600 on Unix). The public key is derived on load — we
//! never store it separately.
//!
//! ## TLS
//!
//! Peer-to-peer connections use [raw public-key TLS][rfc7250] via
//! rustls 0.23. There is no CA, no X.509 chain, no name verification —
//! the peer's public key *is* its identity, and the peer either
//! presents the key we expected or the handshake fails.
//!
//! TLS 1.3 only (RFC 7250 is not specified for TLS 1.2). The rustls
//! `ring` provider supplies the signature algorithms; both sides use
//! the same `AlwaysResolvesXRawPublicKeys` resolver pattern from the
//! canonical rustls example.
//!
//! [rfc7250]: https://datatracker.ietf.org/doc/html/rfc7250
//!
//! ## Status
//!
//! Fully wired: identity persistence + raw-PK `ServerConfig` /
//! `ClientConfig` builders. Round-trip handshake on loopback is
//! covered by an integration test.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use furcate_mesh_core::PeerId;
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    PeerIncompatible, SignatureScheme,
};
use thiserror::Error;
use tracing::debug;

/// Identity-crate errors.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// IO failure reading or writing the on-disk key file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// PKCS#8 PEM decode/encode failure.
    #[error("pkcs8: {0}")]
    Pkcs8(String),
    /// TLS config build failure — malformed key material, bad SPKI in
    /// the allow-list, or a rustls provider error loading the private
    /// key.
    #[error("tls: {0}")]
    Tls(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, IdentityError>;

/// The local peer's Ed25519 keypair plus its derived [`PeerId`].
///
/// Hold one of these for the process's lifetime — Ed25519 signing is
/// cheap and zero-allocation. Generated keys are constant-time-safe by
/// way of `ed25519-dalek`.
#[derive(Clone)]
pub struct PeerIdentity {
    signing: SigningKey,
}

impl PeerIdentity {
    /// Generate a brand new Ed25519 keypair from the OS RNG.
    #[must_use]
    pub fn generate() -> Self {
        // Use a CSPRNG; ed25519-dalek 2.x SigningKey::generate takes an
        // RngCore + CryptoRng.
        let mut rng = rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut rng);
        Self { signing }
    }

    /// Load an existing keypair from `<config_dir>/identity.pem`.
    ///
    /// # Errors
    /// [`IdentityError::Io`] if the file isn't readable;
    /// [`IdentityError::Pkcs8`] if the PEM isn't a valid PKCS#8 Ed25519
    /// private key.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("identity.pem");
        let pem = std::fs::read_to_string(&path)?;
        let signing = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| IdentityError::Pkcs8(format!("decoding {}: {e}", path.display())))?;
        debug!(path = %path.display(), "loaded peer identity");
        Ok(Self { signing })
    }

    /// Load the identity at `<config_dir>/identity.pem`, generating and
    /// persisting one if the file does not exist.
    ///
    /// On Unix the file is created mode 0o600. On other platforms the
    /// platform default applies.
    ///
    /// # Errors
    /// [`IdentityError`] variants per failure mode.
    pub fn load_or_generate(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("identity.pem");
        if path.exists() {
            return Self::load(config_dir);
        }
        std::fs::create_dir_all(config_dir)?;
        let id = Self::generate();
        id.save(config_dir)?;
        debug!(path = %path.display(), "generated new peer identity");
        Ok(id)
    }

    /// Persist this keypair to `<config_dir>/identity.pem`.
    ///
    /// # Errors
    /// [`IdentityError::Io`] on write failure;
    /// [`IdentityError::Pkcs8`] on encode failure.
    pub fn save(&self, config_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(config_dir)?;
        let path = config_dir.join("identity.pem");
        let pem = self
            .signing
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| IdentityError::Pkcs8(format!("encoding: {e}")))?;
        std::fs::write(&path, pem.as_bytes())?;
        // Tighten permissions on Unix. We forbid unsafe_code, so use
        // std::fs::set_permissions rather than libc::chmod.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&path)?.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&path, permissions)?;
        }
        debug!(path = %path.display(), "saved peer identity");
        Ok(())
    }

    /// The 32-byte public key — this peer's stable address.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        let vk: VerifyingKey = self.signing.verifying_key();
        PeerId::from_bytes(vk.to_bytes())
    }

    /// Default config directory: `~/.config/furcate-mesh` on Linux/macOS.
    #[must_use]
    pub fn default_config_dir() -> PathBuf {
        // Mirror the convention used by furcate-inference's registry:
        // /var/lib/furcate-mesh when root, ~/.config/furcate-mesh else.
        if cfg!(unix) && unix_uid_zero() {
            PathBuf::from("/var/lib/furcate-mesh")
        } else if let Some(home) = home_dir() {
            home.join(".config").join("furcate-mesh")
        } else {
            PathBuf::from(".furcate-mesh")
        }
    }
}

// ---------------------------------------------------------------------------
// Raw-public-key TLS config builders
// ---------------------------------------------------------------------------

/// Convert a [`PeerId`] (raw 32-byte Ed25519 pubkey) to a DER-encoded
/// `SubjectPublicKeyInfo`. This is what rustls's raw-PK code compares
/// against — it does not understand the 32-byte form directly.
fn peer_id_to_spki(peer: PeerId) -> Result<SubjectPublicKeyInfoDer<'static>> {
    let vk = VerifyingKey::from_bytes(peer.as_bytes())
        .map_err(|e| IdentityError::Tls(format!("invalid peer pubkey: {e}")))?;
    let der = vk
        .to_public_key_der()
        .map_err(|e| IdentityError::Tls(format!("encoding peer SPKI: {e}")))?;
    Ok(SubjectPublicKeyInfoDer::from(der.as_bytes().to_vec()))
}

/// Build a [`CertifiedKey`] from a local `SigningKey`. The "cert"
/// here is the SPKI DER bytes (rustls overloads `CertificateDer` to
/// hold an SPKI when `requires_raw_public_keys()` is true).
fn certified_key_from(signing: &SigningKey) -> Result<Arc<CertifiedKey>> {
    let pkcs8_der = signing
        .to_pkcs8_der()
        .map_err(|e| IdentityError::Tls(format!("encoding private PKCS#8: {e}")))?;
    let priv_key = PrivateKeyDer::try_from(pkcs8_der.as_bytes().to_vec())
        .map_err(|e| IdentityError::Tls(format!("rustls private key parse: {e}")))?;
    let signing_key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(priv_key)
        .map_err(|e| IdentityError::Tls(format!("rustls load_private_key: {e}")))?;
    let public_spki = signing_key
        .public_key()
        .ok_or_else(|| IdentityError::Tls("signing key has no public key".into()))?;
    let public_as_cert = CertificateDer::from(public_spki.to_vec());
    Ok(Arc::new(CertifiedKey::new(
        vec![public_as_cert],
        signing_key,
    )))
}

/// rustls server config for raw-public-key TLS.
pub struct ServerTlsConfig {
    /// The local peer's keypair, used to present the raw public key
    /// during the handshake.
    pub identity: PeerIdentity,
    /// Allow-list of peers we accept connections from. If empty, accept
    /// any peer that proves possession of its private key — useful in
    /// open-LAN mode where the operator gates joining with
    /// `minima-attest` instead of a static allow-list.
    pub allowed: Vec<PeerId>,
}

impl ServerTlsConfig {
    /// Build the rustls `ServerConfig` for raw-public-key TLS.
    ///
    /// # Errors
    /// [`IdentityError::Tls`] if the key material fails to load into
    /// the rustls provider (e.g. PKCS#8 decode failure) or if any peer
    /// in `allowed` has a malformed public key.
    pub fn build(self) -> Result<rustls::ServerConfig> {
        let allowed_spki: Vec<SubjectPublicKeyInfoDer<'static>> = self
            .allowed
            .iter()
            .copied()
            .map(peer_id_to_spki)
            .collect::<Result<_>>()?;
        let certified_key = certified_key_from(&self.identity.signing)?;
        let verifier: Arc<dyn ClientCertVerifier> =
            Arc::new(RpkClientCertVerifier::new(allowed_spki));
        let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_key));
        let config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);
        Ok(config)
    }
}

/// rustls client config for raw-public-key TLS.
pub struct ClientTlsConfig {
    /// Local keypair.
    pub identity: PeerIdentity,
    /// The peer we expect on the other side of this connection. The
    /// handshake fails if the server presents a different public key.
    pub expected_server: PeerId,
}

impl ClientTlsConfig {
    /// Build the rustls `ClientConfig` for raw-public-key TLS.
    ///
    /// # Errors
    /// [`IdentityError::Tls`] if the key material fails to load into
    /// the rustls provider or the expected-server pubkey is malformed.
    pub fn build(self) -> Result<rustls::ClientConfig> {
        let server_spki = peer_id_to_spki(self.expected_server)?;
        let certified_key = certified_key_from(&self.identity.signing)?;
        let verifier: Arc<dyn ServerCertVerifier> =
            Arc::new(RpkServerCertVerifier::new(vec![server_spki]));
        let resolver = Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified_key));
        let config = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(resolver);
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Raw-PK verifiers
// ---------------------------------------------------------------------------
//
// Adapted from rustls 0.23.40's `raw_key_openssl_interop.rs` example.
// Both verifiers compare the presented SPKI against an allow-list and
// then delegate signature verification to
// `verify_tls13_signature_with_raw_key`. TLS 1.2 is explicitly
// refused — RFC 7250 doesn't specify it.

/// Server-cert verifier (used client-side) that accepts only peers
/// whose SPKI is in the trust list.
#[derive(Debug)]
struct RpkServerCertVerifier {
    trusted: Vec<SubjectPublicKeyInfoDer<'static>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl RpkServerCertVerifier {
    fn new(trusted: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
        Self {
            trusted,
            supported_algs: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for RpkServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let presented = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
        if self.trusted.contains(&presented) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Client-cert verifier (used server-side). Accepts any client when
/// the trust list is empty; otherwise requires the client's SPKI to
/// be in the list.
#[derive(Debug)]
struct RpkClientCertVerifier {
    trusted: Vec<SubjectPublicKeyInfoDer<'static>>,
    open: bool,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl RpkClientCertVerifier {
    fn new(trusted: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
        let open = trusted.is_empty();
        Self {
            trusted,
            open,
            supported_algs: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for RpkClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, RustlsError> {
        if self.open {
            return Ok(ClientCertVerified::assertion());
        }
        let presented = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
        if self.trusted.contains(&presented) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Tiny helpers (avoid pulling in `dirs` crate just for one path)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn unix_uid_zero() -> bool {
    // Reading /proc/self/status / geteuid require either libc (which is
    // not unsafe-free at the surface we care about, but does ride
    // `extern "C"`) or env vars. Use $SUDO_UID / $USER as a proxy: if we
    // were launched via sudo the user expects root paths. This is best
    // effort; getting it wrong only changes the default cache dir.
    std::env::var_os("SUDO_UID").is_some() || std::env::var_os("USER").is_some_and(|u| u == "root")
}

#[cfg(not(unix))]
const fn unix_uid_zero() -> bool {
    false
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_a_32_byte_peer_id() {
        let id = PeerIdentity::generate();
        assert_eq!(id.peer_id().as_bytes().len(), 32);
    }

    #[test]
    fn save_then_load_roundtrips_the_keypair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = PeerIdentity::generate();
        let pid = id.peer_id();
        id.save(dir.path()).expect("save ok");
        let loaded = PeerIdentity::load(dir.path()).expect("load ok");
        assert_eq!(loaded.peer_id(), pid);
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = PeerIdentity::load_or_generate(dir.path()).expect("first call");
        let b = PeerIdentity::load_or_generate(dir.path()).expect("second call");
        assert_eq!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn server_tls_build_open_mode_succeeds() {
        // Open mode (empty allow-list) is the LAN default — operator
        // gates joining elsewhere. The config must build cleanly.
        let cfg = ServerTlsConfig {
            identity: PeerIdentity::generate(),
            allowed: vec![],
        };
        cfg.build().expect("open-mode server config builds");
    }

    #[test]
    fn server_tls_build_with_allowlist_succeeds() {
        let allowed = PeerIdentity::generate().peer_id();
        let cfg = ServerTlsConfig {
            identity: PeerIdentity::generate(),
            allowed: vec![allowed],
        };
        cfg.build().expect("allow-listed server config builds");
    }

    #[test]
    fn client_tls_build_succeeds() {
        let server_id = PeerIdentity::generate().peer_id();
        let cfg = ClientTlsConfig {
            identity: PeerIdentity::generate(),
            expected_server: server_id,
        };
        cfg.build().expect("client config builds");
    }
}
