// SPDX-License-Identifier: Apache-2.0

//! Loopback raw-public-key TLS handshake.
//!
//! Spins up a TCP listener on `127.0.0.1:0`, wraps both ends in rustls
//! via the `ServerTlsConfig` / `ClientTlsConfig` builders, performs the
//! handshake, and exchanges one round-trip of bytes. This is the
//! "module docs claim a round-trip handshake test exists" test.

use std::sync::Arc;

use furcate_mesh_identity::{ClientTlsConfig, PeerIdentity, ServerTlsConfig};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn raw_pk_loopback_roundtrip() {
    let server_id = PeerIdentity::generate();
    let client_id = PeerIdentity::generate();
    let server_peer = server_id.peer_id();
    let client_peer = client_id.peer_id();

    // Server: allow-list the client so we exercise the verifier's
    // non-open path. The open path is covered by the unit tests.
    let server_cfg = ServerTlsConfig {
        identity: server_id,
        allowed: vec![client_peer],
    }
    .build()
    .expect("server config builds");

    let client_cfg = ClientTlsConfig {
        identity: client_id,
        expected_server: server_peer,
    }
    .build()
    .expect("client config builds");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let local = listener.local_addr().expect("local_addr");

    // Server side: accept one TCP, upgrade to TLS, echo one read.
    let server_task = tokio::spawn(async move {
        let (raw, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(raw).await.expect("server tls handshake");
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"hello");
        tls.write_all(b"world").await.expect("server write");
        tls.shutdown().await.ok();
    });

    // Client side: connect, upgrade, send + receive.
    let raw = TcpStream::connect(local).await.expect("connect");
    // The server name is required by the rustls API but our custom
    // verifier ignores it — RFC 7250 raw-PK means name is meaningless.
    let dummy_name = ServerName::try_from("peer.local").expect("dummy server name");
    let mut tls = connector
        .connect(dummy_name, raw)
        .await
        .expect("client tls handshake");
    tls.write_all(b"hello").await.expect("client write");
    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"world");

    server_task.await.expect("server task join");
}

#[tokio::test]
async fn rejects_unknown_client_when_allowlist_set() {
    let server_id = PeerIdentity::generate();
    let allowed_client = PeerIdentity::generate().peer_id();
    // The actual client uses a *different* keypair than allowed.
    let actual_client = PeerIdentity::generate();
    let server_peer = server_id.peer_id();

    let server_cfg = ServerTlsConfig {
        identity: server_id,
        allowed: vec![allowed_client],
    }
    .build()
    .expect("server config builds");

    let client_cfg = ClientTlsConfig {
        identity: actual_client,
        expected_server: server_peer,
    }
    .build()
    .expect("client config builds");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let local = listener.local_addr().expect("local_addr");

    let server_task = tokio::spawn(async move {
        let (raw, _) = listener.accept().await.expect("accept");
        // We expect this handshake to FAIL — the client's pubkey isn't
        // on the allow-list, so the server's verifier rejects it.
        let res = acceptor.accept(raw).await;
        assert!(res.is_err(), "server should reject unknown client");
    });

    let raw = TcpStream::connect(local).await.expect("connect");
    let dummy_name = ServerName::try_from("peer.local").expect("dummy server name");
    // In TLS 1.3 the client may report handshake-complete before the
    // server's `Finished` triggers the abort, so the failure surfaces
    // on the first read/write. Drive I/O until we see it.
    let probe_result: std::io::Result<()> = async {
        let mut tls = connector.connect(dummy_name, raw).await?;
        tls.write_all(b"ping").await?;
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await?;
        Ok(())
    }
    .await;
    assert!(
        probe_result.is_err(),
        "client should observe handshake failure once the server's reject reaches it"
    );

    server_task.await.expect("server task join");
}

#[tokio::test]
async fn rejects_wrong_server_pubkey() {
    let server_id = PeerIdentity::generate();
    let client_id = PeerIdentity::generate();
    // The client expects a DIFFERENT server pubkey than the server has.
    let wrong_expected = PeerIdentity::generate().peer_id();

    let server_cfg = ServerTlsConfig {
        identity: server_id,
        allowed: vec![], // open client policy — isolate the failure to the server side
    }
    .build()
    .expect("server config builds");

    let client_cfg = ClientTlsConfig {
        identity: client_id,
        expected_server: wrong_expected,
    }
    .build()
    .expect("client config builds");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let local = listener.local_addr().expect("local_addr");

    let server_task = tokio::spawn(async move {
        let (raw, _) = listener.accept().await.expect("accept");
        let _ = acceptor.accept(raw).await; // may succeed or fail depending on which side aborts first
    });

    let raw = TcpStream::connect(local).await.expect("connect");
    let dummy_name = ServerName::try_from("peer.local").expect("dummy server name");
    let res = connector.connect(dummy_name, raw).await;
    assert!(
        res.is_err(),
        "client should reject server presenting unexpected pubkey"
    );

    server_task.await.expect("server task join");
}
