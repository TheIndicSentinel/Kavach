//! What a Postgres connection puts on the wire (T1). No database is
//! needed: a listener stands in for a server that speaks no TLS and
//! records what the client sends first.
//!
//! - A client that insists on TLS opens with an `SSLRequest` and, told
//!   "no", gives up: it never sends its startup message (user, database)
//!   in plaintext.
//! - `PGSSLMODE=disable` in the environment changes nothing.
//! - Only a URL that asks for `sslmode=disable`, in a development mode,
//!   opens in plaintext.

use std::time::Duration;

use kavach_storage::{connect_runtime, DatabaseTls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// `SSLRequest`: length 8, code 80877103.
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
/// Protocol 3.0, the second word of a plaintext startup message.
const PROTOCOL_3: [u8; 4] = [0, 3, 0, 0];

/// What the stand-in server saw from one client.
struct Seen {
    first: Vec<u8>,
    /// Bytes sent after the server refused TLS (none, for a client that
    /// gives up).
    after_refusal: Vec<u8>,
}

/// Accepts one connection, answers an `SSLRequest` with `N` (no TLS), and
/// reports what arrived.
async fn plaintext_only_server() -> (String, tokio::task::JoinHandle<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut first = vec![0u8; 8];
        socket.read_exact(&mut first).await.unwrap();
        let mut after_refusal = Vec::new();
        if first == SSL_REQUEST {
            socket.write_all(b"N").await.unwrap();
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                socket.read_to_end(&mut after_refusal),
            )
            .await;
        }
        Seen {
            first,
            after_refusal,
        }
    });
    (
        format!("postgres://kavach_runtime:secret-pw@{address}/kavach"),
        handle,
    )
}

async fn attempt(url: &str, tls: &DatabaseTls) -> String {
    let result = tokio::time::timeout(Duration::from_secs(10), connect_runtime(url, tls)).await;
    match result {
        Ok(Err(err)) => err.to_string(),
        Ok(Ok(_)) => panic!("connected to a server that is not Postgres"),
        Err(_) => "timed out".into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_without_tls_is_refused_and_nothing_is_sent_in_plaintext() {
    // The default: no sslmode in the URL, production policy.
    let (url, server) = plaintext_only_server().await;
    let error = attempt(&url, &DatabaseTls::default()).await;
    let seen = server.await.unwrap();
    assert_eq!(
        seen.first, SSL_REQUEST,
        "the client opens by asking for TLS"
    );
    assert!(
        seen.after_refusal.is_empty(),
        "no startup message after the server refused TLS: {:?}",
        seen.after_refusal
    );
    assert!(error.contains("postgres io"), "{error}");
    assert!(!error.contains("secret-pw"), "{error}");

    // PGSSLMODE=disable in the environment does not weaken that, neither
    // for an unspecified mode nor in a development mode. (This test binary
    // has no other test that connects.)
    std::env::set_var("PGSSLMODE", "disable");
    for tls in [DatabaseTls::default(), DatabaseTls::development()] {
        let (url, server) = plaintext_only_server().await;
        attempt(&url, &tls).await;
        let seen = server.await.unwrap();
        assert_eq!(seen.first, SSL_REQUEST, "{tls:?}");
        assert!(seen.after_refusal.is_empty(), "{tls:?}");
    }
    std::env::remove_var("PGSSLMODE");

    // A weaker mode in the URL, outside development: refused before any
    // connection is made.
    for weaker in ["disable", "prefer", "require", "verify-ca"] {
        let (url, server) = plaintext_only_server().await;
        let error = attempt(&format!("{url}?sslmode={weaker}"), &DatabaseTls::default()).await;
        assert!(error.contains(&format!("sslmode={weaker}")), "{error}");
        assert!(error.contains("verify-full"), "{error}");
        assert!(!error.contains("secret-pw"), "{error}");
        // The stand-in server is still waiting: nobody connected.
        assert!(!server.is_finished(), "{weaker}: a connection was made");
        server.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_happens_only_when_the_url_asks_and_development_allows() {
    let (url, server) = plaintext_only_server().await;
    attempt(
        &format!("{url}?sslmode=disable"),
        &DatabaseTls::development(),
    )
    .await;
    let seen = server.await.unwrap();
    assert_ne!(seen.first, SSL_REQUEST);
    assert_eq!(seen.first[4..], PROTOCOL_3, "a plaintext startup message");
}
