use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::Item;

use crate::config::TlsConfig;
use crate::mtls::PeerCertAcceptor;

fn io_other<E>(err: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::other(err)
}

fn parse_server_key(key_pem: &[u8]) -> Result<PrivateKeyDer<'static>, std::io::Error> {
    let mut reader = key_pem;
    let mut keys = rustls_pemfile::read_all(&mut reader).filter_map(|item| match item.ok()? {
        Item::Sec1Key(key) => Some(PrivateKeyDer::from(key)),
        Item::Pkcs1Key(key) => Some(PrivateKeyDer::from(key)),
        Item::Pkcs8Key(key) => Some(PrivateKeyDer::from(key)),
        _ => None,
    });
    // Exactly one key: none, or a second one, is refused.
    match (keys.next(), keys.next()) {
        (Some(key), None) => Ok(key),
        _ => Err(io_other("private key format not supported".to_string())),
    }
}

fn parse_certs(cert_pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
    rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_other)
}

/// The explicit crypto provider, so TLS never depends on which rustls
/// provider features other crates happen to enable.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

async fn build_rustls_config(config: &TlsConfig) -> Result<RustlsConfig, std::io::Error> {
    let (cert_pem, key_pem) = config.read_server_pem().await?;
    let certs = parse_certs(&cert_pem)?;
    let key = parse_server_key(&key_pem)?;

    let mut server_config = if let Some(client_ca_pem) = config.read_client_ca().await? {
        let ca_certs = parse_certs(&client_ca_pem)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).map_err(io_other)?;
        }
        let client_verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), ring_provider())
                .build()
                .map_err(io_other)?;
        ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .map_err(io_other)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .map_err(io_other)?
    } else {
        ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .map_err(io_other)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(io_other)?
    };

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

pub async fn serve_http(
    app: Router,
    addr: SocketAddr,
    tls: Option<&TlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_http_on(app, std::net::TcpListener::bind(addr)?, tls).await
}

/// Serves on an already-bound listener. With TLS, every request carries the
/// client certificate's SANs as a [`crate::mtls::PeerCertificate`] extension
/// (empty when the client sent no certificate).
pub async fn serve_http_on(
    app: Router,
    listener: std::net::TcpListener,
    tls: Option<&TlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    listener.set_nonblocking(true)?;
    match tls {
        None => {
            axum::serve(tokio::net::TcpListener::from_std(listener)?, app).await?;
        }
        Some(config) => {
            let rustls = build_rustls_config(config).await?;
            axum_server::from_tcp(listener)
                .acceptor(PeerCertAcceptor::new(rustls))
                .serve(app.into_make_service())
                .await?;
        }
    }
    Ok(())
}

/// [`serve_http_on`] that stops when `stop` resolves: no new connection is
/// accepted, and requests in flight finish. With TLS the connections are
/// closed after `drain` at the latest; without it the caller bounds the
/// wait (a timeout around this future).
pub async fn serve_http_on_until(
    app: Router,
    listener: std::net::TcpListener,
    tls: Option<&TlsConfig>,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
    drain: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    listener.set_nonblocking(true)?;
    match tls {
        None => {
            axum::serve(tokio::net::TcpListener::from_std(listener)?, app)
                .with_graceful_shutdown(stop)
                .await?;
        }
        Some(config) => {
            let rustls = build_rustls_config(config).await?;
            let handle = axum_server::Handle::new();
            let on_stop = handle.clone();
            tokio::spawn(async move {
                stop.await;
                on_stop.graceful_shutdown(Some(drain));
            });
            axum_server::from_tcp(listener)
                .acceptor(PeerCertAcceptor::new(rustls))
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
    }
    Ok(())
}

/// [`serve_http`] that stops when `stop` resolves (see
/// [`serve_http_on_until`]).
pub async fn serve_http_until(
    app: Router,
    addr: SocketAddr,
    tls: Option<&TlsConfig>,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
    drain: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_http_on_until(app, std::net::TcpListener::bind(addr)?, tls, stop, drain).await
}

pub async fn grpc_server_tls_config(
    tls: Option<&TlsConfig>,
) -> Result<Option<tonic::transport::ServerTlsConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(config) = tls else {
        return Ok(None);
    };
    let (cert, key) = config.read_server_pem().await?;
    let identity = tonic::transport::Identity::from_pem(cert, key);
    let mut server_tls = tonic::transport::ServerTlsConfig::new().identity(identity);
    if let Some(client_ca) = config.read_client_ca().await? {
        server_tls = server_tls.client_ca_root(tonic::transport::Certificate::from_pem(client_ca));
    }
    Ok(Some(server_tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pem() -> String {
        rcgen::KeyPair::generate().unwrap().serialize_pem()
    }

    /// Exactly one private key is accepted; none, two, or a certificate in
    /// its place are refused, and never by a panic.
    #[test]
    fn exactly_one_private_key_is_accepted() {
        let one = key_pem();
        assert!(parse_server_key(one.as_bytes()).is_ok());
        let two = format!("{one}\n{}", key_pem());
        assert!(parse_server_key(two.as_bytes()).is_err());
        for not_a_key in [
            "",
            "not pem at all",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            assert!(
                parse_server_key(not_a_key.as_bytes()).is_err(),
                "{not_a_key:?}"
            );
        }
        // A garbled key block is one that does not parse: no key, so refused.
        let garbled = one.replace(&one[40..60], "????????????????????");
        assert!(parse_server_key(garbled.as_bytes()).is_err());
    }
}
