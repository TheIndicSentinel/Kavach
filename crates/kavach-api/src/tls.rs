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
    let mut keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::read_all(&mut &*key_pem)
        .filter_map(|item| match item.ok()? {
            Item::Sec1Key(key) => Some(key.into()),
            Item::Pkcs1Key(key) => Some(key.into()),
            Item::Pkcs8Key(key) => Some(key.into()),
            _ => None,
        })
        .collect();
    if keys.len() != 1 {
        return Err(io_other("private key format not supported".to_string()));
    }
    Ok(keys.pop().expect("one key"))
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
