use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::Item;

use tonic::codegen::tokio_stream::wrappers::ReceiverStream;

use crate::config::TlsConfig;
use crate::grpc::GrpcEvaluateService;
use crate::limits::{ConnHandle, DeadlineIo, LimitAcceptor, LimitedListener, ListenerLimits};
use crate::mtls::PeerCertAcceptor;
use crate::proto::kavach::v1::evaluate_service_server::EvaluateServiceServer;

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

/// The server's rustls configuration, offering `alpn`.
async fn build_server_config(
    config: &TlsConfig,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, std::io::Error> {
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

    server_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(server_config))
}

async fn build_rustls_config(config: &TlsConfig) -> Result<RustlsConfig, std::io::Error> {
    Ok(RustlsConfig::from_config(
        build_server_config(config, &[b"h2", b"http/1.1"]).await?,
    ))
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type StopSignal = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Serves `app` on `listener` with `limits` (see [`crate::limits`]) until
/// `stop` resolves, if given.
async fn serve_limited(
    app: Router,
    listener: std::net::TcpListener,
    tls: Option<&TlsConfig>,
    stop: Option<(StopSignal, Duration)>,
    limits: ListenerLimits,
) -> Result<(), BoxError> {
    limits.validate()?;
    listener.set_nonblocking(true)?;
    let app = crate::limits::gated(app, &limits);
    match tls {
        None => {
            let listener = LimitedListener::new(
                tokio::net::TcpListener::from_std(listener)?,
                limits.header_read_timeout,
            );
            let app = app.into_make_service_with_connect_info::<ConnHandle>();
            match stop {
                Some((stop, _)) => {
                    axum::serve(listener, app)
                        .with_graceful_shutdown(stop)
                        .await?;
                }
                None => axum::serve(listener, app).await?,
            }
        }
        Some(config) => {
            let rustls = build_rustls_config(config).await?;
            let acceptor = PeerCertAcceptor::over(
                RustlsAcceptor::new(rustls)
                    .handshake_timeout(limits.tls_handshake_timeout)
                    .acceptor(LimitAcceptor::new(limits.header_read_timeout)),
            );
            let handle = axum_server::Handle::new();
            if let Some((stop, drain)) = stop {
                let on_stop = handle.clone();
                tokio::spawn(async move {
                    stop.await;
                    on_stop.graceful_shutdown(Some(drain));
                });
            }
            axum_server::from_tcp(listener)
                .acceptor(acceptor)
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
    }
    Ok(())
}

pub async fn serve_http(
    app: Router,
    addr: SocketAddr,
    tls: Option<&TlsConfig>,
) -> Result<(), BoxError> {
    serve_http_on(app, std::net::TcpListener::bind(addr)?, tls).await
}

/// Serves on an already-bound listener, with the default
/// [`ListenerLimits`]. With TLS, every request carries the client
/// certificate's SANs as a [`crate::mtls::PeerCertificate`] extension
/// (empty when the client sent no certificate).
pub async fn serve_http_on(
    app: Router,
    listener: std::net::TcpListener,
    tls: Option<&TlsConfig>,
) -> Result<(), BoxError> {
    serve_limited(app, listener, tls, None, ListenerLimits::default()).await
}

/// [`serve_http_on`] with explicit limits.
pub async fn serve_http_on_with_limits(
    app: Router,
    listener: std::net::TcpListener,
    tls: Option<&TlsConfig>,
    limits: ListenerLimits,
) -> Result<(), BoxError> {
    serve_limited(app, listener, tls, None, limits).await
}

/// [`serve_http_on`] that stops when `stop` resolves: no new connection is
/// accepted, and requests in flight finish. With TLS the connections are
/// closed after `drain` at the latest; without it the caller bounds the
/// wait (a timeout around this future).
pub async fn serve_http_on_until(
    app: Router,
    listener: std::net::TcpListener,
    tls: Option<&TlsConfig>,
    stop: impl Future<Output = ()> + Send + 'static,
    drain: Duration,
) -> Result<(), BoxError> {
    serve_http_on_until_with_limits(app, listener, tls, stop, drain, ListenerLimits::default())
        .await
}

/// [`serve_http_on_until`] with explicit limits.
pub async fn serve_http_on_until_with_limits(
    app: Router,
    listener: std::net::TcpListener,
    tls: Option<&TlsConfig>,
    stop: impl Future<Output = ()> + Send + 'static,
    drain: Duration,
    limits: ListenerLimits,
) -> Result<(), BoxError> {
    serve_limited(app, listener, tls, Some((Box::pin(stop), drain)), limits).await
}

/// [`serve_http`] that stops when `stop` resolves (see
/// [`serve_http_on_until`]).
pub async fn serve_http_until(
    app: Router,
    addr: SocketAddr,
    tls: Option<&TlsConfig>,
    stop: impl Future<Output = ()> + Send + 'static,
    drain: Duration,
) -> Result<(), BoxError> {
    serve_http_on_until(app, std::net::TcpListener::bind(addr)?, tls, stop, drain).await
}

/// [`serve_http_until`] with explicit limits.
pub async fn serve_http_until_with_limits(
    app: Router,
    addr: SocketAddr,
    tls: Option<&TlsConfig>,
    stop: impl Future<Output = ()> + Send + 'static,
    drain: Duration,
    limits: ListenerLimits,
) -> Result<(), BoxError> {
    serve_http_on_until_with_limits(
        app,
        std::net::TcpListener::bind(addr)?,
        tls,
        stop,
        drain,
        limits,
    )
    .await
}

type PlainIo = DeadlineIo<tokio::net::TcpStream>;
type TlsIo = tokio_rustls::server::TlsStream<PlainIo>;
type Accepted<IO> = tokio::sync::mpsc::Sender<std::io::Result<IO>>;

/// The next connection, or `None` once told to stop or once tonic stopped
/// reading.
async fn next_connection<IO>(
    listener: &tokio::net::TcpListener,
    limits: &ListenerLimits,
    stopping: &mut tokio::sync::watch::Receiver<bool>,
    tx: &Accepted<IO>,
) -> Option<PlainIo> {
    loop {
        let accepted = tokio::select! {
            () = tx.closed() => return None,
            _ = stopping.wait_for(|stop| *stop) => return None,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _)) => return Some(DeadlineIo::new(stream, limits.header_read_timeout)),
            Err(e) => crate::limits::accept_error_pause(&e).await,
        }
    }
}

/// Hands plain connections to tonic.
fn spawn_plain_accept(
    listener: tokio::net::TcpListener,
    limits: ListenerLimits,
    mut stopping: tokio::sync::watch::Receiver<bool>,
    tx: Accepted<PlainIo>,
) {
    tokio::spawn(async move {
        while let Some(io) = next_connection(&listener, &limits, &mut stopping, &tx).await {
            if tx.send(Ok(io)).await.is_err() {
                break;
            }
        }
    });
}

/// Hands TLS connections to tonic. Each handshake runs in a task of its
/// own for at most the handshake timeout, so a stalled one holds up
/// nobody else.
fn spawn_tls_accept(
    listener: tokio::net::TcpListener,
    limits: ListenerLimits,
    acceptor: tokio_rustls::TlsAcceptor,
    mut stopping: tokio::sync::watch::Receiver<bool>,
    tx: Accepted<TlsIo>,
) {
    tokio::spawn(async move {
        while let Some(io) = next_connection(&listener, &limits, &mut stopping, &tx).await {
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                match tokio::time::timeout(limits.tls_handshake_timeout, acceptor.accept(io)).await
                {
                    Ok(Ok(stream)) => {
                        let _ = tx.send(Ok(stream)).await;
                    }
                    Ok(Err(e)) => tracing::debug!(error = %e, "gRPC TLS handshake failed"),
                    Err(_) => tracing::debug!("gRPC TLS handshake timed out"),
                }
            });
        }
    });
}

/// Serves the gRPC evaluate service on `addr` with `limits` until `stop`
/// resolves: our own accept loop and TLS (the same rustls configuration
/// as HTTP, offering only `h2`) so that the handshake timeout and the
/// header read deadline apply; tonic's request timeout; the service's own
/// in-flight cap ([`GrpcEvaluateService::with_limits`]).
pub async fn serve_grpc_until(
    service: GrpcEvaluateService,
    addr: SocketAddr,
    tls: Option<&TlsConfig>,
    stop: impl Future<Output = ()> + Send + 'static,
    limits: ListenerLimits,
) -> Result<(), BoxError> {
    limits.validate()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let (stop_tx, stopping) = tokio::sync::watch::channel(false);
    let mut stopped = stopping.clone();
    tokio::spawn(async move {
        stop.await;
        let _ = stop_tx.send(true);
    });
    let signal = async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let router = tonic::transport::Server::builder()
        .timeout(limits.request_timeout)
        .add_service(EvaluateServiceServer::new(service));
    match tls {
        None => {
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            spawn_plain_accept(listener, limits, stopping, tx);
            router
                .serve_with_incoming_shutdown(ReceiverStream::new(rx), signal)
                .await?;
        }
        Some(config) => {
            let acceptor =
                tokio_rustls::TlsAcceptor::from(build_server_config(config, &[b"h2"]).await?);
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            spawn_tls_accept(listener, limits, acceptor, stopping, tx);
            router
                .serve_with_incoming_shutdown(ReceiverStream::new(rx), signal)
                .await?;
        }
    }
    Ok(())
}

/// tonic's own TLS settings, for a server built with tonic's builder (tests).
/// The binary serves gRPC with [`serve_grpc_until`] instead.
pub async fn grpc_server_tls_config(
    tls: Option<&TlsConfig>,
) -> Result<Option<tonic::transport::ServerTlsConfig>, BoxError> {
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
