//! mTLS client-certificate principals (ADR-008 §1, H2b).
//!
//! rustls verifies the client chain against `--tls-client-ca` during the
//! handshake. After that, the HTTP acceptor attaches the leaf certificate's
//! subject alternative names to every request on the connection; gRPC reads
//! them from `Request::peer_certs`. With `--mtls-principal-san uri|dns`, the
//! single SAN of that type becomes the Cedar principal id.

use std::future::Future;
use std::io;
use std::pin::Pin;

use axum_server::accept::{Accept, DefaultAcceptor};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower_http::add_extension::AddExtension;
use x509_parser::extensions::GeneralName;

/// Which subject alternative name type names the principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MtlsSanKind {
    /// URI SAN, e.g. a SPIFFE id `spiffe://bank.example/los`.
    Uri,
    /// DNS SAN, e.g. `los.bank.example`.
    Dns,
}

/// SANs of a verified client leaf certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCertificate {
    pub uri_sans: Vec<String>,
    pub dns_sans: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MtlsError {
    #[error("client certificate has no {0:?} SAN")]
    NoSan(MtlsSanKind),
    #[error("client certificate has more than one {0:?} SAN")]
    AmbiguousSan(MtlsSanKind),
    #[error("client certificate SAN is not a valid principal id")]
    InvalidSan,
}

impl PeerCertificate {
    /// Reads the SANs of a DER certificate. A certificate that does not parse,
    /// or has a malformed SAN extension, yields no SANs (and so no principal).
    #[must_use]
    pub fn from_der(der: &[u8]) -> Self {
        let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
            return Self::default();
        };
        let Ok(Some(san)) = cert.subject_alternative_name() else {
            return Self::default();
        };
        let mut peer = Self::default();
        for name in &san.value.general_names {
            match name {
                GeneralName::URI(uri) => peer.uri_sans.push((*uri).to_string()),
                GeneralName::DNSName(dns) => peer.dns_sans.push((*dns).to_string()),
                _ => {}
            }
        }
        peer
    }

    /// The principal id: exactly one SAN of the configured type.
    pub fn principal(&self, kind: MtlsSanKind) -> Result<&str, MtlsError> {
        let sans = match kind {
            MtlsSanKind::Uri => &self.uri_sans,
            MtlsSanKind::Dns => &self.dns_sans,
        };
        match sans.as_slice() {
            [] => Err(MtlsError::NoSan(kind)),
            [one] if valid_principal_id(one) => Ok(one),
            [_] => Err(MtlsError::InvalidSan),
            _ => Err(MtlsError::AmbiguousSan(kind)),
        }
    }
}

fn valid_principal_id(id: &str) -> bool {
    (1..=256).contains(&id.len()) && !id.chars().any(char::is_control)
}

/// TLS acceptor that exposes the client certificate to HTTP handlers as a
/// [`PeerCertificate`] request extension.
#[derive(Clone)]
pub struct PeerCertAcceptor {
    inner: RustlsAcceptor<DefaultAcceptor>,
}

impl PeerCertAcceptor {
    #[must_use]
    pub fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

type AcceptFuture<I, S> = Pin<
    Box<dyn Future<Output = io::Result<(TlsStream<I>, AddExtension<S, PeerCertificate>)>> + Send>,
>;

impl<I, S> Accept<I, S> for PeerCertAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, PeerCertificate>;
    type Future = AcceptFuture<I, S>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let peer = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| PeerCertificate::from_der(leaf.as_ref()))
                .unwrap_or_default();
            Ok((stream, AddExtension::new(service, peer)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uris: &[&str], dns: &[&str]) -> PeerCertificate {
        PeerCertificate {
            uri_sans: uris.iter().map(ToString::to_string).collect(),
            dns_sans: dns.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn principal_needs_exactly_one_san_of_the_configured_type() {
        let one = peer(&["spiffe://bank/los"], &["los.bank"]);
        assert_eq!(one.principal(MtlsSanKind::Uri), Ok("spiffe://bank/los"));
        assert_eq!(one.principal(MtlsSanKind::Dns), Ok("los.bank"));
        assert_eq!(
            peer(&[], &["los.bank"]).principal(MtlsSanKind::Uri),
            Err(MtlsError::NoSan(MtlsSanKind::Uri))
        );
        assert_eq!(
            peer(&["spiffe://a", "spiffe://b"], &[]).principal(MtlsSanKind::Uri),
            Err(MtlsError::AmbiguousSan(MtlsSanKind::Uri))
        );
        assert_eq!(
            peer(&["spiffe://a\nb"], &[]).principal(MtlsSanKind::Uri),
            Err(MtlsError::InvalidSan)
        );
    }

    #[test]
    fn garbage_der_has_no_sans() {
        assert_eq!(
            PeerCertificate::from_der(b"not a cert"),
            PeerCertificate::default()
        );
    }

    #[test]
    fn reads_sans_from_a_real_certificate() {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params =
            rcgen::CertificateParams::new(vec!["los.bank.example".into()]).expect("params");
        params.subject_alt_names.push(rcgen::SanType::URI(
            "spiffe://bank.example/los".try_into().expect("uri"),
        ));
        let cert = params.self_signed(&key).expect("cert");
        let peer = PeerCertificate::from_der(cert.der());
        assert_eq!(peer.uri_sans, vec!["spiffe://bank.example/los"]);
        assert_eq!(peer.dns_sans, vec!["los.bank.example"]);
    }
}
