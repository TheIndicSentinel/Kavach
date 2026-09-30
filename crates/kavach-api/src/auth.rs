//! Principal resolution and Cedar authorization for API routes (ADR-008).
//!
//! Principal sources, in order:
//! 1. `Authorization: Bearer <jwt>` verified against the configured OIDC
//!    issuer (groups from the token feed Cedar).
//! 2. The mTLS client-certificate SAN, when `--mtls-principal-san` is set
//!    (groups from the entities file). A token wins over the certificate: the
//!    token names the acting principal, the certificate the workload.
//! 3. `X-Kavach-Principal` — **only with `--insecure-dev`**; never trusted
//!    otherwise.
//!
//! Sending `X-Kavach-Principal` together with a token or a certificate
//! principal is rejected.

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use kavach_auth::KavachAction;
use tonic::metadata::MetadataMap;

use crate::error::ApiError;
use crate::mtls::PeerCertificate;
use crate::oidc::OidcError;
use crate::state::AppState;

const PRINCIPAL_HEADER: &str = "x-kavach-principal";

/// How the principal was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalSource {
    /// Verified OIDC/OAuth 2.0 JWT access token.
    Jwt,
    /// Verified mTLS client-certificate SAN.
    MtlsSan,
    /// Self-asserted header, accepted only in `--insecure-dev`.
    InsecureHeader,
}

/// A principal established by the transport or a verified credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub id: String,
    pub groups: Vec<String>,
    pub source: PrincipalSource,
    /// Token issuer, for source-qualified identity (JWT principals only).
    pub issuer: Option<String>,
}

impl AuthenticatedPrincipal {
    /// Source-qualified identity used to tell principals apart (the display
    /// id alone could collide across sources or issuers).
    #[must_use]
    pub fn identity_key(&self) -> String {
        match self.source {
            PrincipalSource::Jwt => format!(
                "oidc:{}#{}",
                self.issuer.as_deref().unwrap_or_default(),
                self.id
            ),
            PrincipalSource::MtlsSan => format!("mtls:{}", self.id),
            PrincipalSource::InsecureHeader => format!("header:{}", self.id),
        }
    }
}

/// Credential material of an HTTP request: its headers and, over TLS, the
/// client certificate attached by [`crate::mtls::PeerCertAcceptor`].
#[derive(Debug, Clone)]
pub struct Credentials {
    pub headers: HeaderMap,
    pub peer: Option<PeerCertificate>,
}

impl<S: Send + Sync> FromRequestParts<S> for Credentials {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self {
            headers: parts.headers.clone(),
            peer: parts.extensions.get::<PeerCertificate>().cloned(),
        }))
    }
}

fn bearer_token(authorization: Option<&str>) -> Result<Option<&str>, ApiError> {
    let Some(value) = authorization else {
        return Ok(None);
    };
    let (scheme, token) = value.split_once(' ').ok_or(ApiError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return Err(ApiError::Unauthorized);
    }
    Ok(Some(token.trim()))
}

fn verify_token(state: &AppState, token: &str) -> Result<AuthenticatedPrincipal, ApiError> {
    let verifier = state.oidc().ok_or(ApiError::Unauthorized)?;
    match verifier.verify(token) {
        Ok(token_claims) => Ok(AuthenticatedPrincipal {
            id: token_claims.principal,
            groups: token_claims.groups,
            source: PrincipalSource::Jwt,
            issuer: Some(verifier.issuer().to_string()),
        }),
        Err(OidcError::UnknownKid(_)) => {
            verifier.request_refresh();
            Err(ApiError::Unauthorized)
        }
        Err(_) => Err(ApiError::Unauthorized),
    }
}

/// Resolves the request principal from the credential material presented.
pub fn resolve_principal(
    state: &AppState,
    authorization: Option<&str>,
    principal_header: Option<&str>,
    peer: Option<&PeerCertificate>,
) -> Result<AuthenticatedPrincipal, ApiError> {
    let token = bearer_token(authorization)?;
    let cert_principal = state
        .mtls_principal_san()
        .zip(peer)
        .and_then(|(kind, peer)| peer.principal(kind).ok());
    match (token, cert_principal, principal_header) {
        (Some(_), _, Some(_)) => Err(ApiError::BadRequest(
            "send either a bearer token or X-Kavach-Principal, not both".into(),
        )),
        (None, Some(_), Some(_)) => Err(ApiError::BadRequest(
            "X-Kavach-Principal is not accepted with a client-certificate principal".into(),
        )),
        (Some(token), _, None) => verify_token(state, token),
        (None, Some(id), None) => Ok(AuthenticatedPrincipal {
            id: id.to_string(),
            groups: vec![],
            source: PrincipalSource::MtlsSan,
            issuer: None,
        }),
        (None, None, Some(principal)) if state.insecure_dev() => Ok(AuthenticatedPrincipal {
            id: principal.to_string(),
            groups: vec![],
            source: PrincipalSource::InsecureHeader,
            issuer: None,
        }),
        _ => Err(ApiError::Unauthorized),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn metadata<'a>(metadata: &'a MetadataMap, name: &str) -> Option<&'a str> {
    metadata.get(name).and_then(|value| value.to_str().ok())
}

pub fn resolve_credentials(
    state: &AppState,
    credentials: &Credentials,
) -> Result<AuthenticatedPrincipal, ApiError> {
    resolve_principal(
        state,
        header(&credentials.headers, "authorization"),
        header(&credentials.headers, PRINCIPAL_HEADER),
        credentials.peer.as_ref(),
    )
}

pub fn authorize_credentials(
    state: &AppState,
    credentials: &Credentials,
    action: KavachAction,
) -> Result<(), ApiError> {
    if state.access_control().is_none() {
        return Ok(());
    }
    let principal = resolve_credentials(state, credentials)?;
    authorize_principal(state, &principal, action)
}

/// gRPC: token from `authorization` metadata, certificate from the TLS
/// connection (`Request::peer_certs`).
pub fn authorize_metadata(
    state: &AppState,
    md: &MetadataMap,
    peer: Option<&PeerCertificate>,
    action: KavachAction,
) -> Result<(), ApiError> {
    if state.access_control().is_none() {
        return Ok(());
    }
    let principal = resolve_principal(
        state,
        metadata(md, "authorization"),
        metadata(md, PRINCIPAL_HEADER),
        peer,
    )?;
    authorize_principal(state, &principal, action)
}

/// Resolves and authorizes the caller, returning the principal. Change
/// requests need the identity even when access control is off (development).
pub fn authorized_principal(
    state: &AppState,
    credentials: &Credentials,
    action: KavachAction,
) -> Result<AuthenticatedPrincipal, ApiError> {
    let principal = resolve_credentials(state, credentials)?;
    authorize_principal(state, &principal, action)?;
    Ok(principal)
}

fn authorize_principal(
    state: &AppState,
    principal: &AuthenticatedPrincipal,
    action: KavachAction,
) -> Result<(), ApiError> {
    let Some(auth) = state.access_control() else {
        return Ok(());
    };
    let allowed = auth
        .authorize_with_groups(&principal.id, &principal.groups, action)
        .map_err(|e| ApiError::Internal(format!("cedar authorize: {e}")))?;
    if allowed {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
