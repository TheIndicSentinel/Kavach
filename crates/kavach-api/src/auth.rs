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
//!
//! Cedar also receives the operator roles bound to the principal (ADR-019),
//! read per request with no cache. If they cannot be read the request is
//! refused with 503: it is never decided on the token's groups alone.

use std::collections::HashMap;
use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use kavach_auth::{KavachAction, OperatorRequest};
use tonic::metadata::MetadataMap;

use crate::error::ApiError;
use crate::mtls::PeerCertificate;
use crate::oidc::OidcError;
use crate::state::AppState;

const PRINCIPAL_HEADER: &str = "x-kavach-principal";

/// The issuer under which an `--insecure-dev` header principal can be bound
/// (ADR-019 §3). It is no OIDC issuer, so a binding made on a dev stack is
/// valid nowhere else.
pub const DEV_HEADER_ISSUER: &str = "dev:x-kavach-principal";

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
    /// The token's `sub`, which person bindings name (JWT principals only).
    pub subject: Option<String>,
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
            subject: token_claims.subject,
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
            subject: None,
        }),
        (None, None, Some(principal)) if state.insecure_dev() => Ok(AuthenticatedPrincipal {
            id: principal.to_string(),
            groups: vec![],
            source: PrincipalSource::InsecureHeader,
            issuer: None,
            subject: None,
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

/// What an allowed request carries into its audit row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Decision {
    /// Only a superadmin policy allowed the request (ADR-019 §7).
    pub acting_as_superadmin: bool,
}

/// A principal Cedar allowed to take an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    pub principal: AuthenticatedPrincipal,
    /// Only a superadmin policy allowed the request (ADR-019 §7).
    pub acting_as_superadmin: bool,
}

impl Deref for Authorized {
    type Target = AuthenticatedPrincipal;

    fn deref(&self) -> &AuthenticatedPrincipal {
        &self.principal
    }
}

pub async fn authorize_credentials(
    state: &AppState,
    credentials: &Credentials,
    action: KavachAction,
) -> Result<Decision, ApiError> {
    if state.access_control().is_none() {
        return Ok(Decision::default());
    }
    let principal = resolve_credentials(state, credentials)?;
    authorize_principal(state, &principal, action, None).await
}

/// gRPC: token from `authorization` metadata, certificate from the TLS
/// connection (`Request::peer_certs`).
pub async fn authorize_metadata(
    state: &AppState,
    md: &MetadataMap,
    peer: Option<&PeerCertificate>,
    action: KavachAction,
) -> Result<Decision, ApiError> {
    if state.access_control().is_none() {
        return Ok(Decision::default());
    }
    let principal = resolve_principal(
        state,
        metadata(md, "authorization"),
        metadata(md, PRINCIPAL_HEADER),
        peer,
    )?;
    authorize_principal(state, &principal, action, None).await
}

/// Resolves and authorizes the caller, returning the principal. Change
/// requests need the identity even when access control is off (development).
pub async fn authorized_principal(
    state: &AppState,
    credentials: &Credentials,
    action: KavachAction,
) -> Result<Authorized, ApiError> {
    authorized_for(state, credentials, action, None).await
}

/// [`authorized_principal`] for one of the four role-change actions: Cedar
/// decides with the role being granted or revoked in its context, so only a
/// `superadmin` may propose or approve a `superadmin` change (ADR-019 §4).
pub async fn authorized_role_change(
    state: &AppState,
    credentials: &Credentials,
    action: KavachAction,
    role: kavach_storage::Role,
) -> Result<Authorized, ApiError> {
    authorized_for(state, credentials, action, Some(role.as_str())).await
}

async fn authorized_for(
    state: &AppState,
    credentials: &Credentials,
    action: KavachAction,
    role_change: Option<&str>,
) -> Result<Authorized, ApiError> {
    let principal = resolve_credentials(state, credentials)?;
    let decision = authorize_principal(state, &principal, action, role_change).await?;
    Ok(Authorized {
        principal,
        acting_as_superadmin: decision.acting_as_superadmin,
    })
}

/// Where a principal's bindings live: `(issuer, subject)`, or `None` for a
/// principal no binding can name (a certificate workload).
pub(crate) fn binding_identity(principal: &AuthenticatedPrincipal) -> Option<(&str, Option<&str>)> {
    match principal.source {
        PrincipalSource::Jwt => Some((
            principal.issuer.as_deref().unwrap_or_default(),
            principal.subject.as_deref(),
        )),
        PrincipalSource::InsecureHeader => Some((DEV_HEADER_ISSUER, Some(principal.id.as_str()))),
        PrincipalSource::MtlsSan => None,
    }
}

/// The operator roles bound to the principal, read now (ADR-019 §3). A read
/// failure is a 503, never an empty set.
pub async fn bound_roles(
    state: &AppState,
    principal: &AuthenticatedPrincipal,
) -> Result<Vec<&'static str>, ApiError> {
    let Some((issuer, subject)) = binding_identity(principal) else {
        return Ok(Vec::new());
    };
    let roles = state
        .roles()
        .roles_for(state.tenant_id(), issuer, subject, &principal.groups)
        .await
        .map_err(|e| {
            // The store error names no principal.
            tracing::error!(error = %e, "role bindings could not be read; request refused");
            ApiError::Unavailable("role bindings could not be read".into())
        })?;
    Ok(roles
        .into_iter()
        .map(kavach_storage::Role::as_str)
        .collect())
}

async fn authorize_principal(
    state: &AppState,
    principal: &AuthenticatedPrincipal,
    action: KavachAction,
    role_change: Option<&str>,
) -> Result<Decision, ApiError> {
    let Some(auth) = state.access_control() else {
        return Ok(Decision::default());
    };
    let roles = bound_roles(state, principal).await?;
    record_seen(state, principal).await;
    let decision = auth
        .decide(&OperatorRequest {
            principal_id: &principal.id,
            groups: &principal.groups,
            roles: &roles,
            action,
            role_change,
        })
        .map_err(|e| ApiError::Internal(format!("cedar authorize: {e}")))?;
    if decision.allowed {
        Ok(Decision {
            acting_as_superadmin: decision.superadmin_only,
        })
    } else {
        Err(ApiError::Forbidden)
    }
}

/// How often this process rewrites one person's directory row. The store
/// moves `last_seen_at` at most hourly anyway; this spares the round trip.
const SEEN_INTERVAL: Duration = Duration::from_mins(15);
/// Entries kept before the throttle forgets everyone (a bound on memory, not
/// on correctness: forgetting only costs a write).
const SEEN_MAX_ENTRIES: usize = 10_000;

/// Remembers when this process last wrote each person's directory row.
#[derive(Debug, Default)]
pub struct SeenThrottle(Mutex<HashMap<(String, String), Instant>>);

impl SeenThrottle {
    /// True when the row is due for a write; marks it written.
    fn due(&self, issuer: &str, subject: &str, now: Instant) -> bool {
        let Ok(mut seen) = self.0.lock() else {
            return true;
        };
        let key = (issuer.to_string(), subject.to_string());
        if seen
            .get(&key)
            .is_some_and(|at| now.duration_since(*at) < SEEN_INTERVAL)
        {
            return false;
        }
        if seen.len() >= SEEN_MAX_ENTRIES {
            seen.clear();
        }
        seen.insert(key, now);
        true
    }
}

/// Adds an OIDC person to the principals directory, or moves their
/// `last_seen_at` on (ADR-019 §4). The directory informs the access review
/// and never an authorization decision, so a failed write is logged and the
/// request goes on.
async fn record_seen(state: &AppState, principal: &AuthenticatedPrincipal) {
    let (PrincipalSource::Jwt, Some(issuer), Some(subject)) = (
        principal.source,
        principal.issuer.as_deref(),
        principal.subject.as_deref(),
    ) else {
        return;
    };
    if !state.seen().due(issuer, subject, Instant::now()) {
        return;
    }
    if let Err(e) = state
        .roles()
        .record_principal_seen(
            state.tenant_id(),
            issuer,
            subject,
            &principal.id,
            chrono::Utc::now(),
        )
        .await
    {
        tracing::warn!(error = %e, "principals directory not updated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seen_throttle_writes_once_per_interval_per_person() {
        let throttle = SeenThrottle::default();
        let t0 = Instant::now();
        assert!(throttle.due("iss", "alice", t0));
        assert!(!throttle.due("iss", "alice", t0 + Duration::from_secs(60)));
        assert!(
            throttle.due("iss", "bob", t0),
            "another person is not throttled"
        );
        assert!(
            throttle.due("other-iss", "alice", t0),
            "nor the same subject at another issuer"
        );
        assert!(throttle.due("iss", "alice", t0 + SEEN_INTERVAL));
    }

    fn principal(source: PrincipalSource) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            id: "alice".into(),
            groups: vec![],
            source,
            issuer: (source == PrincipalSource::Jwt).then(|| "https://idp.example".into()),
            subject: (source == PrincipalSource::Jwt).then(|| "sub-alice".into()),
        }
    }

    #[test]
    fn a_dev_header_principal_binds_under_the_dev_source_and_a_certificate_not_at_all() {
        assert_eq!(
            binding_identity(&principal(PrincipalSource::Jwt)),
            Some(("https://idp.example", Some("sub-alice")))
        );
        assert_eq!(
            binding_identity(&principal(PrincipalSource::InsecureHeader)),
            Some((DEV_HEADER_ISSUER, Some("alice")))
        );
        assert_eq!(binding_identity(&principal(PrincipalSource::MtlsSan)), None);
    }
}
