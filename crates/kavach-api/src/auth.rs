//! Principal resolution and Cedar authorization for API routes (ADR-008).
//!
//! Principal sources, in order:
//! 1. `Authorization: Bearer <jwt>` verified against the configured OIDC
//!    issuer (groups from the token feed Cedar).
//! 2. (H2b) the mTLS client-certificate SAN.
//! 3. `X-Kavach-Principal` — **only with `--insecure-dev`**; never trusted
//!    otherwise.
//!
//! Sending a bearer token and `X-Kavach-Principal` together is rejected.

use axum::http::HeaderMap;
use kavach_auth::KavachAction;
use tonic::metadata::MetadataMap;

use crate::error::ApiError;
use crate::oidc::OidcError;
use crate::state::AppState;

const PRINCIPAL_HEADER: &str = "x-kavach-principal";
const APPROVER_HEADER: &str = "x-kavach-approver";

/// How the principal was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalSource {
    /// Verified OIDC/OAuth 2.0 JWT access token.
    Jwt,
    /// Self-asserted header, accepted only in `--insecure-dev`.
    InsecureHeader,
}

/// A principal established by the transport or a verified credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub id: String,
    pub groups: Vec<String>,
    pub source: PrincipalSource,
}

#[derive(Debug, Clone)]
pub struct DualControlPrincipals {
    /// Authenticated principal making the change.
    pub actor: String,
    /// Approver named in `X-Kavach-Approver`. Still self-asserted until H3
    /// (change requests approved by a different authenticated principal).
    pub approver: String,
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

/// Resolves the request principal from the credential material presented.
pub fn resolve_principal(
    state: &AppState,
    authorization: Option<&str>,
    principal_header: Option<&str>,
) -> Result<AuthenticatedPrincipal, ApiError> {
    match (bearer_token(authorization)?, principal_header) {
        (Some(_), Some(_)) => Err(ApiError::BadRequest(
            "send either a bearer token or X-Kavach-Principal, not both".into(),
        )),
        (Some(token), None) => {
            let verifier = state.oidc().ok_or(ApiError::Unauthorized)?;
            match verifier.verify(token) {
                Ok(token_claims) => Ok(AuthenticatedPrincipal {
                    id: token_claims.principal,
                    groups: token_claims.groups,
                    source: PrincipalSource::Jwt,
                }),
                Err(OidcError::UnknownKid(_)) => {
                    verifier.request_refresh();
                    Err(ApiError::Unauthorized)
                }
                Err(_) => Err(ApiError::Unauthorized),
            }
        }
        (None, Some(principal)) if state.insecure_dev() => Ok(AuthenticatedPrincipal {
            id: principal.to_string(),
            groups: vec![],
            source: PrincipalSource::InsecureHeader,
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

pub fn resolve_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedPrincipal, ApiError> {
    resolve_principal(
        state,
        header(headers, "authorization"),
        header(headers, PRINCIPAL_HEADER),
    )
}

pub fn authorize_headers(
    state: &AppState,
    headers: &HeaderMap,
    action: KavachAction,
) -> Result<(), ApiError> {
    if state.access_control().is_none() {
        return Ok(());
    }
    let principal = resolve_headers(state, headers)?;
    authorize_principal(state, &principal, action)
}

pub fn authorize_metadata(
    state: &AppState,
    md: &MetadataMap,
    action: KavachAction,
) -> Result<(), ApiError> {
    if state.access_control().is_none() {
        return Ok(());
    }
    let principal = resolve_principal(
        state,
        metadata(md, "authorization"),
        metadata(md, PRINCIPAL_HEADER),
    )?;
    authorize_principal(state, &principal, action)
}

pub fn authorize_dual_control(
    state: &AppState,
    headers: &HeaderMap,
    action: KavachAction,
) -> Result<DualControlPrincipals, ApiError> {
    let actor = resolve_headers(state, headers)?;
    let approver = header(headers, APPROVER_HEADER).ok_or(ApiError::BadRequest(
        "dual control requires X-Kavach-Approver header".into(),
    ))?;
    if actor.id == approver {
        return Err(ApiError::BadRequest(
            "approver must differ from actor principal".into(),
        ));
    }
    if state.access_control().is_some() {
        authorize_principal(state, &actor, action)?;
        authorize_principal(
            state,
            &AuthenticatedPrincipal {
                id: approver.to_string(),
                groups: vec![],
                source: PrincipalSource::InsecureHeader,
            },
            action,
        )?;
    }
    Ok(DualControlPrincipals {
        actor: actor.id,
        approver: approver.to_string(),
    })
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
