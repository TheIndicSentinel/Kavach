//! Keycloak OIDC step-up authorization request construction (PRD D17).
//!
//! This module starts a challenge and persists its action-bound context. The
//! callback and code exchange are separate from this slice; callers must keep
//! the returned nonce and PKCE verifier in the authenticated server session.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use kavach_ports::{
    PortError, StepUpChallenge, StepUpChallengeState, StepUpChallengeStore, StepUpRequest,
    TokenSecret,
};
use reqwest::Url;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// OIDC client and Keycloak LoA configuration for the step-up request.
#[derive(Clone)]
pub struct KeycloakStepUpConfig {
    pub authorization_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// A Keycloak ACR value configured to require the intended WebAuthn flow.
    pub expected_acr: String,
    /// Permit plain HTTP only for explicit loopback development endpoints.
    pub allow_http_loopback: bool,
}

/// Secrets returned to the operator callback handler for server-side session
/// custody. Do not serialize or log this value.
pub struct KeycloakStepUpStart {
    challenge: StepUpChallenge,
    state: TokenSecret,
    nonce: TokenSecret,
    pkce_verifier: TokenSecret,
}

impl KeycloakStepUpStart {
    #[must_use]
    pub fn challenge(&self) -> &StepUpChallenge {
        &self.challenge
    }

    /// Transfers the challenge and callback secrets to the caller. The
    /// caller must bind these secrets to the authenticated browser session.
    #[must_use]
    pub fn into_parts(self) -> (StepUpChallenge, TokenSecret, TokenSecret, TokenSecret) {
        (self.challenge, self.state, self.nonce, self.pkce_verifier)
    }
}

/// Builds Keycloak authorization requests and stores their server-side
/// action/reviewer binding before returning the redirect URL.
pub struct KeycloakStepUpInitiator<S> {
    store: S,
    authorization_endpoint: Url,
    client_id: String,
    redirect_uri: String,
    expected_acr: String,
    rng: SystemRandom,
}

impl<S: StepUpChallengeStore> KeycloakStepUpInitiator<S> {
    pub fn new(config: KeycloakStepUpConfig, store: S) -> Result<Self, PortError> {
        if config.client_id.is_empty()
            || config.client_id.len() > 256
            || config.expected_acr.is_empty()
            || config.expected_acr.len() > 128
            || config.expected_acr.chars().any(char::is_control)
        {
            return Err(PortError::invalid("invalid Keycloak step-up client config"));
        }
        let authorization_endpoint = parse_endpoint(
            &config.authorization_endpoint,
            config.allow_http_loopback,
            "authorization endpoint",
        )?;
        if authorization_endpoint.query().is_some() {
            return Err(PortError::invalid(
                "step-up authorization endpoint must not contain a query",
            ));
        }
        let redirect_uri = parse_endpoint(
            &config.redirect_uri,
            config.allow_http_loopback,
            "redirect URI",
        )?;
        if redirect_uri.query().is_some() {
            return Err(PortError::invalid(
                "step-up redirect URI must not contain a query",
            ));
        }

        Ok(Self {
            store,
            authorization_endpoint,
            client_id: config.client_id,
            redirect_uri: redirect_uri.into(),
            expected_acr: config.expected_acr,
            rng: SystemRandom::new(),
        })
    }

    pub async fn begin(
        &self,
        request: StepUpRequest,
        now: chrono::DateTime<Utc>,
    ) -> Result<KeycloakStepUpStart, PortError> {
        request.validate(now)?;
        let state = TokenSecret::new(self.random()?);
        let nonce = TokenSecret::new(self.random()?);
        let pkce_verifier = TokenSecret::new(self.random()?);
        let pkce_challenge =
            URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.expose().as_bytes()));
        let state_hash = digest(state.expose());
        let nonce_hash = digest(nonce.expose());

        let claims = json!({
            "id_token": {
                "acr": {
                    "essential": true,
                    "values": [self.expected_acr]
                }
            }
        });
        let mut url = self.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", "openid")
            .append_pair("state", state.expose())
            .append_pair("nonce", nonce.expose())
            .append_pair("code_challenge", &pkce_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("claims", &claims.to_string())
            .append_pair("max_age", "0");

        let state_record = StepUpChallengeState {
            challenge_id: state.expose().to_string(),
            state_hash,
            nonce_hash,
            tenant_id: request.tenant_id,
            principal_key: request.principal_key,
            action_hash: request.action_hash,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
        };
        self.store.insert(state_record).await?;

        let challenge = StepUpChallenge {
            challenge_id: state.expose().to_string(),
            authorization_url: url.into(),
            expires_at: request.expires_at,
        };
        Ok(KeycloakStepUpStart {
            challenge,
            state,
            nonce,
            pkce_verifier,
        })
    }

    fn random(&self) -> Result<String, PortError> {
        let mut bytes = [0u8; 32];
        self.rng
            .fill(&mut bytes)
            .map_err(|_| PortError::unavailable("step-up random generation failed"))?;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        Ok(encoded)
    }
}

fn digest(value: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
}

fn parse_endpoint(value: &str, allow_http_loopback: bool, name: &str) -> Result<Url, PortError> {
    let url = Url::parse(value).map_err(|_| PortError::invalid(format!("invalid {name}")))?;
    let secure = url.scheme() == "https";
    let loopback_http = allow_http_loopback
        && url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1"));
    if (!secure && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(PortError::invalid(format!("unsafe {name}")));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use kavach_ports::{StepUpChallengeStore, StepUpRequest};
    use kavach_storage::MemoryStepUpChallengeStore;

    use super::*;

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap()
    }

    fn request(now: chrono::DateTime<Utc>) -> StepUpRequest {
        StepUpRequest {
            tenant_id: "tenant-1".into(),
            principal_key: "oidc:https://idp.example#reviewer-1".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            issued_at: now,
            expires_at: now + Duration::minutes(2),
        }
    }

    fn initiator(
        store: MemoryStepUpChallengeStore,
        authorization_endpoint: &str,
        allow_http_loopback: bool,
    ) -> Result<KeycloakStepUpInitiator<MemoryStepUpChallengeStore>, PortError> {
        KeycloakStepUpInitiator::new(
            KeycloakStepUpConfig {
                authorization_endpoint: authorization_endpoint.into(),
                client_id: "kavach-console".into(),
                redirect_uri: "https://console.example/auth/step-up/callback".into(),
                expected_acr: "webauthn-2".into(),
                allow_http_loopback,
            },
            store,
        )
    }

    #[tokio::test]
    async fn begin_persists_digest_bound_state_and_builds_fresh_pkce_step_up_url() {
        let store = MemoryStepUpChallengeStore::default();
        let initiator = initiator(
            store,
            "https://idp.example/realms/kavach/protocol/openid-connect/auth",
            false,
        )
        .unwrap();
        let started = initiator.begin(request(now()), now()).await.unwrap();
        let (challenge, state, nonce, verifier) = started.into_parts();
        let url = Url::parse(&challenge.authorization_url).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let claims: serde_json::Value = serde_json::from_str(query.get("claims").unwrap()).unwrap();
        let state_hash = digest(state.expose());

        assert_eq!(query.get("response_type").unwrap(), "code");
        assert_eq!(query.get("client_id").unwrap(), "kavach-console");
        assert_eq!(
            query.get("redirect_uri").unwrap(),
            "https://console.example/auth/step-up/callback"
        );
        assert_eq!(query.get("scope").unwrap(), "openid");
        assert_eq!(query.get("state").unwrap(), state.expose());
        assert_eq!(query.get("nonce").unwrap(), nonce.expose());
        assert_eq!(query.get("max_age").unwrap(), "0");
        assert_eq!(query.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(
            query.get("code_challenge").unwrap(),
            &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose().as_bytes()))
        );
        assert_eq!(
            claims["id_token"]["acr"],
            json!({"essential": true, "values": ["webauthn-2"]})
        );
        assert_eq!(
            challenge.challenge_id,
            state.expose(),
            "callback state is the opaque challenge handle"
        );
        let saved = initiator
            .store
            .get_live(&state_hash, now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saved.challenge_id, state.expose());
        assert_eq!(saved.nonce_hash, digest(nonce.expose()));
        assert_eq!(saved.tenant_id, "tenant-1");
        assert_eq!(saved.principal_key, "oidc:https://idp.example#reviewer-1");
        assert_eq!(saved.action_hash, request(now()).action_hash);
        assert!(!format!("{saved:?}").contains(nonce.expose()));
    }

    #[test]
    fn production_urls_require_https_and_clean_endpoints() {
        assert!(initiator(
            MemoryStepUpChallengeStore::default(),
            "http://idp.example/auth",
            false,
        )
        .is_err());
        assert!(initiator(
            MemoryStepUpChallengeStore::default(),
            "https://user:password@idp.example/auth",
            false,
        )
        .is_err());
        assert!(initiator(
            MemoryStepUpChallengeStore::default(),
            "https://idp.example/auth?claims=weak",
            false,
        )
        .is_err());
        assert!(initiator(
            MemoryStepUpChallengeStore::default(),
            "http://127.0.0.1:8081/auth",
            true,
        )
        .is_ok());
        assert!(initiator(
            MemoryStepUpChallengeStore::default(),
            "http://idp.example/auth",
            true,
        )
        .is_err());
    }
}
