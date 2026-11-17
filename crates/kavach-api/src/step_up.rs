//! Keycloak OIDC step-up authorization and callback verification (PRD D17).
//!
//! It starts a challenge, persists its action-bound context, and verifies the
//! callback. HTTP route wiring remains separate; callback secrets and the
//! challenge's tenant/reviewer/action context stay in server-side session state.

use axum::http::header::{HeaderValue, ACCEPT, AUTHORIZATION};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use kavach_domain::Decision;
use kavach_ports::agent_evidence::AgentDecisionRecord;
use kavach_ports::{
    PortError, PublicKey, StepUpChallenge, StepUpChallengeState, StepUpChallengeStore,
    StepUpRequest, TokenSecret, VerifiedStepUp,
};
use reqwest::Url;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const STEP_UP_CALLBACK_PATH: &str = "/auth/step-up/callback";

/// Builds step-up context only from a committed HUMAN_REVIEW evidence record
/// and a reviewer identity obtained from the authenticated console session.
/// The caller must load the record from the server-side evidence store and
/// supply the trusted evidence key set.
pub fn request_for_human_review(
    record: &AgentDecisionRecord,
    evidence_keys: &std::collections::BTreeMap<String, PublicKey>,
    allow_dev_keys: bool,
    tenant_id: &str,
    reviewer_principal_key: &str,
    issued_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
) -> Result<StepUpRequest, PortError> {
    kavach_ports::agent_evidence::check_record_signature(record, evidence_keys, allow_dev_keys)
        .map_err(|_| PortError::rejected("review evidence signature is invalid"))?;
    if record.payload.tenant_id != tenant_id
        || record.payload.policy_decision != Decision::HumanReview
        || record.payload.returned_decision != Decision::HumanReview
    {
        return Err(PortError::rejected(
            "step-up requires a HUMAN_REVIEW record for this tenant",
        ));
    }
    let action_hash = record
        .payload
        .review_action_hash
        .clone()
        .ok_or_else(|| PortError::rejected("review record has no exact-action binding"))?;
    let request = StepUpRequest {
        tenant_id: tenant_id.to_string(),
        principal_key: reviewer_principal_key.to_string(),
        action_hash,
        issued_at,
        expires_at,
    };
    request.validate(issued_at)?;
    Ok(request)
}

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
    tenant_id: String,
    principal_key: String,
    action_hash: String,
    state: TokenSecret,
    nonce: TokenSecret,
    pkce_verifier: TokenSecret,
}

impl KeycloakStepUpStart {
    #[must_use]
    pub fn challenge(&self) -> &StepUpChallenge {
        &self.challenge
    }

    #[must_use]
    pub fn principal_key(&self) -> &str {
        &self.principal_key
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn action_hash(&self) -> &str {
        &self.action_hash
    }

    /// Transfers the challenge and callback secrets to the caller. The
    /// caller must bind these secrets to the authenticated browser session.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        StepUpChallenge,
        String,
        String,
        String,
        TokenSecret,
        TokenSecret,
        TokenSecret,
    ) {
        (
            self.challenge,
            self.tenant_id,
            self.principal_key,
            self.action_hash,
            self.state,
            self.nonce,
            self.pkce_verifier,
        )
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

/// Callback inputs. All token and PKCE values arrive from the callback
/// handler's server-side session, never from agent-controlled parameters.
pub struct KeycloakStepUpCallbackRequest<'a> {
    pub state: &'a TokenSecret,
    pub code: &'a TokenSecret,
    pub nonce: &'a TokenSecret,
    pub pkce_verifier: &'a TokenSecret,
    pub authenticated_principal_key: &'a str,
    pub expected_tenant_id: &'a str,
    pub expected_action_hash: &'a str,
    pub now: chrono::DateTime<Utc>,
}

/// Exchanges a Keycloak authorization code, verifies the resulting step-up
/// ID token against its durable challenge, and consumes that challenge once.
pub struct KeycloakStepUpCallback<S> {
    store: S,
    token_endpoint: Url,
    client_id: String,
    client_secret: TokenSecret,
    redirect_uri: String,
    expected_acr: String,
    verifier: std::sync::Arc<crate::oidc::OidcVerifier>,
    http: reqwest::Client,
}

pub struct KeycloakStepUpCallbackConfig {
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: TokenSecret,
    pub redirect_uri: String,
    pub expected_acr: String,
    pub verifier: std::sync::Arc<crate::oidc::OidcVerifier>,
    pub allow_http_loopback: bool,
}

struct SecretTokenResponse {
    id_token: TokenSecret,
}

impl<'de> Deserialize<'de> for SecretTokenResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Response {
            id_token: String,
        }
        let response = Response::deserialize(deserializer)?;
        Ok(Self {
            id_token: TokenSecret::new(response.id_token),
        })
    }
}

impl<S: StepUpChallengeStore> KeycloakStepUpCallback<S> {
    pub fn new(store: S, config: KeycloakStepUpCallbackConfig) -> Result<Self, PortError> {
        let KeycloakStepUpCallbackConfig {
            token_endpoint,
            client_id,
            client_secret,
            redirect_uri,
            expected_acr,
            verifier,
            allow_http_loopback,
        } = config;
        if client_id.is_empty()
            || client_id.len() > 256
            || expected_acr.is_empty()
            || expected_acr.len() > 128
            || expected_acr.chars().any(char::is_control)
            || client_secret.expose().is_empty()
            || client_secret.expose().len() > 4096
            || client_secret.expose().contains(['\r', '\n'])
        {
            return Err(PortError::invalid("invalid Keycloak step-up client config"));
        }
        let token_endpoint =
            parse_endpoint(&token_endpoint, allow_http_loopback, "token endpoint")?;
        let redirect_uri = parse_endpoint(&redirect_uri, allow_http_loopback, "redirect URI")?;
        if token_endpoint.query().is_some()
            || redirect_uri.query().is_some()
            || redirect_uri.path() != STEP_UP_CALLBACK_PATH
        {
            return Err(PortError::invalid(
                "step-up endpoints must be query-free and use the fixed callback path",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!allow_http_loopback)
            .build()
            .map_err(|_| PortError::unavailable("step-up HTTP client could not be built"))?;
        Ok(Self {
            store,
            token_endpoint,
            client_id,
            client_secret,
            redirect_uri: redirect_uri.into(),
            expected_acr,
            verifier,
            http,
        })
    }

    pub async fn finish(
        &self,
        request: KeycloakStepUpCallbackRequest<'_>,
    ) -> Result<VerifiedStepUp, PortError> {
        let KeycloakStepUpCallbackRequest {
            state,
            code,
            nonce,
            pkce_verifier,
            authenticated_principal_key,
            expected_tenant_id,
            expected_action_hash,
            now,
        } = request;
        for (name, value) in [
            ("state", state.expose()),
            ("nonce", nonce.expose()),
            ("PKCE verifier", pkce_verifier.expose()),
        ] {
            if !is_random_value(value) {
                return Err(PortError::rejected(format!("invalid step-up {name}")));
            }
        }
        if code.expose().is_empty()
            || code.expose().len() > 4096
            || code.expose().chars().any(char::is_control)
        {
            return Err(PortError::rejected("invalid step-up authorization code"));
        }
        let state_hash = digest(state.expose());
        let challenge = self
            .store
            .get_live(&state_hash, now)
            .await?
            .ok_or_else(|| PortError::rejected("step-up challenge is missing, expired, or used"))?;
        if challenge.challenge_id != state.expose()
            || challenge.nonce_hash != digest(nonce.expose())
            || challenge.principal_key != authenticated_principal_key
            || challenge.tenant_id != expected_tenant_id
            || challenge.action_hash != expected_action_hash
        {
            return Err(PortError::rejected(
                "step-up callback does not match its authenticated challenge",
            ));
        }
        let subject_prefix = format!("oidc:{}#", self.verifier.issuer());
        let expected_subject = challenge
            .principal_key
            .strip_prefix(&subject_prefix)
            .filter(|subject| !subject.is_empty())
            .ok_or_else(|| PortError::rejected("step-up reviewer identity source differs"))?;

        let token = self.exchange_code(code, pkce_verifier).await?;
        self.verifier
            .verify_step_up_id_token(&crate::oidc::StepUpIdTokenRequest {
                token: token.id_token.expose(),
                client_id: &self.client_id,
                nonce: nonce.expose(),
                expected_subject,
                expected_acr: &self.expected_acr,
                challenge_issued_at: challenge.issued_at,
                now,
            })
            .map_err(|_| PortError::rejected("step-up ID token was refused"))?;

        let consumed = self
            .store
            .consume(&state_hash, now)
            .await?
            .ok_or_else(|| PortError::rejected("step-up challenge was already used"))?;
        if consumed != challenge {
            return Err(PortError::rejected(
                "step-up challenge changed during verification",
            ));
        }
        Ok(VerifiedStepUp {
            tenant_id: challenge.tenant_id,
            principal_key: challenge.principal_key,
            action_hash: challenge.action_hash,
            step_up_ref: format!("keycloak-step-up:{}", challenge.challenge_id),
            verified_at: now,
        })
    }

    async fn exchange_code(
        &self,
        code: &TokenSecret,
        pkce_verifier: &TokenSecret,
    ) -> Result<SecretTokenResponse, PortError> {
        let encoded_client_id = oauth_form_encode(&self.client_id);
        let encoded_client_secret = oauth_form_encode(self.client_secret.expose());
        let client_credentials = TokenSecret::new(format!(
            "{}:{}",
            encoded_client_id.expose(),
            encoded_client_secret.expose()
        ));
        let encoded_credentials = TokenSecret::new(STANDARD.encode(client_credentials.expose()));
        let authorization = TokenSecret::new(format!("Basic {}", encoded_credentials.expose()));
        let mut authorization_header = HeaderValue::from_str(authorization.expose())
            .map_err(|_| PortError::rejected("invalid step-up client credentials"))?;
        authorization_header.set_sensitive(true);
        let mut response = self
            .http
            .post(self.token_endpoint.clone())
            .header(AUTHORIZATION, authorization_header)
            .header(ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.expose()),
                ("redirect_uri", &self.redirect_uri),
                ("code_verifier", pkce_verifier.expose()),
            ])
            .send()
            .await
            .map_err(|_| PortError::unavailable("step-up token endpoint is unavailable"))?;
        let status = response.status();
        if !status.is_success() {
            return if status.is_server_error() {
                Err(PortError::unavailable(
                    "step-up token endpoint is unavailable",
                ))
            } else {
                Err(PortError::rejected(
                    "step-up authorization code was refused",
                ))
            };
        }
        let mut body = Vec::new();
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => {
                    body.zeroize();
                    return Err(PortError::unavailable(
                        "step-up token response could not be read",
                    ));
                }
            };
            if body.len().saturating_add(chunk.len()) > 65_536 {
                body.zeroize();
                return Err(PortError::rejected("step-up token response is oversized"));
            }
            body.extend_from_slice(&chunk);
        }
        let parsed = serde_json::from_slice::<SecretTokenResponse>(&body);
        body.zeroize();
        parsed.map_err(|_| PortError::rejected("step-up token response was invalid"))
    }
}

fn is_random_value(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn oauth_form_encode(value: &str) -> TokenSecret {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
    TokenSecret::new(encoded)
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
        if redirect_uri.query().is_some() || redirect_uri.path() != STEP_UP_CALLBACK_PATH {
            return Err(PortError::invalid(
                "step-up redirect URI must be the fixed callback path without a query",
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

        let tenant_id = request.tenant_id.clone();
        let principal_key = request.principal_key.clone();
        let action_hash = request.action_hash.clone();
        let state_record = StepUpChallengeState {
            challenge_id: state.expose().to_string(),
            state_hash,
            nonce_hash,
            tenant_id: request.tenant_id,
            principal_key: request.principal_key.clone(),
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
            tenant_id,
            principal_key,
            action_hash,
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
    use std::collections::HashMap;

    use axum::extract::{Form, State};
    use axum::http::{header::AUTHORIZATION, HeaderMap};
    use axum::routing::post;
    use axum::{Json, Router};
    use base64::engine::general_purpose::STANDARD;
    use chrono::{Duration, TimeZone};
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use kavach_ports::agent_evidence::{
        signing_message, Actor, AgentDecisionPayload, PolicyVersions, TimeSync, HASH_ALG_V2,
        KIND_AGENT_DECISION,
    };
    use kavach_ports::{KeyAlgorithm, StepUpChallengeStore, StepUpRequest};
    use kavach_storage::MemoryStepUpChallengeStore;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap()
    }

    fn human_review_record() -> (
        AgentDecisionRecord,
        std::collections::BTreeMap<String, PublicKey>,
    ) {
        let keypair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
        let payload = AgentDecisionPayload {
            record_id: "adr:tenant-1:0:1".into(),
            tenant_id: "tenant-1".into(),
            partition_id: 0,
            seq: 1,
            prev_hash: "0".repeat(64),
            kind: KIND_AGENT_DECISION.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: "evidence-key-1".into(),
            actor: Actor {
                agent_id: "collections-agent".into(),
                identity_key: "oidc:https://agent.example#collections-agent".into(),
            },
            chain: vec!["mandate-1".into()],
            mandate_id: "mandate-1".into(),
            purpose: "loan_recovery".into(),
            consent_refs: vec![],
            action: "propose_plan".into(),
            request_id: "request-1".into(),
            subject_pseudonym: "psn:review-subject".into(),
            params_mac: None,
            review_action_hash: Some(format!("sha256-action-v1:{}", "a".repeat(64))),
            policy_versions: PolicyVersions {
                cedar: "sha256:cedar".into(),
                cel: None,
                packs: vec![],
                tools: Some("sha256:tools".into()),
                build: "test".into(),
            },
            signals: vec!["escalated".into()],
            pre_commit_decision: Decision::HumanReview,
            policy_decision: Decision::HumanReview,
            returned_decision: Decision::HumanReview,
            obligations: vec![],
            credential_id: None,
            credential_expires_at: None,
            send_by: None,
            time_sync: TimeSync {
                status: "synced".into(),
                max_error_ms: Some(1),
            },
            ts: now(),
        };
        let hash = kavach_ports::agent_evidence::payload_hash(&payload).unwrap();
        let sig = hex::encode(keypair.sign(&signing_message(&hash)).as_ref());
        let record = AgentDecisionRecord { payload, hash, sig };
        let public_key = PublicKey {
            kid: "evidence-key-1".into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: keypair.public_key().as_ref().try_into().unwrap(),
        };
        (
            record,
            std::collections::BTreeMap::from([("evidence-key-1".into(), public_key)]),
        )
    }

    #[test]
    fn review_step_up_request_uses_only_matching_human_review_evidence() {
        let (record, evidence_keys) = human_review_record();
        let reviewer = "oidc:https://idp.example#reviewer-1";
        let request = request_for_human_review(
            &record,
            &evidence_keys,
            false,
            "tenant-1",
            reviewer,
            now(),
            now() + Duration::minutes(2),
        )
        .unwrap();
        assert_eq!(request.tenant_id, "tenant-1");
        assert_eq!(request.principal_key, reviewer);
        assert_eq!(
            request.action_hash,
            record.payload.review_action_hash.as_deref().unwrap()
        );

        assert!(request_for_human_review(
            &record,
            &evidence_keys,
            false,
            "tenant-2",
            reviewer,
            now(),
            now() + Duration::minutes(2),
        )
        .is_err());

        let mut not_review = record.clone();
        not_review.payload.returned_decision = Decision::Block;
        assert!(request_for_human_review(
            &not_review,
            &evidence_keys,
            false,
            "tenant-1",
            reviewer,
            now(),
            now() + Duration::minutes(2),
        )
        .is_err());

        let mut tampered = record.clone();
        tampered.hash = "edited-record-hash".into();
        assert!(request_for_human_review(
            &tampered,
            &evidence_keys,
            false,
            "tenant-1",
            reviewer,
            now(),
            now() + Duration::minutes(2),
        )
        .is_err());

        let mut invalid_signature = record.clone();
        invalid_signature.sig = hex::encode([0u8; 64]);
        assert!(request_for_human_review(
            &invalid_signature,
            &evidence_keys,
            false,
            "tenant-1",
            reviewer,
            now(),
            now() + Duration::minutes(2),
        )
        .is_err());

        let mut missing_hash = record;
        missing_hash.payload.review_action_hash = None;
        assert!(request_for_human_review(
            &missing_hash,
            &evidence_keys,
            false,
            "tenant-1",
            reviewer,
            now(),
            now() + Duration::minutes(2),
        )
        .is_err());
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

    fn verifier() -> std::sync::Arc<crate::oidc::OidcVerifier> {
        let public = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let jwks: JwkSet = serde_json::from_value(json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(public.public_key().as_ref()),
            "kid": "step-up", "alg": "EdDSA", "use": "sig"
        }]}))
        .unwrap();
        crate::oidc::OidcVerifier::from_jwks(
            crate::oidc::OidcConfig {
                issuer: "https://idp.example".into(),
                audience: "kavach-api".into(),
                jwks: crate::oidc::JwksSource::File(std::path::PathBuf::new()),
                principal_claim: "sub".into(),
                groups_claim: "groups".into(),
                leeway_seconds: 0,
            },
            &jwks,
        )
    }

    fn signed_step_up_id_token(nonce: &str, now: chrono::DateTime<Utc>) -> String {
        let now_seconds = now.timestamp();
        let claims = json!({
            "iss": "https://idp.example",
            "aud": "kavach-console",
            "azp": "kavach-console",
            "sub": "reviewer-1",
            "nonce": nonce,
            "acr": "webauthn-2",
            "auth_time": now_seconds - 1,
            "iat": now_seconds,
            "exp": now_seconds + 300
        });
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&[1; 32]);
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("step-up".into());
        encode(&header, &claims, &EncodingKey::from_ed_der(&der)).unwrap()
    }

    async fn token_server(id_token: String) -> (String, tokio::task::JoinHandle<()>) {
        async fn exchange(
            State(id_token): State<String>,
            headers: HeaderMap,
            Form(form): Form<HashMap<String, String>>,
        ) -> Json<serde_json::Value> {
            let basic = headers
                .get(AUTHORIZATION)
                .and_then(|header| header.to_str().ok())
                .and_then(|header| header.strip_prefix("Basic "))
                .and_then(|basic| STANDARD.decode(basic).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok());
            assert_eq!(basic.as_deref(), Some("kavach-console:test-secret"));
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("authorization_code")
            );
            assert_eq!(form.get("code").map(String::as_str), Some("auth-code"));
            assert_eq!(
                form.get("code_verifier").map(String::as_str),
                Some("v".repeat(43).as_str())
            );
            assert_eq!(
                form.get("redirect_uri").map(String::as_str),
                Some("http://127.0.0.1/auth/step-up/callback")
            );
            Json(json!({"id_token": id_token}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/token", post(exchange))
            .with_state(id_token);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/token"), task)
    }

    fn state_record(state: &str, nonce: &str, now: chrono::DateTime<Utc>) -> StepUpChallengeState {
        StepUpChallengeState {
            challenge_id: state.into(),
            state_hash: digest(state),
            nonce_hash: digest(nonce),
            tenant_id: "tenant-1".into(),
            principal_key: "oidc:https://idp.example#reviewer-1".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            issued_at: now - Duration::seconds(2),
            expires_at: now + Duration::minutes(2),
        }
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
        let (challenge, _tenant_id, _principal_key, _action_hash, state, nonce, verifier) =
            started.into_parts();
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

    #[tokio::test]
    async fn callback_exchanges_code_verifies_exact_identity_and_consumes_once() {
        let now = Utc::now();
        let state = TokenSecret::new("s".repeat(43));
        let nonce = TokenSecret::new("n".repeat(43));
        let code = TokenSecret::new("auth-code");
        let pkce_verifier = TokenSecret::new("v".repeat(43));
        let store = MemoryStepUpChallengeStore::default();
        let state_record = state_record(state.expose(), nonce.expose(), now);
        store.insert(state_record.clone()).await.unwrap();
        let (token_endpoint, server) =
            token_server(signed_step_up_id_token(nonce.expose(), now)).await;
        let callback = KeycloakStepUpCallback::new(
            store.clone(),
            KeycloakStepUpCallbackConfig {
                token_endpoint,
                client_id: "kavach-console".into(),
                client_secret: TokenSecret::new("test-secret"),
                redirect_uri: "http://127.0.0.1/auth/step-up/callback".into(),
                expected_acr: "webauthn-2".into(),
                verifier: verifier(),
                allow_http_loopback: true,
            },
        )
        .unwrap();

        let verified = callback
            .finish(KeycloakStepUpCallbackRequest {
                state: &state,
                code: &code,
                nonce: &nonce,
                pkce_verifier: &pkce_verifier,
                authenticated_principal_key: &state_record.principal_key,
                expected_tenant_id: &state_record.tenant_id,
                expected_action_hash: &state_record.action_hash,
                now,
            })
            .await
            .unwrap();
        server.abort();

        assert_eq!(verified.tenant_id, state_record.tenant_id);
        assert_eq!(verified.principal_key, state_record.principal_key);
        assert_eq!(verified.action_hash, state_record.action_hash);
        assert_eq!(verified.verified_at, now);
        assert!(verified.step_up_ref.starts_with("keycloak-step-up:"));
        assert!(store
            .get_live(&digest(state.expose()), now)
            .await
            .unwrap()
            .is_none());
        assert!(callback
            .finish(KeycloakStepUpCallbackRequest {
                state: &state,
                code: &code,
                nonce: &nonce,
                pkce_verifier: &pkce_verifier,
                authenticated_principal_key: &state_record.principal_key,
                expected_tenant_id: &state_record.tenant_id,
                expected_action_hash: &state_record.action_hash,
                now,
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn callback_refuses_a_different_session_principal_before_code_exchange() {
        let now = Utc::now();
        let state = TokenSecret::new("t".repeat(43));
        let nonce = TokenSecret::new("m".repeat(43));
        let code = TokenSecret::new("auth-code");
        let pkce_verifier = TokenSecret::new("v".repeat(43));
        let store = MemoryStepUpChallengeStore::default();
        let record = state_record(state.expose(), nonce.expose(), now);
        store.insert(record.clone()).await.unwrap();
        let callback = KeycloakStepUpCallback::new(
            store.clone(),
            KeycloakStepUpCallbackConfig {
                token_endpoint: "http://127.0.0.1:9/token".into(),
                client_id: "kavach-console".into(),
                client_secret: TokenSecret::new("test-secret"),
                redirect_uri: "http://127.0.0.1/auth/step-up/callback".into(),
                expected_acr: "webauthn-2".into(),
                verifier: verifier(),
                allow_http_loopback: true,
            },
        )
        .unwrap();

        assert!(callback
            .finish(KeycloakStepUpCallbackRequest {
                state: &state,
                code: &code,
                nonce: &nonce,
                pkce_verifier: &pkce_verifier,
                authenticated_principal_key: "oidc:https://idp.example#different-reviewer",
                expected_tenant_id: &record.tenant_id,
                expected_action_hash: &record.action_hash,
                now,
            })
            .await
            .is_err());
        assert!(store
            .get_live(&digest(state.expose()), now)
            .await
            .unwrap()
            .is_some());
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
