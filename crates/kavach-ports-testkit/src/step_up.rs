//! Test-only step-up provider for D17 approval workflow tests.
//!
//! Proofs are synthetic and are not WebAuthn assertions. This adapter must
//! never be configured in a production service.

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use kavach_ports::{
    PortError, StepUpChallenge, StepUpProof, StepUpProvider, StepUpRequest, TokenSecret,
    VerifiedStepUp,
};

#[derive(Default)]
pub struct FakeStepUpProvider {
    next_id: AtomicU64,
    challenges: Mutex<HashMap<String, FakeChallenge>>,
}

struct FakeChallenge {
    request: StepUpRequest,
    proof: Option<StepUpProof>,
    verified: bool,
}

impl FakeStepUpProvider {
    /// Creates the synthetic proof for an existing fake challenge.
    pub fn issue_proof(&self, challenge_id: &str) -> Result<StepUpProof, PortError> {
        let mut challenges = self
            .challenges
            .lock()
            .map_err(|_| PortError::unavailable("fake step-up lock poisoned"))?;
        let challenge = challenges
            .get_mut(challenge_id)
            .ok_or_else(|| PortError::rejected("unknown step-up challenge"))?;
        if challenge.verified {
            return Err(PortError::rejected("step-up challenge was already used"));
        }
        let proof = TokenSecret::new(format!("fake-webauthn-proof:{challenge_id}"));
        challenge.proof = Some(proof.clone());
        Ok(proof)
    }
}

impl StepUpProvider for FakeStepUpProvider {
    fn begin(
        &self,
        request: StepUpRequest,
    ) -> impl Future<Output = Result<StepUpChallenge, PortError>> + Send {
        let result = (|| {
            request.validate(request.issued_at)?;
            let id = format!(
                "fake-step-up-{}",
                self.next_id.fetch_add(1, Ordering::Relaxed)
            );
            let challenge = StepUpChallenge {
                challenge_id: id.clone(),
                authorization_url: format!("https://step-up.invalid/challenge/{id}"),
                expires_at: request.expires_at,
            };
            self.challenges
                .lock()
                .map_err(|_| PortError::unavailable("fake step-up lock poisoned"))?
                .insert(
                    id,
                    FakeChallenge {
                        request,
                        proof: None,
                        verified: false,
                    },
                );
            Ok(challenge)
        })();
        ready(result)
    }

    fn verify(
        &self,
        challenge_id: &str,
        proof: StepUpProof,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<VerifiedStepUp, PortError>> + Send {
        let result = (|| {
            let mut challenges = self
                .challenges
                .lock()
                .map_err(|_| PortError::unavailable("fake step-up lock poisoned"))?;
            let challenge = challenges
                .get_mut(challenge_id)
                .ok_or_else(|| PortError::rejected("unknown step-up challenge"))?;
            if challenge.verified {
                return Err(PortError::rejected("step-up challenge was already used"));
            }
            challenge.request.validate(now)?;
            if challenge
                .proof
                .as_ref()
                .is_none_or(|expected| expected.expose() != proof.expose())
            {
                return Err(PortError::rejected("step-up proof was not verified"));
            }
            challenge.verified = true;
            challenge.proof = None;
            Ok(VerifiedStepUp {
                tenant_id: challenge.request.tenant_id.clone(),
                principal_key: challenge.request.principal_key.clone(),
                action_hash: challenge.request.action_hash.clone(),
                step_up_ref: format!("fake-webauthn:{challenge_id}"),
                verified_at: now,
            })
        })();
        ready(result)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use kavach_ports::{ErrorClass, StepUpProvider, StepUpRequest};

    use super::*;

    fn request(now: DateTime<Utc>) -> StepUpRequest {
        StepUpRequest {
            tenant_id: "tenant-1".into(),
            principal_key: "oidc:https://idp.example#reviewer-1".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            issued_at: now,
            expires_at: now + Duration::minutes(2),
        }
    }

    #[tokio::test]
    async fn verified_result_is_bound_to_tenant_principal_and_exact_action() {
        let now = Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap();
        let provider = FakeStepUpProvider::default();
        let request = request(now);
        let expected_hash = request.action_hash.clone();
        let challenge = provider.begin(request.clone()).await.unwrap();
        let proof = provider.issue_proof(&challenge.challenge_id).unwrap();
        let verified = provider
            .verify(&challenge.challenge_id, proof, now + Duration::seconds(1))
            .await
            .unwrap();

        assert_eq!(verified.tenant_id, request.tenant_id);
        assert_eq!(verified.principal_key, request.principal_key);
        assert_eq!(verified.action_hash, expected_hash);
        assert_eq!(verified.verified_at, now + Duration::seconds(1));
        assert!(!verified.step_up_ref.is_empty());
    }

    #[tokio::test]
    async fn invalid_expired_and_replayed_proofs_are_refused() {
        let now = Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap();
        let provider = FakeStepUpProvider::default();
        let challenge = provider.begin(request(now)).await.unwrap();

        let invalid = TokenSecret::new("not-the-fake-proof");
        assert_eq!(
            provider
                .verify(&challenge.challenge_id, invalid, now)
                .await
                .err()
                .unwrap()
                .class,
            ErrorClass::Rejected
        );
        let proof = provider.issue_proof(&challenge.challenge_id).unwrap();
        assert!(provider
            .verify(&challenge.challenge_id, proof.clone(), challenge.expires_at)
            .await
            .is_err());

        let fresh = provider.begin(request(now)).await.unwrap();
        let proof = provider.issue_proof(&fresh.challenge_id).unwrap();
        provider
            .verify(&fresh.challenge_id, proof.clone(), now)
            .await
            .unwrap();
        assert_eq!(
            provider
                .verify(&fresh.challenge_id, proof, now)
                .await
                .err()
                .unwrap()
                .class,
            ErrorClass::Rejected
        );
    }

    #[tokio::test]
    async fn malformed_action_hash_does_not_start_a_challenge() {
        let now = Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap();
        let provider = FakeStepUpProvider::default();
        let mut request = request(now);
        request.action_hash = "sha256:other".into();
        assert_eq!(
            provider.begin(request).await.unwrap_err().class,
            ErrorClass::Invalid
        );
    }
}
