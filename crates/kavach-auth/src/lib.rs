//! Cedar RBAC for Kavach API actions (Milestone B.1).

mod error;

use std::path::Path;
use std::str::FromStr;

use cedar_policy::{Authorizer, Decision, Entities, EntityUid, PolicySet, Request};
pub use error::AuthError;

const SYSTEM_RESOURCE: &str = r#"Kavach::System::"api""#;

/// API actions guarded by Cedar policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KavachAction {
    Evaluate,
    ReadHealth,
    ReadMetrics,
}

impl KavachAction {
    fn cedar_name(self) -> &'static str {
        match self {
            Self::Evaluate => "evaluate",
            Self::ReadHealth => "read_health",
            Self::ReadMetrics => "read_metrics",
        }
    }
}

/// Cedar policy evaluator loaded from policy + entity files.
pub struct KavachAuthorizer {
    authorizer: Authorizer,
    policies: PolicySet,
    entities: Entities,
    resource: EntityUid,
}

impl KavachAuthorizer {
    pub fn from_files(policy_path: &Path, entities_path: &Path) -> Result<Self, AuthError> {
        let policy_text =
            std::fs::read_to_string(policy_path).map_err(|source| AuthError::ReadPolicy {
                path: policy_path.display().to_string(),
                source,
            })?;
        let entities_json =
            std::fs::read_to_string(entities_path).map_err(|source| AuthError::ReadEntities {
                path: entities_path.display().to_string(),
                source,
            })?;

        Self::from_str(&policy_text, &entities_json)
    }

    pub fn from_str(policy_text: &str, entities_json: &str) -> Result<Self, AuthError> {
        let policies = PolicySet::from_str(policy_text)
            .map_err(|err| AuthError::ParsePolicy(err.to_string()))?;
        let entities = Entities::from_json_str(entities_json, None)
            .map_err(|err| AuthError::ParseEntities(err.to_string()))?;
        let resource = EntityUid::from_str(SYSTEM_RESOURCE)
            .map_err(|err| AuthError::Request(err.to_string()))?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
            entities,
            resource,
        })
    }

    pub fn authorize(&self, principal_id: &str, action: KavachAction) -> Result<bool, AuthError> {
        let principal = user_uid(principal_id)?;
        let action_uid = action_uid(action)?;

        let request = Request::new(
            principal,
            action_uid,
            self.resource.clone(),
            cedar_policy::Context::empty(),
            None,
        )
        .map_err(|err| AuthError::Request(err.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &self.entities);

        Ok(response.decision() == Decision::Allow)
    }
}

fn user_uid(principal_id: &str) -> Result<EntityUid, AuthError> {
    EntityUid::from_str(&format!(r#"Kavach::User::"{principal_id}""#))
        .map_err(|err| AuthError::InvalidPrincipal(err.to_string()))
}

fn action_uid(action: KavachAction) -> Result<EntityUid, AuthError> {
    EntityUid::from_str(&format!(
        r#"Kavach::Action::"{name}""#,
        name = action.cedar_name()
    ))
    .map_err(|err| AuthError::Request(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_authorizer() -> KavachAuthorizer {
        let policy = include_str!("../policies/kavach.cedar");
        let entities = include_str!("../policies/entities.example.json");
        KavachAuthorizer::from_str(policy, entities).expect("fixture authorizer")
    }

    #[test]
    fn operator_may_evaluate() {
        let auth = fixture_authorizer();
        assert!(auth
            .authorize("operator-1", KavachAction::Evaluate)
            .unwrap());
    }

    #[test]
    fn viewer_may_read_health_but_not_evaluate() {
        let auth = fixture_authorizer();
        assert!(auth
            .authorize("viewer-1", KavachAction::ReadHealth)
            .unwrap());
        assert!(!auth.authorize("viewer-1", KavachAction::Evaluate).unwrap());
    }

    #[test]
    fn admin_may_evaluate_and_read_metrics() {
        let auth = fixture_authorizer();
        assert!(auth.authorize("admin-1", KavachAction::Evaluate).unwrap());
        assert!(auth
            .authorize("admin-1", KavachAction::ReadMetrics)
            .unwrap());
    }

    #[test]
    fn unknown_principal_is_denied() {
        let auth = fixture_authorizer();
        assert!(!auth.authorize("unknown", KavachAction::ReadHealth).unwrap());
    }
}
