//! Cedar RBAC for Kavach API actions (Milestone B.1).

mod error;

use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    Schema, ValidationMode, Validator,
};
pub use error::AuthError;

const SYSTEM_RESOURCE: &str = r#"Kavach::System::"api""#;

/// Cedar schema for API RBAC. It is part of the API contract, so it is
/// compiled in; deployments supply policies and entities.
pub const API_SCHEMA: &str = include_str!("../policies/schema.cedarschema");

fn api_schema() -> Result<Schema, AuthError> {
    Schema::from_cedarschema_str(API_SCHEMA)
        .map(|(schema, _warnings)| schema)
        .map_err(|err| AuthError::Schema(err.to_string()))
}

/// API actions guarded by Cedar policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KavachAction {
    Evaluate,
    ReadHealth,
    ReadMetrics,
    ReadGovernance,
    ActivatePack,
    RollbackPack,
    UpdateModel,
    ReadAudit,
    ReadRetention,
    UpdateRetention,
    ReadTombstones,
    EraseEvidence,
    ApplyRetention,
    ReadIncidents,
    ReadBatchJobs,
}

impl KavachAction {
    fn cedar_name(self) -> &'static str {
        match self {
            Self::Evaluate => "evaluate",
            Self::ReadHealth => "read_health",
            Self::ReadMetrics => "read_metrics",
            Self::ReadGovernance => "read_governance",
            Self::ActivatePack => "activate_pack",
            Self::RollbackPack => "rollback_pack",
            Self::UpdateModel => "update_model",
            Self::ReadAudit => "read_audit",
            Self::ReadRetention => "read_retention",
            Self::UpdateRetention => "update_retention",
            Self::ReadTombstones => "read_tombstones",
            Self::EraseEvidence => "erase_evidence",
            Self::ApplyRetention => "apply_retention",
            Self::ReadIncidents => "read_incidents",
            Self::ReadBatchJobs => "read_batch_jobs",
        }
    }
}

/// Cedar policy evaluator loaded from policy + entity files.
pub struct KavachAuthorizer {
    authorizer: Authorizer,
    policies: PolicySet,
    entities: Entities,
    resource: EntityUid,
    schema: Schema,
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
        let schema = api_schema()?;
        let policies = PolicySet::from_str(policy_text)
            .map_err(|err| AuthError::ParsePolicy(err.to_string()))?;
        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            let errors: Vec<String> = validation
                .validation_errors()
                .map(ToString::to_string)
                .collect();
            return Err(AuthError::InvalidPolicy(errors.join("; ")));
        }
        let entities = Entities::from_json_str(entities_json, Some(&schema))
            .map_err(|err| AuthError::ParseEntities(err.to_string()))?;
        let resource = EntityUid::from_str(SYSTEM_RESOURCE)
            .map_err(|err| AuthError::Request(err.to_string()))?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
            entities,
            resource,
            schema,
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
            Some(&self.schema),
        )
        .map_err(|err| AuthError::Request(err.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &self.entities);

        Ok(response.decision() == Decision::Allow)
    }
}

/// Builds the principal uid from the raw header value. `EntityId::new` treats
/// the value literally, so quotes or Cedar syntax in a header cannot change
/// the entity being authorized.
fn user_uid(principal_id: &str) -> Result<EntityUid, AuthError> {
    if principal_id.is_empty() || principal_id.len() > 256 {
        return Err(AuthError::InvalidPrincipal(
            "principal must be 1-256 characters".into(),
        ));
    }
    let type_name = EntityTypeName::from_str("Kavach::User")
        .map_err(|err| AuthError::InvalidPrincipal(err.to_string()))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(principal_id),
    ))
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
    fn viewer_may_read_governance() {
        let auth = fixture_authorizer();
        assert!(auth
            .authorize("viewer-1", KavachAction::ReadGovernance)
            .unwrap());
    }

    #[test]
    fn unknown_principal_is_denied() {
        let auth = fixture_authorizer();
        assert!(!auth.authorize("unknown", KavachAction::ReadHealth).unwrap());
    }

    #[test]
    fn policy_with_unknown_action_fails_schema_validation() {
        let policy = r#"permit (principal, action == Kavach::Action::"evaluat", resource);"#;
        let entities = include_str!("../policies/entities.example.json");
        let err = KavachAuthorizer::from_str(policy, entities)
            .err()
            .expect("typo in action must be rejected");
        assert!(matches!(err, AuthError::InvalidPolicy(_)), "{err}");
    }

    #[test]
    fn entities_with_unknown_type_fail_schema_validation() {
        let policy = include_str!("../policies/kavach.cedar");
        let entities = r#"[{"uid":{"type":"Kavach::Robot","id":"r1"},"attrs":{},"parents":[]}]"#;
        let err = KavachAuthorizer::from_str(policy, entities)
            .err()
            .expect("unknown entity type must be rejected");
        assert!(matches!(err, AuthError::ParseEntities(_)), "{err}");
    }

    #[test]
    fn principal_header_is_treated_literally() {
        let auth = fixture_authorizer();
        // A value crafted to look like Cedar syntax is just an unknown user.
        let crafted = r#"admin-1" in Kavach::Group::"admins"#;
        assert!(!auth.authorize(crafted, KavachAction::Evaluate).unwrap());
        assert!(auth.authorize("", KavachAction::Evaluate).is_err());
    }
}
