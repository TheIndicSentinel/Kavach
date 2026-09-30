//! Cedar RBAC for Kavach API actions (Milestone B.1).

mod error;

use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, Schema, ValidationMode, Validator,
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
    ReadAudit,
    ReadRetention,
    ReadTombstones,
    ReadIncidents,
    ReadBatchJobs,
    ProposeActivatePack,
    ApproveActivatePack,
    ProposeRollbackPack,
    ApproveRollbackPack,
    ProposeUpdateModel,
    ApproveUpdateModel,
    ProposeUpdateRetention,
    ApproveUpdateRetention,
    ProposeEraseEvidence,
    ApproveEraseEvidence,
    ProposeApplyRetention,
    ApproveApplyRetention,
    ReadChangeRequests,
}

impl KavachAction {
    fn cedar_name(self) -> &'static str {
        match self {
            Self::Evaluate => "evaluate",
            Self::ReadHealth => "read_health",
            Self::ReadMetrics => "read_metrics",
            Self::ReadGovernance => "read_governance",
            Self::ReadAudit => "read_audit",
            Self::ReadRetention => "read_retention",
            Self::ReadTombstones => "read_tombstones",
            Self::ReadIncidents => "read_incidents",
            Self::ReadBatchJobs => "read_batch_jobs",
            Self::ProposeActivatePack => "propose_activate_pack",
            Self::ApproveActivatePack => "approve_activate_pack",
            Self::ProposeRollbackPack => "propose_rollback_pack",
            Self::ApproveRollbackPack => "approve_rollback_pack",
            Self::ProposeUpdateModel => "propose_update_model",
            Self::ApproveUpdateModel => "approve_update_model",
            Self::ProposeUpdateRetention => "propose_update_retention",
            Self::ApproveUpdateRetention => "approve_update_retention",
            Self::ProposeEraseEvidence => "propose_erase_evidence",
            Self::ApproveEraseEvidence => "approve_erase_evidence",
            Self::ProposeApplyRetention => "propose_apply_retention",
            Self::ApproveApplyRetention => "approve_apply_retention",
            Self::ReadChangeRequests => "read_change_requests",
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

    /// Authorizes a principal known from the static entities file.
    pub fn authorize(&self, principal_id: &str, action: KavachAction) -> Result<bool, AuthError> {
        self.authorize_with_groups(principal_id, &[], action)
    }

    /// Authorizes an authenticated principal whose group memberships come from
    /// its credential (e.g. an OIDC `groups` claim). Groups are merged with any
    /// memberships in the static entities file; group names are used as
    /// literal entity ids.
    pub fn authorize_with_groups(
        &self,
        principal_id: &str,
        groups: &[String],
        action: KavachAction,
    ) -> Result<bool, AuthError> {
        let principal = user_uid(principal_id)?;
        let action_uid = action_uid(action)?;
        let entities = if groups.is_empty() {
            self.entities.clone()
        } else {
            self.entities_with_principal(&principal, groups)?
        };

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
            .is_authorized(&request, &self.policies, &entities);

        Ok(response.decision() == Decision::Allow)
    }

    /// Static entities plus `principal` with parents = static memberships ∪
    /// `groups`, validated against the schema.
    fn entities_with_principal(
        &self,
        principal: &EntityUid,
        groups: &[String],
    ) -> Result<Entities, AuthError> {
        let mut parents: HashSet<EntityUid> = groups
            .iter()
            .map(|g| group_uid(g))
            .collect::<Result<_, _>>()?;
        let mut others = Vec::new();
        for entity in self.entities.iter() {
            if entity.uid() == *principal {
                parents.extend(entity.clone().into_inner().2);
            } else {
                others.push(entity.clone());
            }
        }
        others.push(Entity::new_no_attrs(principal.clone(), parents));
        Entities::from_entities(others, Some(&self.schema))
            .map_err(|err| AuthError::ParseEntities(err.to_string()))
    }
}

/// Group ids come from credentials; they are used literally and bounded.
fn group_uid(group: &str) -> Result<EntityUid, AuthError> {
    if group.is_empty() || group.len() > 256 || group.chars().any(char::is_control) {
        return Err(AuthError::InvalidPrincipal(format!(
            "invalid group name: {group:?}"
        )));
    }
    let type_name = EntityTypeName::from_str("Kavach::Group")
        .map_err(|err| AuthError::InvalidPrincipal(err.to_string()))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(group),
    ))
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
    fn groups_from_credentials_grant_group_permissions() {
        let auth = fixture_authorizer();
        // Unknown user with no groups: denied.
        assert!(!auth
            .authorize("sso-user-42", KavachAction::Evaluate)
            .unwrap());
        // Same user asserted into the operators group by its credential.
        assert!(auth
            .authorize_with_groups("sso-user-42", &["operators".into()], KavachAction::Evaluate)
            .unwrap());
        // A group that grants nothing still denies.
        assert!(!auth
            .authorize_with_groups("sso-user-42", &["nobody".into()], KavachAction::Evaluate)
            .unwrap());
        // Static memberships are kept when credential groups are added.
        assert!(auth
            .authorize_with_groups("viewer-1", &["unrelated".into()], KavachAction::ReadHealth)
            .unwrap());
        // Control characters in a group name are rejected.
        assert!(auth
            .authorize_with_groups("x", &["bad\u{7}group".into()], KavachAction::ReadHealth)
            .is_err());
        assert!(auth
            .authorize_with_groups("x", &[String::new()], KavachAction::ReadHealth)
            .is_err());
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
