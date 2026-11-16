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
/// The bundled operator API policies (`kavach dev up` runs with them).
pub const API_POLICIES: &str = include_str!("../policies/kavach.cedar");

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
    /// Read one agent decision record (`kavach why`); audited.
    ReadEvidence,
    /// Move a development clock forward (`kavach dev clock`; dev stacks only).
    SetDevClock,
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
    ProposeActivateModel,
    ApproveActivateModel,
    /// Restrict, quarantine or revoke an agent (ADR-013 §3). Only tightens;
    /// one principal. A separate action, so who may stop an agent is a
    /// policy change (an incident-responder role), not a code change.
    StopAgent,
    ReconcileClosedRecords,
    /// Read an agent's state.
    ReadAgentState,
    /// Propose bringing a stopped agent back (ADR-013 §3): needs a second
    /// principal's approval.
    ProposeReinstateAgent,
    ApproveReinstateAgent,
    /// The principals directory and the role bindings (ADR-019 §8).
    ReadPrincipals,
    /// The access review export (ADR-019 §9).
    ReadAccessReview,
    /// The four role-change actions carry the role being changed in the
    /// Cedar context ([`OperatorRequest::role_change`]).
    ProposeGrantRole,
    ApproveGrantRole,
    ProposeRevokeRole,
    ApproveRevokeRole,
    /// Record an operator's one-person delivered attestation (ADR-017).
    AttestOutcomeDelivered,
}

impl KavachAction {
    /// Every action, in declaration order.
    pub const ALL: [Self; 38] = [
        Self::Evaluate,
        Self::ReadHealth,
        Self::ReadMetrics,
        Self::ReadGovernance,
        Self::ReadAudit,
        Self::ReadEvidence,
        Self::SetDevClock,
        Self::ReadRetention,
        Self::ReadTombstones,
        Self::ReadIncidents,
        Self::ReadBatchJobs,
        Self::ProposeActivatePack,
        Self::ApproveActivatePack,
        Self::ProposeRollbackPack,
        Self::ApproveRollbackPack,
        Self::ProposeUpdateModel,
        Self::ApproveUpdateModel,
        Self::ProposeUpdateRetention,
        Self::ApproveUpdateRetention,
        Self::ProposeEraseEvidence,
        Self::ApproveEraseEvidence,
        Self::ProposeApplyRetention,
        Self::ApproveApplyRetention,
        Self::ReadChangeRequests,
        Self::ProposeActivateModel,
        Self::ApproveActivateModel,
        Self::StopAgent,
        Self::ReconcileClosedRecords,
        Self::ReadAgentState,
        Self::ProposeReinstateAgent,
        Self::ApproveReinstateAgent,
        Self::ReadPrincipals,
        Self::ReadAccessReview,
        Self::ProposeGrantRole,
        Self::ApproveGrantRole,
        Self::ProposeRevokeRole,
        Self::ApproveRevokeRole,
        Self::AttestOutcomeDelivered,
    ];

    /// Whether the action changes a role binding, and so needs the role
    /// being changed in its Cedar context.
    #[must_use]
    pub fn changes_a_role(self) -> bool {
        matches!(
            self,
            Self::ProposeGrantRole
                | Self::ApproveGrantRole
                | Self::ProposeRevokeRole
                | Self::ApproveRevokeRole
        )
    }

    /// The action's name in the Cedar schema and policies.
    #[must_use]
    pub fn cedar_name(self) -> &'static str {
        match self {
            Self::Evaluate => "evaluate",
            Self::ReadHealth => "read_health",
            Self::ReadMetrics => "read_metrics",
            Self::ReadGovernance => "read_governance",
            Self::ReadAudit => "read_audit",
            Self::ReadEvidence => "read_evidence",
            Self::SetDevClock => "set_dev_clock",
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
            Self::ProposeActivateModel => "propose_activate_model",
            Self::ApproveActivateModel => "approve_activate_model",
            Self::StopAgent => "stop_agent",
            Self::ReconcileClosedRecords => "reconcile_closed_records",
            Self::ReadAgentState => "read_agent_state",
            Self::ProposeReinstateAgent => "propose_reinstate_agent",
            Self::ApproveReinstateAgent => "approve_reinstate_agent",
            Self::ReadPrincipals => "read_principals",
            Self::ReadAccessReview => "read_access_review",
            Self::ProposeGrantRole => "propose_grant_role",
            Self::ApproveGrantRole => "approve_grant_role",
            Self::ProposeRevokeRole => "propose_revoke_role",
            Self::ApproveRevokeRole => "approve_revoke_role",
            Self::AttestOutcomeDelivered => "attest_outcome_delivered",
        }
    }
}

/// The operator role names Cedar knows (ADR-019 §1), as `Kavach::Role` ids.
pub const OPERATOR_ROLES: [&str; 7] = [
    "superadmin",
    "user_admin",
    "policy_admin",
    "approver",
    "operator",
    "auditor",
    "viewer",
];

/// Policies whose `@id` starts with this are superadmin's. A decision
/// allowed by these alone is flagged in the audit (ADR-019 §7).
pub const SUPERADMIN_POLICY_PREFIX: &str = "superadmin-";

/// One operator request, as Cedar is asked it.
#[derive(Debug, Clone, Copy)]
pub struct OperatorRequest<'a> {
    pub principal_id: &'a str,
    /// The credential's groups (`Kavach::Group` parents).
    pub groups: &'a [String],
    /// The roles bound to the principal or its groups (`Kavach::Role`
    /// parents); each must be one of [`OPERATOR_ROLES`].
    pub roles: &'a [&'a str],
    pub action: KavachAction,
    /// The role a grant or revoke changes: required for the four
    /// role-change actions, refused for every other action.
    pub role_change: Option<&'a str>,
}

/// What Cedar decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorDecision {
    pub allowed: bool,
    /// Allowed, and only by superadmin policies: the audit row for the
    /// action is flagged `acting_as_superadmin`.
    pub superadmin_only: bool,
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
        self.decide(&OperatorRequest {
            principal_id,
            groups,
            roles: &[],
            action,
            role_change: None,
        })
        .map(|decision| decision.allowed)
    }

    /// Decides an operator request: the credential's groups and the bound
    /// roles become the principal's parents, merged with its memberships in
    /// the static entities file. A role-change action without the role it
    /// changes, any other action with one, or an unknown role is an error,
    /// never a decision.
    pub fn decide(&self, request: &OperatorRequest<'_>) -> Result<OperatorDecision, AuthError> {
        let principal = user_uid(request.principal_id)?;
        let action_uid = action_uid(request.action)?;
        let role_parents = request
            .roles
            .iter()
            .map(|role| role_uid(role))
            .collect::<Result<Vec<_>, _>>()?;
        let entities = if request.groups.is_empty() && role_parents.is_empty() {
            self.entities.clone()
        } else {
            self.entities_with_parents(&principal, request.groups, role_parents)?
        };
        let context = match (request.action.changes_a_role(), request.role_change) {
            (true, Some(role)) => {
                role_uid(role)?;
                cedar_policy::Context::from_pairs([(
                    "role".to_string(),
                    cedar_policy::RestrictedExpression::new_string(role.to_string()),
                )])
                .map_err(|err| AuthError::Request(err.to_string()))?
            }
            (false, None) => cedar_policy::Context::empty(),
            (true, None) => {
                return Err(AuthError::Request(format!(
                    "{} needs the role it changes",
                    request.action.cedar_name()
                )))
            }
            (false, Some(_)) => {
                return Err(AuthError::Request(format!(
                    "{} takes no role",
                    request.action.cedar_name()
                )))
            }
        };

        let cedar_request = Request::new(
            principal,
            action_uid,
            self.resource.clone(),
            context,
            Some(&self.schema),
        )
        .map_err(|err| AuthError::Request(err.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&cedar_request, &self.policies, &entities);
        let allowed = response.decision() == Decision::Allow;
        let mut reasons = response.diagnostics().reason().peekable();
        let superadmin_only = allowed
            && reasons.peek().is_some()
            && reasons.all(|id| {
                self.policies
                    .policy(id)
                    .and_then(|policy| policy.annotation("id"))
                    .is_some_and(|name| name.starts_with(SUPERADMIN_POLICY_PREFIX))
            });
        Ok(OperatorDecision {
            allowed,
            superadmin_only,
        })
    }

    /// The groups [`Self::authorize_with_groups`] evaluates `principal_id`
    /// in: the credential's `groups` and the principal's memberships in the
    /// static entities file, read back from the entity set Cedar is given.
    /// Sorted, without repeats. For display only (the console's role
    /// hints); it decides nothing.
    pub fn effective_groups(
        &self,
        principal_id: &str,
        groups: &[String],
    ) -> Result<Vec<String>, AuthError> {
        let principal = user_uid(principal_id)?;
        let entities = self.entities_with_parents(&principal, groups, Vec::new())?;
        let group_type = EntityTypeName::from_str("Kavach::Group")
            .map_err(|err| AuthError::InvalidPrincipal(err.to_string()))?;
        let mut found: Vec<String> = entities
            .ancestors(&principal)
            .into_iter()
            .flatten()
            .filter(|uid| uid.type_name() == &group_type)
            .map(|uid| uid.id().unescaped().to_string())
            .collect();
        found.sort();
        found.dedup();
        Ok(found)
    }

    /// Static entities plus `principal` with parents = static memberships ∪
    /// `groups` ∪ `roles`, validated against the schema.
    fn entities_with_parents(
        &self,
        principal: &EntityUid,
        groups: &[String],
        roles: Vec<EntityUid>,
    ) -> Result<Entities, AuthError> {
        let mut parents: HashSet<EntityUid> = groups
            .iter()
            .map(|g| group_uid(g))
            .collect::<Result<_, _>>()?;
        parents.extend(roles);
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

/// Role ids come from Kavach's own bindings or a change request; only the
/// seven known names become `Kavach::Role` entities.
fn role_uid(role: &str) -> Result<EntityUid, AuthError> {
    if !OPERATOR_ROLES.contains(&role) {
        return Err(AuthError::InvalidPrincipal(format!(
            "unknown operator role: {role:?}"
        )));
    }
    let type_name = EntityTypeName::from_str("Kavach::Role")
        .map_err(|err| AuthError::InvalidPrincipal(err.to_string()))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(role),
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

    #[test]
    fn effective_groups_are_the_credential_groups_and_the_static_memberships() {
        let auth = fixture_authorizer();
        // A static member of `viewers`, asserted into `operators` by its token:
        // Cedar sees both, and so does the caller.
        assert_eq!(
            auth.effective_groups("viewer-1", &["operators".into()])
                .unwrap(),
            ["operators", "viewers"]
        );
        assert!(auth
            .authorize_with_groups("viewer-1", &["operators".into()], KavachAction::Evaluate)
            .unwrap());
        // No credential groups: the static memberships alone.
        assert_eq!(auth.effective_groups("viewer-1", &[]).unwrap(), ["viewers"]);
        // Unknown to the entities file: the credential's groups, sorted, once.
        assert_eq!(
            auth.effective_groups(
                "sso-user-42",
                &["viewers".into(), "admins".into(), "viewers".into()]
            )
            .unwrap(),
            ["admins", "viewers"]
        );
        assert!(auth
            .effective_groups("sso-user-42", &[])
            .unwrap()
            .is_empty());
        // The same refusals as authorization.
        assert!(auth
            .effective_groups("x", &["bad\u{7}group".into()])
            .is_err());
        assert!(auth.effective_groups("", &[]).is_err());
    }

    /// What one cell of the ADR-019 §2 matrix says.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Cell {
        Allowed,
        AllowedExceptSuperadmin,
        Denied,
    }

    const GOVERNANCE_KINDS: [&str; 8] = [
        "activate_pack",
        "rollback_pack",
        "update_model",
        "activate_model",
        "update_retention",
        "erase_evidence",
        "apply_retention",
        "reinstate_agent",
    ];

    /// The §2 table of ADR-019, read from the ADR: (role, action) → cell.
    /// The test below checks the shipped policy against it, so the
    /// documented matrix and the policy cannot drift apart.
    fn adr_matrix() -> std::collections::HashMap<(String, String), Cell> {
        let adr = include_str!("../../../docs/ADR-019-operator-roles.md");
        let section = adr
            .split("### 2. Role-to-action matrix")
            .nth(1)
            .and_then(|rest| rest.split("### 3.").next())
            .expect("ADR-019 has the §2 matrix");
        let mut lines = section.lines().filter(|line| line.starts_with('|'));
        let header: Vec<String> = lines
            .next()
            .expect("matrix header")
            .split('|')
            .map(|cell| cell.trim().to_string())
            .collect();
        let roles = &header[2..header.len() - 1];
        assert_eq!(roles, OPERATOR_ROLES, "the matrix columns are the 7 roles");
        let mut matrix = std::collections::HashMap::new();
        for line in lines.filter(|line| line.starts_with("| `")) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let named: Vec<&str> = cells[1].split('`').skip(1).step_by(2).collect();
            let actions: Vec<String> = named
                .iter()
                .flat_map(|name| match *name {
                    "propose_*" | "approve_*" => GOVERNANCE_KINDS
                        .iter()
                        .map(|kind| format!("{}{kind}", &name[..name.len() - 1]))
                        .collect(),
                    other => vec![other.to_string()],
                })
                .collect();
            for (role, cell) in roles.iter().zip(&cells[2..cells.len() - 1]) {
                let cell = match *cell {
                    "✓" => Cell::Allowed,
                    "✓ (not `superadmin`)" => Cell::AllowedExceptSuperadmin,
                    "" => Cell::Denied,
                    other => panic!("unreadable matrix cell {other:?}"),
                };
                for action in &actions {
                    let previous = matrix.insert((role.clone(), action.clone()), cell);
                    assert!(previous.is_none(), "{action} is listed twice");
                }
            }
        }
        matrix
    }

    fn shipped_authorizer() -> KavachAuthorizer {
        KavachAuthorizer::from_str(API_POLICIES, "[]").expect("shipped policies")
    }

    fn decide_as(
        auth: &KavachAuthorizer,
        roles: &[&str],
        groups: &[String],
        action: KavachAction,
        role_change: Option<&str>,
    ) -> OperatorDecision {
        auth.decide(&OperatorRequest {
            principal_id: "role-holder",
            groups,
            roles,
            action,
            role_change,
        })
        .expect("decision")
    }

    #[test]
    fn every_role_is_allowed_exactly_its_column_of_the_adr_matrix() {
        let auth = shipped_authorizer();
        let matrix = adr_matrix();
        for action in KavachAction::ALL {
            for role in OPERATOR_ROLES {
                let cell = matrix
                    .get(&(role.to_string(), action.cedar_name().to_string()))
                    .copied()
                    .unwrap_or_else(|| panic!("{} is not in the matrix", action.cedar_name()));
                let changes: &[Option<&str>] = if action.changes_a_role() {
                    &[Some("viewer"), Some("superadmin")]
                } else {
                    &[None]
                };
                for &role_change in changes {
                    let expected = match cell {
                        Cell::Allowed => true,
                        Cell::AllowedExceptSuperadmin => role_change != Some("superadmin"),
                        Cell::Denied => false,
                    };
                    let decision = decide_as(&auth, &[role], &[], action, role_change);
                    assert_eq!(
                        decision.allowed,
                        expected,
                        "{role} / {} / {role_change:?}",
                        action.cedar_name()
                    );
                    assert_eq!(
                        decision.superadmin_only,
                        expected && role == "superadmin",
                        "flag for {role} / {}",
                        action.cedar_name()
                    );
                }
            }
        }
        assert_eq!(
            matrix.len(),
            KavachAction::ALL.len() * OPERATOR_ROLES.len(),
            "the matrix names an action the code does not have"
        );
    }

    #[test]
    fn a_group_named_like_a_role_gets_nothing_from_the_role() {
        let auth = shipped_authorizer();
        for role in OPERATOR_ROLES {
            for action in KavachAction::ALL {
                let role_change = action.changes_a_role().then_some("viewer");
                let decision = decide_as(&auth, &[], &[role.to_string()], action, role_change);
                assert!(!decision.allowed, "group {role} / {}", action.cedar_name());
            }
        }
    }

    #[test]
    fn the_alias_groups_keep_their_permissions_and_get_no_role_action() {
        let auth = shipped_authorizer();
        let admins = ["admins".to_string()];
        assert!(decide_as(&auth, &[], &admins, KavachAction::ProposeActivatePack, None).allowed);
        assert!(!decide_as(&auth, &[], &admins, KavachAction::ReadPrincipals, None).allowed);
        for alias in ["admins", "change-approvers", "operators", "viewers"] {
            for action in KavachAction::ALL.into_iter().filter(|a| a.changes_a_role()) {
                let groups = [alias.to_string()];
                assert!(
                    !decide_as(&auth, &[], &groups, action, Some("viewer")).allowed,
                    "{alias} / {}",
                    action.cedar_name()
                );
            }
        }
    }

    #[test]
    fn a_decision_another_role_also_allows_is_not_flagged_superadmin() {
        let auth = shipped_authorizer();
        let both = decide_as(
            &auth,
            &["superadmin", "policy_admin"],
            &[],
            KavachAction::ProposeActivatePack,
            None,
        );
        assert_eq!(
            both,
            OperatorDecision {
                allowed: true,
                superadmin_only: false
            }
        );
        let approving = decide_as(
            &auth,
            &["superadmin", "policy_admin"],
            &[],
            KavachAction::ApproveActivatePack,
            None,
        );
        assert!(approving.allowed && approving.superadmin_only);
        let denied = decide_as(&auth, &[], &[], KavachAction::ReadHealth, None);
        assert!(!denied.allowed && !denied.superadmin_only);
    }

    #[test]
    fn a_role_change_needs_its_role_and_other_actions_take_none() {
        let auth = shipped_authorizer();
        let request = |action, roles: &'static [&'static str], role_change| OperatorRequest {
            principal_id: "role-holder",
            groups: &[],
            roles,
            action,
            role_change,
        };
        assert!(auth
            .decide(&request(
                KavachAction::ProposeGrantRole,
                &["user_admin"],
                None
            ))
            .is_err());
        assert!(auth
            .decide(&request(
                KavachAction::ReadHealth,
                &["viewer"],
                Some("viewer")
            ))
            .is_err());
        assert!(auth
            .decide(&request(
                KavachAction::ProposeGrantRole,
                &["user_admin"],
                Some("root")
            ))
            .is_err());
        assert!(auth
            .decide(&request(KavachAction::ReadHealth, &["root"], None))
            .is_err());
    }
}
