//! Operator roles (ADR-019): role bindings and the principals directory.
//!
//! A binding gives one role, in one tenant, to a person (OIDC issuer and
//! subject) or to an IdP group (issuer and group name). Bindings are created
//! and ended only by an approved change request, or, for the first two
//! superadmins, by the one-time bootstrap. An ended binding keeps its row.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admin::{AuditInsert, MemoryAdminStore};

/// The seven operator roles (ADR-019 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Superadmin,
    UserAdmin,
    PolicyAdmin,
    Approver,
    Operator,
    Auditor,
    Viewer,
}

impl Role {
    pub const ALL: [Self; 7] = [
        Self::Superadmin,
        Self::UserAdmin,
        Self::PolicyAdmin,
        Self::Approver,
        Self::Operator,
        Self::Auditor,
        Self::Viewer,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Superadmin => "superadmin",
            Self::UserAdmin => "user_admin",
            Self::PolicyAdmin => "policy_admin",
            Self::Approver => "approver",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
            Self::Viewer => "viewer",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == value)
    }
}

/// Who a binding names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// An OIDC subject: one person.
    Principal,
    /// A group name from the token's groups claim; the IdP keeps membership.
    Group,
}

impl SubjectKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Group => "group",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "principal" => Some(Self::Principal),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

/// A person or IdP group, by issuer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BindingSubject {
    pub kind: SubjectKind,
    pub issuer: String,
    /// The OIDC subject, or the group name.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleBinding {
    pub id: String,
    pub tenant_id: String,
    pub role: Role,
    pub subject: BindingSubject,
    /// `None` only for a bootstrap binding.
    pub granted_by_change_request: Option<String>,
    pub granted_at: DateTime<Utc>,
    pub ended_by_change_request: Option<String>,
    pub ended_at: Option<DateTime<Utc>>,
}

impl RoleBinding {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.ended_at.is_none()
    }
}

/// A person who has signed in, as the directory keeps them: nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalRecord {
    pub tenant_id: String,
    pub issuer: String,
    pub subject: String,
    pub display_name: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// How long a `last_seen_at` stands before a later request rewrites it, so a
/// busy operator does not cause one write per request.
pub const LAST_SEEN_GRANULARITY: Duration = Duration::hours(1);

/// Display names are kept to this many characters.
pub const DISPLAY_NAME_MAX_CHARS: usize = 200;

/// What the bootstrap did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// The two bindings it wrote.
    Written(Vec<RoleBinding>),
    /// The tenant already has an active superadmin binding; nothing written.
    AlreadyPresent,
}

#[derive(Debug, thiserror::Error)]
pub enum RoleStoreError {
    #[error("role store io: {0}")]
    Io(String),
    /// A stored value the code does not know (a role or subject kind). The
    /// lookup fails closed rather than skip the row.
    #[error("role store holds an unknown {0}")]
    Corrupt(String),
    #[error("the bootstrap needs two different OIDC subjects")]
    BootstrapSubjects,
}

/// Action and resource type of a bootstrap audit row.
pub const BOOTSTRAP_AUDIT_ACTION: &str = "bootstrap_superadmin";
pub const ROLE_BINDING_RESOURCE: &str = "role_binding";
/// Actor of a bootstrap audit row: the deployment, not a signed-in person.
pub const BOOTSTRAP_ACTOR: &str = "kavach-api --bootstrap-superadmins";

pub(crate) fn bootstrap_audit(binding: &RoleBinding) -> AuditInsert {
    AuditInsert {
        action: BOOTSTRAP_AUDIT_ACTION.into(),
        resource_type: ROLE_BINDING_RESOURCE.into(),
        resource_id: binding.id.clone(),
        actor_principal: BOOTSTRAP_ACTOR.into(),
        approver_principal: String::new(),
        payload: json!({
            "tenant_id": binding.tenant_id,
            "role": binding.role.as_str(),
            "subject_kind": binding.subject.kind.as_str(),
            "issuer": binding.subject.issuer,
            "subject": binding.subject.value,
        }),
    }
}

pub(crate) fn truncate_display_name(name: &str) -> String {
    name.chars().take(DISPLAY_NAME_MAX_CHARS).collect()
}

/// Checks the bootstrap's input: exactly two different OIDC subjects.
pub(crate) fn check_bootstrap_subjects(subjects: &[BindingSubject]) -> Result<(), RoleStoreError> {
    let ok = subjects.len() == 2
        && subjects.iter().all(|s| {
            s.kind == SubjectKind::Principal && !s.issuer.is_empty() && !s.value.is_empty()
        })
        && subjects[0] != subjects[1];
    if ok {
        Ok(())
    } else {
        Err(RoleStoreError::BootstrapSubjects)
    }
}

pub(crate) fn new_binding(
    tenant_id: &str,
    role: Role,
    subject: BindingSubject,
    granted_by_change_request: Option<String>,
    now: DateTime<Utc>,
) -> RoleBinding {
    RoleBinding {
        id: format!("rb_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: tenant_id.to_string(),
        role,
        subject,
        granted_by_change_request,
        granted_at: now,
        ended_by_change_request: None,
        ended_at: None,
    }
}

/// In-memory role store, for a stack without Postgres (development, tests).
/// One mutex over everything, so the bootstrap's check-then-write is atomic.
#[derive(Default)]
pub struct MemoryRoleStore {
    inner: Mutex<MemoryRoles>,
}

#[derive(Default)]
struct MemoryRoles {
    bindings: Vec<RoleBinding>,
    principals: HashMap<(String, String, String), PrincipalRecord>,
}

fn poisoned<T>(_: T) -> RoleStoreError {
    RoleStoreError::Io("lock poisoned".into())
}

impl MemoryRoleStore {
    fn roles_for(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        groups: &[String],
    ) -> Result<BTreeSet<Role>, RoleStoreError> {
        let inner = self.inner.lock().map_err(poisoned)?;
        Ok(inner
            .bindings
            .iter()
            .filter(|b| b.is_active() && b.tenant_id == tenant_id && b.subject.issuer == issuer)
            .filter(|b| match b.subject.kind {
                SubjectKind::Principal => b.subject.value == subject,
                SubjectKind::Group => groups.contains(&b.subject.value),
            })
            .map(|b| b.role)
            .collect())
    }

    fn list_bindings(
        &self,
        tenant_id: &str,
        include_ended: bool,
    ) -> Result<Vec<RoleBinding>, RoleStoreError> {
        let inner = self.inner.lock().map_err(poisoned)?;
        let mut out: Vec<RoleBinding> = inner
            .bindings
            .iter()
            .filter(|b| b.tenant_id == tenant_id && (include_ended || b.is_active()))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.granted_at.cmp(&b.granted_at).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    fn record_principal_seen(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        display_name: &str,
        now: DateTime<Utc>,
    ) -> Result<(), RoleStoreError> {
        let display_name = truncate_display_name(display_name);
        let mut inner = self.inner.lock().map_err(poisoned)?;
        let key = (
            tenant_id.to_string(),
            issuer.to_string(),
            subject.to_string(),
        );
        match inner.principals.get_mut(&key) {
            Some(p) => {
                if now - p.last_seen_at >= LAST_SEEN_GRANULARITY || p.display_name != display_name {
                    p.last_seen_at = p.last_seen_at.max(now);
                    p.display_name = display_name;
                }
            }
            None => {
                inner.principals.insert(
                    key,
                    PrincipalRecord {
                        tenant_id: tenant_id.to_string(),
                        issuer: issuer.to_string(),
                        subject: subject.to_string(),
                        display_name,
                        first_seen_at: now,
                        last_seen_at: now,
                    },
                );
            }
        }
        Ok(())
    }

    fn list_principals(&self, tenant_id: &str) -> Result<Vec<PrincipalRecord>, RoleStoreError> {
        let inner = self.inner.lock().map_err(poisoned)?;
        let mut out: Vec<PrincipalRecord> = inner
            .principals
            .values()
            .filter(|p| p.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| (&a.issuer, &a.subject).cmp(&(&b.issuer, &b.subject)));
        Ok(out)
    }

    fn bootstrap_superadmins(
        &self,
        admin: &MemoryAdminStore,
        tenant_id: &str,
        subjects: &[BindingSubject],
        now: DateTime<Utc>,
    ) -> Result<BootstrapOutcome, RoleStoreError> {
        check_bootstrap_subjects(subjects)?;
        let mut inner = self.inner.lock().map_err(poisoned)?;
        if inner
            .bindings
            .iter()
            .any(|b| b.is_active() && b.tenant_id == tenant_id && b.role == Role::Superadmin)
        {
            return Ok(BootstrapOutcome::AlreadyPresent);
        }
        let written: Vec<RoleBinding> = subjects
            .iter()
            .map(|s| new_binding(tenant_id, Role::Superadmin, s.clone(), None, now))
            .collect();
        for binding in &written {
            admin
                .append_audit_flagged(bootstrap_audit(binding), true)
                .map_err(|e| RoleStoreError::Io(e.to_string()))?;
        }
        inner.bindings.extend(written.iter().cloned());
        Ok(BootstrapOutcome::Written(written))
    }
}

/// The role store a stack uses: memory or Postgres.
#[derive(Clone)]
pub enum RoleBackend {
    Memory {
        roles: Arc<MemoryRoleStore>,
        admin: Arc<MemoryAdminStore>,
    },
    Postgres(crate::postgres::PostgresRoleStore),
}

impl RoleBackend {
    #[must_use]
    pub fn memory(admin: Arc<MemoryAdminStore>) -> Self {
        Self::Memory {
            roles: Arc::new(MemoryRoleStore::default()),
            admin,
        }
    }

    /// The roles bound, in `tenant_id`, to the person `(issuer, subject)` or
    /// to any of `groups` under that issuer. Fails, never returns fewer
    /// roles, when a stored row cannot be read.
    pub async fn roles_for(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        groups: &[String],
    ) -> Result<BTreeSet<Role>, RoleStoreError> {
        match self {
            Self::Memory { roles, .. } => roles.roles_for(tenant_id, issuer, subject, groups),
            Self::Postgres(store) => store.roles_for(tenant_id, issuer, subject, groups).await,
        }
    }

    /// The tenant's bindings, oldest first; ended ones only when asked.
    pub async fn list_bindings(
        &self,
        tenant_id: &str,
        include_ended: bool,
    ) -> Result<Vec<RoleBinding>, RoleStoreError> {
        match self {
            Self::Memory { roles, .. } => roles.list_bindings(tenant_id, include_ended),
            Self::Postgres(store) => store.list_bindings(tenant_id, include_ended).await,
        }
    }

    /// Records that a person signed in or made a request: adds them to the
    /// directory, or moves `last_seen_at` on when it is at least
    /// [`LAST_SEEN_GRANULARITY`] old (or the display name changed).
    pub async fn record_principal_seen(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        display_name: &str,
        now: DateTime<Utc>,
    ) -> Result<(), RoleStoreError> {
        match self {
            Self::Memory { roles, .. } => {
                roles.record_principal_seen(tenant_id, issuer, subject, display_name, now)
            }
            Self::Postgres(store) => {
                store
                    .record_principal_seen(tenant_id, issuer, subject, display_name, now)
                    .await
            }
        }
    }

    /// The tenant's directory, by issuer then subject.
    pub async fn list_principals(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<PrincipalRecord>, RoleStoreError> {
        match self {
            Self::Memory { roles, .. } => roles.list_principals(tenant_id),
            Self::Postgres(store) => store.list_principals(tenant_id).await,
        }
    }

    /// ADR-019 §5: binds `superadmin` to exactly two different people, with
    /// one flagged audit row each, in one step, unless the tenant already
    /// has an active superadmin binding.
    pub async fn bootstrap_superadmins(
        &self,
        tenant_id: &str,
        subjects: &[BindingSubject],
        now: DateTime<Utc>,
    ) -> Result<BootstrapOutcome, RoleStoreError> {
        match self {
            Self::Memory { roles, admin } => {
                roles.bootstrap_superadmins(admin, tenant_id, subjects, now)
            }
            Self::Postgres(store) => store.bootstrap_superadmins(tenant_id, subjects, now).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(sub: &str) -> BindingSubject {
        BindingSubject {
            kind: SubjectKind::Principal,
            issuer: "https://idp.example".into(),
            value: sub.into(),
        }
    }

    #[test]
    fn every_role_round_trips_through_its_name() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("admins"), None, "an alias group is not a role");
        assert_eq!(Role::parse("Superadmin"), None);
    }

    #[test]
    fn the_bootstrap_takes_exactly_two_different_people() {
        assert!(check_bootstrap_subjects(&[person("a"), person("b")]).is_ok());
        assert!(check_bootstrap_subjects(&[person("a")]).is_err());
        assert!(check_bootstrap_subjects(&[person("a"), person("a")]).is_err());
        assert!(check_bootstrap_subjects(&[person("a"), person("b"), person("c")]).is_err());
        let mut group = person("b");
        group.kind = SubjectKind::Group;
        assert!(check_bootstrap_subjects(&[person("a"), group]).is_err());
        assert!(check_bootstrap_subjects(&[person("a"), person("")]).is_err());
    }

    #[tokio::test]
    async fn memory_lookup_matches_the_postgres_rules() {
        let admin = Arc::new(MemoryAdminStore::default());
        let backend = RoleBackend::memory(admin.clone());
        let RoleBackend::Memory { roles, .. } = &backend else {
            unreachable!()
        };
        let now = Utc::now();
        let group = BindingSubject {
            kind: SubjectKind::Group,
            issuer: "https://idp.example".into(),
            value: "audit-team".into(),
        };
        {
            let mut inner = roles.inner.lock().unwrap();
            inner.bindings.push(new_binding(
                "t1",
                Role::Approver,
                person("alice"),
                None,
                now,
            ));
            inner
                .bindings
                .push(new_binding("t1", Role::Auditor, group, None, now));
            inner.bindings.push(new_binding(
                "t2",
                Role::Superadmin,
                person("alice"),
                None,
                now,
            ));
            let mut ended = new_binding("t1", Role::Operator, person("alice"), None, now);
            ended.ended_at = Some(now);
            inner.bindings.push(ended);
        }
        let got = backend
            .roles_for("t1", "https://idp.example", "alice", &["audit-team".into()])
            .await
            .unwrap();
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            vec![Role::Approver, Role::Auditor]
        );
        assert!(backend
            .roles_for("t1", "https://other.example", "alice", &[])
            .await
            .unwrap()
            .is_empty());

        let first = backend
            .bootstrap_superadmins("t1", &[person("alice"), person("bob")], now)
            .await
            .unwrap();
        assert!(matches!(first, BootstrapOutcome::Written(ref w) if w.len() == 2));
        let again = backend
            .bootstrap_superadmins("t1", &[person("carol"), person("dave")], now)
            .await
            .unwrap();
        assert_eq!(again, BootstrapOutcome::AlreadyPresent);
        let audit = admin.list_audit(10).unwrap();
        assert_eq!(audit.len(), 2);
        assert!(audit.iter().all(|e| e.acting_as_superadmin));
        // t2 already has a superadmin.
        let t2 = backend
            .bootstrap_superadmins("t2", &[person("carol"), person("dave")], now)
            .await
            .unwrap();
        assert_eq!(t2, BootstrapOutcome::AlreadyPresent);
    }

    #[test]
    fn display_names_are_cut_to_200_characters() {
        let long = "न".repeat(250);
        assert_eq!(truncate_display_name(&long).chars().count(), 200);
    }
}
