//! Postgres role store (ADR-019): `role_bindings` and `principals`.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};

use crate::roles::{
    binding_not_active_reason, bootstrap_audit, check_bootstrap_subjects, duplicate_binding_reason,
    last_admin_reason, new_binding, truncate_display_name, BindingSubject, BootstrapOutcome,
    PrincipalRecord, Role, RoleBinding, RoleStoreError, SubjectKind, LAST_SEEN_GRANULARITY,
};

#[derive(Clone)]
pub struct PostgresRoleStore {
    pool: PgPool,
}

fn io(err: &sqlx::Error) -> RoleStoreError {
    RoleStoreError::Io(err.to_string())
}

fn parse_role(value: &str) -> Result<Role, RoleStoreError> {
    Role::parse(value).ok_or_else(|| RoleStoreError::Corrupt(format!("role {value:?}")))
}

#[derive(sqlx::FromRow)]
struct BindingRow {
    id: String,
    tenant_id: String,
    role: String,
    subject_kind: String,
    issuer: String,
    subject: String,
    granted_by_change_request: Option<String>,
    granted_at: DateTime<Utc>,
    ended_by_change_request: Option<String>,
    ended_at: Option<DateTime<Utc>>,
}

impl BindingRow {
    fn into_binding(self) -> Result<RoleBinding, RoleStoreError> {
        let kind = SubjectKind::parse(&self.subject_kind).ok_or_else(|| {
            RoleStoreError::Corrupt(format!("subject kind {:?}", self.subject_kind))
        })?;
        Ok(RoleBinding {
            id: self.id,
            tenant_id: self.tenant_id,
            role: parse_role(&self.role)?,
            subject: BindingSubject {
                kind,
                issuer: self.issuer,
                value: self.subject,
            },
            granted_by_change_request: self.granted_by_change_request,
            granted_at: self.granted_at,
            ended_by_change_request: self.ended_by_change_request,
            ended_at: self.ended_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PrincipalRow {
    tenant_id: String,
    issuer: String,
    subject: String,
    display_name: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

const BINDING_COLUMNS: &str = "id, tenant_id, role, subject_kind, issuer, subject, \
    granted_by_change_request, granted_at, ended_by_change_request, ended_at";

impl PostgresRoleStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Serialises writes to one tenant's bindings (the bootstrap here, grant
    /// and revoke in the change-request transaction).
    pub(crate) async fn lock_tenant(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('kavach-role-bindings:' || $1, 0))",
        )
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }

    /// The approval's check of a grant: takes the tenant lock, then looks
    /// for the same active binding.
    pub(crate) async fn check_grant(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        role: Role,
        subject: &BindingSubject,
    ) -> Result<Option<String>, sqlx::Error> {
        Self::lock_tenant(tx, tenant_id).await?;
        let duplicate: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM role_bindings \
             WHERE tenant_id = $1 AND role = $2 AND subject_kind = $3 AND issuer = $4 \
               AND subject = $5 AND ended_at IS NULL)",
        )
        .bind(tenant_id)
        .bind(role.as_str())
        .bind(subject.kind.as_str())
        .bind(&subject.issuer)
        .bind(&subject.value)
        .fetch_one(&mut **tx)
        .await?;
        Ok(duplicate.then(|| duplicate_binding_reason(role)))
    }

    /// The approval's check of a revoke: takes the tenant lock, so two
    /// concurrent revokes of a role's last two person bindings are decided
    /// one after the other and the second sees the first.
    pub(crate) async fn check_end(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        binding_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        Self::lock_tenant(tx, tenant_id).await?;
        let target: Option<(String, String)> = sqlx::query_as(
            "SELECT role, subject_kind FROM role_bindings \
             WHERE id = $1 AND tenant_id = $2 AND ended_at IS NULL",
        )
        .bind(binding_id)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((role, kind)) = target else {
            return Ok(Some(binding_not_active_reason(binding_id)));
        };
        // A role the code does not know cannot be guarded; it is refused
        // anyway rather than ended blind.
        let Some(role) = Role::parse(&role) else {
            return Ok(Some(format!(
                "role binding holds an unknown role: {binding_id}"
            )));
        };
        if !role.is_guarded() || kind != SubjectKind::Principal.as_str() {
            return Ok(None);
        }
        let others: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM role_bindings \
             WHERE tenant_id = $1 AND role = $2 AND subject_kind = 'principal' \
               AND ended_at IS NULL AND id <> $3)",
        )
        .bind(tenant_id)
        .bind(role.as_str())
        .bind(binding_id)
        .fetch_one(&mut **tx)
        .await?;
        Ok((!others).then(|| last_admin_reason(role)))
    }

    pub(crate) async fn insert_binding(
        tx: &mut Transaction<'_, Postgres>,
        binding: &RoleBinding,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            "INSERT INTO role_bindings ({BINDING_COLUMNS}) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL)"
        ))
        .bind(&binding.id)
        .bind(&binding.tenant_id)
        .bind(binding.role.as_str())
        .bind(binding.subject.kind.as_str())
        .bind(&binding.subject.issuer)
        .bind(&binding.subject.value)
        .bind(binding.granted_by_change_request.as_deref())
        .bind(binding.granted_at)
        .execute(&mut **tx)
        .await
        .map(|_| ())
    }

    /// Ends an active binding; an error when it is not active (the check
    /// under the same lock said it was).
    pub(crate) async fn end_binding(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        binding_id: &str,
        change_request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), RoleStoreError> {
        let ended = sqlx::query(
            "UPDATE role_bindings SET ended_at = $3, ended_by_change_request = $4 \
             WHERE id = $1 AND tenant_id = $2 AND ended_at IS NULL",
        )
        .bind(binding_id)
        .bind(tenant_id)
        .bind(now)
        .bind(change_request_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| io(&e))?
        .rows_affected();
        if ended == 1 {
            Ok(())
        } else {
            Err(RoleStoreError::Io(binding_not_active_reason(binding_id)))
        }
    }

    pub async fn roles_for(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: Option<&str>,
        groups: &[String],
    ) -> Result<BTreeSet<Role>, RoleStoreError> {
        // A NULL subject matches no person binding.
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT role FROM role_bindings \
             WHERE tenant_id = $1 AND issuer = $2 AND ended_at IS NULL \
               AND ((subject_kind = 'principal' AND subject = $3) \
                 OR (subject_kind = 'group' AND subject = ANY($4)))",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .bind(groups)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| io(&e))?;
        rows.iter().map(|r| parse_role(r)).collect()
    }

    pub async fn list_bindings(
        &self,
        tenant_id: &str,
        include_ended: bool,
    ) -> Result<Vec<RoleBinding>, RoleStoreError> {
        let rows = sqlx::query_as::<_, BindingRow>(&format!(
            "SELECT {BINDING_COLUMNS} FROM role_bindings \
             WHERE tenant_id = $1 AND ($2 OR ended_at IS NULL) \
             ORDER BY granted_at, id"
        ))
        .bind(tenant_id)
        .bind(include_ended)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| io(&e))?;
        rows.into_iter().map(BindingRow::into_binding).collect()
    }

    pub async fn record_principal_seen(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        display_name: &str,
        now: DateTime<Utc>,
    ) -> Result<(), RoleStoreError> {
        let display_name = truncate_display_name(display_name);
        sqlx::query(
            "INSERT INTO principals \
                (tenant_id, issuer, subject, display_name, first_seen_at, last_seen_at) \
             VALUES ($1, $2, $3, $4, $5, $5) \
             ON CONFLICT (tenant_id, issuer, subject) DO UPDATE \
                SET last_seen_at = GREATEST(principals.last_seen_at, EXCLUDED.last_seen_at), \
                    display_name = EXCLUDED.display_name \
                WHERE principals.last_seen_at <= $6 \
                   OR principals.display_name <> EXCLUDED.display_name",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .bind(display_name)
        .bind(now)
        .bind(now - LAST_SEEN_GRANULARITY)
        .execute(&self.pool)
        .await
        .map_err(|e| io(&e))?;
        Ok(())
    }

    pub async fn list_principals(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<PrincipalRecord>, RoleStoreError> {
        let rows = sqlx::query_as::<_, PrincipalRow>(
            "SELECT tenant_id, issuer, subject, display_name, first_seen_at, last_seen_at \
             FROM principals WHERE tenant_id = $1 ORDER BY issuer, subject",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| io(&e))?;
        Ok(rows
            .into_iter()
            .map(|r| PrincipalRecord {
                tenant_id: r.tenant_id,
                issuer: r.issuer,
                subject: r.subject,
                display_name: r.display_name,
                first_seen_at: r.first_seen_at,
                last_seen_at: r.last_seen_at,
            })
            .collect())
    }

    /// One transaction under the tenant lock: check for an active
    /// superadmin, then write both bindings and their flagged audit rows.
    pub async fn bootstrap_superadmins(
        &self,
        tenant_id: &str,
        subjects: &[BindingSubject],
        now: DateTime<Utc>,
    ) -> Result<BootstrapOutcome, RoleStoreError> {
        check_bootstrap_subjects(subjects)?;
        let mut tx = self.pool.begin().await.map_err(|e| io(&e))?;
        Self::lock_tenant(&mut tx, tenant_id)
            .await
            .map_err(|e| io(&e))?;
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM role_bindings \
             WHERE tenant_id = $1 AND role = 'superadmin' AND ended_at IS NULL)",
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| io(&e))?;
        if present {
            return Ok(BootstrapOutcome::AlreadyPresent);
        }
        let written: Vec<RoleBinding> = subjects
            .iter()
            .map(|s| new_binding(tenant_id, Role::Superadmin, s.clone(), None, now))
            .collect();
        for binding in &written {
            Self::insert_binding(&mut tx, binding)
                .await
                .map_err(|e| io(&e))?;
            let audit = bootstrap_audit(binding);
            sqlx::query(
                "INSERT INTO admin_audit_log \
                    (action, resource_type, resource_id, actor_principal, approver_principal, \
                     payload, acting_as_superadmin) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&audit.action)
            .bind(&audit.resource_type)
            .bind(&audit.resource_id)
            .bind(&audit.actor_principal)
            .bind(&audit.approver_principal)
            .bind(audit.payload)
            .bind(audit.acting_as_superadmin)
            .execute(&mut *tx)
            .await
            .map_err(|e| io(&e))?;
        }
        tx.commit().await.map_err(|e| io(&e))?;
        Ok(BootstrapOutcome::Written(written))
    }
}
