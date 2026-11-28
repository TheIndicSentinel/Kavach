//! Isolated Postgres coverage for the read-only authority projections.

use chrono::{DateTime, Duration, Utc};
use kavach_domain::mandate::{ConsentRecord, ContactPreferenceRecord, ContactPreferenceStatus};
use kavach_ports::{
    require_contact_permission, ConsentSource, ContactPreferenceSource, ErrorClass,
};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{connect_runtime, DatabaseTls, StoragePool};

async fn seed(owner: &StoragePool, now: DateTime<Utc>) -> (ConsentRecord, ContactPreferenceRecord) {
    let consent = ConsentRecord {
        consent_id: "C-1".into(),
        tenant_id: "tenant-a".into(),
        subject_ref: "ref:borrower:B-1".into(),
        purposes: ["loan_recovery".into()].into(),
        expires_at: now + Duration::days(1),
        active: true,
        artefact: None,
    };
    let preference = ContactPreferenceRecord {
        tenant_id: "tenant-a".into(),
        subject_ref: consent.subject_ref.clone(),
        channel: "sms".into(),
        status: ContactPreferenceStatus::Allowed,
        valid_from: now - Duration::minutes(1),
        expires_at: now + Duration::hours(1),
    };
    let consent_json = serde_json::to_value(&consent).unwrap();
    let preference_json = serde_json::to_value(&preference).unwrap();
    sqlx::query(
        "INSERT INTO authority_updates \
         (tenant_id, source_system, update_id, kind, consent_id, payload_sha256, record, occurred_at) \
         VALUES ($1, 'lms', 'consent-1', 'consent', $2, $3, $4, $5)",
    )
    .bind(&consent.tenant_id)
    .bind(&consent.consent_id)
    .bind("a".repeat(64))
    .bind(&consent_json)
    .bind(now)
    .execute(&owner.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO consent_current \
         (tenant_id, consent_id, record, source_system, update_id, version) \
         VALUES ($1, $2, $3, 'lms', 'consent-1', 1)",
    )
    .bind(&consent.tenant_id)
    .bind(&consent.consent_id)
    .bind(&consent_json)
    .execute(&owner.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO authority_updates \
         (tenant_id, source_system, update_id, kind, subject_ref, channel, \
          payload_sha256, record, occurred_at) \
         VALUES ($1, 'lms', 'preference-1', 'contact_preference', $2, $3, $4, $5, $6)",
    )
    .bind(&preference.tenant_id)
    .bind(&preference.subject_ref)
    .bind(&preference.channel)
    .bind("b".repeat(64))
    .bind(&preference_json)
    .bind(now)
    .execute(&owner.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO contact_preference_current \
         (tenant_id, subject_ref, channel, record, source_system, update_id, version) \
         VALUES ($1, $2, $3, $4, 'lms', 'preference-1', 1)",
    )
    .bind(&preference.tenant_id)
    .bind(&preference.subject_ref)
    .bind(&preference.channel)
    .bind(&preference_json)
    .execute(&owner.pool)
    .await
    .unwrap();

    let mut raw_subject = consent_json.clone();
    raw_subject["consent_id"] = "C-2".into();
    raw_subject["subject_ref"] = "raw-destination".into();
    assert!(sqlx::query(
        "INSERT INTO authority_updates \
         (tenant_id, source_system, update_id, kind, consent_id, payload_sha256, record, occurred_at) \
         VALUES ('tenant-a', 'lms', 'raw-subject', 'consent', 'C-2', $1, $2, $3)",
    )
    .bind("c".repeat(64))
    .bind(raw_subject)
    .bind(now)
    .execute(&owner.pool)
    .await
    .is_err());

    (consent, preference)
}

async fn assert_tampered_projections_fail(owner: &StoragePool, runtime: &StoragePool) {
    sqlx::query("UPDATE consent_current SET record = jsonb_set(record, '{active}', 'false') WHERE tenant_id = 'tenant-a' AND consent_id = 'C-1'")
        .execute(&owner.pool)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .consent_source()
            .get("tenant-a", "C-1")
            .await
            .unwrap_err()
            .class,
        ErrorClass::Unavailable
    );
    sqlx::query("UPDATE contact_preference_current SET record = jsonb_set(record, '{status}', to_jsonb('opted_out'::text)) WHERE tenant_id = 'tenant-a' AND subject_ref = 'ref:borrower:B-1' AND channel = 'sms'")
        .execute(&owner.pool)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .contact_preference_source()
            .get("tenant-a", "ref:borrower:B-1", "sms")
            .await
            .unwrap_err()
            .class,
        ErrorClass::Unavailable
    );
    assert!(
        sqlx::query("DELETE FROM authority_updates WHERE update_id = 'consent-1'")
            .execute(&owner.pool)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn postgres_authority_projections_are_tenant_scoped_with_scoped_runtime_grants() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls).await.unwrap();
    let runtime = connect_runtime(&runtime_url, &tls).await.unwrap();
    let now = Utc::now();
    let (consent, preference) = seed(&owner, now).await;

    assert_eq!(
        runtime
            .consent_source()
            .get("tenant-a", "C-1")
            .await
            .unwrap(),
        Some(consent)
    );
    assert_eq!(
        runtime
            .consent_source()
            .get("tenant-b", "C-1")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        runtime
            .contact_preference_source()
            .get("tenant-a", "ref:borrower:B-1", "sms")
            .await
            .unwrap(),
        Some(preference)
    );
    assert!(require_contact_permission(
        &runtime.contact_preference_source(),
        "tenant-a",
        "ref:borrower:B-1",
        "sms",
        now,
    )
    .await
    .is_ok());
    assert_eq!(
        require_contact_permission(
            &runtime.contact_preference_source(),
            "tenant-b",
            "ref:borrower:B-1",
            "sms",
            now,
        )
        .await
        .unwrap_err()
        .class,
        ErrorClass::Rejected
    );

    for (table, privilege, expected) in [
        ("authority_updates", "INSERT", true),
        ("authority_updates", "UPDATE", false),
        ("authority_updates", "DELETE", false),
        ("authority_updates", "TRUNCATE", false),
        ("consent_current", "INSERT", true), // granted by 035 for signed consent updates
        ("consent_current", "UPDATE", true),
        ("consent_current", "DELETE", false),
        ("consent_current", "TRUNCATE", false),
        ("contact_preference_current", "INSERT", true),
        ("contact_preference_current", "UPDATE", true),
        ("contact_preference_current", "DELETE", false),
        ("contact_preference_current", "TRUNCATE", false),
    ] {
        let allowed: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user, $1, $2)")
            .bind(table)
            .bind(privilege)
            .fetch_one(&runtime.pool)
            .await
            .unwrap();
        assert_eq!(allowed, expected, "runtime {privilege} on {table}");
    }

    assert_tampered_projections_fail(&owner, &runtime).await;
}
