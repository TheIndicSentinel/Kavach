//! Signed consent grants commit their history and projection together.

use chrono::{Duration, Utc};
use kavach_domain::authority::{AuthorityChange, AuthorityUpdateEvent};
use kavach_domain::mandate::{ConsentArtefactSubset, ConsentRecord, ConsentStatus};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{self, KeySet, TYP_AUTHORITY_UPDATE};
use kavach_mandate::{AuthorityVerifier, MandateConfig, SorIssuer};
use kavach_ports::{ErrorClass, SyncStatus, TrustedNow};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{connect_runtime, DatabaseTls, StoragePool};

fn consent(now: chrono::DateTime<Utc>, active: bool) -> ConsentRecord {
    ConsentRecord {
        consent_id: "C-1".into(),
        tenant_id: "tenant-a".into(),
        subject_ref: "ref:borrower:B-1".into(),
        purposes: ["loan_recovery".into()].into(),
        expires_at: now + Duration::days(30),
        active,
        artefact: Some(ConsentArtefactSubset {
            data_types: ["account_transactions".into()].into(),
            valid_from: now - Duration::hours(1),
            data_from: now - Duration::days(30),
            data_to: now,
            status: if active {
                ConsentStatus::Active
            } else {
                ConsentStatus::Revoked
            },
        }),
    }
}

fn event(now: chrono::DateTime<Utc>, id: &str, active: bool) -> AuthorityUpdateEvent {
    AuthorityUpdateEvent {
        update_id: id.into(),
        tenant_id: "tenant-a".into(),
        system: "lms".into(),
        occurred_at: now,
        nonce: format!("nonce-{id}"),
        change: AuthorityChange::Consent(consent(now, active)),
    }
}

fn verifier(public_key: kavach_ports::PublicKey) -> AuthorityVerifier {
    AuthorityVerifier::new(
        "tenant-a",
        MandateConfig {
            issuer_id: "test".into(),
            signing_kid: "unused".into(),
            mandate_keys: KeySet::new([public_key.clone()]),
            sor_issuers: vec![SorIssuer {
                tenant_id: "tenant-a".into(),
                system: "lms".into(),
                key: public_key,
            }],
            templates: Vec::new(),
            passports: Vec::new(),
            event_freshness_seconds: 300,
            replay_window_seconds: 3600,
            max_clock_error_ms: 500,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn signed_consent_grants_are_atomic_idempotent_and_withdrawals_are_refused() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls).await.unwrap();
    let runtime = connect_runtime(&runtime_url, &tls).await.unwrap();
    let store = runtime.authority_update_store();
    let now = Utc::now();
    let trusted = TrustedNow {
        utc: now,
        sync: SyncStatus::Synced { max_error_ms: 0 },
    };
    let mut signer = InMemoryKeyProvider::new();
    let public_key = signer.insert_seed("lms-1", [7; 32]).unwrap();
    let verifier = verifier(public_key);
    let grant = event(now, "consent-1", true);
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &grant)
        .await
        .unwrap();
    let verified_grant = verifier.verify(&token, trusted).unwrap();

    let (first, retry) = tokio::join!(
        store.apply_consent_grant(&verified_grant),
        store.apply_consent_grant(&verified_grant)
    );
    assert_ne!(first.unwrap().replayed, retry.unwrap().replayed);
    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 1);
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM consent_current WHERE tenant_id = 'tenant-a' AND consent_id = 'C-1'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert_eq!(version, 1);

    let mut conflicting_grant = grant;
    if let AuthorityChange::Consent(record) = &mut conflicting_grant.change {
        record.purposes = ["different_purpose".into()].into();
    }
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &conflicting_grant)
        .await
        .unwrap();
    let conflict = verifier.verify(&token, trusted).unwrap();
    assert_eq!(
        store
            .apply_consent_grant(&conflict)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    let withdrawal = event(now + Duration::seconds(1), "consent-2", false);
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &withdrawal)
        .await
        .unwrap();
    let verified_withdrawal = verifier.verify(&token, trusted).unwrap();
    assert_eq!(
        store
            .apply_consent_grant(&verified_withdrawal)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 1);

    let consent_update_allowed: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('kavach_runtime', 'consent_current', 'UPDATE')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    assert!(consent_update_allowed);
}
