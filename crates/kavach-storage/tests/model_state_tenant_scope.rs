//! Governed model state remains isolated by tenant (ADR-014 §2.3).

use chrono::Utc;
use kavach_domain::{GovernanceMode, ModelStatus};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{DatabaseTls, ModelState, StoragePool};

fn state(mode: GovernanceMode) -> ModelState {
    ModelState {
        model_id: "shared-model".into(),
        status: ModelStatus::Production,
        governance_mode: mode,
        updated_at: Utc::now(),
        updated_by: "operator".into(),
        approved_by: "approver".into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_model_state_reads_and_inserts_are_tenant_scoped() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let pool = StoragePool::connect(&url, &DatabaseTls::development())
        .await
        .expect("connect and migrate");
    let admin = pool.admin_store();

    assert!(admin
        .insert_model_state_if_absent("tenant-a", &state(GovernanceMode::Shadow))
        .await
        .unwrap());
    assert!(admin
        .insert_model_state_if_absent("tenant-b", &state(GovernanceMode::Enforce))
        .await
        .unwrap());

    assert_eq!(
        admin
            .get_model_state("tenant-a", "shared-model")
            .await
            .unwrap()
            .unwrap()
            .governance_mode,
        GovernanceMode::Shadow
    );
    assert_eq!(
        admin
            .get_model_state("tenant-b", "shared-model")
            .await
            .unwrap()
            .unwrap()
            .governance_mode,
        GovernanceMode::Enforce
    );
    assert!(admin
        .get_model_state("tenant-c", "shared-model")
        .await
        .unwrap()
        .is_none());
    assert_eq!(admin.list_model_states("tenant-a").await.unwrap().len(), 1);
    assert!(admin
        .list_model_states("tenant-c")
        .await
        .unwrap()
        .is_empty());
}
