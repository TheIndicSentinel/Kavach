//! The digest that tells a retried revoking event from a reuse of its id
//! (docs/specs/mandate-and-sor-event.md section 5): written in the tagged
//! form now, and a row stored in the legacy form still recognises its retry.

mod common;

use common::*;
use kavach_domain::mandate::SorEvent;
use kavach_mandate::{event_digest, legacy_content_sha256};
use kavach_ports::{ErrorClass, MandateStore, StoredRevocation};

fn paid(f: &Fixture, id: &str) -> SorEvent {
    SorEvent {
        event_type: "loan.paid".into(),
        ..event(f.now, id)
    }
}

fn row(event: &SorEvent, digest: String) -> StoredRevocation {
    StoredRevocation {
        tenant_id: event.tenant_id.clone(),
        system: event.system.clone(),
        event_id: event.event_id.clone(),
        event_digest: digest,
        event_type: event.event_type.clone(),
        record_ref: event.record_ref.clone(),
        occurred_at: event.occurred_at,
        revoked: vec![],
        revoked_at: event.occurred_at,
    }
}

#[tokio::test]
async fn a_new_revocation_stores_the_tagged_digest_and_its_retry_matches() {
    let f = fixture();
    let event = paid(&f, "pay-1");
    let token = sign_event(&f.sor, "lms-issuer-1", &event).await;
    let done = f.service.revoke_from_event(&token).await.unwrap();
    assert_eq!(done.stored.event_digest, event_digest(&event).unwrap());
    assert!(done.stored.event_digest.starts_with("sha256-jcs-v1:"));
    let retry = f
        .service
        .existing_revocation(&token)
        .await
        .unwrap()
        .unwrap();
    assert!(retry.replayed);
}

#[tokio::test]
async fn a_revocation_stored_in_the_legacy_form_still_recognises_its_retry() {
    let f = fixture();
    let event = paid(&f, "pay-old");
    f.service
        .store()
        .record_revocation(row(&event, legacy_content_sha256(&event).unwrap()))
        .await
        .unwrap();
    let token = sign_event(&f.sor, "lms-issuer-1", &event).await;
    let retry = f.service.existing_revocation(&token).await.unwrap();
    assert!(
        retry.is_some_and(|r| r.replayed),
        "the legacy row is a retry"
    );

    // The same id with other content is still a conflict, in either form.
    let other = SorEvent {
        nonce: "another".into(),
        ..event
    };
    let token = sign_event(&f.sor, "lms-issuer-1", &other).await;
    let err = f.service.existing_revocation(&token).await.unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected, "{err}");
}

#[tokio::test]
async fn a_reused_event_id_is_a_conflict_in_the_new_form() {
    let f = fixture();
    let event = paid(&f, "pay-2");
    let token = sign_event(&f.sor, "lms-issuer-1", &event).await;
    f.service.revoke_from_event(&token).await.unwrap();
    let other = SorEvent {
        nonce: "changed".into(),
        ..event
    };
    let token = sign_event(&f.sor, "lms-issuer-1", &other).await;
    let err = f.service.existing_revocation(&token).await.unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected, "{err}");
}
