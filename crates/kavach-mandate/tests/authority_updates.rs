mod common;

use chrono::Duration;
use common::{consent, fixture, t0, TENANT};
use kavach_domain::authority::{
    AuthorityChange, AuthorityUpdateEvent, ReferenceDestinationRecord, SensitiveDestination,
};
use kavach_domain::mandate::{
    ConsentArtefactSubset, ConsentStatus, ContactPreferenceRecord, ContactPreferenceStatus,
};
use kavach_mandate::jws::{self, TYP_AUTHORITY_UPDATE, TYP_SOR_EVENT};
use kavach_mandate::{AuthorityVerifier, UNTRUSTED_ISSUER};
use kavach_ports::{ErrorClass, SyncStatus, TrustedNow};

fn now(sync: SyncStatus) -> TrustedNow {
    TrustedNow { utc: t0(), sync }
}

fn consent_update() -> AuthorityUpdateEvent {
    let mut record = consent(t0());
    record.artefact = Some(ConsentArtefactSubset {
        data_types: ["loan_account".into()].into(),
        valid_from: t0() - Duration::days(1),
        data_from: t0() - Duration::days(30),
        data_to: t0(),
        status: ConsentStatus::Active,
    });
    AuthorityUpdateEvent {
        update_id: "update-1".into(),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        occurred_at: t0(),
        nonce: "nonce-1".into(),
        change: AuthorityChange::Consent(record),
    }
}

fn preference_update() -> AuthorityUpdateEvent {
    AuthorityUpdateEvent {
        update_id: "preference-1".into(),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        occurred_at: t0(),
        nonce: "nonce-2".into(),
        change: AuthorityChange::ContactPreference(ContactPreferenceRecord {
            tenant_id: TENANT.into(),
            subject_ref: common::SUBJECT.into(),
            channel: "sms".into(),
            status: ContactPreferenceStatus::Allowed,
            valid_from: t0() - Duration::hours(1),
            expires_at: t0() + Duration::days(1),
        }),
    }
}

fn reference_destination_update() -> AuthorityUpdateEvent {
    AuthorityUpdateEvent {
        update_id: "destination-1".into(),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        occurred_at: t0(),
        nonce: "nonce-destination-1".into(),
        change: AuthorityChange::ReferenceDestination(ReferenceDestinationRecord {
            tenant_id: TENANT.into(),
            subject_ref: common::SUBJECT.into(),
            channel: "sms".into(),
            destination: SensitiveDestination::new("+919876543210"),
        }),
    }
}

#[tokio::test]
async fn signed_updates_require_registered_tenant_and_system_key() {
    let f = fixture();
    let verifier = AuthorityVerifier::new(TENANT, f.config.clone()).unwrap();
    let event = consent_update();
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    let accepted = verifier
        .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
        .unwrap();
    assert_eq!(accepted.event(), &event);
    assert_eq!(accepted.payload_sha256().len(), 64);

    let wrong_typ = jws::sign(&f.sor, "lms-issuer-1", TYP_SOR_EVENT, &event)
        .await
        .unwrap();
    assert!(verifier
        .verify(&wrong_typ, now(SyncStatus::Synced { max_error_ms: 0 }))
        .is_err());
    let wrong_key = jws::sign(&f.sor, "crm-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    let refused = verifier
        .verify(&wrong_key, now(SyncStatus::Synced { max_error_ms: 0 }))
        .unwrap_err();
    assert_eq!(refused.message, UNTRUSTED_ISSUER);
    let other_tenant = AuthorityVerifier::new("other-tenant", f.config).unwrap();
    assert_eq!(
        other_tenant
            .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
            .unwrap_err()
            .message,
        UNTRUSTED_ISSUER
    );
}

#[tokio::test]
async fn signed_destination_updates_are_fresh_scoped_and_redacted() {
    let f = fixture();
    let verifier = AuthorityVerifier::new(TENANT, f.config).unwrap();
    let event = reference_destination_update();
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    let verified = verifier
        .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
        .unwrap();
    assert_eq!(verified.event(), &event);
    assert!(!format!("{event:?}").contains("+919876543210"));
    assert!(!format!("{verified:?}").contains("+919876543210"));

    let mut wrong_tenant = reference_destination_update();
    if let AuthorityChange::ReferenceDestination(record) = &mut wrong_tenant.change {
        record.tenant_id = "other-tenant".into();
    }
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &wrong_tenant)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
            .unwrap_err()
            .class,
        ErrorClass::Invalid
    );

    let mut stale = reference_destination_update();
    stale.occurred_at = t0() - Duration::days(1);
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &stale)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    let mut invalid = reference_destination_update();
    if let AuthorityChange::ReferenceDestination(record) = &mut invalid.change {
        record.channel = "email".into();
    }
    assert!(invalid.validate().is_err());
    let mut invalid = reference_destination_update();
    if let AuthorityChange::ReferenceDestination(record) = &mut invalid.change {
        record.destination = SensitiveDestination::new("+919876543210\nsecret");
    }
    assert!(invalid.validate().is_err());
}

#[tokio::test]
async fn permissive_updates_need_fresh_trusted_time_but_restrictions_do_not() {
    let f = fixture();
    let verifier = AuthorityVerifier::new(TENANT, f.config).unwrap();
    let mut event = consent_update();
    event.occurred_at = t0() - Duration::hours(1);
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    event.occurred_at = t0();
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Unsynced))
            .unwrap_err()
            .class,
        ErrorClass::Unavailable
    );
    let allowed_preference = preference_update();
    let signed = jws::sign(
        &f.sor,
        "lms-issuer-1",
        TYP_AUTHORITY_UPDATE,
        &allowed_preference,
    )
    .await
    .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Unsynced))
            .unwrap_err()
            .class,
        ErrorClass::Unavailable
    );

    let mut opt_out = preference_update();
    opt_out.occurred_at = t0() - Duration::days(10);
    if let AuthorityChange::ContactPreference(record) = &mut opt_out.change {
        record.status = ContactPreferenceStatus::OptedOut;
    }
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &opt_out)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Unsynced))
            .unwrap()
            .event(),
        &opt_out
    );

    let mut withdrawal = consent_update();
    withdrawal.occurred_at = t0() - Duration::days(10);
    if let AuthorityChange::Consent(record) = &mut withdrawal.change {
        record.active = false;
        record.artefact.as_mut().unwrap().status = ConsentStatus::Revoked;
    }
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &withdrawal)
        .await
        .unwrap();
    assert!(verifier.verify(&signed, now(SyncStatus::Unsynced)).is_ok());
}

#[tokio::test]
async fn signed_payload_cannot_cross_tenant_or_carry_raw_subject() {
    let f = fixture();
    let verifier = AuthorityVerifier::new(TENANT, f.config).unwrap();
    let mut event = consent_update();
    if let AuthorityChange::Consent(record) = &mut event.change {
        record.tenant_id = "other-tenant".into();
    }
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
            .unwrap_err()
            .class,
        ErrorClass::Invalid
    );
    if let AuthorityChange::Consent(record) = &mut event.change {
        record.tenant_id = TENANT.into();
        record.subject_ref = "raw-destination".into();
    }
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
            .unwrap_err()
            .class,
        ErrorClass::Invalid
    );
    if let AuthorityChange::Consent(record) = &mut event.change {
        record.subject_ref = common::SUBJECT.into();
        record.artefact = None;
    }
    let signed = jws::sign(&f.sor, "lms-issuer-1", TYP_AUTHORITY_UPDATE, &event)
        .await
        .unwrap();
    assert_eq!(
        verifier
            .verify(&signed, now(SyncStatus::Synced { max_error_ms: 0 }))
            .unwrap_err()
            .class,
        ErrorClass::Invalid
    );
}
