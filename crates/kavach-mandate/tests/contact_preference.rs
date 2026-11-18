use chrono::{DateTime, Duration, Utc};
use kavach_domain::mandate::{ContactPreferenceRecord, ContactPreferenceStatus};
use kavach_mandate::memory::InMemoryContactPreferenceSource;
use kavach_ports::{require_contact_permission, ErrorClass};

fn record(now: DateTime<Utc>) -> ContactPreferenceRecord {
    ContactPreferenceRecord {
        tenant_id: "tenant-a".into(),
        subject_ref: "ref:borrower:B-1".into(),
        channel: "sms".into(),
        status: ContactPreferenceStatus::Allowed,
        valid_from: now - Duration::hours(1),
        expires_at: now + Duration::hours(1),
    }
}

#[tokio::test]
async fn contact_lookup_requires_current_tenant_subject_and_channel_allow() {
    let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    let source = InMemoryContactPreferenceSource::new([record(now)]).unwrap();
    assert!(
        require_contact_permission(&source, "tenant-a", "ref:borrower:B-1", "sms", now)
            .await
            .is_ok()
    );
    for (tenant, subject, channel, time) in [
        ("tenant-b", "ref:borrower:B-1", "sms", now),
        ("tenant-a", "ref:borrower:B-2", "sms", now),
        ("tenant-a", "ref:borrower:B-1", "whatsapp", now),
        (
            "tenant-a",
            "ref:borrower:B-1",
            "sms",
            now + Duration::hours(1),
        ),
    ] {
        assert_eq!(
            require_contact_permission(&source, tenant, subject, channel, time)
                .await
                .unwrap_err()
                .class,
            ErrorClass::Rejected
        );
    }
}

#[tokio::test]
async fn opted_out_and_malformed_fixture_never_authorize_contact() {
    let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    let mut opted_out = record(now);
    opted_out.status = ContactPreferenceStatus::OptedOut;
    let source = InMemoryContactPreferenceSource::new([opted_out]).unwrap();
    assert_eq!(
        require_contact_permission(&source, "tenant-a", "ref:borrower:B-1", "sms", now)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    let mut invalid = record(now);
    invalid.channel = "unknown".into();
    assert_eq!(
        InMemoryContactPreferenceSource::new([invalid])
            .unwrap_err()
            .class,
        ErrorClass::Invalid
    );
    assert_eq!(
        InMemoryContactPreferenceSource::new([record(now), record(now)])
            .unwrap_err()
            .class,
        ErrorClass::Invalid
    );
}
