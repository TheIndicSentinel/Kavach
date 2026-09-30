mod common;

use chrono::Duration;
use common::*;
use kavach_domain::mandate::{DelegationRequest, RevocationReason};
use kavach_ports::{DomainEvent, ErrorClass, TimeSource};

#[tokio::test]
async fn event_to_mandate_happy_path() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-1")).await;
    let issued = f.service.issue_from_event(&token).await.expect("issue");
    let m = &issued.mandate;
    assert_eq!(m.subject_ref, SUBJECT);
    assert_eq!(m.holder, "collections-agent");
    assert_eq!(m.purpose, "loan_recovery");
    assert_eq!(m.depth, 0);
    assert_eq!(m.source.record_ref, "lms:loan/L-4471");
    assert_eq!(m.exp, f.now + Duration::days(7));
    assert_eq!(f.service.verify_active(&issued.token).await.unwrap(), *m);
    assert!(matches!(
        f.service.events().events().as_slice(),
        [DomainEvent::MandateIssued { .. }]
    ));
}

#[tokio::test]
async fn replayed_stale_or_misattributed_events_are_rejected() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-1")).await;
    f.service.issue_from_event(&token).await.expect("first");
    let replay = f.service.issue_from_event(&token).await.unwrap_err();
    assert_eq!(replay.class, ErrorClass::Rejected, "{replay}");

    let stale = sign_event(
        &f.sor,
        "lms-issuer-1",
        &event(f.now - Duration::minutes(10), "evt-stale"),
    )
    .await;
    assert_eq!(
        f.service.issue_from_event(&stale).await.unwrap_err().class,
        ErrorClass::Rejected
    );

    // CRM key cannot sign LMS events.
    let wrong = sign_event(&f.sor, "crm-issuer-1", &event(f.now, "evt-2")).await;
    assert_eq!(
        f.service.issue_from_event(&wrong).await.unwrap_err().class,
        ErrorClass::Rejected
    );

    // Unregistered key.
    let mut rogue = kavach_keys::InMemoryKeyProvider::new();
    rogue.insert_seed("lms-issuer-1", [99u8; 32]).unwrap();
    let forged = sign_event(&rogue, "lms-issuer-1", &event(f.now, "evt-3")).await;
    assert_eq!(
        f.service.issue_from_event(&forged).await.unwrap_err().class,
        ErrorClass::Rejected
    );
}

#[tokio::test]
async fn issuance_validation_rules() {
    // Wildcard / raw subject.
    let f = fixture();
    let mut e = event(f.now, "evt-w");
    e.subject_ref = "ref:borrower:*".into();
    let token = sign_event(&f.sor, "lms-issuer-1", &e).await;
    assert_eq!(
        f.service.issue_from_event(&token).await.unwrap_err().class,
        ErrorClass::Invalid
    );

    // Agent not eligible for this event type.
    let mut e = event(f.now, "evt-a");
    e.assigned_agent = "translator-agent".into();
    let token = sign_event(&f.sor, "lms-issuer-1", &e).await;
    assert!(f.service.issue_from_event(&token).await.is_err());

    // Consent that does not cover the purpose.
    let mut c = consent(t0());
    c.purposes = set(&["marketing"]);
    let f = fixture_with(vec![c], template());
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-c")).await;
    assert!(f.service.issue_from_event(&token).await.is_err());

    // Template ceiling above the holder's passport: refused at config load.
    let mut tmpl = template();
    tmpl.ceilings.insert("waiver_bps".into(), 5000);
    let err = try_fixture(vec![consent(t0())], vec![tmpl], passports())
        .err()
        .unwrap();
    assert_eq!(err.class, ErrorClass::Invalid);
}

#[tokio::test]
async fn mandate_lifetime_is_clamped_to_consent_expiry() {
    let mut c = consent(t0());
    c.expires_at = t0() + Duration::hours(2);
    let f = fixture_with(vec![c], template());
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-1")).await;
    let issued = f.service.issue_from_event(&token).await.unwrap();
    assert_eq!(issued.mandate.exp, t0() + Duration::hours(2));
}

#[tokio::test]
async fn delegation_narrows_and_is_bounded() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-1")).await;
    let parent = f.service.issue_from_event(&token).await.unwrap().mandate;

    let request = DelegationRequest {
        actions: set(&["read_fields", "update_status", "place_call"]),
        data_fields: set(&["name", "loan_ref", "overdue_amount"]),
        channels: set(&["whatsapp"]),
        ..Default::default()
    };
    let child = f
        .service
        .delegate(
            TENANT,
            &parent.id,
            "collections-agent",
            "translator-agent",
            &request,
        )
        .await
        .expect("delegate")
        .mandate;
    // Translator passport is read-only: update_status / place_call are dropped.
    assert_eq!(child.actions, set(&["read_fields"]));
    assert_eq!(child.data_fields, set(&["loan_ref", "name"]));
    assert!(child.ceilings.is_empty());
    assert_eq!(child.depth, 1);
    assert_eq!(child.parent_id.as_deref(), Some(parent.id.as_str()));
    assert!(kavach_mandate::delegation::is_within(&child, &parent));

    // Depth limit, non-holder and non-allowed recipients are refused.
    assert!(f
        .service
        .delegate(
            TENANT,
            &child.id,
            "translator-agent",
            "translator-agent",
            &request
        )
        .await
        .is_err());
    assert!(f
        .service
        .delegate(
            TENANT,
            &parent.id,
            "translator-agent",
            "translator-agent",
            &request
        )
        .await
        .is_err());
    assert!(f
        .service
        .delegate(
            TENANT,
            &parent.id,
            "collections-agent",
            "collections-agent",
            &request
        )
        .await
        .is_err());
}

#[tokio::test]
async fn revocation_cascades_and_expiry_is_enforced() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-1")).await;
    let parent = f.service.issue_from_event(&token).await.unwrap();
    let child = f
        .service
        .delegate(
            TENANT,
            &parent.mandate.id,
            "collections-agent",
            "translator-agent",
            &DelegationRequest {
                actions: set(&["read_fields"]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let revoked = f
        .service
        .revoke(TENANT, &parent.mandate.id, RevocationReason::Dispute)
        .await
        .unwrap();
    assert_eq!(revoked.revoked.len(), 2);
    assert!(revoked.publish_errors.is_empty());
    for token in [&parent.token, &child.token] {
        let err = f.service.verify_active(token).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Rejected);
    }

    // A fresh mandate stops verifying once trusted time passes its expiry.
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.service_now(), "evt-2")).await;
    let issued = f.service.issue_from_event(&token).await.unwrap();
    f.advance(Duration::days(8));
    assert!(f.service.verify_active(&issued.token).await.is_err());
}

#[tokio::test]
async fn tampered_or_non_canonical_tokens_are_rejected() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-1")).await;
    let issued = f.service.issue_from_event(&token).await.unwrap();

    let mut parts: Vec<String> = issued.token.split('.').map(String::from).collect();
    // Re-encode the payload with whitespace: same meaning, not canonical.
    let payload = base64_url_decode(&parts[1]);
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&payload).unwrap())
            .unwrap();
    parts[1] = base64_url_encode(&pretty);
    assert!(f.service.verify_active(&parts.join(".")).await.is_err());

    // A token for a different mandate id with the original signature.
    let other = issued.token.replacen('.', ".x", 1);
    assert!(f.service.verify_active(&other).await.is_err());
}

fn base64_url_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

fn base64_url_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

trait FixtureClock {
    fn service_now(&self) -> chrono::DateTime<chrono::Utc>;
    fn advance(&self, by: Duration);
}

impl FixtureClock for Fixture {
    fn service_now(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock().now().utc
    }
    fn advance(&self, by: Duration) {
        self.clock().advance(by);
    }
}
