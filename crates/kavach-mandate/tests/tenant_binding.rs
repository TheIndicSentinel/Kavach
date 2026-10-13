//! Issuer-to-tenant binding (ADR-014 §2.1): a system-of-record key is
//! registered for exactly one tenant and one system, and an event is
//! accepted only from a key registered for **its own** tenant.
//!
//! Two tenants share one service here (as a pooled deployment would): each
//! has its own issuer key for the same system `lms`, and its own template,
//! passports and consent. Every cross-tenant attempt is refused with the
//! one external message that does not say whose key it was.

mod common;

use common::*;
use kavach_domain::mandate::SorEvent;
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::KeySet;
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateConfig, MandateDeps, MandateService, SorIssuer, UNTRUSTED_ISSUER};
use kavach_ports::{ErrorClass, PortError};
use kavach_ports_testkit::{FakeClock, InMemoryReplayGuard};

const A: &str = "tenant-a";
const B: &str = "tenant-b";

struct World {
    service: Service,
    sor: InMemoryKeyProvider,
}

fn registered(sor: &mut InMemoryKeyProvider) -> Vec<SorIssuer> {
    vec![
        SorIssuer {
            tenant_id: A.into(),
            system: "lms".into(),
            key: sor.insert_seed("lms-a", [21u8; 32]).unwrap(),
        },
        SorIssuer {
            tenant_id: B.into(),
            system: "lms".into(),
            key: sor.insert_seed("lms-b", [22u8; 32]).unwrap(),
        },
    ]
}

fn config(issuers: Vec<SorIssuer>, kavach: &mut InMemoryKeyProvider) -> MandateConfig {
    let kavach_pub = kavach.insert_seed("kavach-mandate-1", [1u8; 32]).unwrap();
    let mut templates = Vec::new();
    let mut passports = Vec::new();
    for tenant in [A, B] {
        let mut t = template();
        t.tenant_id = tenant.into();
        templates.push(t);
        for mut p in self::passports() {
            p.tenant_id = tenant.into();
            passports.push(p);
        }
    }
    MandateConfig {
        issuer_id: "kavach-dev".into(),
        signing_kid: "kavach-mandate-1".into(),
        mandate_keys: KeySet::new([kavach_pub]),
        sor_issuers: issuers,
        templates,
        passports,
        event_freshness_seconds: 300,
        replay_window_seconds: 24 * 3600,
    }
}

fn world() -> World {
    let mut sor = InMemoryKeyProvider::new();
    let mut kavach = InMemoryKeyProvider::new();
    let issuers = registered(&mut sor);
    // A key nobody registered: the attacker's own.
    sor.insert_seed("lms-rogue", [23u8; 32]).unwrap();
    let consents = [A, B].map(|tenant| {
        let mut c = consent(t0());
        c.tenant_id = tenant.into();
        c
    });
    let config = config(issuers, &mut kavach);
    let service = MandateService::new(
        MandateDeps {
            keys: kavach,
            replay: InMemoryReplayGuard::new(),
            consents: InMemoryConsentSource::new(consents),
            store: InMemoryMandateStore::new(),
            events: InMemoryEventBus::new(),
            clock: FakeClock::synced_at(t0()),
        },
        config,
    )
    .expect("valid two-tenant configuration");
    World { service, sor }
}

fn event_for(tenant: &str, id: &str, kind: &str) -> SorEvent {
    SorEvent {
        tenant_id: tenant.into(),
        event_type: kind.into(),
        ..event(t0(), id)
    }
}

async fn signed(w: &World, kid: &str, e: &SorEvent) -> String {
    sign_event(&w.sor, kid, e).await
}

fn untrusted(err: &PortError) {
    assert_eq!(err.class, ErrorClass::Rejected, "{err}");
    assert!(err.message.contains(UNTRUSTED_ISSUER), "{err}");
}

#[tokio::test]
async fn each_tenants_key_issues_for_its_own_tenant_and_the_same_event_id_is_independent() {
    let w = world();
    let a = signed(&w, "lms-a", &event_for(A, "evt-1", "loan.dpd30")).await;
    let b = signed(&w, "lms-b", &event_for(B, "evt-1", "loan.dpd30")).await;
    let ma = w.service.issue_from_event(&a).await.expect("A issues");
    let mb = w.service.issue_from_event(&b).await.expect("B issues");
    assert_eq!(ma.mandate.tenant_id, A);
    assert_eq!(mb.mandate.tenant_id, B);
    assert_ne!(ma.mandate.id, mb.mandate.id);
    // Each is replay-guarded in its own tenant only.
    assert!(w.service.issue_from_event(&a).await.is_err());
    assert!(w.service.issue_from_event(&b).await.is_err());
}

/// The point of the binding: one tenant's key signing for another tenant
/// is refused, for issuing and for revoking, in both directions.
#[tokio::test]
async fn a_key_registered_for_one_tenant_cannot_sign_for_another() {
    let w = world();
    for (kid, victim) in [("lms-a", B), ("lms-b", A)] {
        let issuing = signed(&w, kid, &event_for(victim, "evt-x", "loan.dpd30")).await;
        untrusted(&w.service.issue_from_event(&issuing).await.unwrap_err());
        untrusted(&w.service.existing_for_event(&issuing).await.unwrap_err());
        let revoking = signed(&w, kid, &event_for(victim, "evt-y", "loan.paid")).await;
        untrusted(&w.service.revoke_from_event(&revoking).await.unwrap_err());
        untrusted(&w.service.existing_revocation(&revoking).await.unwrap_err());
    }
}

/// An unknown key id, a key registered for another tenant and a bad
/// signature are one external message: the refusal cannot be used to find
/// out which keys exist or whose they are.
#[tokio::test]
async fn the_refusal_does_not_say_whether_the_key_exists() {
    let w = world();
    let event = event_for(A, "evt-z", "loan.dpd30");
    let wrong_tenant = signed(&w, "lms-b", &event).await;
    let unknown = signed(&w, "lms-rogue", &event).await;
    let mut bad_signature = signed(&w, "lms-a", &event).await;
    let at = bad_signature.rfind('.').unwrap() + 1;
    let swap = if bad_signature.as_bytes()[at] == b'A' {
        "B"
    } else {
        "A"
    };
    bad_signature.replace_range(at..=at, swap);
    let mut messages = Vec::new();
    for token in [&wrong_tenant, &unknown, &bad_signature] {
        let err = w.service.issue_from_event(token).await.unwrap_err();
        untrusted(&err);
        messages.push(err.message);
    }
    assert!(messages.iter().all(|m| m == &messages[0]), "{messages:?}");
    assert!(
        !messages[0].contains("lms-") && !messages[0].contains(A) && !messages[0].contains(B),
        "{messages:?}"
    );
}

/// A key is registered for a system as well: tenant A's `lms` key does not
/// sign for A's `crm`.
#[tokio::test]
async fn a_key_is_bound_to_its_system_as_well() {
    let w = world();
    let mut e = event_for(A, "evt-sys", "loan.dpd30");
    e.system = "crm".into();
    let token = signed(&w, "lms-a", &e).await;
    untrusted(&w.service.issue_from_event(&token).await.unwrap_err());
}

/// A revocation naming the same loan reference in another tenant touches
/// nothing there: the same reference in two tenants is two loans.
#[tokio::test]
async fn a_revocation_for_a_loan_id_reaches_only_its_own_tenant() {
    let w = world();
    let a = signed(&w, "lms-a", &event_for(A, "evt-1", "loan.dpd30")).await;
    let b = signed(&w, "lms-b", &event_for(B, "evt-1", "loan.dpd30")).await;
    let ma = w.service.issue_from_event(&a).await.unwrap();
    let mb = w.service.issue_from_event(&b).await.unwrap();

    let paid_in_a = signed(&w, "lms-a", &event_for(A, "pay-1", "loan.paid")).await;
    let done = w.service.revoke_from_event(&paid_in_a).await.unwrap();
    assert_eq!(
        done.revoked,
        std::slice::from_ref(&ma.mandate.id),
        "only A's mandate"
    );
    assert!(w.service.verify_active(&ma.token).await.is_err());
    assert!(
        w.service.verify_active(&mb.token).await.is_ok(),
        "B untouched"
    );

    // Tenant B's payment with the same event id is its own event.
    let paid_in_b = signed(&w, "lms-b", &event_for(B, "pay-1", "loan.paid")).await;
    let done = w.service.revoke_from_event(&paid_in_b).await.unwrap();
    assert_eq!(done.revoked, [mb.mandate.id]);
}

/// Tenant A's key, validly signed, naming a loan that exists only in B:
/// the event is A's, so it finds nothing of B's.
#[tokio::test]
async fn a_revocation_signed_for_a_names_no_loan_of_b() {
    let w = world();
    let b = signed(&w, "lms-b", &event_for(B, "evt-1", "loan.dpd30")).await;
    let mb = w.service.issue_from_event(&b).await.unwrap();
    let paid_in_a = signed(&w, "lms-a", &event_for(A, "pay-9", "loan.paid")).await;
    let done = w.service.revoke_from_event(&paid_in_a).await.unwrap();
    assert!(done.revoked.is_empty());
    assert!(w.service.verify_active(&mb.token).await.is_ok());
}

#[test]
fn a_configuration_that_blurs_the_binding_does_not_load() {
    let mut sor = InMemoryKeyProvider::new();
    let mut kavach = InMemoryKeyProvider::new();
    let good = registered(&mut sor);
    assert!(config(good.clone(), &mut kavach).validate().is_ok());

    // The same key id for two tenants.
    let mut twice = good.clone();
    twice[1].key.kid = good[0].key.kid.clone();
    let err = config(twice, &mut kavach).validate().unwrap_err();
    assert!(err.message.contains("registered twice"), "{err}");

    // The same public key under two key ids, for two tenants.
    let mut same_key = good.clone();
    same_key[1].key.bytes = good[0].key.bytes;
    let err = config(same_key, &mut kavach).validate().unwrap_err();
    assert!(err.message.contains("same public key"), "{err}");

    // No tenant: nothing is inferred.
    let mut blank = good;
    blank[0].tenant_id = String::new();
    let err = config(blank, &mut kavach).validate().unwrap_err();
    assert!(err.message.contains("tenant"), "{err}");
}
