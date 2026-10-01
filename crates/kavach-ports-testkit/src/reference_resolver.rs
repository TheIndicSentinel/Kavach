//! `ReferenceResolver` contract (H5b). Every adapter is seeded with
//! [`seed`] (synthetic numbers only) and must pass [`conformance`].

use kavach_ports::{ErrorClass, PortError, ReferenceResolver};

pub const TENANT: &str = "conformance";

/// One reference and its destinations per channel.
#[derive(Debug, Clone)]
pub struct SeedEntry {
    pub tenant_id: &'static str,
    pub subject_ref: &'static str,
    pub destinations: &'static [(&'static str, &'static str)],
}

/// Synthetic data: `+910…` numbers are never assigned to Indian mobiles
/// (those start with 6-9).
pub fn seed() -> Vec<SeedEntry> {
    vec![
        SeedEntry {
            tenant_id: TENANT,
            subject_ref: "ref:borrower:B-1",
            destinations: &[("whatsapp", "+910000000001"), ("voice", "+910000000002")],
        },
        SeedEntry {
            tenant_id: TENANT,
            subject_ref: "ref:borrower:B-2",
            destinations: &[("whatsapp", "+910000000003")],
        },
        SeedEntry {
            tenant_id: "other-tenant",
            subject_ref: "ref:borrower:B-9",
            destinations: &[("whatsapp", "+910000000009")],
        },
    ]
}

fn no_destination(text: &str) {
    for entry in seed() {
        for (_, value) in entry.destinations {
            assert!(
                !text.contains(value) && !text.contains(&value[3..]),
                "a destination leaked: {text}"
            );
        }
    }
}

async fn refused<R: ReferenceResolver>(
    resolver: &R,
    tenant: &str,
    subject_ref: &str,
    channel: &str,
    class: ErrorClass,
) {
    let err: PortError = resolver
        .resolve(tenant, subject_ref, channel)
        .await
        .expect_err("no destination");
    assert_eq!(
        err.class, class,
        "{tenant} {subject_ref} {channel}: {}",
        err.message
    );
    no_destination(&err.message);
}

/// The contract every resolver must meet, seeded with [`seed`].
pub async fn conformance<R: ReferenceResolver>(resolver: &R) {
    // Resolves per channel.
    let d = resolver
        .resolve(TENANT, "ref:borrower:B-1", "whatsapp")
        .await
        .expect("resolves");
    assert_eq!(d.expose(), "+910000000001");
    assert_eq!(format!("{d:?}"), "Destination(<redacted>)");
    let d = resolver
        .resolve(TENANT, "ref:borrower:B-1", "voice")
        .await
        .expect("resolves");
    assert_eq!(d.expose(), "+910000000002");

    // No address for the channel, unknown reference, another tenant's.
    refused(
        resolver,
        TENANT,
        "ref:borrower:B-2",
        "voice",
        ErrorClass::Rejected,
    )
    .await;
    refused(
        resolver,
        TENANT,
        "ref:borrower:B-404",
        "whatsapp",
        ErrorClass::Rejected,
    )
    .await;
    refused(
        resolver,
        TENANT,
        "ref:borrower:B-9",
        "whatsapp",
        ErrorClass::Rejected,
    )
    .await;

    // Malformed: a raw number as the reference, an empty channel.
    refused(
        resolver,
        TENANT,
        "+910000000001",
        "whatsapp",
        ErrorClass::Invalid,
    )
    .await;
    refused(
        resolver,
        TENANT,
        "ref:borrower:B-1",
        "",
        ErrorClass::Invalid,
    )
    .await;

    no_destination(&resolver.describe());
}
