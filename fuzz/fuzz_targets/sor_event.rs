//! A system-of-record event payload (any bytes), signed by the registered
//! `lms` issuer, through the whole issuance path: verification, issuer
//! binding, freshness, replay guard, template, passport and consent checks,
//! mandate signing and storage.
//!
//! Invariants when an event issues a mandate: the mandate verifies as
//! active, a retry of the event finds the same mandate, and issuing from
//! the same event again is refused (replay).

#![no_main]

use kavach_fuzz::{block_on, mandate_service, sign_raw, SIGNING_SEED};
use libfuzzer_sys::fuzz_target;

const HEADER: &[u8] = br#"{"alg":"EdDSA","kid":"lms-issuer-1","typ":"kavach-sor-event+jws"}"#;

fuzz_target!(|payload: &[u8]| {
    let token = sign_raw(&SIGNING_SEED, HEADER, payload);
    let service = mandate_service();
    block_on(async {
        let Ok(issued) = service.issue_from_event(&token).await else {
            return;
        };
        let active = service
            .verify_active(&issued.token)
            .await
            .expect("an issued mandate verifies");
        assert_eq!(active.id, issued.mandate.id);
        let existing = service
            .existing_for_event(&token)
            .await
            .expect("a retry finds the event")
            .expect("the event issued a mandate");
        assert_eq!(existing.mandate.id, issued.mandate.id);
        assert!(
            service.issue_from_event(&token).await.is_err(),
            "a replayed event must not issue twice"
        );
    });
});
