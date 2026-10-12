//! Known-answer vectors for mandate and system-of-record event tokens
//! (`docs/specs/mandate-and-sor-event.md`).
//!
//! `tests/vectors/mandate-v1.json` is written once from fixed keys, ids and
//! times (test keys only) and checked in, so a change to the token format
//! shows up as a failure here. An independent verifier is written against
//! it (`conformance/kavach_verify.py mandate`).
//!
//! Regenerate only on a deliberate format change:
//! `cargo test -p kavach-mandate --test vectors -- --ignored generate`.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use kavach_domain::mandate::{
    ContactWindow, DelegationRules, Mandate, MandateSource, SorEvent, TimeZoneId,
    MANDATE_FORMAT_VERSION,
};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::content_sha256;
use kavach_mandate::jws::{self, KeySet, TYP_MANDATE, TYP_SOR_EVENT};
use kavach_ports::{KeyProvider, PublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/mandate-v1.json");
const MANDATE_KID: &str = "kavach-mandate-kat";
const MANDATE_SEED: [u8; 32] = [31u8; 32];
const SOR_KID: &str = "lms-issuer-kat";
const SOR_SEED: [u8; 32] = [32u8; 32];
const OTHER_KID: &str = "crm-issuer-kat";
const OTHER_SEED: [u8; 32] = [33u8; 32];
const TENANT: &str = "nbfc-demo";

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap()
}

fn provider() -> (InMemoryKeyProvider, PublicKey, PublicKey, PublicKey) {
    let mut p = InMemoryKeyProvider::new();
    let m = p.insert_seed(MANDATE_KID, MANDATE_SEED).unwrap();
    let s = p.insert_seed(SOR_KID, SOR_SEED).unwrap();
    let o = p.insert_seed(OTHER_KID, OTHER_SEED).unwrap();
    (p, m, s, o)
}

fn window() -> ContactWindow {
    ContactWindow {
        tz: TimeZoneId::AsiaKolkata,
        from_min: 8 * 60,
        to_min: 19 * 60,
        max_per_day: 3,
    }
}

fn root() -> Mandate {
    Mandate {
        mv: MANDATE_FORMAT_VERSION,
        id: "00000000-0000-4000-8000-000000000001".into(),
        tenant_id: TENANT.into(),
        issuer: "kavach-kat".into(),
        source: MandateSource {
            system: "lms".into(),
            record_ref: "lms:loan/B-9382".into(),
            event_id: "evt-dpd30-1".into(),
        },
        principal: "collections-ops".into(),
        holder: "collections-agent".into(),
        subject_ref: "ref:borrower:B-9382".into(),
        purpose: "loan_recovery".into(),
        consent_refs: set(&["C-1"]),
        actions: set(&["read_fields", "send_reminder", "place_call"]),
        data_fields: set(&["name", "overdue_amount", "loan_ref"]),
        channels: set(&["whatsapp", "voice"]),
        window: Some(window()),
        ceilings: BTreeMap::from([("waiver_bps".to_string(), 1000)]),
        delegation: DelegationRules {
            max_depth: 1,
            allowed_agents: set(&["translator-agent"]),
        },
        parent_id: None,
        depth: 0,
        nbf: t0(),
        exp: t0() + chrono::Duration::days(7),
        nonce: "00000000-0000-4000-8000-0000000000a1".into(),
    }
}

fn child() -> Mandate {
    let parent = root();
    Mandate {
        id: "00000000-0000-4000-8000-000000000002".into(),
        holder: "translator-agent".into(),
        actions: set(&["read_fields"]),
        data_fields: set(&["name", "loan_ref"]),
        channels: set(&["voice"]),
        window: Some(ContactWindow {
            from_min: 10 * 60,
            max_per_day: 1,
            ..window()
        }),
        ceilings: BTreeMap::new(),
        delegation: DelegationRules {
            max_depth: 1,
            allowed_agents: BTreeSet::new(),
        },
        parent_id: Some(parent.id.clone()),
        depth: 1,
        nbf: t0() + chrono::Duration::seconds(60),
        exp: t0() + chrono::Duration::days(1),
        nonce: "00000000-0000-4000-8000-0000000000a2".into(),
        ..parent
    }
}

fn event(id: &str, kind: &str, at: DateTime<Utc>, nonce: &str) -> SorEvent {
    SorEvent {
        event_id: id.into(),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        event_type: kind.into(),
        record_ref: "lms:loan/B-9382".into(),
        subject_ref: "ref:borrower:B-9382".into(),
        principal: "collections-ops".into(),
        consent_refs: set(&["C-1"]),
        assigned_agent: "collections-agent".into(),
        occurred_at: at,
        nonce: nonce.into(),
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A token with exactly the bytes given for header and payload, signed.
fn raw(provider: &InMemoryKeyProvider, kid: &str, header: &[u8], payload: &[u8]) -> String {
    let input = format!("{}.{}", b64(header), b64(payload));
    let sig = tokio_block(provider.sign(kid, input.as_bytes())).unwrap();
    format!("{input}.{}", b64(&sig))
}

fn tokio_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn header(kid: &str, typ: &str) -> Vec<u8> {
    format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"{typ}"}}"#).into_bytes()
}

fn jcs(value: &Value) -> Vec<u8> {
    kavach_ports::jcs::to_vec(value).unwrap()
}

fn decode_payload(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn token_of<T: serde::Serialize>(p: &InMemoryKeyProvider, kid: &str, typ: &str, v: &T) -> String {
    tokio_block(jws::sign(p, kid, typ, v)).unwrap()
}

fn build() -> Value {
    let (p, m, s, o) = provider();
    let jwk =
        |k: &PublicKey| json!({"kty": "OKP", "crv": "Ed25519", "kid": k.kid, "x": b64(&k.bytes)});
    let root_token = token_of(&p, MANDATE_KID, TYP_MANDATE, &root());
    let child_token = token_of(&p, MANDATE_KID, TYP_MANDATE, &child());
    let dpd = event("evt-dpd30-1", "loan.dpd30", t0(), "n-1");
    let paid = event(
        "evt-paid-1",
        "loan.paid",
        t0() + chrono::Duration::days(2),
        "n-2",
    );
    let dpd_token = token_of(&p, SOR_KID, TYP_SOR_EVENT, &dpd);
    let paid_token = token_of(&p, SOR_KID, TYP_SOR_EVENT, &paid);

    // The same event in non-canonical or malformed forms, signed by the
    // right key so that only the form is wrong.
    let good = serde_json::to_value(&dpd).unwrap();
    let canonical = String::from_utf8(jcs(&good)).unwrap();
    // Swap the first two members: canonical order is alphabetical.
    let members: Vec<&str> = canonical[1..canonical.len() - 1].splitn(3, ',').collect();
    let reordered = format!("{{{},{},{}}}", members[1], members[0], members[2]);
    let mut extra = good.clone();
    extra["note"] = "x".into();
    let mut offset = good.clone();
    offset["occurred_at"] = "2026-10-01T05:30:00+00:00".into();
    let mut fraction = good.clone();
    fraction["occurred_at"] = "2026-10-01T05:30:00.000Z".into();
    let float_text = String::from_utf8(jcs(&serde_json::to_value(root()).unwrap()))
        .unwrap()
        .replace(r#""waiver_bps":1000"#, r#""waiver_bps":1000.0"#);
    let flipped = {
        let mut parts: Vec<String> = dpd_token.split('.').map(String::from).collect();
        let mut sig = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
        sig[0] ^= 1;
        parts[2] = b64(&sig);
        parts.join(".")
    };
    let duplicated = {
        let text = String::from_utf8(jcs(&good)).unwrap();
        text.replacen(r#""nonce":"n-1""#, r#""nonce":"n-1","nonce":"n-1""#, 1)
    };
    let mut repeated = good.clone();
    repeated["consent_refs"] = json!(["C-1", "C-1"]);
    let padded = {
        let mut parts: Vec<String> = dpd_token.split('.').map(String::from).collect();
        parts[1].push('=');
        parts.join(".")
    };
    let refused = json!([
        {"name": "bad-signature", "typ": TYP_SOR_EVENT, "token": flipped},
        {"name": "wrong-typ", "typ": TYP_SOR_EVENT, "token": root_token},
        {"name": "unknown-key", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, &header("unknown-kat", TYP_SOR_EVENT), &jcs(&good))},
        {"name": "payload-not-canonical", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, &header(SOR_KID, TYP_SOR_EVENT), reordered.as_bytes())},
        {"name": "header-not-canonical", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, br#"{"typ":"kavach-sor-event+jws","alg":"EdDSA","kid":"lms-issuer-kat"}"#, &jcs(&good))},
        {"name": "unknown-member", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, &header(SOR_KID, TYP_SOR_EVENT), &jcs(&extra))},
        {"name": "time-with-offset", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, &header(SOR_KID, TYP_SOR_EVENT), &jcs(&offset))},
        {"name": "time-with-zero-fraction", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, &header(SOR_KID, TYP_SOR_EVENT), &jcs(&fraction))},
        {"name": "non-integer-number", "typ": TYP_MANDATE,
         "token": raw(&p, MANDATE_KID, &header(MANDATE_KID, TYP_MANDATE), float_text.as_bytes())},
        {"name": "duplicate-member-name", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, &header(SOR_KID, TYP_SOR_EVENT), duplicated.as_bytes())},
        {"name": "set-with-repeat", "typ": TYP_SOR_EVENT,
         "token": raw(&p, SOR_KID, &header(SOR_KID, TYP_SOR_EVENT), &jcs(&repeated))},
        {"name": "four-parts", "typ": TYP_SOR_EVENT, "token": format!("{dpd_token}.AAAA")},
        {"name": "padded-base64", "typ": TYP_SOR_EVENT,
         "token": padded}
    ]);

    json!({
        "description": "Kavach mandate and system-of-record event tokens v1: compact JWS, EdDSA, RFC 8785 canonical header and payload. Test keys only.",
        "mandate_key": jwk(&m),
        "sor_issuers": [
            {"system": "lms", "key": jwk(&s)},
            {"system": "crm", "key": jwk(&o)},
        ],
        "freshness_seconds": 300,
        "mandates": [
            {"name": "root", "token": root_token, "payload": decode_payload(&root_token)},
            {"name": "child", "token": child_token, "payload": decode_payload(&child_token),
             "parent": "root"},
        ],
        "events": [
            {"name": "issuing", "token": dpd_token, "payload": decode_payload(&dpd_token),
             "content_sha256": content_sha256(&dpd).unwrap(),
             "signed_payload_sha256": hex::encode(Sha256::digest(jcs(&good))),
             "fresh_at": t0().timestamp()},
            {"name": "revoking", "token": paid_token, "payload": decode_payload(&paid_token),
             "content_sha256": content_sha256(&paid).unwrap(),
             "fresh_at": (t0() + chrono::Duration::days(2)).timestamp(),
             "revokes": {"mandate": "root", "reason": "payment"},
             "spares_issued_after": true},
        ],
        "refused": refused,
    })
}

#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate() {
    std::fs::create_dir_all(std::path::Path::new(PATH).parent().unwrap()).unwrap();
    std::fs::write(PATH, serde_json::to_string_pretty(&build()).unwrap() + "\n").unwrap();
}

fn vector() -> Value {
    serde_json::from_slice(&std::fs::read(PATH).expect("vector file")).unwrap()
}

fn key_of(v: &Value) -> PublicKey {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(v["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    PublicKey {
        kid: v["kid"].as_str().unwrap().into(),
        algorithm: kavach_ports::KeyAlgorithm::Ed25519,
        bytes,
    }
}

#[test]
fn the_checked_in_tokens_verify_to_the_expected_content() {
    let v = vector();
    let mandate_keys = KeySet::new([key_of(&v["mandate_key"])]);
    for item in v["mandates"].as_array().unwrap() {
        let token = item["token"].as_str().unwrap();
        let (kid, mandate): (String, Mandate) =
            jws::verify(token, TYP_MANDATE, &mandate_keys).unwrap();
        assert_eq!(kid, MANDATE_KID);
        assert_eq!(serde_json::to_value(&mandate).unwrap(), item["payload"]);
    }
    let sor = KeySet::new(
        v["sor_issuers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| key_of(&i["key"])),
    );
    for item in v["events"].as_array().unwrap() {
        let token = item["token"].as_str().unwrap();
        let (_, event): (String, SorEvent) = jws::verify(token, TYP_SOR_EVENT, &sor).unwrap();
        assert_eq!(serde_json::to_value(&event).unwrap(), item["payload"]);
        assert_eq!(content_sha256(&event).unwrap(), item["content_sha256"]);
    }
}

#[test]
fn the_generator_is_deterministic_and_matches_the_file() {
    assert_eq!(build(), vector());
}

#[test]
fn every_negative_vector_is_refused() {
    let v = vector();
    let all = KeySet::new(
        [
            &v["mandate_key"],
            &v["sor_issuers"][0]["key"],
            &v["sor_issuers"][1]["key"],
        ]
        .into_iter()
        .map(key_of),
    );
    for case in v["refused"].as_array().unwrap() {
        let (token, typ) = (
            case["token"].as_str().unwrap(),
            case["typ"].as_str().unwrap(),
        );
        let refused = if typ == TYP_MANDATE {
            jws::verify::<Mandate>(token, typ, &all).is_err()
        } else {
            jws::verify::<SorEvent>(token, typ, &all).is_err()
        };
        assert!(refused, "{} was accepted", case["name"]);
    }
}
