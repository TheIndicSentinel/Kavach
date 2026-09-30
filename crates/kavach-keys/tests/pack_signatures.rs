use std::path::PathBuf;

use kavach_keys::{
    sign_pack, signature_path, verify_pack_file, verify_pack_signature, InMemoryKeyProvider,
    TrustedSigners,
};
use kavach_ports::ErrorClass;

fn temp_pack(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("kavach-sig-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/finance/v0.yaml");
    let path = dir.join("v0.yaml");
    std::fs::copy(src, &path).unwrap();
    path
}

fn digest(path: &PathBuf) -> String {
    kavach_policy::pack_digest(&std::fs::read(path).unwrap())
}

fn signer() -> (InMemoryKeyProvider, TrustedSigners) {
    let mut provider = InMemoryKeyProvider::new();
    let public = provider.insert_seed("pack-signer-1", [7u8; 32]).unwrap();
    (provider, TrustedSigners::new(vec![public]).unwrap())
}

#[tokio::test]
async fn signed_pack_verifies_and_tamper_is_rejected() {
    let (provider, trusted) = signer();
    let pack = temp_pack("ok");
    let sig = sign_pack(&provider, "pack-signer-1", &pack).await.unwrap();
    std::fs::write(signature_path(&pack), serde_json::to_string(&sig).unwrap()).unwrap();
    verify_pack_file(&pack, &digest(&pack), &trusted).expect("valid signature");

    // Any byte change to the pack invalidates the signature.
    let original = std::fs::read_to_string(&pack).unwrap();
    std::fs::write(&pack, format!("{original}\n# edited\n")).unwrap();
    let err = verify_pack_file(&pack, &digest(&pack), &trusted).unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);
}

#[tokio::test]
async fn missing_untrusted_or_forged_signatures_are_rejected() {
    let (provider, trusted) = signer();
    let pack = temp_pack("bad");
    let pack_digest = digest(&pack);

    // Missing signature file.
    let err = verify_pack_file(&pack, &pack_digest, &trusted).unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);

    // Signed by a key that is not trusted.
    let mut other = InMemoryKeyProvider::new();
    other.insert_seed("pack-signer-1", [9u8; 32]).unwrap();
    let forged = sign_pack(&other, "pack-signer-1", &pack).await.unwrap();
    assert_eq!(
        verify_pack_signature(&forged, &pack_digest, &trusted)
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    // Unknown signer kid.
    let mut unknown = InMemoryKeyProvider::new();
    unknown.insert_seed("someone-else", [7u8; 32]).unwrap();
    let sig = sign_pack(&unknown, "someone-else", &pack).await.unwrap();
    assert_eq!(
        verify_pack_signature(&sig, &pack_digest, &trusted)
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    // Valid signature presented for a different digest.
    let good = sign_pack(&provider, "pack-signer-1", &pack).await.unwrap();
    assert!(verify_pack_signature(&good, "sha256:00", &trusted).is_err());
}

#[test]
fn trusted_signers_file_is_strict() {
    let key = "11".repeat(32);
    assert!(TrustedSigners::from_json(&format!(
        r#"{{"signers":[{{"kid":"k1","public_key":"{key}"}}]}}"#
    ))
    .is_ok());
    for bad in [
        r#"{"signers":[]}"#,
        r#"{"signers":[{"kid":"k1","public_key":"abcd"}]}"#,
        r#"{"signers":[{"kid":"../x","public_key":"11"}]}"#,
        r#"{"signers":[{"kid":"k1","public_key":"11","extra":1}]}"#,
    ] {
        assert!(TrustedSigners::from_json(bad).is_err(), "{bad}");
    }
}

#[test]
fn signer_roles_are_explicit_and_strict() {
    let key = "11".repeat(32);
    let entry =
        |roles: &str| format!(r#"{{"signers":[{{"kid":"k1","public_key":"{key}"{roles}}}]}}"#);
    assert!(TrustedSigners::from_json(&entry(r#","roles":["pack","model"]"#)).is_ok());
    assert!(TrustedSigners::from_json(&entry(r#","roles":["model"]"#)).is_ok());
    for bad in [
        r#","roles":[]"#,
        r#","roles":["admin"]"#,
        r#","roles":["Pack"]"#,
    ] {
        assert!(TrustedSigners::from_json(&entry(bad)).is_err(), "{bad}");
    }
}

#[tokio::test]
async fn model_signatures_bind_id_version_digest_and_role() {
    use kavach_keys::{sign_model, verify_model_signature, ModelIdentity, SignerRole};

    let mut provider = InMemoryKeyProvider::new();
    let public = provider.insert_seed("model-signer-1", [9u8; 32]).unwrap();
    let identity = ModelIdentity {
        model_id: "credit-underwriting-v1",
        model_version: "1.1.0",
        model_sha256: "sha256:aa",
    };
    let signature = sign_model(&provider, "model-signer-1", identity)
        .await
        .unwrap();

    let model_signer =
        TrustedSigners::with_roles(vec![(public.clone(), vec![SignerRole::Model])]).unwrap();
    verify_model_signature(&signature, identity, &model_signer).unwrap();

    // Another version, id or digest does not verify.
    for other in [
        ModelIdentity {
            model_version: "1.0.0",
            ..identity
        },
        ModelIdentity {
            model_id: "other",
            ..identity
        },
        ModelIdentity {
            model_sha256: "sha256:bb",
            ..identity
        },
    ] {
        assert!(verify_model_signature(&signature, other, &model_signer).is_err());
    }
    // A pack-only signer cannot sign models, and the reverse.
    let pack_signer = TrustedSigners::new(vec![public]).unwrap();
    let err = verify_model_signature(&signature, identity, &pack_signer).unwrap_err();
    assert!(
        err.to_string().contains("not trusted to sign models"),
        "{err}"
    );
}
