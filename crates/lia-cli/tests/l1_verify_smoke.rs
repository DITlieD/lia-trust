use std::fs;
use std::path::PathBuf;
use std::process::Command;

use lia_journal::SigningIdentity;
use lia_verify::build_demo_bundle;

fn lia_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lia"))
}

#[test]
fn verify_known_good_exit_zero() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let journal = SigningIdentity::generate("journal");
    let verifier = SigningIdentity::generate("verifier");
    let (bundle, _) = build_demo_bundle(dir.path(), &journal, &verifier).expect("bundle");
    let secret = hex::encode(verifier.signing_key.to_bytes());

    let status = Command::new(lia_bin())
        .arg("verify")
        .arg(&bundle)
        .arg("--verifier-secret-key-hex")
        .arg(&secret)
        .arg("--verifier-key-id")
        .arg("verifier")
        .status()
        .expect("spawn lia verify");
    assert!(status.success(), "known-good bundle must exit 0");
}

#[test]
fn verify_corrupted_hash_nonzero() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let journal = SigningIdentity::generate("journal");
    let verifier = SigningIdentity::generate("verifier");
    let (bundle, _) = build_demo_bundle(dir.path(), &journal, &verifier).expect("bundle");

    let artifact = bundle.join("evidence/artifact.bin");
    let mut bytes = fs::read(&artifact).expect("read");
    bytes[0] ^= 0x01;
    fs::write(&artifact, bytes).expect("corrupt");

    let status = Command::new(lia_bin())
        .arg("verify")
        .arg(&bundle)
        .status()
        .expect("spawn lia verify");
    assert!(!status.success(), "corrupted evidence hash must be NONZERO");
}

#[test]
fn gate_evaluate_frozen_exit_codes() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let journal = SigningIdentity::generate("journal");
    let verifier = SigningIdentity::generate("verifier");
    let (bundle, _) = build_demo_bundle(dir.path(), &journal, &verifier).expect("bundle");

    let ok = Command::new(lia_bin())
        .arg("gate")
        .arg("--rules")
        .arg(bundle.join("policy.frozen.yaml"))
        .arg("--evidence")
        .arg(bundle.join("evidence-set.json"))
        .status()
        .expect("spawn lia gate");
    assert!(ok.success(), "complete evidence must allow");

    let missing = dir.path().join("missing.json");
    fs::write(&missing, r#"{"items":{}}"#).expect("write");
    let denied = Command::new(lia_bin())
        .arg("gate")
        .arg("--rules")
        .arg(bundle.join("policy.frozen.yaml"))
        .arg("--evidence")
        .arg(&missing)
        .status()
        .expect("spawn lia gate deny");
    assert_eq!(
        denied.code(),
        Some(2),
        "missing evidence must deny with exit 2"
    );
}
