use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use lia_journal::{verify_chain, Journal, JournalError, SigningIdentity};
use lia_policy::{
    evaluate_frozen, freeze_policy_from_path, load_evidence_json, validate_reason_code,
    EvidenceItem, EvidenceSet, EvaluationReport,
};
use lia_protocol::{canonical_json, Event, JournalRow, SignerIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const BUNDLE_VERSION: &str = "lia-bundle-v1";
pub const VERIFICATION_REPORT_VERSION: &str = "lia-verification-report-v1";

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("journal: {0}")]
    Journal(#[from] JournalError),
    #[error("policy: {0}")]
    Policy(#[from] lia_policy::PolicyError),
    #[error("protocol: {0}")]
    Protocol(#[from] lia_protocol::ProtocolError),
    #[error("bundle: {0}")]
    Bundle(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("rejected: {0}")]
    Rejected(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRoot {
    pub keys: Vec<SignerIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningConfigSnapshot {
    pub gate_manifest_version: String,
    pub journal_signer_key_id: String,
    pub verifier_signer_key_id: String,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEntry {
    pub id: String,
    pub kind: String,
    pub relative_path: String,
    pub sha256: String,
    #[serde(default)]
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub bundle_version: String,
    pub run_id: Uuid,
    pub policy_hash: String,
    pub journal_path: String,
    pub policy_path: String,
    pub trust_root_path: String,
    pub signing_config_path: String,
    pub action_stream_path: String,
    pub evidence: Vec<EvidenceEntry>,
    #[serde(default)]
    pub evidence_set_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    pub report_version: String,
    pub run_id: Uuid,
    pub bundle_version: String,
    pub accepted: bool,
    pub reason_code: String,
    pub policy_hash: String,
    pub journal_rows: u64,
    pub evidence_checked: u64,
    pub findings: Vec<VerificationFinding>,
    pub gate_evaluation: Option<EvaluationReport>,
    pub verifier: SignerIdentity,
    pub signature_hex: String,
    pub timestamp: DateTime<Utc>,
}

pub fn verify_bundle(bundle_dir: impl AsRef<Path>) -> Result<VerificationReport, VerifyError> {
    let bundle_dir = bundle_dir.as_ref();
    let manifest = load_manifest(bundle_dir)?;
    if manifest.bundle_version != BUNDLE_VERSION {
        return Err(VerifyError::Bundle(format!(
            "unsupported bundle_version {}",
            manifest.bundle_version
        )));
    }

    let trust_root = load_trust_root(bundle_dir.join(&manifest.trust_root_path))?;
    let signing_config = load_signing_config(bundle_dir.join(&manifest.signing_config_path))?;
    let verifier_key = trust_root
        .keys
        .iter()
        .find(|k| k.key_id == signing_config.verifier_signer_key_id)
        .cloned()
        .ok_or_else(|| {
            VerifyError::Rejected(format!(
                "TRUST_ROOT_MISSING: verifier key_id '{}' not in archived trust-root",
                signing_config.verifier_signer_key_id
            ))
        })?;

    let mut findings = Vec::new();
    let mut accepted = true;
    let mut reason_code = "ACCEPTED".to_string();

    let journal_path = bundle_dir.join(&manifest.journal_path);
    if !journal_path.is_file() {
        accepted = false;
        reason_code = "BUNDLE_INCOMPLETE".into();
        findings.push(finding("BUNDLE_INCOMPLETE", "journal.db missing"));
    } else if let Err(e) = verify_chain(&journal_path) {
        accepted = false;
        reason_code = "JOURNAL_INTEGRITY_FAILED".into();
        findings.push(finding(
            "JOURNAL_INTEGRITY_FAILED",
            format!("journal verify failed: {e}"),
        ));
    }

    let journal_rows = if journal_path.is_file() {
        match Journal::open_readonly(&journal_path) {
            Ok(j) => match j.load_rows() {
                Ok(rows) => {
                    if let Err(e) =
                        assert_signers_in_trust_root(&rows, &trust_root, &signing_config)
                    {
                        accepted = false;
                        reason_code = "SIGNATURE_INVALID".into();
                        findings.push(finding("SIGNATURE_INVALID", e));
                    }
                    if let Err(e) = replay_action_stream(
                        bundle_dir,
                        &manifest,
                        &rows,
                        &manifest.run_id,
                    ) {
                        accepted = false;
                        reason_code = "REPLAY_MISMATCH".into();
                        findings.push(finding("REPLAY_MISMATCH", e));
                    }
                    rows.len() as u64
                }
                Err(e) => {
                    accepted = false;
                    reason_code = "JOURNAL_INTEGRITY_FAILED".into();
                    findings.push(finding(
                        "JOURNAL_INTEGRITY_FAILED",
                        format!("load_rows failed: {e}"),
                    ));
                    0
                }
            },
            Err(e) => {
                accepted = false;
                reason_code = "JOURNAL_INTEGRITY_FAILED".into();
                findings.push(finding(
                    "JOURNAL_INTEGRITY_FAILED",
                    format!("open journal failed: {e}"),
                ));
                0
            }
        }
    } else {
        0
    };

    let mut evidence_checked = 0u64;
    let mut evidence_ok = true;
    match recompute_evidence_hashes(bundle_dir, &manifest.evidence) {
        Ok(n) => evidence_checked = n,
        Err(e) => {
            accepted = false;
            evidence_ok = false;
            reason_code = "HASH_MISMATCH".into();
            findings.push(finding("HASH_MISMATCH", e));
        }
    }

    let policy_path = bundle_dir.join(&manifest.policy_path);
    let frozen = match freeze_policy_from_path(&policy_path) {
        Ok(f) => {
            if f.policy_hash != manifest.policy_hash {
                accepted = false;
                evidence_ok = false;
                reason_code = "HASH_MISMATCH".into();
                findings.push(finding(
                    "HASH_MISMATCH",
                    format!(
                        "policy_hash mismatch: manifest {} recomputed {}",
                        manifest.policy_hash, f.policy_hash
                    ),
                ));
            }
            Some(f)
        }
        Err(e) => {
            accepted = false;
            evidence_ok = false;
            reason_code = "BUNDLE_INCOMPLETE".into();
            findings.push(finding(
                "BUNDLE_INCOMPLETE",
                format!("policy load failed: {e}"),
            ));
            None
        }
    };

    let gate_evaluation = if evidence_ok {
        match (&frozen, &manifest.evidence_set_path) {
            (Some(frozen), Some(rel)) => {
                let evidence_path = bundle_dir.join(rel);
                match load_evidence_json(&evidence_path) {
                    Ok(evidence) => match evaluate_frozen(frozen, &evidence) {
                        Ok(report) => {
                            if !matches!(
                                report.overall,
                                lia_protocol::Verdict::Allow | lia_protocol::Verdict::Advisory
                            ) {
                                accepted = false;
                                if reason_code == "ACCEPTED" {
                                    reason_code = report.reason_code.clone();
                                }
                                findings.push(finding(
                                    &report.reason_code,
                                    format!("gate overall {:?}", report.overall),
                                ));
                            }
                            Some(report)
                        }
                        Err(e) => {
                            accepted = false;
                            reason_code = "RULE_CONDITION_FAILED".into();
                            findings.push(finding(
                                "RULE_CONDITION_FAILED",
                                format!("gate eval failed: {e}"),
                            ));
                            None
                        }
                    },
                    Err(e) => {
                        accepted = false;
                        reason_code = "BUNDLE_INCOMPLETE".into();
                        findings.push(finding(
                            "BUNDLE_INCOMPLETE",
                            format!("evidence set load failed: {e}"),
                        ));
                        None
                    }
                }
            }
            (Some(_), None) => None,
            (None, _) => None,
        }
    } else {
        None
    };

    if !accepted && reason_code == "ACCEPTED" {
        reason_code = "REJECTED".into();
    }
    if accepted {
        reason_code = "ACCEPTED".into();
        findings.clear();
    }
    validate_reason_code(&reason_code)?;

    let mut report = VerificationReport {
        report_version: VERIFICATION_REPORT_VERSION.to_string(),
        run_id: manifest.run_id,
        bundle_version: manifest.bundle_version.clone(),
        accepted: false,
        reason_code: reason_code.clone(),
        policy_hash: manifest.policy_hash.clone(),
        journal_rows,
        evidence_checked,
        findings: findings.clone(),
        gate_evaluation,
        verifier: verifier_key.clone(),
        signature_hex: String::new(),
        timestamp: Utc::now(),
    };

    report.accepted = accepted && reason_code == "ACCEPTED";
    if !report.accepted && report.reason_code == "ACCEPTED" {
        report.reason_code = "REJECTED".into();
    }

    Ok(report)
}

pub fn sign_verification_report(
    report: &mut VerificationReport,
    identity: &SigningIdentity,
) -> Result<(), VerifyError> {
    if identity.key_id != report.verifier.key_id {
        return Err(VerifyError::Crypto(format!(
            "signer key_id '{}' != report verifier '{}'",
            identity.key_id, report.verifier.key_id
        )));
    }
    let pk = identity.public_key_hex();
    if pk != report.verifier.public_key_hex {
        return Err(VerifyError::Crypto(
            "signer public key does not match archived trust-root verifier key".into(),
        ));
    }
    report.signature_hex.clear();
    let payload = report_signing_payload(report)?;
    let sig = identity.signing_key.sign(payload.as_bytes());
    report.signature_hex = hex::encode(sig.to_bytes());
    Ok(())
}

pub fn verify_report_signature(report: &VerificationReport) -> Result<(), VerifyError> {
    if report.signature_hex.is_empty() {
        return Err(VerifyError::Rejected(
            "VERIFICATION-REPORT has empty signature".into(),
        ));
    }
    let mut unsigned = report.clone();
    unsigned.signature_hex.clear();
    let payload = report_signing_payload(&unsigned)?;
    verify_ed25519(
        &report.verifier.public_key_hex,
        payload.as_bytes(),
        &report.signature_hex,
    )
}

pub fn write_verification_report(
    report: &VerificationReport,
    path: impl AsRef<Path>,
) -> Result<(), VerifyError> {
    let json = serde_json::to_vec_pretty(report)?;
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, json)?;
    Ok(())
}

pub fn build_demo_bundle(
    bundle_dir: impl AsRef<Path>,
    journal_identity: &SigningIdentity,
    verifier_identity: &SigningIdentity,
) -> Result<(PathBuf, Uuid), VerifyError> {
    let bundle_dir = bundle_dir.as_ref();
    fs::create_dir_all(bundle_dir.join("evidence"))?;

    let policy_yaml = r#"
policy_id: l1-demo
version: "1"
rules:
  - id: need-artifact
    risk_tier: security
    required_evidence:
      - key: artifact
        kind: sha256
    reason_code_on_fail: MISSING_EVIDENCE
"#;
    let policy_path = bundle_dir.join("policy.frozen.yaml");
    fs::write(&policy_path, policy_yaml)?;
    let frozen = freeze_policy_from_path(&policy_path)?;

    let artifact_bytes = b"lia-trust-l1-known-good";
    let artifact_sha = sha256_hex(artifact_bytes);
    let evidence_rel = "evidence/artifact.bin";
    fs::write(bundle_dir.join(evidence_rel), artifact_bytes)?;

    let mut evidence_items = BTreeMap::new();
    evidence_items.insert(
        "artifact".to_string(),
        EvidenceItem {
            sha256: Some(artifact_sha.clone()),
            value: None,
            bytes: Some(artifact_bytes.len() as u64),
        },
    );
    let evidence_set = EvidenceSet {
        items: evidence_items,
    };
    let evidence_set_path = bundle_dir.join("evidence-set.json");
    fs::write(
        &evidence_set_path,
        serde_json::to_vec_pretty(&evidence_set)?,
    )?;

    let run_id = Uuid::new_v4();
    let journal_path = bundle_dir.join("journal.db");
    let journal = Journal::create(&journal_path)?;
    let event = Event::EvidenceCaptured(lia_protocol::EvidenceCaptured {
        evidence_id: Uuid::new_v4(),
        kind: "artifact".into(),
        path: Some(evidence_rel.into()),
        sha256: artifact_sha.clone(),
        bytes: Some(artifact_bytes.len() as u64),
        timestamp: Utc::now(),
    });
    journal.append_signed(run_id, event, journal_identity)?;

    let rows = journal.load_rows()?;
    let stream_path = bundle_dir.join("action-stream.jsonl");
    write_action_stream(&stream_path, &rows)?;

    let trust_root = TrustRoot {
        keys: vec![
            journal_identity.signer_identity(),
            verifier_identity.signer_identity(),
        ],
    };
    fs::write(
        bundle_dir.join("trust-root.json"),
        serde_json::to_vec_pretty(&trust_root)?,
    )?;

    let signing_config = SigningConfigSnapshot {
        gate_manifest_version: lia_protocol::GATE_MANIFEST_VERSION.to_string(),
        journal_signer_key_id: journal_identity.key_id.clone(),
        verifier_signer_key_id: verifier_identity.key_id.clone(),
        captured_at: Utc::now(),
    };
    fs::write(
        bundle_dir.join("signing-config.json"),
        serde_json::to_vec_pretty(&signing_config)?,
    )?;

    let manifest = BundleManifest {
        bundle_version: BUNDLE_VERSION.to_string(),
        run_id,
        policy_hash: frozen.policy_hash,
        journal_path: "journal.db".into(),
        policy_path: "policy.frozen.yaml".into(),
        trust_root_path: "trust-root.json".into(),
        signing_config_path: "signing-config.json".into(),
        action_stream_path: "action-stream.jsonl".into(),
        evidence: vec![EvidenceEntry {
            id: "artifact".into(),
            kind: "artifact".into(),
            relative_path: evidence_rel.into(),
            sha256: artifact_sha,
            bytes: Some(artifact_bytes.len() as u64),
        }],
        evidence_set_path: Some("evidence-set.json".into()),
    };
    fs::write(
        bundle_dir.join("MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    let _ = frozen;
    Ok((bundle_dir.to_path_buf(), run_id))
}

pub fn build_gate_receipt_bundle(
    bundle_dir: impl AsRef<Path>,
    journal_path: impl AsRef<Path>,
    journal_identity: &SigningIdentity,
    verifier_identity: &SigningIdentity,
    outcome_json: &[u8],
) -> Result<PathBuf, VerifyError> {
    let bundle_dir = bundle_dir.as_ref();
    fs::create_dir_all(bundle_dir.join("evidence"))?;

    let policy_yaml = r#"
policy_id: gate-receipt
version: "1"
rules:
  - id: receipt-present
    risk_tier: quality
    required_evidence:
      - key: gate_receipt
        kind: present
    on_fail: advisory
"#;
    let policy_path = bundle_dir.join("policy.frozen.yaml");
    fs::write(&policy_path, policy_yaml)?;
    let frozen = freeze_policy_from_path(&policy_path)?;

    let evidence_rel = "evidence/outcome.json";
    fs::write(bundle_dir.join(evidence_rel), outcome_json)?;
    let artifact_sha = sha256_hex(outcome_json);

    fs::copy(journal_path.as_ref(), bundle_dir.join("journal.db"))?;
    let journal = Journal::open_readonly(bundle_dir.join("journal.db"))?;
    let rows = journal.load_rows()?;
    if rows.is_empty() {
        return Err(VerifyError::Bundle("journal has no rows".into()));
    }
    let run_id = rows[0].run_id;
    write_action_stream(&bundle_dir.join("action-stream.jsonl"), &rows)?;

    let trust_root = TrustRoot {
        keys: vec![
            journal_identity.signer_identity(),
            verifier_identity.signer_identity(),
        ],
    };
    fs::write(
        bundle_dir.join("trust-root.json"),
        serde_json::to_vec_pretty(&trust_root)?,
    )?;

    let signing_config = SigningConfigSnapshot {
        gate_manifest_version: lia_protocol::GATE_MANIFEST_VERSION.to_string(),
        journal_signer_key_id: journal_identity.key_id.clone(),
        verifier_signer_key_id: verifier_identity.key_id.clone(),
        captured_at: Utc::now(),
    };
    fs::write(
        bundle_dir.join("signing-config.json"),
        serde_json::to_vec_pretty(&signing_config)?,
    )?;

    let manifest = BundleManifest {
        bundle_version: BUNDLE_VERSION.to_string(),
        run_id,
        policy_hash: frozen.policy_hash,
        journal_path: "journal.db".into(),
        policy_path: "policy.frozen.yaml".into(),
        trust_root_path: "trust-root.json".into(),
        signing_config_path: "signing-config.json".into(),
        action_stream_path: "action-stream.jsonl".into(),
        evidence: vec![EvidenceEntry {
            id: "outcome".into(),
            kind: "gate_outcome".into(),
            relative_path: evidence_rel.into(),
            sha256: artifact_sha,
            bytes: Some(outcome_json.len() as u64),
        }],
        evidence_set_path: None,
    };
    fs::write(
        bundle_dir.join("MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    Ok(bundle_dir.to_path_buf())
}

fn load_manifest(bundle_dir: &Path) -> Result<BundleManifest, VerifyError> {
    let path = bundle_dir.join("MANIFEST.json");
    if !path.is_file() {
        return Err(VerifyError::Bundle(
            "MANIFEST.json missing from bundle".into(),
        ));
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn load_trust_root(path: impl AsRef<Path>) -> Result<TrustRoot, VerifyError> {
    let path = path.as_ref();
    if !path.is_file() {
        return Err(VerifyError::Rejected(
            "TRUST_ROOT_MISSING: trust-root.json not archived in bundle".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let root: TrustRoot = serde_json::from_slice(&bytes)?;
    if root.keys.is_empty() {
        return Err(VerifyError::Rejected(
            "TRUST_ROOT_MISSING: trust-root has no keys".into(),
        ));
    }
    Ok(root)
}

fn load_signing_config(path: impl AsRef<Path>) -> Result<SigningConfigSnapshot, VerifyError> {
    let path = path.as_ref();
    if !path.is_file() {
        return Err(VerifyError::Bundle(
            "signing-config.json missing from bundle".into(),
        ));
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn recompute_evidence_hashes(
    bundle_dir: &Path,
    entries: &[EvidenceEntry],
) -> Result<u64, String> {
    let mut checked = 0u64;
    for entry in entries {
        let path = bundle_dir.join(&entry.relative_path);
        if !path.is_file() {
            return Err(format!(
                "evidence file missing: {}",
                entry.relative_path
            ));
        }
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        let got = sha256_hex(&bytes);
        if !got.eq_ignore_ascii_case(&entry.sha256) {
            return Err(format!(
                "evidence '{}' hash mismatch: expected {}, got {}",
                entry.id, entry.sha256, got
            ));
        }
        if let Some(expected_len) = entry.bytes {
            if expected_len != bytes.len() as u64 {
                return Err(format!(
                    "evidence '{}' byte length mismatch: expected {expected_len}, got {}",
                    entry.id,
                    bytes.len()
                ));
            }
        }
        checked += 1;
    }
    Ok(checked)
}

fn assert_signers_in_trust_root(
    rows: &[JournalRow],
    trust_root: &TrustRoot,
    signing_config: &SigningConfigSnapshot,
) -> Result<(), String> {
    let allowed: BTreeSet<&str> = trust_root.keys.iter().map(|k| k.key_id.as_str()).collect();
    let key_map: BTreeMap<&str, &str> = trust_root
        .keys
        .iter()
        .map(|k| (k.key_id.as_str(), k.public_key_hex.as_str()))
        .collect();

    for row in rows {
        let receipt = row
            .receipt
            .as_ref()
            .ok_or_else(|| format!("row seq {} missing receipt", row.seq))?;
        if receipt.signer.key_id != signing_config.journal_signer_key_id {
            return Err(format!(
                "row seq {} signer key_id '{}' != signing-config journal signer '{}'",
                row.seq, receipt.signer.key_id, signing_config.journal_signer_key_id
            ));
        }
        if !allowed.contains(receipt.signer.key_id.as_str()) {
            return Err(format!(
                "row seq {} signer '{}' not in archived trust-root",
                row.seq, receipt.signer.key_id
            ));
        }
        match key_map.get(receipt.signer.key_id.as_str()) {
            Some(pk) if *pk == receipt.signer.public_key_hex => {}
            Some(_) => {
                return Err(format!(
                    "row seq {} signer pubkey disagrees with trust-root",
                    row.seq
                ));
            }
            None => {
                return Err(format!(
                    "row seq {} signer missing from trust-root",
                    row.seq
                ));
            }
        }
    }
    Ok(())
}

fn replay_action_stream(
    bundle_dir: &Path,
    manifest: &BundleManifest,
    rows: &[JournalRow],
    run_id: &Uuid,
) -> Result<(), String> {
    let stream_path = bundle_dir.join(&manifest.action_stream_path);
    if !stream_path.is_file() {
        return Err(format!(
            "action stream missing: {}",
            manifest.action_stream_path
        ));
    }
    let text = fs::read_to_string(&stream_path).map_err(|e| e.to_string())?;
    let mut expected = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: ActionStreamRow =
            serde_json::from_str(line).map_err(|e| format!("action-stream line {}: {e}", i + 1))?;
        expected.push(row);
    }
    if expected.len() != rows.len() {
        return Err(format!(
            "action-stream length {} != journal rows {}",
            expected.len(),
            rows.len()
        ));
    }
    for (row, stream) in rows.iter().zip(expected.iter()) {
        if row.run_id != *run_id {
            return Err(format!(
                "journal run_id {} != manifest run_id {run_id}",
                row.run_id
            ));
        }
        if row.seq != stream.seq {
            return Err(format!(
                "replay seq mismatch: journal {} stream {}",
                row.seq, stream.seq
            ));
        }
        if row.row_hash != stream.row_hash {
            return Err(format!("replay row_hash mismatch at seq {}", row.seq));
        }
        if row.event_canonical_json != stream.event_canonical_json {
            return Err(format!(
                "replay event_canonical_json mismatch at seq {}",
                row.seq
            ));
        }
    }
    Ok(())
}

fn write_action_stream(path: &Path, rows: &[JournalRow]) -> Result<(), VerifyError> {
    let mut out = String::new();
    for row in rows {
        let stream = ActionStreamRow {
            seq: row.seq,
            run_id: row.run_id,
            row_hash: row.row_hash.clone(),
            prev_hash: row.prev_hash.clone(),
            event_canonical_json: row.event_canonical_json.clone(),
        };
        out.push_str(&serde_json::to_string(&stream)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActionStreamRow {
    seq: u64,
    run_id: Uuid,
    row_hash: String,
    prev_hash: String,
    event_canonical_json: String,
}

fn finding(code: &str, detail: impl Into<String>) -> VerificationFinding {
    VerificationFinding {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn report_signing_payload(report: &VerificationReport) -> Result<String, VerifyError> {
    let value = serde_json::json!({
        "report_version": report.report_version,
        "run_id": report.run_id.to_string(),
        "bundle_version": report.bundle_version,
        "accepted": report.accepted,
        "reason_code": report.reason_code,
        "policy_hash": report.policy_hash,
        "journal_rows": report.journal_rows,
        "evidence_checked": report.evidence_checked,
        "findings": report.findings,
        "gate_evaluation": report.gate_evaluation,
        "verifier": {
            "key_id": report.verifier.key_id,
            "public_key_hex": report.verifier.public_key_hex,
        },
        "timestamp": report.timestamp.to_rfc3339(),
    });
    Ok(canonical_json(&value)?)
}

fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<(), VerifyError> {
    let pk_bytes = hex::decode(public_key_hex)?;
    if pk_bytes.len() != 32 {
        return Err(VerifyError::Crypto(format!(
            "expected 32-byte public key, got {}",
            pk_bytes.len()
        )));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| VerifyError::Crypto(e.to_string()))?;

    let sig_bytes = hex::decode(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(VerifyError::Crypto(format!(
            "expected 64-byte signature, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(message, &sig)
        .map_err(|e| VerifyError::Rejected(format!("SIGNATURE_INVALID: {e}")))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_good_bundle_accepts() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let journal_id = SigningIdentity::generate("journal");
        let verifier_id = SigningIdentity::generate("verifier");
        let (bundle, _) =
            build_demo_bundle(dir.path(), &journal_id, &verifier_id).expect("build");
        let mut report = verify_bundle(&bundle).expect("verify");
        assert!(report.accepted, "findings: {:?}", report.findings);
        assert_eq!(report.reason_code, "ACCEPTED");
        sign_verification_report(&mut report, &verifier_id).expect("sign");
        verify_report_signature(&report).expect("sig");
        assert!(report.accepted);
    }

    #[test]
    fn corrupted_evidence_hash_rejects() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let journal_id = SigningIdentity::generate("journal");
        let verifier_id = SigningIdentity::generate("verifier");
        let (bundle, _) =
            build_demo_bundle(dir.path(), &journal_id, &verifier_id).expect("build");

        let artifact = bundle.join("evidence/artifact.bin");
        let mut bytes = fs::read(&artifact).expect("read");
        bytes[0] ^= 0x01;
        fs::write(&artifact, bytes).expect("corrupt");

        let report = verify_bundle(&bundle).expect("verify returns report");
        assert!(!report.accepted);
        assert_eq!(report.reason_code, "HASH_MISMATCH");
    }

    #[test]
    fn missing_trust_root_rejects() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let journal_id = SigningIdentity::generate("journal");
        let verifier_id = SigningIdentity::generate("verifier");
        let (bundle, _) =
            build_demo_bundle(dir.path(), &journal_id, &verifier_id).expect("build");
        fs::remove_file(bundle.join("trust-root.json")).expect("rm");
        let err = verify_bundle(&bundle).expect_err("must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("TRUST_ROOT_MISSING") || msg.contains("trust-root"),
            "got {msg}"
        );
    }

    #[test]
    fn only_signed_report_marks_accepted_authority() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let journal_id = SigningIdentity::generate("journal");
        let verifier_id = SigningIdentity::generate("verifier");
        let (bundle, _) =
            build_demo_bundle(dir.path(), &journal_id, &verifier_id).expect("build");
        let mut report = verify_bundle(&bundle).expect("verify");
        assert!(report.accepted);
        assert!(report.signature_hex.is_empty());
        sign_verification_report(&mut report, &verifier_id).expect("sign");
        assert!(!report.signature_hex.is_empty());
        verify_report_signature(&report).expect("ok");

        report.accepted = true;
        report.signature_hex.push('0');
        assert!(verify_report_signature(&report).is_err());
    }
}
