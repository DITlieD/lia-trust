use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use lia_protocol::{RiskTier, Verdict};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const REASON_CODES: &[&str] = &[
    "ACCEPTED",
    "ADVISORY",
    "BUNDLE_INCOMPLETE",
    "DENY_HIGH_RISK",
    "EVIDENCE_MISMATCH",
    "HASH_MISMATCH",
    "JOURNAL_INTEGRITY_FAILED",
    "MISSING_EVIDENCE",
    "OK",
    "POLICY_EMPTY",
    "POLICY_NOT_FROZEN",
    "QUARANTINE_LOW_RISK",
    "REJECTED",
    "REPLAY_MISMATCH",
    "RULE_CONDITION_FAILED",
    "SIGNATURE_INVALID",
    "TRUST_ANCHOR_MISMATCH",
    "TRUST_ROOT_MISSING",
];

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid policy: {0}")]
    Invalid(String),
    #[error("unknown reason code: {0}")]
    UnknownReasonCode(String),
    #[error("policy is not frozen")]
    NotFrozen,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub policy_id: String,
    pub version: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub risk_tier: RiskTier,
    pub required_evidence: Vec<EvidenceRequirement>,
    #[serde(default)]
    pub reason_code_on_fail: Option<String>,
    #[serde(default)]
    pub on_fail: Option<FailDisposition>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum FailDisposition {
    Deny,
    Quarantine,
    Advisory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequirement {
    pub key: String,
    #[serde(default = "default_evidence_kind")]
    pub kind: EvidenceKind,
    #[serde(default)]
    pub expected_sha256: Option<String>,
}

fn default_evidence_kind() -> EvidenceKind {
    EvidenceKind::Present
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum EvidenceKind {
    Present,
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSet {
    pub items: BTreeMap<String, EvidenceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrozenPolicy {
    pub policy_id: String,
    pub version: String,
    pub rules: Vec<Rule>,
    pub policy_hash: String,
    pub frozen_at: DateTime<Utc>,
    pub source_bytes_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleResult {
    pub rule_id: String,
    pub verdict: Verdict,
    pub reason_code: String,
    pub risk_tier: RiskTier,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReport {
    pub policy_id: String,
    pub policy_hash: String,
    pub overall: Verdict,
    pub reason_code: String,
    pub results: Vec<RuleResult>,
}

pub fn validate_reason_code(code: &str) -> Result<(), PolicyError> {
    if REASON_CODES.contains(&code) {
        Ok(())
    } else {
        Err(PolicyError::UnknownReasonCode(code.to_string()))
    }
}

pub fn load_rules_yaml(path: impl AsRef<Path>) -> Result<PolicyDocument, PolicyError> {
    let bytes = fs::read(path.as_ref())?;
    load_rules_yaml_bytes(&bytes)
}

pub fn load_rules_yaml_bytes(bytes: &[u8]) -> Result<PolicyDocument, PolicyError> {
    let doc: PolicyDocument = serde_yaml::from_slice(bytes)?;
    validate_document(&doc)?;
    Ok(doc)
}

pub fn load_evidence_json(path: impl AsRef<Path>) -> Result<EvidenceSet, PolicyError> {
    let bytes = fs::read(path.as_ref())?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn freeze_policy(doc: &PolicyDocument) -> Result<FrozenPolicy, PolicyError> {
    validate_document(doc)?;
    let yaml = serde_yaml::to_string(doc)?;
    let source_bytes_sha256 = sha256_hex(yaml.as_bytes());
    let policy_hash = blake3_hex(yaml.as_bytes());
    Ok(FrozenPolicy {
        policy_id: doc.policy_id.clone(),
        version: doc.version.clone(),
        rules: doc.rules.clone(),
        policy_hash,
        frozen_at: Utc::now(),
        source_bytes_sha256,
    })
}

pub fn freeze_policy_from_path(path: impl AsRef<Path>) -> Result<FrozenPolicy, PolicyError> {
    let bytes = fs::read(path.as_ref())?;
    let doc = load_rules_yaml_bytes(&bytes)?;
    let mut frozen = freeze_policy(&doc)?;
    frozen.source_bytes_sha256 = sha256_hex(&bytes);
    frozen.policy_hash = blake3_hex(&bytes);
    Ok(frozen)
}

pub fn write_frozen_yaml(
    frozen: &FrozenPolicy,
    path: impl AsRef<Path>,
) -> Result<(), PolicyError> {
    let doc = PolicyDocument {
        policy_id: frozen.policy_id.clone(),
        version: frozen.version.clone(),
        rules: frozen.rules.clone(),
    };
    let yaml = serde_yaml::to_string(&doc)?;
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, yaml)?;
    Ok(())
}

pub fn evaluate_frozen(
    frozen: &FrozenPolicy,
    evidence: &EvidenceSet,
) -> Result<EvaluationReport, PolicyError> {
    if frozen.policy_hash.is_empty() {
        return Err(PolicyError::NotFrozen);
    }
    if frozen.rules.is_empty() {
        return Ok(EvaluationReport {
            policy_id: frozen.policy_id.clone(),
            policy_hash: frozen.policy_hash.clone(),
            overall: Verdict::Deny,
            reason_code: "POLICY_EMPTY".to_string(),
            results: Vec::new(),
        });
    }

    let mut results = Vec::with_capacity(frozen.rules.len());
    for rule in &frozen.rules {
        results.push(evaluate_rule(rule, evidence)?);
    }

    let overall = aggregate_verdict(&results);
    let reason_code = overall_reason(&results, &overall).to_string();
    validate_reason_code(&reason_code)?;

    Ok(EvaluationReport {
        policy_id: frozen.policy_id.clone(),
        policy_hash: frozen.policy_hash.clone(),
        overall,
        reason_code,
        results,
    })
}

fn evaluate_rule(rule: &Rule, evidence: &EvidenceSet) -> Result<RuleResult, PolicyError> {
    let fail_code = rule
        .reason_code_on_fail
        .clone()
        .unwrap_or_else(|| "MISSING_EVIDENCE".to_string());
    validate_reason_code(&fail_code)?;

    for req in &rule.required_evidence {
        match evidence.items.get(&req.key) {
            None => {
                return Ok(fail_result(
                    rule,
                    fail_code,
                    format!("missing evidence key '{}'", req.key),
                ));
            }
            Some(item) => {
                if let Err(detail) = check_requirement(req, item) {
                    let code = if detail.contains("hash") {
                        "EVIDENCE_MISMATCH".to_string()
                    } else {
                        fail_code.clone()
                    };
                    validate_reason_code(&code)?;
                    return Ok(fail_result(rule, code, detail));
                }
            }
        }
    }

    Ok(RuleResult {
        rule_id: rule.id.clone(),
        verdict: Verdict::Allow,
        reason_code: "OK".to_string(),
        risk_tier: rule.risk_tier.clone(),
        detail: None,
    })
}

fn check_requirement(req: &EvidenceRequirement, item: &EvidenceItem) -> Result<(), String> {
    match req.kind {
        EvidenceKind::Present => {
            // vacuous presence (an empty string, zero bytes) is not evidence
            let present = item.sha256.as_deref().is_some_and(|s| !s.is_empty())
                || item.value.as_deref().is_some_and(|s| !s.is_empty())
                || item.bytes.is_some_and(|b| b > 0);
            if present {
                Ok(())
            } else {
                Err(format!("evidence key '{}' present but empty", req.key))
            }
        }
        EvidenceKind::Sha256 => {
            let got = item
                .sha256
                .as_deref()
                .ok_or_else(|| format!("evidence key '{}' missing sha256", req.key))?;
            if let Some(expected) = req.expected_sha256.as_deref() {
                if !sha256_eq(got, expected) {
                    return Err(format!(
                        "hash mismatch for '{}': expected {expected}, got {got}",
                        req.key
                    ));
                }
            }
            if got.len() != 64 || !got.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("evidence key '{}' has invalid sha256", req.key));
            }
            Ok(())
        }
    }
}

fn fail_result(rule: &Rule, reason_code: String, detail: String) -> RuleResult {
    let verdict = fail_verdict(rule);
    let reason_code = match &verdict {
        Verdict::Deny if is_high_risk(&rule.risk_tier) => {
            if reason_code == "MISSING_EVIDENCE" || reason_code == "EVIDENCE_MISMATCH" {
                reason_code
            } else {
                "DENY_HIGH_RISK".to_string()
            }
        }
        Verdict::Quarantine => {
            if reason_code == "MISSING_EVIDENCE" || reason_code == "EVIDENCE_MISMATCH" {
                reason_code
            } else {
                "QUARANTINE_LOW_RISK".to_string()
            }
        }
        Verdict::Advisory => "ADVISORY".to_string(),
        _ => reason_code,
    };
    RuleResult {
        rule_id: rule.id.clone(),
        verdict,
        reason_code,
        risk_tier: rule.risk_tier.clone(),
        detail: Some(detail),
    }
}

fn fail_verdict(rule: &Rule) -> Verdict {
    if is_high_risk(&rule.risk_tier) {
        return Verdict::Deny;
    }
    match rule.on_fail.unwrap_or(FailDisposition::Quarantine) {
        FailDisposition::Deny => Verdict::Deny,
        FailDisposition::Quarantine => Verdict::Quarantine,
        FailDisposition::Advisory => Verdict::Advisory,
    }
}

fn is_high_risk(tier: &RiskTier) -> bool {
    matches!(
        tier,
        RiskTier::Security | RiskTier::Irreversible | RiskTier::Secret | RiskTier::Publication
    )
}

fn aggregate_verdict(results: &[RuleResult]) -> Verdict {
    let mut worst = Verdict::Allow;
    for r in results {
        worst = worse(worst, r.verdict.clone());
    }
    worst
}

fn worse(a: Verdict, b: Verdict) -> Verdict {
    if rank(&a) >= rank(&b) {
        a
    } else {
        b
    }
}

fn rank(v: &Verdict) -> u8 {
    match v {
        Verdict::Allow | Verdict::Verified => 0,
        Verdict::Advisory | Verdict::Unsupported | Verdict::Incomplete => 1,
        Verdict::Quarantine => 2,
        Verdict::Deny | Verdict::Refuted => 3,
    }
}

fn overall_reason<'a>(results: &'a [RuleResult], overall: &Verdict) -> &'a str {
    if matches!(overall, Verdict::Allow) {
        return "OK";
    }
    for r in results {
        if &r.verdict == overall {
            return &r.reason_code;
        }
    }
    "RULE_CONDITION_FAILED"
}

fn validate_document(doc: &PolicyDocument) -> Result<(), PolicyError> {
    if doc.policy_id.trim().is_empty() {
        return Err(PolicyError::Invalid("policy_id empty".into()));
    }
    let mut seen = BTreeSet::new();
    for rule in &doc.rules {
        if rule.id.trim().is_empty() {
            return Err(PolicyError::Invalid("rule id empty".into()));
        }
        if !seen.insert(rule.id.clone()) {
            return Err(PolicyError::Invalid(format!(
                "duplicate rule id '{}'",
                rule.id
            )));
        }
        if rule.required_evidence.is_empty() {
            return Err(PolicyError::Invalid(format!(
                "rule '{}' has no required_evidence",
                rule.id
            )));
        }
        if let Some(code) = &rule.reason_code_on_fail {
            validate_reason_code(code)?;
        }
        if is_high_risk(&rule.risk_tier) {
            if let Some(FailDisposition::Quarantine | FailDisposition::Advisory) = rule.on_fail {
                return Err(PolicyError::Invalid(format!(
                    "rule '{}' is high-risk and cannot on_fail quarantine/advisory",
                    rule.id
                )));
            }
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn blake3_hex(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn sha256_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy_yaml() -> &'static str {
        r#"
policy_id: demo
version: "1"
rules:
  - id: need-test
    risk_tier: security
    required_evidence:
      - key: test_stdout
        kind: sha256
      - key: test_exit
        kind: present
    reason_code_on_fail: MISSING_EVIDENCE
  - id: style
    risk_tier: quality
    required_evidence:
      - key: lint_ok
        kind: present
    on_fail: quarantine
    reason_code_on_fail: MISSING_EVIDENCE
"#
    }

    #[test]
    fn missing_evidence_is_deny_not_skip_on_security() {
        let doc = load_rules_yaml_bytes(sample_policy_yaml().as_bytes()).expect("load");
        let frozen = freeze_policy(&doc).expect("freeze");
        let evidence = EvidenceSet {
            items: BTreeMap::from([(
                "test_exit".into(),
                EvidenceItem {
                    sha256: None,
                    value: Some("0".into()),
                    bytes: None,
                },
            )]),
        };
        let report = evaluate_frozen(&frozen, &evidence).expect("eval");
        assert_eq!(report.overall, Verdict::Deny);
        assert_eq!(report.reason_code, "MISSING_EVIDENCE");
        assert!(!report.results.iter().any(|r| r.reason_code == "SKIP"));
        let need = report
            .results
            .iter()
            .find(|r| r.rule_id == "need-test")
            .expect("need-test");
        assert_eq!(need.verdict, Verdict::Deny);
    }

    #[test]
    fn low_risk_missing_evidence_quarantines() {
        let doc = load_rules_yaml_bytes(sample_policy_yaml().as_bytes()).expect("load");
        let frozen = freeze_policy(&doc).expect("freeze");
        let evidence = EvidenceSet {
            items: BTreeMap::from([
                (
                    "test_stdout".into(),
                    EvidenceItem {
                        sha256: Some(
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .into(),
                        ),
                        value: None,
                        bytes: Some(1),
                    },
                ),
                (
                    "test_exit".into(),
                    EvidenceItem {
                        sha256: None,
                        value: Some("0".into()),
                        bytes: None,
                    },
                ),
            ]),
        };
        let report = evaluate_frozen(&frozen, &evidence).expect("eval");
        assert_eq!(report.overall, Verdict::Quarantine);
        let style = report
            .results
            .iter()
            .find(|r| r.rule_id == "style")
            .expect("style");
        assert_eq!(style.verdict, Verdict::Quarantine);
        assert_eq!(style.reason_code, "MISSING_EVIDENCE");
    }

    #[test]
    fn all_evidence_present_allows() {
        let doc = load_rules_yaml_bytes(sample_policy_yaml().as_bytes()).expect("load");
        let frozen = freeze_policy(&doc).expect("freeze");
        let evidence = EvidenceSet {
            items: BTreeMap::from([
                (
                    "test_stdout".into(),
                    EvidenceItem {
                        sha256: Some(
                            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                .into(),
                        ),
                        value: None,
                        bytes: Some(4),
                    },
                ),
                (
                    "test_exit".into(),
                    EvidenceItem {
                        sha256: None,
                        value: Some("0".into()),
                        bytes: None,
                    },
                ),
                (
                    "lint_ok".into(),
                    EvidenceItem {
                        sha256: None,
                        value: Some("true".into()),
                        bytes: None,
                    },
                ),
            ]),
        };
        let report = evaluate_frozen(&frozen, &evidence).expect("eval");
        assert_eq!(report.overall, Verdict::Allow);
        assert_eq!(report.reason_code, "OK");
    }

    #[test]
    fn hash_mismatch_denies() {
        let yaml = r#"
policy_id: hashdemo
version: "1"
rules:
  - id: bind-hash
    risk_tier: security
    required_evidence:
      - key: artifact
        kind: sha256
        expected_sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
"#;
        let doc = load_rules_yaml_bytes(yaml.as_bytes()).expect("load");
        let frozen = freeze_policy(&doc).expect("freeze");
        let evidence = EvidenceSet {
            items: BTreeMap::from([(
                "artifact".into(),
                EvidenceItem {
                    sha256: Some(
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                            .into(),
                    ),
                    value: None,
                    bytes: Some(1),
                },
            )]),
        };
        let report = evaluate_frozen(&frozen, &evidence).expect("eval");
        assert_eq!(report.overall, Verdict::Deny);
        assert_eq!(report.reason_code, "EVIDENCE_MISMATCH");
    }

    #[test]
    fn high_risk_cannot_quarantine_on_fail() {
        let yaml = r#"
policy_id: bad
version: "1"
rules:
  - id: sec
    risk_tier: security
    required_evidence:
      - key: x
        kind: present
    on_fail: quarantine
"#;
        let err = load_rules_yaml_bytes(yaml.as_bytes()).expect_err("must reject");
        assert!(matches!(err, PolicyError::Invalid(_)));
    }

    #[test]
    fn reason_codes_golden_lock() {
        let golden = include_str!("../reason-codes.golden");
        let golden_codes: BTreeSet<&str> = golden
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let registry: BTreeSet<&str> = REASON_CODES.iter().copied().collect();
        for g in &golden_codes {
            assert!(
                registry.contains(g),
                "reason code removed or renamed without golden edit: {g}"
            );
        }
        for c in &registry {
            assert!(
                golden_codes.contains(c),
                "reason code added without golden edit: {c}"
            );
        }
        assert!(
            golden_codes.contains("OK"),
            "OK must remain in the frozen vocabulary"
        );
    }

    #[test]
    fn freeze_is_deterministic_for_same_bytes() {
        let a = freeze_policy_from_path_bytes(sample_policy_yaml().as_bytes()).expect("a");
        let b = freeze_policy_from_path_bytes(sample_policy_yaml().as_bytes()).expect("b");
        assert_eq!(a.policy_hash, b.policy_hash);
        assert_eq!(a.source_bytes_sha256, b.source_bytes_sha256);
    }

    fn freeze_policy_from_path_bytes(bytes: &[u8]) -> Result<FrozenPolicy, PolicyError> {
        let doc = load_rules_yaml_bytes(bytes)?;
        let mut frozen = freeze_policy(&doc)?;
        frozen.source_bytes_sha256 = sha256_hex(bytes);
        frozen.policy_hash = blake3_hex(bytes);
        Ok(frozen)
    }
}
