use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use lia_policy::{freeze_policy_from_path, FrozenPolicy};
use lia_protocol::{ActionKind, RiskTier, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

mod dependency;
mod evidence;
mod expand;
mod filesystem;
mod journal_tamper;
mod secret;
mod shell;
mod test_integrity;

pub use dependency::check_dependency_reality;
pub use evidence::check_evidence_completeness;
pub use expand::{expand_command_paths, ExpandError, ExpandedCommand};
pub use filesystem::check_filesystem_scope;
pub use journal_tamper::check_journal_tamper;
pub use secret::{check_secret_output, ShareableProjection};
pub use shell::check_shell_irreversible;
pub use test_integrity::check_test_integrity;

pub const CORE_GATE_IDS: &[&str] = &[
    "test-integrity",
    "evidence-completeness",
    "filesystem-scope",
    "shell-irreversible",
    "dependency-reality",
    "secret-output",
    "journal-tamper",
];

pub const GATE_REASON_CODES: &[&str] = &[
    "DEP_NOT_FOUND",
    "DEP_TYPOSQUAT",
    "DEP_VERSION_MISSING",
    "EVIDENCE_INCOMPLETE",
    "FS_OUT_OF_SCOPE",
    "FS_PROTECTED_PATH",
    "FS_SYMLINK_ESCAPE",
    "GATE_ALLOW",
    "JOURNAL_CROSS_SESSION",
    "JOURNAL_REORDER",
    "JOURNAL_TAMPER_DETECTED",
    "SECRET_IN_OUTPUT",
    "SHELL_CLEANUP_AMBIGUOUS",
    "SHELL_CLEANUP_APPROVAL_REQUIRED",
    "SHELL_CLEANUP_APPROVED",
    "SHELL_CLEANUP_OUT_OF_SCOPE",
    "SHELL_CLEANUP_PROTECTED_TARGET",
    "SHELL_COMMAND_SUBSTITUTION",
    "SHELL_DESTRUCTIVE",
    "SHELL_OUT_OF_SCOPE",
    "SHELL_PROTECTED_PATH",
    "TEST_FABRICATED_PASS",
    "TEST_INTEGRITY_OK",
    "TEST_MISSING_HL4_FIELDS",
];

#[derive(Debug, Error)]
pub enum GateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("policy: {0}")]
    Policy(#[from] lia_policy::PolicyError),
    #[error("invalid gate input: {0}")]
    Invalid(String),
    #[error("unknown gate id: {0}")]
    UnknownGate(String),
    #[error("expand: {0}")]
    Expand(#[from] ExpandError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateConfig {
    pub allowed_roots: Vec<PathBuf>,
    #[serde(default)]
    pub home_dir: Option<PathBuf>,
    pub cwd: PathBuf,
    #[serde(default)]
    pub protected_paths: Vec<PathBuf>,
    #[serde(default)]
    pub registry: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub run_id: Option<Uuid>,
    #[serde(default)]
    pub cleanup_policy: Option<CleanupPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CleanupPolicy {
    pub version: u32,
    pub approved_targets: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateRequest {
    pub gate_id: String,
    pub action_id: Uuid,
    #[serde(default)]
    pub kind: Option<ActionKind>,
    pub payload: GatePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct GatePayload {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub claimed_pass: Option<bool>,
    #[serde(default)]
    pub wrapper: Option<WrapperObservation>,
    #[serde(default)]
    pub modified_paths: Option<Vec<String>>,
    #[serde(default)]
    pub new_dependencies: Option<Vec<String>>,
    #[serde(default)]
    pub has_test_result: Option<bool>,
    #[serde(default)]
    pub test_unsupported: Option<bool>,
    #[serde(default)]
    pub deps_registry_evidence: Option<bool>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub journal_rows: Option<Vec<JournalRowProbe>>,
    #[serde(default)]
    pub expected_run_id: Option<Uuid>,
    #[serde(default)]
    pub is_delete: Option<bool>,
    #[serde(default)]
    pub is_write: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WrapperObservation {
    pub exit_code: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub coverage_profraw_sha256: String,
    pub wrapper_digest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalRowProbe {
    pub seq: u64,
    pub run_id: Uuid,
    pub row_hash: String,
    pub prev_hash: String,
    #[serde(default)]
    pub receipt_run_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateOutcome {
    pub gate_id: String,
    pub action_id: Uuid,
    pub verdict: Verdict,
    pub reason_code: String,
    pub risk_tier: RiskTier,
    pub detail: Option<String>,
    pub offending: Option<String>,
    pub evidence_sha256: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub hl4: Option<WrapperObservation>,
    #[serde(default)]
    pub shareable: Option<ShareableProjection>,
}

pub fn load_gate_config(path: impl AsRef<Path>) -> Result<GateConfig, GateError> {
    let bytes = fs::read(path.as_ref())?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn load_gate_request(path: impl AsRef<Path>) -> Result<GateRequest, GateError> {
    let bytes = fs::read(path.as_ref())?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn load_core_rules(path: impl AsRef<Path>) -> Result<FrozenPolicy, GateError> {
    Ok(freeze_policy_from_path(path)?)
}

pub fn evaluate_gate(
    request: &GateRequest,
    config: &GateConfig,
) -> Result<GateOutcome, GateError> {
    if !CORE_GATE_IDS.contains(&request.gate_id.as_str()) {
        return Err(GateError::UnknownGate(request.gate_id.clone()));
    }
    let outcome = match request.gate_id.as_str() {
        "test-integrity" => check_test_integrity(request)?,
        "evidence-completeness" => check_evidence_completeness(request)?,
        "filesystem-scope" => check_filesystem_scope(request, config)?,
        "shell-irreversible" => check_shell_irreversible(request, config)?,
        "dependency-reality" => check_dependency_reality(request, config)?,
        "secret-output" => check_secret_output(request)?,
        "journal-tamper" => check_journal_tamper(request, config)?,
        other => return Err(GateError::UnknownGate(other.to_string())),
    };
    validate_gate_reason_code(&outcome.reason_code)?;
    Ok(outcome)
}

fn validate_gate_reason_code(code: &str) -> Result<(), GateError> {
    if GATE_REASON_CODES.contains(&code) {
        Ok(())
    } else {
        Err(GateError::Invalid(format!("unknown gate reason code: {code}")))
    }
}

pub fn evaluate_action_gates(
    kind: &ActionKind,
    action_id: Uuid,
    payload: &GatePayload,
    config: &GateConfig,
) -> Result<Vec<GateOutcome>, GateError> {
    let mut gate_ids: Vec<&str> = Vec::new();
    match kind {
        ActionKind::RunTest => gate_ids.push("test-integrity"),
        ActionKind::CompleteTask => gate_ids.push("evidence-completeness"),
        ActionKind::WriteFile | ActionKind::DeleteFile | ActionKind::ReadFile => {
            gate_ids.push("filesystem-scope");
        }
        ActionKind::Shell => {
            gate_ids.push("shell-irreversible");
        }
        ActionKind::AddDependency => gate_ids.push("dependency-reality"),
        ActionKind::Other | ActionKind::Network => {}
    }
    if payload.text.is_some() {
        gate_ids.push("secret-output");
    }
    if payload.journal_rows.is_some() {
        gate_ids.push("journal-tamper");
    }
    gate_ids.sort_unstable();
    gate_ids.dedup();

    let mut out = Vec::with_capacity(gate_ids.len());
    for id in gate_ids {
        let req = GateRequest {
            gate_id: id.to_string(),
            action_id,
            kind: Some(kind.clone()),
            payload: payload.clone(),
        };
        out.push(evaluate_gate(&req, config)?);
    }
    Ok(out)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub(crate) fn make_outcome(
    gate_id: &str,
    action_id: Uuid,
    verdict: Verdict,
    reason_code: &str,
    risk_tier: RiskTier,
    detail: Option<String>,
    offending: Option<String>,
    evidence: &serde_json::Value,
) -> GateOutcome {
    GateOutcome {
        gate_id: gate_id.to_string(),
        action_id,
        verdict,
        reason_code: reason_code.to_string(),
        risk_tier,
        detail,
        offending,
        evidence_sha256: sha256_hex(&serde_json::to_vec(evidence).unwrap_or_default()),
        timestamp: Utc::now(),
        hl4: None,
        shareable: None,
    }
}

pub fn core_rules_yaml() -> &'static str {
    include_str!("../rules/seven-core.yaml")
}

pub fn write_core_rules(path: impl AsRef<Path>) -> Result<(), GateError> {
    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, core_rules_yaml())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_gate_ids_stable() {
        assert_eq!(CORE_GATE_IDS.len(), 7);
    }

    #[test]
    fn reason_codes_nonempty_and_sorted_unique() {
        let mut codes: Vec<&str> = GATE_REASON_CODES.to_vec();
        let before = codes.clone();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes, before);
    }
}
