use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const GATE_MANIFEST_VERSION: &str = "lia-gate-manifest-v1";
pub const PROTOCOL_VERSION: &str = "lia-protocol-v1";
pub const PROCESS_CONTRACT_VERSION: &str = "lia-process-contract-v1";

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unknown event family: {0}")]
    UnknownEventFamily(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid field: {0}")]
    InvalidField(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignerIdentity {
    pub key_id: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Verdict {
    Allow,
    Deny,
    Quarantine,
    Advisory,
    Refuted,
    Incomplete,
    Verified,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RiskTier {
    Security,
    Irreversible,
    Secret,
    Publication,
    Quality,
    Productivity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "family", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Event {
    ProcessContractDeclared(ProcessContractDeclared),
    ConfinementApplied(ConfinementApplied),
    ActionAttempted(ActionAttempted),
    ActionObserved(ActionObserved),
    GateVerdict(GateVerdictEvent),
    EvidenceCaptured(EvidenceCaptured),
    ClaimSubmitted(ClaimSubmitted),
    JournalMeta(JournalMeta),
    RawHarness(RawHarnessEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessContractDeclared {
    pub contract_id: Uuid,
    pub contract_version: String,
    pub contract_sha256: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfinementApplied {
    pub backend: String,
    pub helper_sha256: String,
    pub network_namespace: String,
    pub mount_namespace: String,
    pub pid_namespace: String,
    pub landlock_abi: u32,
    pub ip_egress_blocked: bool,
    pub host_path_writes_blocked: bool,
    pub evidence_artifacts_write_blocked: bool,
    pub attestation_sha256: String,
    pub credential_names: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionAttempted {
    pub action_id: Uuid,
    pub kind: ActionKind,
    pub payload: ActionPayload,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ActionKind {
    Shell,
    WriteFile,
    DeleteFile,
    ReadFile,
    RunTest,
    AddDependency,
    CompleteTask,
    Network,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionPayload {
    pub command: Option<String>,
    pub path: Option<String>,
    pub content_sha256: Option<String>,
    pub argv: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
    pub claim: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionObserved {
    pub action_id: Uuid,
    pub exit_code: Option<i32>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub coverage_profraw_sha256: Option<String>,
    pub wrapper_digest_sha256: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateVerdictEvent {
    pub action_id: Uuid,
    pub gate_id: String,
    pub verdict: Verdict,
    pub reason_code: String,
    pub risk_tier: RiskTier,
    pub detail: Option<String>,
    pub evidence_sha256: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCaptured {
    pub evidence_id: Uuid,
    pub kind: String,
    pub path: Option<String>,
    pub sha256: String,
    pub bytes: Option<u64>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimSubmitted {
    pub claim_id: Uuid,
    pub claim_type: String,
    pub body: serde_json::Value,
    pub required_evidence: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalMeta {
    pub run_id: Uuid,
    pub gate_manifest_version: String,
    pub protocol_version: String,
    pub note: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawHarnessEvent {
    pub harness: String,
    pub raw: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub receipt_id: Uuid,
    pub run_id: Uuid,
    pub gate_manifest_version: String,
    pub signer: SignerIdentity,
    pub event_row_hash: String,
    pub prev_hash: String,
    pub signature_hex: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalRow {
    pub seq: u64,
    pub run_id: Uuid,
    pub event: Event,
    pub event_canonical_json: String,
    pub row_hash: String,
    pub prev_hash: String,
    pub receipt: Option<Receipt>,
}

/// A caller-supplied, model-neutral task contract. LIA validates this contract;
/// planning, decomposition, recovery, and repair remain outside the trust kernel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessContract {
    pub contract_version: String,
    pub contract_id: Uuid,
    pub run_id: Uuid,
    pub objective: String,
    #[serde(default)]
    pub assumptions: Vec<ProcessAssumption>,
    #[serde(default)]
    pub required_evidence: Vec<ProcessEvidenceRequirement>,
    #[serde(default)]
    pub allowed_actions: Vec<ActionKind>,
    pub completion_predicate: ProcessCompletionPredicate,
    #[serde(default)]
    pub honest_stop_conditions: Vec<HonestStopCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessAssumption {
    pub id: String,
    pub statement: String,
    #[serde(default)]
    pub required_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidenceRequirement {
    pub id: String,
    pub kind: String,
    pub description: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessCompletionPredicate {
    #[serde(default)]
    pub all_evidence: Vec<String>,
    #[serde(default)]
    pub require_all_assumptions_supported: bool,
    #[serde(default)]
    pub require_no_unresolved_claims: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HonestStopCondition {
    pub code: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecution {
    pub contract_id: Uuid,
    pub contract_receipt_id: Uuid,
    #[serde(default)]
    pub performed_actions: Vec<ProcessActionRef>,
    #[serde(default)]
    pub evidence: Vec<ProcessEvidenceRef>,
    #[serde(default)]
    pub supported_assumptions: Vec<String>,
    #[serde(default)]
    pub unresolved_claims: Vec<ProcessUnresolvedClaim>,
    pub outcome: ProcessOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessActionRef {
    pub action_id: Uuid,
    pub kind: ActionKind,
    pub receipt_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidenceRef {
    pub requirement_id: String,
    pub evidence_id: Uuid,
    pub receipt_id: Uuid,
    pub kind: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessUnresolvedClaim {
    pub claim_id: String,
    pub statement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ProcessOutcome {
    Complete {
        receipt_id: Uuid,
    },
    HonestStop {
        condition_code: String,
        receipt_id: Uuid,
        unblocks: Vec<TypedUnblockCondition>,
    },
    InProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TypedUnblockCondition {
    pub tried: Vec<String>,
    pub missing: String,
    pub route: String,
}

pub fn parse_event(json: &str) -> Result<Event, ProtocolError> {
    Ok(serde_json::from_str(json)?)
}

pub fn canonicalize_event(event: &Event) -> Result<String, ProtocolError> {
    let value = serde_json::to_value(event)?;
    canonical_json(&value)
}

pub fn canonical_json(value: &serde_json::Value) -> Result<String, ProtocolError> {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k)?);
                out.push(':');
                out.push_str(&canonical_json(&map[*k])?);
            }
            out.push('}');
            Ok(out)
        }
        serde_json::Value::Array(arr) => {
            let mut parts = Vec::with_capacity(arr.len());
            for item in arr {
                parts.push(canonical_json(item)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        other => Ok(serde_json::to_string(other)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_unknown_fields_on_signer() {
        let bad = r#"{"key_id":"k","public_key_hex":"ab","extra":1}"#;
        let err = serde_json::from_str::<SignerIdentity>(bad).expect_err("extra field");
        let msg = err.to_string();
        assert!(msg.contains("unknown field") || msg.contains("extra"));
    }

    #[test]
    fn deny_unknown_fields_on_verdict_enum() {
        let err = serde_json::from_str::<Verdict>(r#""not_a_verdict""#).expect_err("bad variant");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn canonical_json_is_key_sorted() {
        let v: serde_json::Value = serde_json::json!({"b":1,"a":2});
        assert_eq!(canonical_json(&v).expect("canon"), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn raw_harness_passthrough_roundtrip() {
        let event = Event::RawHarness(RawHarnessEvent {
            harness: "claude-code".into(),
            raw: serde_json::json!({"tool":"Bash","input":{"command":"ls"}}),
            timestamp: Utc::now(),
        });
        let json = serde_json::to_string(&event).expect("ser");
        let back: Event = serde_json::from_str(&json).expect("de");
        assert_eq!(event, back);
        let canon = canonicalize_event(&event).expect("canon");
        assert!(canon.contains("\"family\":\"raw_harness\""));
    }

    #[test]
    fn unknown_event_family_rejected() {
        let bad = r#"{"family":"not_a_real_family","timestamp":"2026-07-18T00:00:00Z"}"#;
        assert!(parse_event(bad).is_err());
    }
}
