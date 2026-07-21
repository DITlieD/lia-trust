use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use lia_journal::{verify_chain, Journal};
use lia_protocol::{
    Event, JournalRow, ProcessContract, ProcessExecution, ProcessOutcome, Verdict,
    PROCESS_CONTRACT_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProcessContractError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("journal: {0}")]
    Journal(#[from] lia_journal::JournalError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessValidationReport {
    pub contract_version: String,
    pub contract_id: Uuid,
    pub followed: bool,
    pub status: String,
    pub reason_code: String,
    pub journal_verified: bool,
    pub receipts_checked: u64,
    pub evidence_checked: u64,
    pub findings: Vec<ProcessValidationFinding>,
}

pub fn load_and_validate_process_contract(
    contract_path: impl AsRef<Path>,
    execution_path: impl AsRef<Path>,
    journal_path: impl AsRef<Path>,
) -> Result<ProcessValidationReport, ProcessContractError> {
    let contract: ProcessContract = serde_json::from_slice(&fs::read(contract_path)?)?;
    let execution: ProcessExecution = serde_json::from_slice(&fs::read(execution_path)?)?;
    validate_process_contract(&contract, &execution, journal_path)
}

pub fn validate_process_contract(
    contract: &ProcessContract,
    execution: &ProcessExecution,
    journal_path: impl AsRef<Path>,
) -> Result<ProcessValidationReport, ProcessContractError> {
    let journal_path = journal_path.as_ref();
    verify_chain(journal_path)?;
    let rows = Journal::open_readonly(journal_path)?.load_rows()?;
    Ok(validate_against_verified_rows(contract, execution, &rows))
}

pub fn process_contract_sha256(contract: &ProcessContract) -> Result<String, ProcessContractError> {
    let bytes = serde_json::to_vec(contract)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub fn process_execution_manifest_sha256(
    contract: &ProcessContract,
    execution: &ProcessExecution,
) -> Result<String, ProcessContractError> {
    #[derive(Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum TerminalManifest<'a> {
        Complete,
        HonestStop {
            condition_code: &'a str,
            unblocks: &'a [lia_protocol::TypedUnblockCondition],
        },
        InProgress,
    }

    #[derive(Serialize)]
    struct ExecutionManifest<'a> {
        manifest_version: &'static str,
        contract_id: Uuid,
        contract_sha256: String,
        contract_receipt_id: Uuid,
        performed_actions: &'a [lia_protocol::ProcessActionRef],
        evidence: &'a [lia_protocol::ProcessEvidenceRef],
        supported_assumptions: &'a [String],
        unresolved_claims: &'a [lia_protocol::ProcessUnresolvedClaim],
        outcome: TerminalManifest<'a>,
    }

    let outcome = match &execution.outcome {
        ProcessOutcome::Complete { .. } => TerminalManifest::Complete,
        ProcessOutcome::HonestStop {
            condition_code,
            unblocks,
            ..
        } => TerminalManifest::HonestStop {
            condition_code,
            unblocks,
        },
        ProcessOutcome::InProgress => TerminalManifest::InProgress,
    };
    let manifest = ExecutionManifest {
        manifest_version: "lia-process-execution-manifest-v1",
        contract_id: execution.contract_id,
        contract_sha256: process_contract_sha256(contract)?,
        contract_receipt_id: execution.contract_receipt_id,
        performed_actions: &execution.performed_actions,
        evidence: &execution.evidence,
        supported_assumptions: &execution.supported_assumptions,
        unresolved_claims: &execution.unresolved_claims,
        outcome,
    };
    let bytes = serde_json::to_vec(&manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn validate_against_verified_rows(
    contract: &ProcessContract,
    execution: &ProcessExecution,
    rows: &[JournalRow],
) -> ProcessValidationReport {
    let mut findings = Vec::new();
    let mut receipts_checked = 0u64;
    let mut evidence_checked = 0u64;
    let receipt_rows: BTreeMap<Uuid, &JournalRow> = rows
        .iter()
        .filter_map(|row| {
            row.receipt
                .as_ref()
                .map(|receipt| (receipt.receipt_id, row))
        })
        .collect();

    if contract.contract_version != PROCESS_CONTRACT_VERSION {
        return rejected(
            contract,
            "PROCESS_CONTRACT_VERSION_UNSUPPORTED",
            format!(
                "expected {PROCESS_CONTRACT_VERSION}, got {}",
                contract.contract_version
            ),
            receipts_checked,
            evidence_checked,
        );
    }
    if contract.objective.trim().is_empty() {
        return rejected(
            contract,
            "PROCESS_OBJECTIVE_MISSING",
            "objective must not be empty",
            receipts_checked,
            evidence_checked,
        );
    }
    if contract
        .allowed_actions
        .iter()
        .enumerate()
        .any(|(index, kind)| {
            contract.allowed_actions[..index]
                .iter()
                .any(|prior| prior == kind)
        })
    {
        return rejected(
            contract,
            "PROCESS_ACTION_SCHEMA_INVALID",
            "allowed_actions contains duplicates",
            receipts_checked,
            evidence_checked,
        );
    }
    if execution.contract_id != contract.contract_id {
        return rejected(
            contract,
            "PROCESS_CONTRACT_ID_MISMATCH",
            format!(
                "execution contract_id {} does not match {}",
                execution.contract_id, contract.contract_id
            ),
            receipts_checked,
            evidence_checked,
        );
    }

    let contract_sha256 = match process_contract_sha256(contract) {
        Ok(digest) => digest,
        Err(error) => {
            return rejected(
                contract,
                "PROCESS_CONTRACT_DIGEST_FAILED",
                error.to_string(),
                receipts_checked,
                evidence_checked,
            )
        }
    };
    let Some(declaration_row) = receipt_rows.get(&execution.contract_receipt_id) else {
        return rejected(
            contract,
            "PROCESS_CONTRACT_RECEIPT_MISSING",
            format!(
                "contract declaration receipt {} is absent",
                execution.contract_receipt_id
            ),
            receipts_checked,
            evidence_checked,
        );
    };
    receipts_checked += 1;
    if declaration_row.run_id != contract.run_id
        || !matches!(
            declaration_row.event,
            Event::ProcessContractDeclared(ref event)
                if event.contract_id == contract.contract_id
                    && event.contract_version == contract.contract_version
                    && event.contract_sha256 == contract_sha256
        )
    {
        return rejected(
            contract,
            "PROCESS_CONTRACT_RECEIPT_INVALID",
            "contract declaration receipt does not bind this contract and run",
            receipts_checked,
            evidence_checked,
        );
    }
    let declaration_seq = declaration_row.seq;
    let mut last_referenced_seq = declaration_seq;

    let requirement_ids = match unique_nonempty_ids(
        contract
            .required_evidence
            .iter()
            .map(|requirement| requirement.id.as_str()),
    ) {
        Ok(ids) => ids,
        Err(detail) => {
            return rejected(
                contract,
                "PROCESS_EVIDENCE_SCHEMA_INVALID",
                detail,
                receipts_checked,
                evidence_checked,
            )
        }
    };
    let requirement_kinds: BTreeMap<&str, &str> = contract
        .required_evidence
        .iter()
        .map(|requirement| (requirement.id.as_str(), requirement.kind.as_str()))
        .collect();
    let assumption_ids = match unique_nonempty_ids(
        contract
            .assumptions
            .iter()
            .map(|assumption| assumption.id.as_str()),
    ) {
        Ok(ids) => ids,
        Err(detail) => {
            return rejected(
                contract,
                "PROCESS_ASSUMPTION_SCHEMA_INVALID",
                detail,
                receipts_checked,
                evidence_checked,
            )
        }
    };
    let stop_codes = match unique_nonempty_ids(
        contract
            .honest_stop_conditions
            .iter()
            .map(|condition| condition.code.as_str()),
    ) {
        Ok(ids) => ids,
        Err(detail) => {
            return rejected(
                contract,
                "PROCESS_HONEST_STOP_SCHEMA_INVALID",
                detail,
                receipts_checked,
                evidence_checked,
            )
        }
    };

    if contract.required_evidence.iter().any(|requirement| {
        requirement.kind.trim().is_empty() || requirement.description.trim().is_empty()
    }) || contract
        .honest_stop_conditions
        .iter()
        .any(|condition| condition.description.trim().is_empty())
    {
        return rejected(
            contract,
            "PROCESS_CONTRACT_SCHEMA_INVALID",
            "evidence kinds/descriptions and honest-stop descriptions must not be empty",
            receipts_checked,
            evidence_checked,
        );
    }

    for assumption in &contract.assumptions {
        if assumption.statement.trim().is_empty()
            || assumption.required_evidence.is_empty()
            || assumption
                .required_evidence
                .iter()
                .any(|id| !requirement_ids.contains(id.as_str()))
        {
            return rejected(
                contract,
                "PROCESS_ASSUMPTION_SCHEMA_INVALID",
                format!(
                    "assumption '{}' has an empty statement, no evidence, or unknown evidence",
                    assumption.id
                ),
                receipts_checked,
                evidence_checked,
            );
        }
    }
    if contract
        .completion_predicate
        .all_evidence
        .iter()
        .any(|id| !requirement_ids.contains(id.as_str()))
    {
        return rejected(
            contract,
            "PROCESS_COMPLETION_PREDICATE_INVALID",
            "completion predicate references undeclared evidence",
            receipts_checked,
            evidence_checked,
        );
    }

    let mut seen_actions = BTreeSet::new();
    for action in &execution.performed_actions {
        if !seen_actions.insert(action.action_id) {
            return rejected(
                contract,
                "PROCESS_ACTION_DUPLICATE",
                format!("duplicate action_id {}", action.action_id),
                receipts_checked,
                evidence_checked,
            );
        }
        if !contract
            .allowed_actions
            .iter()
            .any(|allowed| allowed == &action.kind)
        {
            return rejected(
                contract,
                "PROCESS_ACTION_NOT_ALLOWED",
                format!("action {:?} is outside the declared allowlist", action.kind),
                receipts_checked,
                evidence_checked,
            );
        }
        let Some(row) = receipt_rows.get(&action.receipt_id) else {
            return rejected(
                contract,
                "PROCESS_RECEIPT_MISSING",
                format!("action receipt {} is absent", action.receipt_id),
                receipts_checked,
                evidence_checked,
            );
        };
        receipts_checked += 1;
        if row.seq <= declaration_seq {
            return rejected(
                contract,
                "PROCESS_CONTRACT_DECLARED_TOO_LATE",
                format!("action {} predates its process contract", action.action_id),
                receipts_checked,
                evidence_checked,
            );
        }
        last_referenced_seq = last_referenced_seq.max(row.seq);
        if row.run_id != contract.run_id {
            return rejected(
                contract,
                "PROCESS_RECEIPT_RUN_MISMATCH",
                format!(
                    "action receipt {} belongs to another run",
                    action.receipt_id
                ),
                receipts_checked,
                evidence_checked,
            );
        }
        match &row.event {
            Event::ActionAttempted(event)
                if event.action_id == action.action_id && event.kind == action.kind => {}
            _ => {
                return rejected(
                    contract,
                    "PROCESS_ACTION_RECEIPT_MISMATCH",
                    format!(
                        "receipt {} does not bind the declared action",
                        action.receipt_id
                    ),
                    receipts_checked,
                    evidence_checked,
                )
            }
        }
    }

    let mut satisfied = BTreeSet::new();
    let mut seen_evidence_ids = BTreeSet::new();
    for evidence in &execution.evidence {
        if !requirement_ids.contains(evidence.requirement_id.as_str()) {
            return rejected(
                contract,
                "PROCESS_EVIDENCE_UNDECLARED",
                format!("unknown requirement_id {}", evidence.requirement_id),
                receipts_checked,
                evidence_checked,
            );
        }
        if !seen_evidence_ids.insert(evidence.evidence_id) {
            return rejected(
                contract,
                "PROCESS_EVIDENCE_DUPLICATE",
                format!("duplicate evidence_id {}", evidence.evidence_id),
                receipts_checked,
                evidence_checked,
            );
        }
        if !is_sha256(&evidence.sha256) {
            return rejected(
                contract,
                "PROCESS_EVIDENCE_HASH_INVALID",
                format!("evidence {} has a non-SHA256 digest", evidence.evidence_id),
                receipts_checked,
                evidence_checked,
            );
        }
        let Some(row) = receipt_rows.get(&evidence.receipt_id) else {
            return rejected(
                contract,
                "PROCESS_RECEIPT_MISSING",
                format!("evidence receipt {} is absent", evidence.receipt_id),
                receipts_checked,
                evidence_checked,
            );
        };
        receipts_checked += 1;
        evidence_checked += 1;
        if row.seq <= declaration_seq {
            return rejected(
                contract,
                "PROCESS_CONTRACT_DECLARED_TOO_LATE",
                format!(
                    "evidence {} predates its process contract",
                    evidence.evidence_id
                ),
                receipts_checked,
                evidence_checked,
            );
        }
        last_referenced_seq = last_referenced_seq.max(row.seq);
        if row.run_id != contract.run_id {
            return rejected(
                contract,
                "PROCESS_RECEIPT_RUN_MISMATCH",
                format!(
                    "evidence receipt {} belongs to another run",
                    evidence.receipt_id
                ),
                receipts_checked,
                evidence_checked,
            );
        }
        match &row.event {
            Event::EvidenceCaptured(event)
                if event.evidence_id == evidence.evidence_id
                    && event.kind == evidence.kind
                    && requirement_kinds.get(evidence.requirement_id.as_str())
                        == Some(&evidence.kind.as_str())
                    && event.sha256 == evidence.sha256 =>
            {
                satisfied.insert(evidence.requirement_id.as_str());
            }
            _ => {
                return rejected(
                    contract,
                    "PROCESS_EVIDENCE_RECEIPT_MISMATCH",
                    format!(
                        "receipt {} does not bind evidence {} and its digest",
                        evidence.receipt_id, evidence.evidence_id
                    ),
                    receipts_checked,
                    evidence_checked,
                )
            }
        }
    }

    let supported: BTreeSet<&str> = execution
        .supported_assumptions
        .iter()
        .map(String::as_str)
        .collect();
    if supported.len() != execution.supported_assumptions.len()
        || supported.iter().any(|id| !assumption_ids.contains(id))
    {
        return rejected(
            contract,
            "PROCESS_ASSUMPTION_SUPPORT_INVALID",
            "supported_assumptions contains duplicates or undeclared ids",
            receipts_checked,
            evidence_checked,
        );
    }
    match unique_nonempty_ids(
        execution
            .unresolved_claims
            .iter()
            .map(|claim| claim.claim_id.as_str()),
    ) {
        Ok(_)
            if execution
                .unresolved_claims
                .iter()
                .all(|claim| !claim.statement.trim().is_empty()) => {}
        _ => {
            return rejected(
                contract,
                "PROCESS_UNRESOLVED_CLAIM_INVALID",
                "unresolved claims require unique ids and non-empty statements",
                receipts_checked,
                evidence_checked,
            )
        }
    }
    match &execution.outcome {
        ProcessOutcome::Complete { receipt_id } => {
            let manifest_sha256 = match process_execution_manifest_sha256(contract, execution) {
                Ok(digest) => digest,
                Err(error) => {
                    return rejected(
                        contract,
                        "PROCESS_EXECUTION_MANIFEST_FAILED",
                        error.to_string(),
                        receipts_checked,
                        evidence_checked,
                    )
                }
            };
            let required_missing: Vec<&str> = contract
                .required_evidence
                .iter()
                .filter(|requirement| requirement.required)
                .map(|requirement| requirement.id.as_str())
                .chain(
                    contract
                        .completion_predicate
                        .all_evidence
                        .iter()
                        .map(String::as_str),
                )
                .filter(|id| !satisfied.contains(id))
                .collect();
            if !required_missing.is_empty() {
                return rejected(
                    contract,
                    "PROCESS_REQUIRED_EVIDENCE_MISSING",
                    format!("missing evidence: {}", required_missing.join(", ")),
                    receipts_checked,
                    evidence_checked,
                );
            }
            if let Some(assumption) = contract.assumptions.iter().find(|assumption| {
                supported.contains(assumption.id.as_str())
                    && assumption
                        .required_evidence
                        .iter()
                        .any(|id| !satisfied.contains(id.as_str()))
            }) {
                return rejected(
                    contract,
                    "PROCESS_ASSUMPTION_EVIDENCE_MISSING",
                    format!("assumption '{}' lacks its declared evidence", assumption.id),
                    receipts_checked,
                    evidence_checked,
                );
            }
            if contract
                .completion_predicate
                .require_all_assumptions_supported
                && contract
                    .assumptions
                    .iter()
                    .any(|assumption| !supported.contains(assumption.id.as_str()))
            {
                return rejected(
                    contract,
                    "PROCESS_ASSUMPTION_UNSUPPORTED",
                    "completion requires every declared assumption to be supported",
                    receipts_checked,
                    evidence_checked,
                );
            }
            if contract.completion_predicate.require_no_unresolved_claims
                && !execution.unresolved_claims.is_empty()
            {
                return rejected(
                    contract,
                    "PROCESS_UNRESOLVED_CLAIMS",
                    "completion is blocked by unresolved claims",
                    receipts_checked,
                    evidence_checked,
                );
            }
            let Some(row) = receipt_rows.get(receipt_id) else {
                return rejected(
                    contract,
                    "PROCESS_COMPLETION_RECEIPT_MISSING",
                    format!("completion receipt {receipt_id} is absent"),
                    receipts_checked,
                    evidence_checked,
                );
            };
            receipts_checked += 1;
            if row.seq <= last_referenced_seq {
                return rejected(
                    contract,
                    "PROCESS_TERMINAL_RECEIPT_ORDER_INVALID",
                    "completion verdict does not follow every referenced action and evidence row",
                    receipts_checked,
                    evidence_checked,
                );
            }
            if row.run_id != contract.run_id {
                return rejected(
                    contract,
                    "PROCESS_RECEIPT_RUN_MISMATCH",
                    format!("completion receipt {receipt_id} belongs to another run"),
                    receipts_checked,
                    evidence_checked,
                );
            }
            if !matches!(
                row.event,
                Event::GateVerdict(ref event)
                    if event.verdict == Verdict::Verified
                        && matches!(event.gate_id.as_str(), "evidence-completeness" | "process-contract")
                        && event.evidence_sha256.as_deref() == Some(manifest_sha256.as_str())
                        && execution
                            .performed_actions
                            .iter()
                            .any(|action| action.action_id == event.action_id)
            ) {
                return rejected(
                    contract,
                    "PROCESS_COMPLETION_RECEIPT_INVALID",
                    "completion receipt is not a verified verdict bound to this execution manifest",
                    receipts_checked,
                    evidence_checked,
                );
            }
            findings.push(ProcessValidationFinding {
                code: "PROCESS_CONTRACT_FOLLOWED".into(),
                detail: "completion predicate and signed journal evidence agree".into(),
            });
            ProcessValidationReport {
                contract_version: contract.contract_version.clone(),
                contract_id: contract.contract_id,
                followed: true,
                status: "complete".into(),
                reason_code: "PROCESS_CONTRACT_FOLLOWED".into(),
                journal_verified: true,
                receipts_checked,
                evidence_checked,
                findings,
            }
        }
        ProcessOutcome::HonestStop {
            condition_code,
            receipt_id,
            unblocks,
        } => {
            let manifest_sha256 = match process_execution_manifest_sha256(contract, execution) {
                Ok(digest) => digest,
                Err(error) => {
                    return rejected(
                        contract,
                        "PROCESS_EXECUTION_MANIFEST_FAILED",
                        error.to_string(),
                        receipts_checked,
                        evidence_checked,
                    )
                }
            };
            if !stop_codes.contains(condition_code.as_str()) {
                return rejected(
                    contract,
                    "PROCESS_HONEST_STOP_UNDECLARED",
                    format!("undeclared honest-stop condition '{condition_code}'"),
                    receipts_checked,
                    evidence_checked,
                );
            }
            if unblocks.is_empty()
                || unblocks.iter().any(|unblock| {
                    unblock.tried.is_empty()
                        || unblock.tried.iter().any(|item| item.trim().is_empty())
                        || unblock.missing.trim().is_empty()
                        || unblock.route.trim().is_empty()
                })
            {
                return rejected(
                    contract,
                    "PROCESS_UNBLOCK_INVALID",
                    "honest-stop requires typed non-empty tried/missing/route fields",
                    receipts_checked,
                    evidence_checked,
                );
            }
            let Some(row) = receipt_rows.get(receipt_id) else {
                return rejected(
                    contract,
                    "PROCESS_HONEST_STOP_RECEIPT_MISSING",
                    format!("honest-stop receipt {receipt_id} is absent"),
                    receipts_checked,
                    evidence_checked,
                );
            };
            receipts_checked += 1;
            if row.seq <= last_referenced_seq {
                return rejected(
                    contract,
                    "PROCESS_TERMINAL_RECEIPT_ORDER_INVALID",
                    "honest-stop verdict does not follow every referenced action and evidence row",
                    receipts_checked,
                    evidence_checked,
                );
            }
            if row.run_id != contract.run_id
                || !matches!(
                    row.event,
                    Event::GateVerdict(ref event)
                        if matches!(event.verdict, Verdict::Incomplete | Verdict::Unsupported)
                            && event.gate_id == "process-contract"
                            && event.reason_code == *condition_code
                            && event.evidence_sha256.as_deref()
                                == Some(manifest_sha256.as_str())
                            && execution
                                .performed_actions
                                .iter()
                                .any(|action| action.action_id == event.action_id)
                )
            {
                return rejected(
                    contract,
                    "PROCESS_HONEST_STOP_RECEIPT_INVALID",
                    "honest-stop receipt does not bind its condition to a same-run incomplete/unsupported verdict",
                    receipts_checked,
                    evidence_checked,
                );
            }
            ProcessValidationReport {
                contract_version: contract.contract_version.clone(),
                contract_id: contract.contract_id,
                followed: true,
                status: "honest_stop".into(),
                reason_code: "PROCESS_HONEST_STOP_VALID".into(),
                journal_verified: true,
                receipts_checked,
                evidence_checked,
                findings: vec![ProcessValidationFinding {
                    code: "PROCESS_HONEST_STOP_VALID".into(),
                    detail: "declared stop condition includes a signed receipt and typed unblock"
                        .into(),
                }],
            }
        }
        ProcessOutcome::InProgress => rejected(
            contract,
            "PROCESS_NOT_TERMINAL",
            "execution has neither completed nor honestly stopped",
            receipts_checked,
            evidence_checked,
        ),
    }
}

fn unique_nonempty_ids<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, String> {
    let mut out = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err("identifier must not be empty".into());
        }
        if !out.insert(value) {
            return Err(format!("duplicate identifier '{value}'"));
        }
    }
    Ok(out)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn rejected(
    contract: &ProcessContract,
    code: &str,
    detail: impl Into<String>,
    receipts_checked: u64,
    evidence_checked: u64,
) -> ProcessValidationReport {
    ProcessValidationReport {
        contract_version: contract.contract_version.clone(),
        contract_id: contract.contract_id,
        followed: false,
        status: "invalid".into(),
        reason_code: code.into(),
        journal_verified: true,
        receipts_checked,
        evidence_checked,
        findings: vec![ProcessValidationFinding {
            code: code.into(),
            detail: detail.into(),
        }],
    }
}
