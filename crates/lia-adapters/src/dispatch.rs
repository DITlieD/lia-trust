use std::path::PathBuf;

use lia_gates::{evaluate_action_gates, GateConfig, GateOutcome, GatePayload};
use lia_journal::{append_signed, Journal, JournalError, SigningIdentity};
use lia_protocol::{ActionKind, Event, GateVerdictEvent, RiskTier, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunContext {
    pub run_id: Uuid,
    pub config: GateConfig,
    #[serde(default)]
    pub journal_path: Option<PathBuf>,
    #[serde(default)]
    pub secret_key_hex: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchResult {
    pub action_id: Uuid,
    pub kind: ActionKind,
    pub outcomes: Vec<GateOutcome>,
    pub overall: Verdict,
    pub journal_receipts: Vec<serde_json::Value>,
    pub allowed: bool,
}

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("journaling requires secret_key_hex")]
    MissingSecret,
    #[error("invalid: {0}")]
    Invalid(String),
}

pub fn worst_verdict(outcomes: &[GateOutcome]) -> Verdict {
    let mut worst = Verdict::Allow;
    for o in outcomes {
        if rank(&o.verdict) > rank(&worst) {
            worst = o.verdict.clone();
        }
    }
    worst
}

fn rank(v: &Verdict) -> u8 {
    match v {
        Verdict::Allow | Verdict::Verified => 0,
        Verdict::Advisory | Verdict::Unsupported | Verdict::Incomplete => 1,
        Verdict::Quarantine => 2,
        Verdict::Deny | Verdict::Refuted => 3,
    }
}

pub fn is_blocking(v: &Verdict) -> bool {
    matches!(
        v,
        Verdict::Deny
            | Verdict::Refuted
            | Verdict::Quarantine
            | Verdict::Incomplete
            | Verdict::Unsupported
    )
}

pub fn dispatch_action(
    kind: ActionKind,
    action_id: Uuid,
    payload: GatePayload,
    ctx: &RunContext,
) -> Result<DispatchResult, DispatchError> {
    let mut outcomes = evaluate_action_gates(&kind, action_id, &payload, &ctx.config)
        .map_err(AdapterError::from)?;
    append_production_quality_outcomes(&kind, action_id, &payload, &ctx.config, &mut outcomes);
    finish_dispatch(kind, action_id, outcomes, ctx)
}

pub(crate) fn dispatch_rejection(
    action_id: Uuid,
    reason_code: &str,
    detail: &str,
    ctx: &RunContext,
) -> Result<DispatchResult, DispatchError> {
    let mut hasher = Sha256::new();
    hasher.update(detail.as_bytes());
    let outcome = GateOutcome {
        gate_id: "adapter-input".into(),
        action_id,
        verdict: Verdict::Deny,
        reason_code: reason_code.into(),
        risk_tier: RiskTier::Security,
        detail: Some(detail.into()),
        offending: None,
        evidence_sha256: hex::encode(hasher.finalize()),
        timestamp: chrono::Utc::now(),
        hl4: None,
        shareable: None,
    };
    finish_dispatch(ActionKind::Other, action_id, vec![outcome], ctx)
}

fn finish_dispatch(
    kind: ActionKind,
    action_id: Uuid,
    outcomes: Vec<GateOutcome>,
    ctx: &RunContext,
) -> Result<DispatchResult, DispatchError> {
    let overall = if outcomes.is_empty() {
        Verdict::Deny
    } else {
        worst_verdict(&outcomes)
    };
    let allowed = !is_blocking(&overall) && !outcomes.is_empty();

    let mut journal_receipts = Vec::new();
    if let Some(db) = &ctx.journal_path {
        let secret = ctx
            .secret_key_hex
            .as_deref()
            .ok_or(DispatchError::MissingSecret)?;
        let key_id = ctx.key_id.clone().unwrap_or_else(|| "lia-default".into());
        let identity = SigningIdentity::from_secret_key_hex(key_id, secret)?;
        let journal = if db.exists() {
            Journal::open(db)?
        } else {
            Journal::create(db)?
        };
        for outcome in &outcomes {
            let event = Event::GateVerdict(GateVerdictEvent {
                action_id: outcome.action_id,
                gate_id: outcome.gate_id.clone(),
                verdict: outcome.verdict.clone(),
                reason_code: outcome.reason_code.clone(),
                risk_tier: outcome.risk_tier.clone(),
                detail: outcome.detail.clone(),
                evidence_sha256: Some(outcome.evidence_sha256.clone()),
                timestamp: outcome.timestamp,
            });
            let row = append_signed(&journal, ctx.run_id, event, &identity)?;
            journal_receipts.push(serde_json::json!({
                "seq": row.seq,
                "row_hash": row.row_hash,
                "prev_hash": row.prev_hash,
                "receipt_id": row.receipt.as_ref().map(|r| r.receipt_id),
                "signature_hex": row.receipt.as_ref().map(|r| &r.signature_hex),
                "gate_id": outcome.gate_id,
                "verdict": outcome.verdict,
                "reason_code": outcome.reason_code,
                "detail": outcome.detail,
            }));
        }
    }

    Ok(DispatchResult {
        action_id,
        kind,
        outcomes,
        overall,
        journal_receipts,
        allowed,
    })
}

fn append_production_quality_outcomes(
    kind: &ActionKind,
    action_id: Uuid,
    payload: &GatePayload,
    config: &GateConfig,
    outcomes: &mut Vec<GateOutcome>,
) {
    if matches!(kind, ActionKind::WriteFile) {
        if let (Some(path), Some(text)) = (payload.path.as_deref(), payload.text.as_deref()) {
            if let Some(language) = language_for_path(path) {
                match lia_ast::scan_source(text, language, &lia_ast::ScanOptions::default()) {
                    Ok(report) => outcomes.push(lia_ast::ast_report_to_outcome(&report, action_id)),
                    Err(error) => outcomes.push(quality_error_outcome(
                        "ast",
                        "AST_INVALID_INPUT",
                        &error.to_string(),
                        text.as_bytes(),
                        action_id,
                    )),
                }
            }
        }
    }

    if let Some(graph_value) = payload.taint_graph.as_ref() {
        let graph_json = graph_value.to_string();
        match lia_taint::parse_graph(&graph_json).and_then(|graph| lia_taint::check_flows(&graph)) {
            Ok(report) => outcomes.push(taint_report_to_outcome(&report, graph_value, action_id)),
            Err(error) => outcomes.push(quality_error_outcome(
                "taint",
                "TAINT_INVALID_INPUT",
                &error.to_string(),
                graph_json.as_bytes(),
                action_id,
            )),
        }
    }

    if let Some(claim_value) = payload.ground_claim.as_ref() {
        let claim_json = claim_value.to_string();
        match lia_ground::parse_claim(&claim_json) {
            Ok(claim) => {
                let ground_context = lia_ground::GroundContext::from_gate_config(config);
                match lia_ground::verify_claim_with_id(&claim, &ground_context, action_id) {
                    Ok(result) => outcomes.push(lia_ground::ground_result_to_outcome(&result)),
                    Err(error) => outcomes.push(quality_error_outcome(
                        "ground",
                        "GROUND_VERIFICATION_ERROR",
                        &error.to_string(),
                        claim_json.as_bytes(),
                        action_id,
                    )),
                }
            }
            Err(error) => outcomes.push(quality_error_outcome(
                "ground",
                "GROUND_INVALID_INPUT",
                &error.to_string(),
                claim_json.as_bytes(),
                action_id,
            )),
        }
    }

    if let Some(exchange_value) = payload.syco_exchange.as_ref() {
        let exchange_json = exchange_value.to_string();
        match lia_syco::parse_exchange(&exchange_json)
            .and_then(|exchange| lia_syco::detect(&exchange))
        {
            Ok(report) => outcomes.push(lia_syco::syco_report_to_outcome(&report, action_id)),
            Err(error) => outcomes.push(quality_error_outcome(
                "syco",
                "SYCO_INVALID_INPUT",
                &error.to_string(),
                exchange_json.as_bytes(),
                action_id,
            )),
        }
    }
}

fn language_for_path(path: &str) -> Option<lia_ast::Language> {
    match std::path::Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("py") => Some(lia_ast::Language::Python),
        Some("rs") => Some(lia_ast::Language::Rust),
        Some("js" | "mjs" | "cjs") => Some(lia_ast::Language::Javascript),
        _ => None,
    }
}

fn taint_report_to_outcome(
    report: &lia_taint::TaintReport,
    graph: &serde_json::Value,
    action_id: Uuid,
) -> GateOutcome {
    let evidence = serde_json::json!({
        "graph": graph,
        "findings": report.findings,
    })
    .to_string();
    let mut hasher = Sha256::new();
    hasher.update(evidence.as_bytes());
    GateOutcome {
        gate_id: "taint".into(),
        action_id,
        verdict: match report.verdict {
            lia_taint::TaintVerdict::Allow => Verdict::Allow,
            lia_taint::TaintVerdict::Deny => Verdict::Deny,
        },
        reason_code: report.reason_code.clone(),
        risk_tier: RiskTier::Security,
        detail: report
            .findings
            .iter()
            .find(|finding| !finding.declassified)
            .map(|finding| format!("{} -> {}", finding.source, finding.sink)),
        offending: None,
        evidence_sha256: hex::encode(hasher.finalize()),
        timestamp: chrono::Utc::now(),
        hl4: None,
        shareable: None,
    }
}

fn quality_error_outcome(
    gate_id: &str,
    reason_code: &str,
    detail: &str,
    evidence: &[u8],
    action_id: Uuid,
) -> GateOutcome {
    let mut hasher = Sha256::new();
    hasher.update(evidence);
    GateOutcome {
        gate_id: gate_id.into(),
        action_id,
        verdict: Verdict::Deny,
        reason_code: reason_code.into(),
        risk_tier: RiskTier::Security,
        detail: Some(detail.into()),
        offending: None,
        evidence_sha256: hex::encode(hasher.finalize()),
        timestamp: chrono::Utc::now(),
        hl4: None,
        shareable: None,
    }
}

pub fn denial_summary(result: &DispatchResult) -> Option<String> {
    result
        .outcomes
        .iter()
        .filter(|o| is_blocking(&o.verdict))
        .map(|o| {
            format!(
                "{}:{}:{}",
                o.gate_id,
                o.reason_code,
                o.offending.as_deref().or(o.detail.as_deref()).unwrap_or("")
            )
        })
        .reduce(|a, b| format!("{a}; {b}"))
}
