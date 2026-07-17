use std::path::PathBuf;

use lia_gates::{evaluate_action_gates, GateConfig, GateOutcome, GatePayload};
use lia_journal::{append_signed, Journal, JournalError, SigningIdentity};
use lia_protocol::{ActionKind, Event, GateVerdictEvent, Verdict};
use serde::{Deserialize, Serialize};
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
    matches!(v, Verdict::Deny | Verdict::Refuted | Verdict::Quarantine)
}

pub fn dispatch_action(
    kind: ActionKind,
    action_id: Uuid,
    payload: GatePayload,
    ctx: &RunContext,
) -> Result<DispatchResult, DispatchError> {
    let outcomes = evaluate_action_gates(&kind, action_id, &payload, &ctx.config)
        .map_err(AdapterError::from)?;
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
