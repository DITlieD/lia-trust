use lia_gates::{evaluate_action_gates, evaluate_gate, GateConfig, GateOutcome, GatePayload, GateRequest};
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("gate: {0}")]
    Gate(#[from] lia_gates::GateError),
    #[error("invalid action: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenericAction {
    pub kind: ActionKind,
    pub action_id: Uuid,
    pub payload: GatePayload,
}

pub fn evaluate_generic_action(
    action: &GenericAction,
    config: &GateConfig,
) -> Result<Vec<GateOutcome>, AdapterError> {
    Ok(evaluate_action_gates(
        &action.kind,
        action.action_id,
        &action.payload,
        config,
    )?)
}

pub fn evaluate_named_gate(
    request: &GateRequest,
    config: &GateConfig,
) -> Result<GateOutcome, AdapterError> {
    Ok(evaluate_gate(request, config)?)
}
