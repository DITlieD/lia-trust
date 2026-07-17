use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use lia_journal::Journal;
use lia_policy::freeze_policy_from_path;
use lia_verify::verify_bundle;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::assurance::{AssuranceReport, CapabilityProbe};
use crate::contracts::{
    MCP_INSPECT_EXPLAIN_DENIAL, MCP_INSPECT_INSPECT_RECEIPTS, MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES,
    MCP_INSPECT_SHOW_POLICY, MCP_INSPECT_VERIFY_RUN,
};
use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InspectionContext {
    #[serde(default)]
    pub journal_path: Option<PathBuf>,
    #[serde(default)]
    pub policy_path: Option<PathBuf>,
    #[serde(default)]
    pub bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub probe_path: Option<PathBuf>,
    #[serde(default)]
    pub adapter: Option<String>,
    #[serde(default)]
    pub last_denials: Vec<DenialRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenialRecord {
    pub action_id: String,
    pub gate_id: String,
    pub reason_code: String,
    pub detail: Option<String>,
    pub offending: Option<String>,
}

pub fn inspection_tool_names() -> &'static [&'static str] {
    &[
        MCP_INSPECT_VERIFY_RUN,
        MCP_INSPECT_INSPECT_RECEIPTS,
        MCP_INSPECT_EXPLAIN_DENIAL,
        MCP_INSPECT_SHOW_POLICY,
        MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES,
    ]
}

pub fn handle_inspection_call(
    name: &str,
    args: &Value,
    ctx: &InspectionContext,
) -> Result<Value, AdapterError> {
    match name {
        MCP_INSPECT_VERIFY_RUN => verify_run(args, ctx),
        MCP_INSPECT_INSPECT_RECEIPTS => inspect_receipts(args, ctx),
        MCP_INSPECT_EXPLAIN_DENIAL => explain_denial(args, ctx),
        MCP_INSPECT_SHOW_POLICY => show_policy(args, ctx),
        MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES => show_adapter_capabilities(args, ctx),
        other => Err(AdapterError::Invalid(format!(
            "unknown inspection tool: {other}"
        ))),
    }
}

fn verify_run(args: &Value, ctx: &InspectionContext) -> Result<Value, AdapterError> {
    let bundle = args
        .get("bundle")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .or_else(|| ctx.bundle_path.clone())
        .ok_or_else(|| AdapterError::Invalid("verify_run needs bundle".into()))?;
    let report = verify_bundle(&bundle).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    Ok(json!({
        "content": [{"type": "text", "text": serde_json::to_string(&report).unwrap_or_default()}],
        "isError": false,
        "mutable": false,
        "report": report,
    }))
}

fn inspect_receipts(args: &Value, ctx: &InspectionContext) -> Result<Value, AdapterError> {
    let journal = args
        .get("journal")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .or_else(|| ctx.journal_path.clone())
        .ok_or_else(|| AdapterError::Invalid("inspect_receipts needs journal".into()))?;
    let j = Journal::open_readonly(&journal).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let rows = j
        .load_rows()
        .map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let mut receipts = Vec::new();
    for row in rows {
        if let Some(receipt) = row.receipt {
            receipts.push(json!({
                "seq": row.seq,
                "run_id": row.run_id,
                "row_hash": row.row_hash,
                "prev_hash": row.prev_hash,
                "receipt_id": receipt.receipt_id,
                "signature_hex": receipt.signature_hex,
                "event": row.event,
            }));
        }
    }
    Ok(json!({
        "content": [{"type": "text", "text": format!("{} receipts", receipts.len())}],
        "isError": false,
        "mutable": false,
        "receipts": receipts,
    }))
}

fn explain_denial(args: &Value, ctx: &InspectionContext) -> Result<Value, AdapterError> {
    let reason = args
        .get("reason_code")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let action_id = args
        .get("action_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let matches: Vec<&DenialRecord> = ctx
        .last_denials
        .iter()
        .filter(|d| {
            reason
                .as_ref()
                .map(|r| &d.reason_code == r)
                .unwrap_or(true)
                && action_id
                    .as_ref()
                    .map(|a| &d.action_id == a)
                    .unwrap_or(true)
        })
        .collect();

    if matches.is_empty() && reason.is_none() && action_id.is_none() {
        return Ok(json!({
            "content": [{"type": "text", "text": "no denial filter; supply reason_code or action_id"}],
            "isError": false,
            "mutable": false,
            "denials": ctx.last_denials,
        }));
    }

    Ok(json!({
        "content": [{"type": "text", "text": format!("{} denial(s)", matches.len())}],
        "isError": false,
        "mutable": false,
        "denials": matches,
    }))
}

fn show_policy(args: &Value, ctx: &InspectionContext) -> Result<Value, AdapterError> {
    let path = args
        .get("policy")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .or_else(|| ctx.policy_path.clone())
        .ok_or_else(|| AdapterError::Invalid("show_policy needs policy".into()))?;
    let frozen = freeze_policy_from_path(&path).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    Ok(json!({
        "content": [{"type": "text", "text": format!("policy_id={} hash={}", frozen.policy_id, frozen.policy_hash)}],
        "isError": false,
        "mutable": false,
        "policy": {
            "policy_id": frozen.policy_id,
            "version": frozen.version,
            "policy_hash": frozen.policy_hash,
            "rules": frozen.rules,
            "frozen_at": frozen.frozen_at,
        }
    }))
}

fn show_adapter_capabilities(args: &Value, ctx: &InspectionContext) -> Result<Value, AdapterError> {
    let adapter = args
        .get("adapter")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| ctx.adapter.clone())
        .ok_or_else(|| AdapterError::Invalid("show_adapter_capabilities needs adapter".into()))?;
    let probe_path = args
        .get("probe")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .or_else(|| ctx.probe_path.clone());
    let probe = match probe_path {
        Some(p) => load_probe(&p)?,
        None => CapabilityProbe {
            adapter: adapter.clone(),
            keys: BTreeMap::new(),
            probed_at: None,
            notes: vec!["no probe file; empty capabilities".into()],
        },
    };
    if probe.adapter != adapter && !probe.adapter.is_empty() {
        return Err(AdapterError::Invalid(format!(
            "probe adapter {} != requested {adapter}",
            probe.adapter
        )));
    }
    let report = AssuranceReport::from_probe(&probe)?;
    Ok(json!({
        "content": [{"type": "text", "text": report.one_line()}],
        "isError": false,
        "mutable": false,
        "capabilities": probe.keys,
        "assurance": report,
    }))
}

pub fn load_probe(path: impl AsRef<Path>) -> Result<CapabilityProbe, AdapterError> {
    let bytes = fs::read(path.as_ref()).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AdapterError::Invalid(e.to_string()))
}

pub fn refuse_mutation(tool: &str) -> Result<(), AdapterError> {
    Err(AdapterError::Invalid(format!(
        "inspection tool {tool} cannot mutate journal or policy"
    )))
}
