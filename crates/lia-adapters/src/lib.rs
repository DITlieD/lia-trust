mod assurance;
mod claude_code;
mod conformance;
mod contracts;
mod codex;
mod dispatch;
mod generic;
mod mcp_inspection;

pub use assurance::{
    known_adapters, load_assurance_from_probe_file, report_for_adapter, AssuranceLevel,
    AssuranceReport, CapabilityProbe, GateAssuranceCell, GateCell,
};
pub use conformance::{assert_adapter, load_suite, ConformanceReport, SuiteManifest};
pub use claude_code::{
    decision_json, handle_pre_tool_stdin, map_tool_to_action, on_pre_tool, parse_pre_tool_use,
    HookDecision, PreToolUseInput,
};
pub use contracts::{
    contracts_value, load_contracts, ADAPTER_CLAUDE_CODE, ADAPTER_CODEX, ADAPTER_GENERIC,
    ALL_CAPABILITY_KEYS, CONTRACTS_JSON, MCP_INSPECT_EXPLAIN_DENIAL, MCP_INSPECT_INSPECT_RECEIPTS,
    MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES, MCP_INSPECT_SHOW_POLICY, MCP_INSPECT_VERIFY_RUN,
};
pub use codex::{handle_jsonrpc, proxy_tool_call, proxy_tool_names, JsonRpcRequest, ProxyCallResult};
pub use dispatch::{
    denial_summary, dispatch_action, is_blocking, worst_verdict, DispatchResult, RunContext,
};
pub use generic::{admit_final_diff, wrap, WrapOptions, WrapReport};
pub use mcp_inspection::{
    handle_inspection_call, inspection_tool_names, load_probe, refuse_mutation, DenialRecord,
    InspectionContext,
};

use lia_gates::{evaluate_action_gates, evaluate_gate, GateConfig, GateOutcome, GatePayload, GateRequest};
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("gate: {0}")]
    Gate(#[from] lia_gates::GateError),
    #[error("journal: {0}")]
    Journal(#[from] lia_journal::JournalError),
    #[error("invalid action: {0}")]
    Invalid(String),
}

impl From<dispatch::DispatchError> for AdapterError {
    fn from(value: dispatch::DispatchError) -> Self {
        match value {
            dispatch::DispatchError::Adapter(e) => e,
            dispatch::DispatchError::Journal(e) => AdapterError::Journal(e),
            dispatch::DispatchError::MissingSecret => {
                AdapterError::Invalid("journaling requires secret_key_hex".into())
            }
            dispatch::DispatchError::Invalid(s) => AdapterError::Invalid(s),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assurance::AssuranceReport;
    use crate::contracts::{
        CAP_COMPLETION_GATE, CAP_IMMUTABLE_JOURNAL, CAP_OFFLINE_VERIFICATION, CAP_POST_WRITE_RECEIPT,
        CAP_PRE_WRITE_BLOCK, CAP_SHELL_PRE_BLOCK, CAP_SHELL_RESULT_CAPTURE,
    };
    use lia_gates::GateConfig;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn cfg(root: PathBuf) -> GateConfig {
        GateConfig {
            allowed_roots: vec![root.clone()],
            home_dir: Some(PathBuf::from("/home/agent")),
            cwd: root,
            protected_paths: vec![],
            registry: BTreeMap::new(),
            env: BTreeMap::new(),
            run_id: None,
        }
    }

    #[test]
    fn assurance_never_confine_even_if_keys_look_confine() {
        let mut keys = BTreeMap::new();
        for k in ALL_CAPABILITY_KEYS {
            keys.insert((*k).to_string(), true);
        }
        let probe = CapabilityProbe {
            adapter: ADAPTER_CLAUDE_CODE.into(),
            keys,
            probed_at: None,
            notes: vec![],
        };
        let report = AssuranceReport::from_probe(&probe).expect("report");
        assert_ne!(report.level, AssuranceLevel::Confine);
        assert_eq!(report.level, AssuranceLevel::Gate);
    }

    #[test]
    fn missing_pre_write_yields_detect_for_fs() {
        let mut keys = BTreeMap::new();
        keys.insert(CAP_POST_WRITE_RECEIPT.into(), true);
        keys.insert(CAP_IMMUTABLE_JOURNAL.into(), true);
        keys.insert(CAP_OFFLINE_VERIFICATION.into(), true);
        let probe = CapabilityProbe {
            adapter: ADAPTER_GENERIC.into(),
            keys,
            probed_at: None,
            notes: vec![],
        };
        let report = AssuranceReport::from_probe(&probe).expect("report");
        let fs = report
            .gates
            .iter()
            .find(|g| g.gate_id == "filesystem-scope")
            .expect("fs");
        assert_eq!(fs.cell, GateCell::Detect);
        assert_eq!(report.level, AssuranceLevel::Observe);
    }

    #[test]
    fn claude_hook_denies_out_of_scope_delete() {
        let root = tempfile::tempdir().unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/outside-lia-delete"},
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "deny");
    }

    #[test]
    fn claude_hook_refutes_fabricated_pass() {
        let root = tempfile::tempdir().unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo lia-fabricate-pass"},
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "deny");
        let d = decision.dispatch.expect("dispatch");
        assert!(d.outcomes.iter().any(|o| o.verdict == lia_protocol::Verdict::Refuted));
    }

    #[test]
    fn inspection_tools_are_read_only_named() {
        assert!(inspection_tool_names().contains(&MCP_INSPECT_VERIFY_RUN));
        assert!(refuse_mutation("verify_run").is_err());
    }

    #[test]
    fn gate_cells_require_probe_keys() {
        let mut keys = BTreeMap::new();
        keys.insert(CAP_PRE_WRITE_BLOCK.into(), true);
        keys.insert(CAP_SHELL_PRE_BLOCK.into(), true);
        keys.insert(CAP_SHELL_RESULT_CAPTURE.into(), true);
        keys.insert(CAP_COMPLETION_GATE.into(), true);
        keys.insert(CAP_POST_WRITE_RECEIPT.into(), true);
        keys.insert(CAP_IMMUTABLE_JOURNAL.into(), true);
        keys.insert(CAP_OFFLINE_VERIFICATION.into(), true);
        let probe = CapabilityProbe {
            adapter: ADAPTER_CLAUDE_CODE.into(),
            keys,
            probed_at: None,
            notes: vec![],
        };
        let report = AssuranceReport::from_probe(&probe).expect("report");
        assert_eq!(report.level, AssuranceLevel::Gate);
        assert!(report
            .gates
            .iter()
            .any(|g| g.gate_id == "shell-irreversible" && g.cell == GateCell::Prevent));
    }
}
