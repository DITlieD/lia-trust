mod assurance;
mod claude_code;
mod conformance;
mod contracts;
mod codex;
mod dispatch;
mod generic;
mod install;
mod mcp_inspection;
mod mcp_stdio;

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
pub use codex::{
    handle_jsonrpc, handle_jsonrpc_opt, proxy_tool_call, proxy_tool_names, serve_mcp_stdio,
    serve_mcp_stdio_io, JsonRpcRequest, ProxyCallResult, MCP_PROTOCOL_VERSION, MCP_SERVER_NAME,
};
pub use mcp_stdio::{frame_json, read_framed_message, write_framed_message};
pub use dispatch::{
    denial_summary, dispatch_action, is_blocking, worst_verdict, DispatchResult, RunContext,
};
pub use generic::{admit_final_diff, wrap, WrapOptions, WrapReport};
pub use mcp_inspection::{
    handle_inspection_call, inspection_tool_names, load_probe, refuse_mutation, DenialRecord,
    InspectionContext,
};
pub use install::{
    claude_hook_present, codex_mcp_present, default_claude_home, default_codex_home,
    default_lia_home, install, looks_like_live_user_home, merge_claude_settings, merge_codex_toml,
    status, uninstall, unmerge_claude_settings, unmerge_codex_toml, InstallError, InstallPaths,
    InstallReport, InstallRequest, KernelBoundary, CLAUDE_PRETOOL_MATCHER, CODEX_MCP_SERVER,
    LIA_HOOK_MARKER, MANIFEST_NAME,
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
    fn claude_hook_gates_multi_edit_out_of_scope() {
        // MultiEdit is in the install matcher; before the mapping fix it hit the
        // unmapped fail-open ALLOW, so an out-of-scope write was ungated.
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
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "/etc/cron.d/evil",
                "edits": [{"old_string": "", "new_string": "* * * * * root sh -c evil"}]
            },
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

    #[test]
    fn admit_write_ast_catches_python_eval() {
        let reason = admit_write_with_ast(
            std::path::Path::new("evil.py"),
            "x = eval(user_input)\n",
        )
        .expect("scan");
        assert_eq!(reason.as_deref(), Some("AST_EVAL"));
    }

    #[test]
    fn admit_taint_graph_denies_untrusted_to_sink() {
        let g = r#"{"nodes":[{"id":"s","kind":"untrusted_source"},{"id":"k","kind":"destructive_sink"}],"edges":[{"from":"s","to":"k"}]}"#;
        let (allow, code) = admit_taint_graph(g).expect("taint");
        assert!(!allow);
        assert_eq!(code, "TAINT_UNTRUSTED_TO_DESTRUCTIVE_SINK");
    }
}

/// Optional AST gate on write/diff admission (P1-11). Returns deny reason if blocked.
pub fn admit_write_with_ast(
    path: &std::path::Path,
    text: &str,
) -> Result<Option<String>, AdapterError> {
    use lia_ast::{scan_source, Language, ScanOptions};
    let lang = match path.extension().and_then(|e| e.to_str()) {
        Some("py") => Language::Python,
        Some("rs") => Language::Rust,
        Some("js") | Some("mjs") | Some("cjs") => Language::Javascript,
        _ => return Ok(None),
    };
    let opts = ScanOptions::default();
    let report =
        scan_source(text, lang, &opts).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    if let Some(hit) = report.hits.first() {
        return Ok(Some(hit.predicate.reason_code().to_string()));
    }
    Ok(None)
}

/// Invoke taint check_flows when graph supplied (P1-12).
pub fn admit_taint_graph(graph_json: &str) -> Result<(bool, String), AdapterError> {
    use lia_taint::{check_flows, parse_graph, TaintVerdict};
    let g = parse_graph(graph_json).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let r = check_flows(&g).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let allow = matches!(r.verdict, TaintVerdict::Allow);
    Ok((allow, r.reason_code.clone()))
}
