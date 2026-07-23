mod assurance;
mod claude_code;
mod codex;
mod confinement;
mod conformance;
mod contracts;
mod cursor;
mod dispatch;
mod envelope;
mod gemini_cli;
mod generic;
mod install;
mod mcp_inspection;
mod mcp_stdio;
mod process_contract;
mod registry;

pub use assurance::{
    known_adapters, load_assurance_from_probe_file, report_for_adapter, AssuranceLevel,
    AssuranceReport, CapabilityProbe, GateAssuranceCell, GateCell,
};
pub use claude_code::{
    decision_json, handle_pre_tool_stdin, map_tool_to_action, on_pre_tool, parse_error_reason,
    parse_pre_tool_use, HookDecision, PreToolUseInput,
};
pub use envelope::{
    default_mediated_tools, default_unmediated_tools, normalize_pre_tool_envelope,
    normalize_tool_name, CanonicalTool, NormalizedEnvelope, ADAPTER_PARSE_CODE,
};
pub use codex::{
    handle_jsonrpc, handle_jsonrpc_opt, proxy_tool_call, proxy_tool_names, serve_mcp_stdio,
    serve_mcp_stdio_io, JsonRpcRequest, ProxyCallResult, MCP_PROTOCOL_VERSION, MCP_SERVER_NAME,
};
pub use confinement::{
    credential_read, internal_confined_exec, spawn_linux_confined, ConfinementReport,
    CredentialSpec, LinuxConfinementOptions,
};
pub use conformance::{assert_adapter, load_suite, ConformanceReport, SuiteManifest};
pub use contracts::{
    contracts_value, load_contracts, ADAPTER_CLAUDE_CODE, ADAPTER_CODEX, ADAPTER_CURSOR,
    ADAPTER_GEMINI_CLI, ADAPTER_GENERIC, ALL_CAPABILITY_KEYS, CONTRACTS_JSON,
    MCP_INSPECT_EXPLAIN_DENIAL, MCP_INSPECT_INSPECT_RECEIPTS,
    MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES, MCP_INSPECT_SHOW_POLICY, MCP_INSPECT_VERIFY_RUN,
};
pub use cursor::{
    handle_cursor_mcp_stdin, handle_cursor_shell_stdin, on_cursor_before_mcp,
    on_cursor_before_shell, CursorHookDecision, CursorMcpInput, CursorShellInput,
};
pub use dispatch::{
    denial_summary, dispatch_action, is_blocking, worst_verdict, DispatchResult, RunContext,
};
pub use gemini_cli::{
    handle_gemini_before_tool_stdin, map_gemini_tool_to_action, on_gemini_before_tool,
    parse_gemini_before_tool, GeminiBeforeToolInput, GeminiHookDecision,
};
pub use generic::{admit_final_diff, wrap, WrapOptions, WrapReport};
pub use install::{
    claude_hook_present, codex_mcp_present, cursor_hooks_present, default_claude_home,
    default_codex_home, default_cursor_home, default_gemini_home, default_lia_home, doctor,
    gemini_hook_present, install, looks_like_live_user_home, merge_claude_settings,
    merge_codex_toml, merge_cursor_hooks, merge_gemini_settings, status, uninstall,
    unmerge_claude_settings, unmerge_codex_toml, unmerge_cursor_hooks, unmerge_gemini_settings,
    DoctorCheck, DoctorReport, InstallError, InstallPaths, InstallReport, InstallRequest,
    KernelBoundary, CLAUDE_PRETOOL_MATCHER, CODEX_MCP_SERVER, GEMINI_BEFORETOOL_MATCHER,
    KERNEL_VERSION, LIA_HOOK_MARKER, MANIFEST_NAME,
};
pub use mcp_inspection::{
    handle_inspection_call, inspection_tool_names, load_probe, refuse_mutation, DenialRecord,
    InspectionContext,
};
pub use mcp_stdio::{frame_json, read_framed_message, write_framed_message};
pub use process_contract::{
    load_and_validate_process_contract, process_contract_sha256, process_execution_manifest_sha256,
    validate_process_contract, ProcessContractError, ProcessValidationFinding,
    ProcessValidationReport,
};
pub use registry::{
    collect_registry_evidence, RegistryEcosystem, RegistryEvidenceError, RegistryEvidenceOptions,
    RegistryEvidenceReport,
};

use lia_gates::{
    evaluate_action_gates, evaluate_gate, GateConfig, GateOutcome, GatePayload, GateRequest,
};
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
    /// Envelope/tool parse failure — operator-distinguishable from FS/SHELL policy denials.
    #[error("ADAPTER_PARSE: {0}")]
    Parse(String),
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
        CAP_COMPLETION_GATE, CAP_IMMUTABLE_JOURNAL, CAP_OFFLINE_VERIFICATION,
        CAP_POST_WRITE_RECEIPT, CAP_PRE_WRITE_BLOCK, CAP_SHELL_PRE_BLOCK, CAP_SHELL_RESULT_CAPTURE,
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
            cleanup_policy: None,
            spawn_policy: None,
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
            gate_cells: BTreeMap::new(),
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
            gate_cells: BTreeMap::new(),
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
        assert!(d
            .outcomes
            .iter()
            .any(|o| o.verdict == lia_protocol::Verdict::Refuted));
    }

    /// Grok camelCase read_file + target_file under allowed root → allow.
    #[test]
    fn grok_camelcase_read_file_allows_in_scope() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("Cargo.toml");
        std::fs::write(&target, "[package]\nname = \"t\"\n").unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "toolName": "read_file",
            "toolInput": {"target_file": target.to_string_lossy()},
            "hookEventName": "pre_tool_use",
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "allow");
        assert_eq!(decision.permission_decision_reason, "lia gates allow");
    }

    /// Grok camelCase run_terminal_command under allowed root → allow.
    #[test]
    fn grok_camelcase_run_terminal_command_allows() {
        let root = tempfile::tempdir().unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "toolName": "run_terminal_command",
            "toolInput": {"command": format!("ls {}", root.path().display())},
            "hookEventName": "pre_tool_use",
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "allow");
    }

    /// Grok camelCase search_replace + target_file under root → allow.
    #[test]
    fn grok_camelcase_search_replace_allows_in_scope() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("src.rs");
        std::fs::write(&target, "fn main() {}\n").unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "toolName": "search_replace",
            "toolInput": {
                "target_file": target.to_string_lossy(),
                "old_string": "fn main() {}",
                "new_string": "fn main() { /* ok */ }",
            },
            "hookEventName": "preToolUse",
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "allow");
        assert_eq!(decision.permission_decision_reason, "lia gates allow");
    }

    /// Claude-native snake_case Read still works after alias support.
    #[test]
    fn claude_native_snake_case_read_still_allows() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("readme.md");
        std::fs::write(&target, "ok\n").unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": target.to_string_lossy()},
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "allow");
    }

    /// Grok read_file with path outside allowed roots → deny (filesystem-scope still works).
    #[test]
    fn grok_camelcase_read_file_denies_out_of_scope() {
        let root = tempfile::tempdir().unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "toolName": "read_file",
            "toolInput": {"target_file": "/etc/passwd"},
            "hookEventName": "pre_tool_use",
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "deny");
    }

    /// Completely missing tool name still errors (fail-closed parse) with ADAPTER_PARSE.
    #[test]
    fn grok_missing_tool_name_still_errors() {
        let err = parse_pre_tool_use(r#"{"hookEventName":"pre_tool_use","toolInput":{}}"#)
            .expect_err("must fail closed without tool name");
        let msg = err.to_string();
        assert!(
            msg.contains(ADAPTER_PARSE_CODE) && msg.contains("missing tool_name"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn adapter_parse_distinct_from_policy_deny_reason() {
        // Parse failure message carries ADAPTER_PARSE; FS OOS deny does not.
        let parse_err = parse_pre_tool_use("{").expect_err("bad json");
        assert!(parse_err.to_string().starts_with(ADAPTER_PARSE_CODE));

        let root = tempfile::tempdir().unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "toolName": "read_file",
            "toolInput": {"target_file": "/etc/passwd"},
            "hookEventName": "pre_tool_use",
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "deny");
        assert!(
            !decision.permission_decision_reason.contains(ADAPTER_PARSE_CODE),
            "policy deny must not look like parse: {}",
            decision.permission_decision_reason
        );
        assert!(
            decision.permission_decision_reason.contains("FS_")
                || decision
                    .dispatch
                    .as_ref()
                    .map(|d| d.outcomes.iter().any(|o| o.reason_code.starts_with("FS_")))
                    .unwrap_or(false),
            "expected FS policy signal: {}",
            decision.permission_decision_reason
        );
    }

    #[test]
    fn cursor_shell_envelope_allows_in_scope_via_shared_tool_map() {
        // ≥1 non-Claude/Grok harness alias on shared normalize path.
        assert_eq!(
            normalize_tool_name("run_shell_command"),
            CanonicalTool::Bash
        );
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
            "tool_name": "run_shell_command",
            "tool_input": {"command": format!("ls {}", root.path().display())},
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "allow");
    }

    #[test]
    fn spawn_subagent_allow_default_policy() {
        let root = tempfile::tempdir().unwrap();
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "toolName": "spawn_subagent",
            "toolInput": {"prompt": "explore the tree", "subagent_type": "explore"},
            "hookEventName": "pre_tool_use",
            "sessionId": "parent-sess",
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "allow");
        let d = decision.dispatch.expect("dispatch");
        assert!(d
            .outcomes
            .iter()
            .any(|o| o.gate_id == "spawn-agent" && o.reason_code == "SPAWN_ALLOWED"));
    }

    #[test]
    fn spawn_task_deny_under_policy() {
        let root = tempfile::tempdir().unwrap();
        let mut config = cfg(root.path().to_path_buf());
        config.spawn_policy = Some(lia_gates::SpawnPolicy { allow: false });
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config,
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        };
        let raw = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_input": {"prompt": "do work", "subagent_type": "general-purpose"},
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "deny");
        let d = decision.dispatch.expect("dispatch");
        assert!(d
            .outcomes
            .iter()
            .any(|o| o.gate_id == "spawn-agent" && o.reason_code == "SPAWN_DENIED"));
    }

    #[test]
    fn spawn_allow_writes_signed_journal_row_with_linkage() {
        let root = tempfile::tempdir().unwrap();
        let journal_path = root.path().join("j.db");
        let secret = lia_journal::random_secret_hex().expect("secret");
        let ctx = RunContext {
            run_id: Uuid::new_v4(),
            config: cfg(root.path().to_path_buf()),
            journal_path: Some(journal_path.clone()),
            secret_key_hex: Some(secret),
            key_id: Some("lia-test".into()),
        };
        // Distinct wire ids so we can prove they survive into the signed journal row.
        const SESS: &str = "child-SESS-v3";
        const PARENT: &str = "parent-SESS-v3";
        const AGENT: &str = "agent-XYZ-v3";
        let raw = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_input": {"prompt": "child work", "subagent_type": "explore"},
            "session_id": SESS,
            "parent_session_id": PARENT,
            "agent_id": AGENT,
            "cwd": root.path().to_string_lossy(),
        })
        .to_string();
        let (decision, _) = on_pre_tool(&raw, &ctx).expect("hook");
        assert_eq!(decision.permission_decision, "allow");
        let d = decision.dispatch.expect("dispatch");
        assert!(!d.journal_receipts.is_empty());
        let rec = d
            .journal_receipts
            .iter()
            .find(|r| r.get("gate_id").and_then(|v| v.as_str()) == Some("spawn-agent"))
            .expect("spawn-agent journal receipt");
        assert_eq!(
            rec.get("reason_code").and_then(|v| v.as_str()),
            Some("SPAWN_ALLOWED")
        );
        assert!(rec.get("signature_hex").is_some());
        let detail = rec.get("detail").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            detail.contains(&format!("session_id={SESS}")),
            "journal receipt detail must carry session_id: {detail}"
        );
        assert!(
            detail.contains(&format!("parent_session_id={PARENT}")),
            "journal receipt detail must carry parent_session_id: {detail}"
        );
        assert!(
            detail.contains(&format!("agent_id={AGENT}")),
            "journal receipt detail must carry agent_id: {detail}"
        );

        // Offline verify chain.
        lia_journal::verify_chain(&journal_path).expect("verify chain");

        // Reload signed rows from the DB — linkage must be recoverable offline, not only
        // in the in-memory receipt mirror.
        let journal = lia_journal::Journal::open(&journal_path).expect("open journal");
        let rows = journal.load_rows().expect("load rows");
        let mut found_linkage = false;
        for row in &rows {
            let event_json = serde_json::to_string(&row.event).unwrap_or_default();
            if event_json.contains("spawn-agent") || event_json.contains("SPAWN_ALLOWED") {
                assert!(
                    event_json.contains(SESS) && event_json.contains(PARENT) && event_json.contains(AGENT),
                    "persisted GateVerdict event must embed wire ids; event={event_json}"
                );
                found_linkage = true;
            }
        }
        assert!(
            found_linkage,
            "expected at least one spawn-agent journal row with linkage ids"
        );

        let outcome = d
            .outcomes
            .iter()
            .find(|o| o.gate_id == "spawn-agent")
            .expect("spawn outcome");
        let od = outcome.detail.as_deref().unwrap_or("");
        assert!(od.contains(SESS) && od.contains(PARENT) && od.contains(AGENT), "{od}");
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
            gate_cells: BTreeMap::new(),
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
