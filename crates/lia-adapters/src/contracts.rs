use serde::Deserialize;
use serde_json::Value;
use std::sync::OnceLock;

pub const CONTRACTS_JSON: &str = include_str!("../contracts.json");

pub const CC_HOOK_EVENT_PRE_TOOL_USE: &str = "PreToolUse";
pub const CC_FIELD_HOOK_EVENT_NAME: &str = "hook_event_name";
pub const CC_FIELD_TOOL_NAME: &str = "tool_name";
pub const CC_FIELD_TOOL_INPUT: &str = "tool_input";
pub const CC_FIELD_TOOL_USE_ID: &str = "tool_use_id";
pub const CC_FIELD_CWD: &str = "cwd";
pub const CC_FIELD_SESSION_ID: &str = "session_id";
pub const CC_OUT_HOOK_SPECIFIC: &str = "hookSpecificOutput";
pub const CC_OUT_HOOK_EVENT_NAME: &str = "hookEventName";
pub const CC_OUT_PERMISSION_DECISION: &str = "permissionDecision";
pub const CC_OUT_PERMISSION_REASON: &str = "permissionDecisionReason";
pub const CC_DECISION_ALLOW: &str = "allow";
pub const CC_DECISION_DENY: &str = "deny";
pub const CC_TOOL_BASH: &str = "Bash";
pub const CC_TOOL_WRITE: &str = "Write";
pub const CC_TOOL_EDIT: &str = "Edit";
pub const CC_TOOL_READ: &str = "Read";
pub const CC_TOOL_AGENT: &str = "Agent";
pub const CC_TOOL_MULTI_EDIT: &str = "MultiEdit";
pub const CC_TOOL_NOTEBOOK_EDIT: &str = "NotebookEdit";
pub const CC_INPUT_COMMAND: &str = "command";
pub const CC_INPUT_FILE_PATH: &str = "file_path";
pub const CC_INPUT_NOTEBOOK_PATH: &str = "notebook_path";
pub const CC_INPUT_CONTENT: &str = "content";
pub const CC_INPUT_NEW_SOURCE: &str = "new_source";
pub const CC_INPUT_EDITS: &str = "edits";

pub const MCP_JSONRPC: &str = "2.0";
pub const MCP_METHOD_LIST: &str = "tools/list";
pub const MCP_METHOD_CALL: &str = "tools/call";
pub const MCP_PARAM_NAME: &str = "name";
pub const MCP_PARAM_ARGUMENTS: &str = "arguments";

pub const MCP_INSPECT_VERIFY_RUN: &str = "verify_run";
pub const MCP_INSPECT_INSPECT_RECEIPTS: &str = "inspect_receipts";
pub const MCP_INSPECT_EXPLAIN_DENIAL: &str = "explain_denial";
pub const MCP_INSPECT_SHOW_POLICY: &str = "show_policy";
pub const MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES: &str = "show_adapter_capabilities";

pub const PROXY_TOOL_WRITE_FILE: &str = "write_file";
pub const PROXY_TOOL_DELETE_FILE: &str = "delete_file";
pub const PROXY_TOOL_SHELL: &str = "shell";
pub const PROXY_TOOL_RUN_TEST: &str = "run_test";
pub const PROXY_TOOL_COMPLETE_TASK: &str = "complete_task";
pub const PROXY_TOOL_ADD_DEPENDENCY: &str = "add_dependency";
pub const PROXY_TOOL_GROUND_CLAIM: &str = "ground_claim";
pub const PROXY_TOOL_CHECK_AGREEMENT: &str = "check_agreement";

pub const CAP_PRE_WRITE_BLOCK: &str = "pre_write_block";
pub const CAP_POST_WRITE_RECEIPT: &str = "post_write_receipt";
pub const CAP_SHELL_PRE_BLOCK: &str = "shell_pre_block";
pub const CAP_SHELL_RESULT_CAPTURE: &str = "shell_result_capture";
pub const CAP_NETWORK_CONTROL: &str = "network_control";
pub const CAP_CREDENTIAL_BROKER: &str = "credential_broker";
pub const CAP_COMPLETION_GATE: &str = "completion_gate";
pub const CAP_SUBAGENT_VISIBILITY: &str = "subagent_visibility";
pub const CAP_IMMUTABLE_JOURNAL: &str = "immutable_journal";
pub const CAP_OFFLINE_VERIFICATION: &str = "offline_verification";

pub const ALL_CAPABILITY_KEYS: &[&str] = &[
    CAP_PRE_WRITE_BLOCK,
    CAP_POST_WRITE_RECEIPT,
    CAP_SHELL_PRE_BLOCK,
    CAP_SHELL_RESULT_CAPTURE,
    CAP_NETWORK_CONTROL,
    CAP_CREDENTIAL_BROKER,
    CAP_COMPLETION_GATE,
    CAP_SUBAGENT_VISIBILITY,
    CAP_IMMUTABLE_JOURNAL,
    CAP_OFFLINE_VERIFICATION,
];

pub const ADAPTER_CLAUDE_CODE: &str = "claude-code";
pub const ADAPTER_CODEX: &str = "codex";
pub const ADAPTER_GENERIC: &str = "generic";

#[derive(Debug, Clone, Deserialize)]
pub struct ContractsFile {
    pub pinned_at: String,
    pub capability_keys: Vec<String>,
    pub assurance_levels: Vec<String>,
    pub gate_cells: Vec<String>,
    pub v1_forbid_confine: bool,
}

fn parsed() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(CONTRACTS_JSON).unwrap_or_else(|e| {
            panic!("contracts.json parse failed: {e}");
        })
    })
}

pub fn contracts_value() -> &'static Value {
    parsed()
}

pub fn load_contracts() -> Result<ContractsFile, serde_json::Error> {
    serde_json::from_str(CONTRACTS_JSON)
}
