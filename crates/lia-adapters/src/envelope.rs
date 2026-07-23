//! Shared multi-harness envelope normalize (V3).
//!
//! Claude snake_case, Grok camelCase, and sibling harness field aliases share one
//! translation path before gate mapping. Parse failures surface as `ADAPTER_PARSE`
//! so operators can distinguish them from FS/SHELL policy denials.

use serde_json::Value;

use crate::contracts::{
    CC_FIELD_CWD, CC_FIELD_HOOK_EVENT_NAME, CC_FIELD_SESSION_ID, CC_FIELD_TOOL_INPUT,
    CC_FIELD_TOOL_NAME, CC_FIELD_TOOL_USE_ID, CC_HOOK_EVENT_PRE_TOOL_USE, CC_INPUT_COMMAND,
    CC_INPUT_CONTENT, CC_INPUT_EDITS, CC_INPUT_FILE_PATH, CC_INPUT_NEW_SOURCE,
    CC_INPUT_NOTEBOOK_PATH, CC_TOOL_AGENT, CC_TOOL_BASH, CC_TOOL_EDIT, CC_TOOL_MULTI_EDIT,
    CC_TOOL_NOTEBOOK_EDIT, CC_TOOL_READ, CC_TOOL_WRITE,
};
use crate::AdapterError;

/// Operator-visible prefix for parse/eval adapter failures (distinct from FS/SHELL).
pub const ADAPTER_PARSE_CODE: &str = "ADAPTER_PARSE";

/// Canonical gate tool after alias normalize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalTool {
    Bash,
    Read,
    Write,
    Edit,
    MultiEdit,
    NotebookEdit,
    Delete,
    /// Task / Agent / spawn_subagent family.
    Spawn,
    /// Unmapped: fail-open allow with explicit reason when used as PreToolUse.
    Other(String),
}

impl CanonicalTool {
    pub fn as_claude_name(&self) -> &str {
        match self {
            CanonicalTool::Bash => CC_TOOL_BASH,
            CanonicalTool::Read => CC_TOOL_READ,
            CanonicalTool::Write => CC_TOOL_WRITE,
            CanonicalTool::Edit => CC_TOOL_EDIT,
            CanonicalTool::MultiEdit => CC_TOOL_MULTI_EDIT,
            CanonicalTool::NotebookEdit => CC_TOOL_NOTEBOOK_EDIT,
            CanonicalTool::Delete => "Delete",
            CanonicalTool::Spawn => CC_TOOL_AGENT,
            CanonicalTool::Other(s) => s.as_str(),
        }
    }
}

/// Normalized PreToolUse-shaped envelope used by Claude/Grok compat and tests.
#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedEnvelope {
    pub session_id: Option<String>,
    pub parent_session_id: Option<String>,
    pub agent_id: Option<String>,
    pub transcript_path: Option<String>,
    pub cwd: Option<String>,
    pub permission_mode: Option<String>,
    pub hook_event_name: String,
    pub tool_name_raw: String,
    pub tool: CanonicalTool,
    pub tool_input: Value,
    pub tool_use_id: Option<String>,
}

/// First non-null string among `keys` on a JSON object.
pub fn first_str_field(v: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = v.get(*key).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

/// Map wire / harness tool names onto a canonical tool.
pub fn normalize_tool_name(raw: &str) -> CanonicalTool {
    match raw {
        "Bash" | "run_terminal_command" | "shell" | "bash" | "run_shell_command" => {
            CanonicalTool::Bash
        }
        "Read" | "read_file" | "read" => CanonicalTool::Read,
        "Write" | "write" | "WriteFile" | "write_file" => CanonicalTool::Write,
        "Edit" | "search_replace" | "StrReplace" | "edit" | "replace" => CanonicalTool::Edit,
        "MultiEdit" | "multi_edit" => CanonicalTool::MultiEdit,
        "NotebookEdit" | "notebook_edit" => CanonicalTool::NotebookEdit,
        "Delete" | "delete_file" | "delete" => CanonicalTool::Delete,
        // Spawn family (V3-A).
        "Task" | "Agent" | "spawn_subagent" | "SubagentStart" | "spawn_agent" | "task" => {
            CanonicalTool::Spawn
        }
        other => CanonicalTool::Other(other.to_string()),
    }
}

/// Normalize hook event aliases to Claude's `PreToolUse` when recognized.
pub fn normalize_hook_event_name(raw: &str) -> String {
    match raw {
        "pre_tool_use" | "preToolUse" | "PreToolUse" | "BeforeTool" => {
            CC_HOOK_EVENT_PRE_TOOL_USE.to_string()
        }
        other => other.to_string(),
    }
}

/// Path field aliases: Claude `file_path`, Grok `target_file`, Cursor `path`, etc.
pub fn tool_path(ti: &Value) -> Option<String> {
    first_str_field(
        ti,
        &[
            CC_INPUT_FILE_PATH,
            "target_file",
            "path",
            "filePath",
            "targetFile",
            CC_INPUT_NOTEBOOK_PATH,
            "notebookPath",
            "notebook_path",
        ],
    )
}

/// Write/edit body aliases.
pub fn tool_write_text(ti: &Value) -> Option<String> {
    first_str_field(
        ti,
        &[
            CC_INPUT_CONTENT,
            "new_string",
            "contents",
            "newString",
            "text",
            CC_INPUT_NEW_SOURCE,
            "newSource",
        ],
    )
}

pub fn tool_command(ti: &Value) -> Option<String> {
    first_str_field(ti, &[CC_INPUT_COMMAND, "cmd", "shell_command"])
}

/// Parse a multi-harness PreToolUse-like JSON string into a normalized envelope.
pub fn normalize_pre_tool_envelope(raw: &str) -> Result<NormalizedEnvelope, AdapterError> {
    let v: Value = serde_json::from_str(raw).map_err(|e| {
        AdapterError::Parse(format!("invalid JSON envelope: {e}"))
    })?;
    normalize_pre_tool_value(&v)
}

pub fn normalize_pre_tool_value(v: &Value) -> Result<NormalizedEnvelope, AdapterError> {
    if !v.is_object() {
        return Err(AdapterError::Parse("envelope must be a JSON object".into()));
    }
    let hook_event_name = normalize_hook_event_name(
        &first_str_field(v, &[CC_FIELD_HOOK_EVENT_NAME, "hookEventName"]).unwrap_or_default(),
    );
    let tool_name_raw = first_str_field(v, &[CC_FIELD_TOOL_NAME, "toolName", "tool"])
        .ok_or_else(|| AdapterError::Parse("missing tool_name".into()))?;
    let tool = normalize_tool_name(&tool_name_raw);
    let tool_input = v
        .get(CC_FIELD_TOOL_INPUT)
        .or_else(|| v.get("toolInput"))
        .or_else(|| v.get("parameters"))
        .cloned()
        .unwrap_or(Value::Null);
    let cwd = first_str_field(v, &[CC_FIELD_CWD, "workspaceRoot", "working_directory"]);
    Ok(NormalizedEnvelope {
        session_id: first_str_field(v, &[CC_FIELD_SESSION_ID, "sessionId"]),
        parent_session_id: first_str_field(
            v,
            &["parent_session_id", "parentSessionId", "parent_id", "parentId"],
        ),
        agent_id: first_str_field(v, &["agent_id", "agentId", "subagent_id", "subagentId"]),
        transcript_path: first_str_field(v, &["transcript_path", "transcriptPath"]),
        cwd,
        permission_mode: first_str_field(v, &["permission_mode", "permissionMode"]),
        hook_event_name,
        tool_name_raw,
        tool,
        tool_input,
        tool_use_id: first_str_field(v, &[CC_FIELD_TOOL_USE_ID, "toolUseId"]),
    })
}

/// Multi-edit joined new_string text (Claude + Grok field names).
pub fn multi_edit_text(ti: &Value) -> Option<String> {
    ti.get(CC_INPUT_EDITS)
        .and_then(|e| e.as_array())
        .map(|edits| {
            edits
                .iter()
                .filter_map(|edit| first_str_field(edit, &["new_string", "newString", "content"]))
                .collect::<Vec<_>>()
                .join("\n")
        })
}

/// Spawn prompt / description from tool input.
pub fn spawn_prompt(ti: &Value) -> Option<String> {
    first_str_field(
        ti,
        &[
            "prompt",
            "description",
            "task",
            "instruction",
            "message",
            "query",
        ],
    )
    .or_else(|| {
        // Some harnesses put the whole input as the description.
        if ti.is_string() {
            ti.as_str().map(|s| s.to_string())
        } else {
            None
        }
    })
}

pub fn spawn_agent_type(ti: &Value) -> Option<String> {
    first_str_field(
        ti,
        &[
            "subagent_type",
            "subagentType",
            "agent_type",
            "agentType",
            "type",
            "model",
        ],
    )
}

/// Known mediated tool names for default Claude/Grok install matcher (operator listing).
pub fn default_mediated_tools() -> &'static [&'static str] {
    &[
        "Bash",
        "Write",
        "Edit",
        "Read",
        "Delete",
        "MultiEdit",
        "NotebookEdit",
        "Task",
        "Agent",
        // Grok / alias surface (same gates after normalize)
        "run_terminal_command",
        "read_file",
        "search_replace",
        "write",
        "delete_file",
        "spawn_subagent",
    ]
}

/// Known common tools that typically never hit LIA under default matchers.
pub fn default_unmediated_tools() -> &'static [&'static str] {
    &[
        "Grep",
        "Glob",
        "list_dir",
        "WebSearch",
        "WebFetch",
        "TodoWrite",
        "MCP mutate (server__tool without proxy)",
        "editor @-path reads",
        "unhooked binary execution",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_snake_case_read() {
        let env = normalize_pre_tool_envelope(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/a"},"cwd":"/w"}"#,
        )
        .unwrap();
        assert_eq!(env.tool, CanonicalTool::Read);
        assert_eq!(tool_path(&env.tool_input).as_deref(), Some("/a"));
        assert_eq!(env.cwd.as_deref(), Some("/w"));
    }

    #[test]
    fn grok_camelcase_read_file() {
        let env = normalize_pre_tool_envelope(
            r#"{"hookEventName":"pre_tool_use","toolName":"read_file","toolInput":{"target_file":"/b"},"cwd":"/w"}"#,
        )
        .unwrap();
        assert_eq!(env.tool, CanonicalTool::Read);
        assert_eq!(tool_path(&env.tool_input).as_deref(), Some("/b"));
    }

    #[test]
    fn cursor_like_shell_aliases_to_bash() {
        assert_eq!(normalize_tool_name("run_shell_command"), CanonicalTool::Bash);
        assert_eq!(normalize_tool_name("shell"), CanonicalTool::Bash);
    }

    #[test]
    fn spawn_aliases() {
        for name in ["Task", "spawn_subagent", "Agent", "SubagentStart"] {
            assert_eq!(normalize_tool_name(name), CanonicalTool::Spawn, "{name}");
        }
    }

    #[test]
    fn missing_tool_name_is_adapter_parse() {
        let err = normalize_pre_tool_envelope(r#"{"hookEventName":"pre_tool_use"}"#).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(ADAPTER_PARSE_CODE), "{msg}");
        assert!(msg.contains("missing tool_name"), "{msg}");
    }

    #[test]
    fn invalid_json_is_adapter_parse() {
        let err = normalize_pre_tool_envelope("{not-json").unwrap_err();
        assert!(err.to_string().contains(ADAPTER_PARSE_CODE));
    }

    #[test]
    fn parent_child_ids_captured() {
        let env = normalize_pre_tool_envelope(
            r#"{"toolName":"Bash","toolInput":{"command":"ls"},"sessionId":"s1","parentSessionId":"p0","agentId":"a9"}"#,
        )
        .unwrap();
        assert_eq!(env.session_id.as_deref(), Some("s1"));
        assert_eq!(env.parent_session_id.as_deref(), Some("p0"));
        assert_eq!(env.agent_id.as_deref(), Some("a9"));
    }
}
