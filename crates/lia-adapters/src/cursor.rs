use lia_gates::GatePayload;
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::dispatch::{denial_summary, dispatch_action, DispatchResult, RunContext};
use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorShellInput {
    pub command: String,
    pub cwd: String,
    #[serde(default)]
    pub sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorMcpInput {
    pub tool_name: String,
    pub tool_input: Value,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CursorHookDecision {
    pub permission: String,
    pub user_message: String,
    pub agent_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<DispatchResult>,
}

pub fn on_cursor_before_shell(
    raw: &str,
    ctx: &RunContext,
) -> Result<CursorHookDecision, AdapterError> {
    let input: CursorShellInput =
        serde_json::from_str(raw).map_err(|error| AdapterError::Invalid(error.to_string()))?;
    if input.command.trim().is_empty() || input.cwd.trim().is_empty() {
        return Err(AdapterError::Invalid(
            "Cursor shell hook requires command and cwd".into(),
        ));
    }
    decide(
        ActionKind::Shell,
        GatePayload {
            command: Some(input.command.clone()),
            cwd: Some(input.cwd),
            is_delete: Some(input.command.contains("rm ") || input.command.contains("rm\t")),
            ..GatePayload::default()
        },
        ctx,
    )
}

pub fn on_cursor_before_mcp(
    raw: &str,
    ctx: &RunContext,
) -> Result<CursorHookDecision, AdapterError> {
    let mut input: CursorMcpInput =
        serde_json::from_str(raw).map_err(|error| AdapterError::Invalid(error.to_string()))?;
    if let Value::String(encoded) = &input.tool_input {
        input.tool_input = serde_json::from_str(encoded)
            .map_err(|error| AdapterError::Invalid(format!("tool_input JSON: {error}")))?;
    }
    let lower = input.tool_name.to_ascii_lowercase();
    let (kind, payload) = if contains_any(&lower, &["shell", "exec", "command", "bash"]) {
        let command = string_field(&input.tool_input, &["command", "cmd"])
            .or(input.command)
            .ok_or_else(|| AdapterError::Invalid("Cursor MCP shell tool missing command".into()))?;
        (
            ActionKind::Shell,
            GatePayload {
                command: Some(command.clone()),
                is_delete: Some(command.contains("rm ") || command.contains("rm\t")),
                ..GatePayload::default()
            },
        )
    } else if contains_any(&lower, &["delete", "remove_file", "unlink"]) {
        (
            ActionKind::DeleteFile,
            GatePayload {
                path: Some(required_field(&input.tool_input, &["path", "file_path"])?),
                is_delete: Some(true),
                ..GatePayload::default()
            },
        )
    } else if contains_any(&lower, &["write", "edit", "replace"]) {
        (
            ActionKind::WriteFile,
            GatePayload {
                path: Some(required_field(&input.tool_input, &["path", "file_path"])?),
                text: string_field(&input.tool_input, &["content", "new_string"]),
                is_write: Some(true),
                ..GatePayload::default()
            },
        )
    } else if contains_any(&lower, &["add_dependency", "install_package"]) {
        (
            ActionKind::AddDependency,
            GatePayload {
                package: Some(required_field(&input.tool_input, &["package", "name"])?),
                version: string_field(&input.tool_input, &["version"]),
                ..GatePayload::default()
            },
        )
    } else {
        return Ok(CursorHookDecision {
            permission: "ask".into(),
            user_message: "LIA cannot classify this Cursor MCP tool; explicit approval is required"
                .into(),
            agent_message: "No deterministic LIA gate is mapped for this MCP tool".into(),
            dispatch: None,
        });
    };
    decide(kind, payload, ctx)
}

pub fn handle_cursor_shell_stdin(raw: &str, ctx: &RunContext) -> Result<String, AdapterError> {
    serialize(on_cursor_before_shell(raw, ctx)?)
}

pub fn handle_cursor_mcp_stdin(raw: &str, ctx: &RunContext) -> Result<String, AdapterError> {
    serialize(on_cursor_before_mcp(raw, ctx)?)
}

fn decide(
    kind: ActionKind,
    payload: GatePayload,
    ctx: &RunContext,
) -> Result<CursorHookDecision, AdapterError> {
    let result = dispatch_action(kind, Uuid::new_v4(), payload, ctx).map_err(AdapterError::from)?;
    let reason = if result.allowed {
        "lia gates allow".into()
    } else {
        denial_summary(&result).unwrap_or_else(|| format!("{:?}", result.overall))
    };
    Ok(CursorHookDecision {
        permission: if result.allowed { "allow" } else { "deny" }.into(),
        user_message: reason.clone(),
        agent_message: reason,
        dispatch: Some(result),
    })
}

fn serialize(decision: CursorHookDecision) -> Result<String, AdapterError> {
    serde_json::to_string(&decision).map_err(|error| AdapterError::Invalid(error.to_string()))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn required_field(value: &Value, fields: &[&str]) -> Result<String, AdapterError> {
    string_field(value, fields).ok_or_else(|| {
        AdapterError::Invalid(format!(
            "missing required string field: {}",
            fields.join(" or ")
        ))
    })
}

fn string_field(value: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| value.get(*field).and_then(Value::as_str))
        .map(str::to_string)
}
