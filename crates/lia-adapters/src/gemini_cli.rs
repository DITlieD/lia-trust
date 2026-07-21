use lia_gates::GatePayload;
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::dispatch::{denial_summary, dispatch_action, DispatchResult, RunContext};
use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiBeforeToolInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub hook_event_name: String,
    pub timestamp: String,
    pub tool_name: String,
    pub tool_input: Value,
    #[serde(default)]
    pub mcp_context: Option<Value>,
    #[serde(default)]
    pub original_request_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GeminiHookDecision {
    pub decision: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<DispatchResult>,
}

pub fn parse_gemini_before_tool(raw: &str) -> Result<GeminiBeforeToolInput, AdapterError> {
    let input: GeminiBeforeToolInput =
        serde_json::from_str(raw).map_err(|error| AdapterError::Invalid(error.to_string()))?;
    if input.hook_event_name != "BeforeTool" {
        return Err(AdapterError::Invalid(format!(
            "expected hook_event_name=BeforeTool, got {}",
            input.hook_event_name
        )));
    }
    Ok(input)
}

pub fn map_gemini_tool_to_action(
    input: &GeminiBeforeToolInput,
) -> Result<(ActionKind, GatePayload), AdapterError> {
    let tool_input = &input.tool_input;
    match input.tool_name.as_str() {
        "run_shell_command" => {
            let command = required_string(tool_input, &["command"])?;
            let claimed_pass = command.to_ascii_lowercase().contains("claimed_pass=true")
                || command.to_ascii_lowercase().contains("lia-fabricate-pass");
            Ok((
                if claimed_pass {
                    ActionKind::RunTest
                } else {
                    ActionKind::Shell
                },
                GatePayload {
                    command: Some(command.clone()),
                    argv: claimed_pass.then(|| vec!["sh".into(), "-lc".into(), command.clone()]),
                    cwd: Some(input.cwd.clone()),
                    claimed_pass: claimed_pass.then_some(true),
                    is_delete: Some(command.contains("rm ") || command.contains("rm\t")),
                    ..GatePayload::default()
                },
            ))
        }
        "write_file" | "replace" => {
            let path = required_string(tool_input, &["file_path", "path"])?;
            let text = optional_string(tool_input, &["content", "new_string"]);
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    text,
                    cwd: Some(input.cwd.clone()),
                    is_write: Some(true),
                    ..GatePayload::default()
                },
            ))
        }
        "read_file" => Ok((
            ActionKind::ReadFile,
            GatePayload {
                path: Some(required_string(tool_input, &["file_path", "path"])?),
                cwd: Some(input.cwd.clone()),
                ..GatePayload::default()
            },
        )),
        _ => Ok((
            ActionKind::Other,
            GatePayload {
                text: Some(tool_input.to_string()),
                cwd: Some(input.cwd.clone()),
                ..GatePayload::default()
            },
        )),
    }
}

pub fn on_gemini_before_tool(
    raw: &str,
    ctx: &RunContext,
) -> Result<GeminiHookDecision, AdapterError> {
    let input = parse_gemini_before_tool(raw)?;
    let (kind, payload) = map_gemini_tool_to_action(&input)?;
    if kind == ActionKind::Other {
        return Ok(GeminiHookDecision {
            decision: "deny".into(),
            reason: format!(
                "unsupported Gemini tool '{}' reached the LIA matcher",
                input.tool_name
            ),
            dispatch: None,
        });
    }
    let result = dispatch_action(kind, Uuid::new_v4(), payload, ctx).map_err(AdapterError::from)?;
    Ok(GeminiHookDecision {
        decision: if result.allowed { "allow" } else { "deny" }.into(),
        reason: if result.allowed {
            "lia gates allow".into()
        } else {
            denial_summary(&result).unwrap_or_else(|| format!("{:?}", result.overall))
        },
        dispatch: Some(result),
    })
}

pub fn handle_gemini_before_tool_stdin(
    raw: &str,
    ctx: &RunContext,
) -> Result<String, AdapterError> {
    serde_json::to_string(&on_gemini_before_tool(raw, ctx)?)
        .map_err(|error| AdapterError::Invalid(error.to_string()))
}

fn required_string(value: &Value, fields: &[&str]) -> Result<String, AdapterError> {
    optional_string(value, fields).ok_or_else(|| {
        AdapterError::Invalid(format!(
            "missing required string field: {}",
            fields.join(" or ")
        ))
    })
}

fn optional_string(value: &Value, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| value.get(*field).and_then(Value::as_str))
        .map(str::to_string)
}
