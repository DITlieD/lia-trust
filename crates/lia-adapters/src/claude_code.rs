use lia_gates::GatePayload;
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::contracts::{
    CC_DECISION_ALLOW, CC_DECISION_DENY, CC_FIELD_CWD, CC_FIELD_HOOK_EVENT_NAME,
    CC_FIELD_SESSION_ID, CC_FIELD_TOOL_INPUT, CC_FIELD_TOOL_NAME, CC_FIELD_TOOL_USE_ID,
    CC_HOOK_EVENT_PRE_TOOL_USE, CC_INPUT_COMMAND, CC_INPUT_CONTENT, CC_INPUT_EDITS,
    CC_INPUT_FILE_PATH, CC_INPUT_NEW_SOURCE, CC_INPUT_NOTEBOOK_PATH, CC_OUT_HOOK_EVENT_NAME,
    CC_OUT_HOOK_SPECIFIC, CC_OUT_PERMISSION_DECISION, CC_OUT_PERMISSION_REASON, CC_TOOL_AGENT,
    CC_TOOL_BASH, CC_TOOL_EDIT, CC_TOOL_MULTI_EDIT, CC_TOOL_NOTEBOOK_EDIT, CC_TOOL_READ,
    CC_TOOL_WRITE,
};
use crate::dispatch::{denial_summary, dispatch_action, DispatchResult, RunContext};
use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreToolUseInput {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub transcript_path: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub permission_mode: Option<String>,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: Value,
    #[serde(default)]
    pub tool_use_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookDecision {
    pub permission_decision: String,
    pub permission_decision_reason: String,
    pub dispatch: Option<DispatchResult>,
}

pub fn parse_pre_tool_use(raw: &str) -> Result<PreToolUseInput, AdapterError> {
    let v: Value = serde_json::from_str(raw).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let hook_event_name = v
        .get(CC_FIELD_HOOK_EVENT_NAME)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let tool_name = v
        .get(CC_FIELD_TOOL_NAME)
        .and_then(|x| x.as_str())
        .ok_or_else(|| AdapterError::Invalid("missing tool_name".into()))?
        .to_string();
    let tool_input = v.get(CC_FIELD_TOOL_INPUT).cloned().unwrap_or(Value::Null);
    let cwd = v
        .get(CC_FIELD_CWD)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    Ok(PreToolUseInput {
        session_id: v
            .get(CC_FIELD_SESSION_ID)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        transcript_path: v
            .get("transcript_path")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        cwd,
        permission_mode: v
            .get("permission_mode")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        hook_event_name,
        tool_name,
        tool_input,
        tool_use_id: v
            .get(CC_FIELD_TOOL_USE_ID)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
    })
}

pub fn map_tool_to_action(
    input: &PreToolUseInput,
) -> Result<(ActionKind, GatePayload), AdapterError> {
    let ti = &input.tool_input;
    match input.tool_name.as_str() {
        CC_TOOL_BASH => {
            let command = ti
                .get(CC_INPUT_COMMAND)
                .and_then(|x| x.as_str())
                .ok_or_else(|| AdapterError::Invalid("Bash missing command".into()))?
                .to_string();
            if is_fabricated_pass_claim(&command) {
                Ok((
                    ActionKind::RunTest,
                    GatePayload {
                        command: Some(command.clone()),
                        argv: Some(vec!["bash".into(), "-lc".into(), command.clone()]),
                        cwd: input.cwd.clone(),
                        claimed_pass: Some(true),
                        ..GatePayload::default()
                    },
                ))
            } else {
                let is_delete = command.contains("rm ") || command.contains("rm\t");
                Ok((
                    ActionKind::Shell,
                    GatePayload {
                        command: Some(command),
                        cwd: input.cwd.clone(),
                        is_delete: Some(is_delete),
                        ..GatePayload::default()
                    },
                ))
            }
        }
        CC_TOOL_WRITE | CC_TOOL_EDIT => {
            let path = ti
                .get(CC_INPUT_FILE_PATH)
                .and_then(|x| x.as_str())
                .ok_or_else(|| AdapterError::Invalid("Write/Edit missing file_path".into()))?
                .to_string();
            let text = ti
                .get(CC_INPUT_CONTENT)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    is_write: Some(true),
                    text,
                    cwd: input.cwd.clone(),
                    ..GatePayload::default()
                },
            ))
        }
        CC_TOOL_MULTI_EDIT => {
            let path = ti
                .get(CC_INPUT_FILE_PATH)
                .and_then(|x| x.as_str())
                .ok_or_else(|| AdapterError::Invalid("MultiEdit missing file_path".into()))?
                .to_string();
            let text = ti
                .get(CC_INPUT_EDITS)
                .and_then(|e| e.as_array())
                .map(|edits| {
                    edits
                        .iter()
                        .filter_map(|edit| edit.get("new_string").and_then(|x| x.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n")
                });
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    is_write: Some(true),
                    text,
                    cwd: input.cwd.clone(),
                    ..GatePayload::default()
                },
            ))
        }
        CC_TOOL_NOTEBOOK_EDIT => {
            let path = ti
                .get(CC_INPUT_NOTEBOOK_PATH)
                .or_else(|| ti.get(CC_INPUT_FILE_PATH))
                .and_then(|x| x.as_str())
                .ok_or_else(|| AdapterError::Invalid("NotebookEdit missing notebook_path".into()))?
                .to_string();
            let text = ti
                .get(CC_INPUT_NEW_SOURCE)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    is_write: Some(true),
                    text,
                    cwd: input.cwd.clone(),
                    ..GatePayload::default()
                },
            ))
        }
        CC_TOOL_READ => {
            let path = ti
                .get(CC_INPUT_FILE_PATH)
                .and_then(|x| x.as_str())
                .ok_or_else(|| AdapterError::Invalid("Read missing file_path".into()))?
                .to_string();
            Ok((
                ActionKind::ReadFile,
                GatePayload {
                    path: Some(path),
                    cwd: input.cwd.clone(),
                    ..GatePayload::default()
                },
            ))
        }
        other if other.eq_ignore_ascii_case("Delete") || other == "delete_file" => {
            let path = ti
                .get(CC_INPUT_FILE_PATH)
                .or_else(|| ti.get("path"))
                .and_then(|x| x.as_str())
                .ok_or_else(|| AdapterError::Invalid("Delete missing file_path".into()))?
                .to_string();
            Ok((
                ActionKind::DeleteFile,
                GatePayload {
                    path: Some(path),
                    is_delete: Some(true),
                    cwd: input.cwd.clone(),
                    ..GatePayload::default()
                },
            ))
        }
        CC_TOOL_AGENT => Ok((
            ActionKind::Other,
            GatePayload {
                text: Some(ti.to_string()),
                cwd: input.cwd.clone(),
                ..GatePayload::default()
            },
        )),
        _ => Ok((
            ActionKind::Other,
            GatePayload {
                text: Some(ti.to_string()),
                cwd: input.cwd.clone(),
                ..GatePayload::default()
            },
        )),
    }
}

fn is_fabricated_pass_claim(command: &str) -> bool {
    let c = command.to_ascii_lowercase();
    c.contains("lia-fabricate-pass") || c.contains("claimed_pass=true")
}

pub fn on_pre_tool(
    raw_stdin: &str,
    ctx: &RunContext,
) -> Result<(HookDecision, Value), AdapterError> {
    let input = parse_pre_tool_use(raw_stdin)?;
    if !input.hook_event_name.is_empty() && input.hook_event_name != CC_HOOK_EVENT_PRE_TOOL_USE {
        return Err(AdapterError::Invalid(format!(
            "expected hook_event_name={CC_HOOK_EVENT_PRE_TOOL_USE}, got {}",
            input.hook_event_name
        )));
    }

    let (kind, payload) = map_tool_to_action(&input)?;
    if matches!(kind, ActionKind::Other) && input.tool_name != CC_TOOL_AGENT {
        let decision = HookDecision {
            permission_decision: CC_DECISION_ALLOW.to_string(),
            permission_decision_reason: "no gate mapped for tool".into(),
            dispatch: None,
        };
        let out = decision_json(&decision);
        return Ok((decision, out));
    }

    let action_id = Uuid::new_v4();
    let result = dispatch_action(kind, action_id, payload, ctx).map_err(AdapterError::from)?;
    let (permission_decision, permission_decision_reason) = if result.allowed {
        (CC_DECISION_ALLOW.to_string(), "lia gates allow".to_string())
    } else {
        (
            CC_DECISION_DENY.to_string(),
            denial_summary(&result).unwrap_or_else(|| format!("{:?}", result.overall)),
        )
    };
    let decision = HookDecision {
        permission_decision,
        permission_decision_reason,
        dispatch: Some(result),
    };
    let out = decision_json(&decision);
    Ok((decision, out))
}

pub fn decision_json(decision: &HookDecision) -> Value {
    json!({
        CC_OUT_HOOK_SPECIFIC: {
            CC_OUT_HOOK_EVENT_NAME: CC_HOOK_EVENT_PRE_TOOL_USE,
            CC_OUT_PERMISSION_DECISION: decision.permission_decision,
            CC_OUT_PERMISSION_REASON: decision.permission_decision_reason,
        }
    })
}

pub fn handle_pre_tool_stdin(raw: &str, ctx: &RunContext) -> Result<String, AdapterError> {
    let (_decision, value) = on_pre_tool(raw, ctx)?;
    serde_json::to_string(&value).map_err(|e| AdapterError::Invalid(e.to_string()))
}
