use lia_gates::GatePayload;
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::contracts::{
    CC_DECISION_ALLOW, CC_DECISION_DENY, CC_HOOK_EVENT_PRE_TOOL_USE, CC_OUT_HOOK_EVENT_NAME,
    CC_OUT_HOOK_SPECIFIC, CC_OUT_PERMISSION_DECISION, CC_OUT_PERMISSION_REASON, CC_TOOL_AGENT,
};
use crate::dispatch::{denial_summary, dispatch_action, DispatchResult, RunContext};
use crate::envelope::{
    multi_edit_text, normalize_pre_tool_envelope, spawn_agent_type, spawn_prompt, tool_command,
    tool_path, tool_write_text, CanonicalTool, NormalizedEnvelope, ADAPTER_PARSE_CODE,
};
use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreToolUseInput {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub parent_session_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
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

impl From<NormalizedEnvelope> for PreToolUseInput {
    fn from(env: NormalizedEnvelope) -> Self {
        Self {
            session_id: env.session_id,
            parent_session_id: env.parent_session_id,
            agent_id: env.agent_id,
            transcript_path: env.transcript_path,
            cwd: env.cwd,
            permission_mode: env.permission_mode,
            hook_event_name: env.hook_event_name,
            tool_name: env.tool.as_claude_name().to_string(),
            tool_input: env.tool_input,
            tool_use_id: env.tool_use_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookDecision {
    pub permission_decision: String,
    pub permission_decision_reason: String,
    pub dispatch: Option<DispatchResult>,
}

pub fn parse_pre_tool_use(raw: &str) -> Result<PreToolUseInput, AdapterError> {
    let env = normalize_pre_tool_envelope(raw)?;
    Ok(PreToolUseInput::from(env))
}

fn linkage_fields(input: &PreToolUseInput) -> (Option<String>, Option<String>, Option<String>) {
    (
        input.session_id.clone(),
        input.parent_session_id.clone(),
        input.agent_id.clone(),
    )
}

pub fn map_tool_to_action(
    input: &PreToolUseInput,
) -> Result<(ActionKind, GatePayload), AdapterError> {
    let ti = &input.tool_input;
    let (session_id, parent_session_id, agent_id) = linkage_fields(input);
    let tool = crate::envelope::normalize_tool_name(&input.tool_name);
    // parse_pre_tool_use already canonicalizes tool_name via as_claude_name; re-normalize
    // for safety when callers construct PreToolUseInput manually with aliases.
    match tool {
        CanonicalTool::Bash => {
            let command = tool_command(ti)
                .ok_or_else(|| AdapterError::Parse("Bash missing command".into()))?;
            if is_fabricated_pass_claim(&command) {
                Ok((
                    ActionKind::RunTest,
                    GatePayload {
                        command: Some(command.clone()),
                        argv: Some(vec!["bash".into(), "-lc".into(), command.clone()]),
                        cwd: input.cwd.clone(),
                        claimed_pass: Some(true),
                        session_id,
                        parent_session_id,
                        agent_id,
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
                        session_id,
                        parent_session_id,
                        agent_id,
                        ..GatePayload::default()
                    },
                ))
            }
        }
        CanonicalTool::Write | CanonicalTool::Edit => {
            let path = tool_path(ti)
                .ok_or_else(|| AdapterError::Parse("Write/Edit missing file_path".into()))?;
            let text = tool_write_text(ti);
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    is_write: Some(true),
                    text,
                    cwd: input.cwd.clone(),
                    session_id,
                    parent_session_id,
                    agent_id,
                    ..GatePayload::default()
                },
            ))
        }
        CanonicalTool::MultiEdit => {
            let path = tool_path(ti)
                .ok_or_else(|| AdapterError::Parse("MultiEdit missing file_path".into()))?;
            let text = multi_edit_text(ti);
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    is_write: Some(true),
                    text,
                    cwd: input.cwd.clone(),
                    session_id,
                    parent_session_id,
                    agent_id,
                    ..GatePayload::default()
                },
            ))
        }
        CanonicalTool::NotebookEdit => {
            let path = tool_path(ti)
                .ok_or_else(|| AdapterError::Parse("NotebookEdit missing notebook_path".into()))?;
            let text = tool_write_text(ti);
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    is_write: Some(true),
                    text,
                    cwd: input.cwd.clone(),
                    session_id,
                    parent_session_id,
                    agent_id,
                    ..GatePayload::default()
                },
            ))
        }
        CanonicalTool::Read => {
            let path = tool_path(ti)
                .ok_or_else(|| AdapterError::Parse("Read missing file_path".into()))?;
            Ok((
                ActionKind::ReadFile,
                GatePayload {
                    path: Some(path),
                    cwd: input.cwd.clone(),
                    session_id,
                    parent_session_id,
                    agent_id,
                    ..GatePayload::default()
                },
            ))
        }
        CanonicalTool::Delete => {
            let path = tool_path(ti)
                .ok_or_else(|| AdapterError::Parse("Delete missing file_path".into()))?;
            Ok((
                ActionKind::DeleteFile,
                GatePayload {
                    path: Some(path),
                    is_delete: Some(true),
                    cwd: input.cwd.clone(),
                    session_id,
                    parent_session_id,
                    agent_id,
                    ..GatePayload::default()
                },
            ))
        }
        CanonicalTool::Spawn => Ok((
            ActionKind::SpawnAgent,
            GatePayload {
                text: spawn_prompt(ti).or_else(|| Some(ti.to_string())),
                spawn_agent_type: spawn_agent_type(ti),
                cwd: input.cwd.clone(),
                session_id,
                parent_session_id,
                agent_id,
                action_label: Some("spawn_agent".into()),
                ..GatePayload::default()
            },
        )),
        CanonicalTool::Other(_) if input.tool_name == CC_TOOL_AGENT => Ok((
            ActionKind::SpawnAgent,
            GatePayload {
                text: spawn_prompt(ti).or_else(|| Some(ti.to_string())),
                spawn_agent_type: spawn_agent_type(ti),
                cwd: input.cwd.clone(),
                session_id,
                parent_session_id,
                agent_id,
                action_label: Some("spawn_agent".into()),
                ..GatePayload::default()
            },
        )),
        CanonicalTool::Other(_) => Ok((
            ActionKind::Other,
            GatePayload {
                text: Some(ti.to_string()),
                cwd: input.cwd.clone(),
                session_id,
                parent_session_id,
                agent_id,
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
        return Err(AdapterError::Parse(format!(
            "expected hook_event_name={CC_HOOK_EVENT_PRE_TOOL_USE}, got {}",
            input.hook_event_name
        )));
    }

    let (kind, payload) = map_tool_to_action(&input)?;
    if matches!(kind, ActionKind::Other) {
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
    serde_json::to_string(&value).map_err(|e| AdapterError::Parse(e.to_string()))
}

/// Surface parse failures with a stable operator code.
pub fn parse_error_reason(err: &AdapterError) -> String {
    match err {
        AdapterError::Parse(msg) => format!("{ADAPTER_PARSE_CODE}: {msg}"),
        other => other.to_string(),
    }
}
