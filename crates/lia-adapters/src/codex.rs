use lia_gates::GatePayload;
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::contracts::{
    MCP_INSPECT_EXPLAIN_DENIAL, MCP_INSPECT_INSPECT_RECEIPTS, MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES,
    MCP_INSPECT_SHOW_POLICY, MCP_INSPECT_VERIFY_RUN, MCP_JSONRPC, MCP_METHOD_CALL, MCP_METHOD_LIST,
    MCP_PARAM_ARGUMENTS, MCP_PARAM_NAME, PROXY_TOOL_ADD_DEPENDENCY, PROXY_TOOL_COMPLETE_TASK,
    PROXY_TOOL_DELETE_FILE, PROXY_TOOL_RUN_TEST, PROXY_TOOL_SHELL, PROXY_TOOL_WRITE_FILE,
};
use crate::dispatch::{denial_summary, dispatch_action, DispatchResult, RunContext};
use crate::mcp_inspection::{handle_inspection_call, InspectionContext};
use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCallResult {
    pub allowed: bool,
    pub dispatch: Option<DispatchResult>,
    pub response: Value,
}

pub fn proxy_tool_names() -> &'static [&'static str] {
    &[
        PROXY_TOOL_WRITE_FILE,
        PROXY_TOOL_DELETE_FILE,
        PROXY_TOOL_SHELL,
        PROXY_TOOL_RUN_TEST,
        PROXY_TOOL_COMPLETE_TASK,
        PROXY_TOOL_ADD_DEPENDENCY,
    ]
}

pub fn handle_jsonrpc(
    raw: &str,
    run_ctx: &RunContext,
    inspect_ctx: &InspectionContext,
) -> Result<Value, AdapterError> {
    let req: JsonRpcRequest =
        serde_json::from_str(raw).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    if req.jsonrpc != MCP_JSONRPC {
        return Ok(rpc_error(req.id, -32600, "invalid jsonrpc version"));
    }
    match req.method.as_str() {
        MCP_METHOD_LIST => Ok(rpc_result(req.id, list_tools())),
        MCP_METHOD_CALL => {
            let params = req.params.unwrap_or(Value::Null);
            let name = params
                .get(MCP_PARAM_NAME)
                .and_then(|v| v.as_str())
                .ok_or_else(|| AdapterError::Invalid("tools/call missing name".into()))?;
            let args = params
                .get(MCP_PARAM_ARGUMENTS)
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            if is_inspection_tool(name) {
                let out = handle_inspection_call(name, &args, inspect_ctx)?;
                return Ok(rpc_result(req.id, out));
            }
            let proxied = proxy_tool_call(req.id.clone(), name, &args, run_ctx)?;
            Ok(proxied.response)
        }
        other => Ok(rpc_error(req.id, -32601, &format!("method not found: {other}"))),
    }
}

fn is_inspection_tool(name: &str) -> bool {
    matches!(
        name,
        MCP_INSPECT_VERIFY_RUN
            | MCP_INSPECT_INSPECT_RECEIPTS
            | MCP_INSPECT_EXPLAIN_DENIAL
            | MCP_INSPECT_SHOW_POLICY
            | MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES
    )
}

fn list_tools() -> Value {
    let mut tools = Vec::new();
    for name in proxy_tool_names() {
        tools.push(json!({
            "name": name,
            "description": format!("LIA-gated proxy tool {name}"),
            "inputSchema": { "type": "object" }
        }));
    }
    for name in [
        MCP_INSPECT_VERIFY_RUN,
        MCP_INSPECT_INSPECT_RECEIPTS,
        MCP_INSPECT_EXPLAIN_DENIAL,
        MCP_INSPECT_SHOW_POLICY,
        MCP_INSPECT_SHOW_ADAPTER_CAPABILITIES,
    ] {
        tools.push(json!({
            "name": name,
            "description": format!("LIA read-only inspection tool {name}"),
            "inputSchema": { "type": "object" }
        }));
    }
    json!({ "tools": tools })
}

pub fn proxy_tool_call(
    id: Value,
    name: &str,
    args: &Value,
    ctx: &RunContext,
) -> Result<ProxyCallResult, AdapterError> {
    let (kind, payload) = map_proxy_args(name, args)?;
    let action_id = Uuid::new_v4();
    let result = dispatch_action(kind, action_id, payload, ctx).map_err(AdapterError::from)?;
    if result.allowed {
        let response = rpc_result(
            id,
            json!({
                "content": [{"type": "text", "text": "allow"}],
                "isError": false,
                "lia": result,
            }),
        );
        Ok(ProxyCallResult {
            allowed: true,
            dispatch: Some(result),
            response,
        })
    } else {
        let reason = denial_summary(&result).unwrap_or_else(|| format!("{:?}", result.overall));
        let response = rpc_result(
            id,
            json!({
                "content": [{"type": "text", "text": format!("denied: {reason}")}],
                "isError": true,
                "lia": result,
            }),
        );
        Ok(ProxyCallResult {
            allowed: false,
            dispatch: Some(result),
            response,
        })
    }
}

fn map_proxy_args(name: &str, args: &Value) -> Result<(ActionKind, GatePayload), AdapterError> {
    match name {
        PROXY_TOOL_WRITE_FILE => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AdapterError::Invalid("write_file needs path".into()))?
                .to_string();
            Ok((
                ActionKind::WriteFile,
                GatePayload {
                    path: Some(path),
                    is_write: Some(true),
                    text: args
                        .get("content")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    ..GatePayload::default()
                },
            ))
        }
        PROXY_TOOL_DELETE_FILE => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AdapterError::Invalid("delete_file needs path".into()))?
                .to_string();
            Ok((
                ActionKind::DeleteFile,
                GatePayload {
                    path: Some(path),
                    is_delete: Some(true),
                    ..GatePayload::default()
                },
            ))
        }
        PROXY_TOOL_SHELL => {
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AdapterError::Invalid("shell needs command".into()))?
                .to_string();
            Ok((
                ActionKind::Shell,
                GatePayload {
                    command: Some(command),
                    ..GatePayload::default()
                },
            ))
        }
        PROXY_TOOL_RUN_TEST => {
            let claimed = args
                .get("claimed_pass")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            Ok((
                ActionKind::RunTest,
                GatePayload {
                    claimed_pass: Some(claimed),
                    argv: args.get("argv").and_then(|v| {
                        v.as_array().map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                    }),
                    cwd: args
                        .get("cwd")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    ..GatePayload::default()
                },
            ))
        }
        PROXY_TOOL_COMPLETE_TASK => Ok((
            ActionKind::CompleteTask,
            GatePayload {
                modified_paths: args.get("modified_paths").and_then(|v| {
                    v.as_array().map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                }),
                has_test_result: args.get("has_test_result").and_then(|v| v.as_bool()),
                test_unsupported: args.get("test_unsupported").and_then(|v| v.as_bool()),
                new_dependencies: args.get("new_dependencies").and_then(|v| {
                    v.as_array().map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                }),
                deps_registry_evidence: args
                    .get("deps_registry_evidence")
                    .and_then(|v| v.as_bool()),
                ..GatePayload::default()
            },
        )),
        PROXY_TOOL_ADD_DEPENDENCY => {
            let package = args
                .get("package")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AdapterError::Invalid("add_dependency needs package".into()))?
                .to_string();
            Ok((
                ActionKind::AddDependency,
                GatePayload {
                    package: Some(package),
                    version: args
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    ..GatePayload::default()
                },
            ))
        }
        other => Err(AdapterError::Invalid(format!("unknown proxy tool: {other}"))),
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": MCP_JSONRPC,
        "id": id,
        "result": result,
    })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": MCP_JSONRPC,
        "id": id,
        "error": { "code": code, "message": message },
    })
}
