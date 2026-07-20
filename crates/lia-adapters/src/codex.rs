use std::io::{BufRead, Write};

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
use crate::mcp_stdio::{read_framed_message, write_framed_message};
use crate::AdapterError;

/// MCP protocol version we advertise (spec pin used by current Codex clients).
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
pub const MCP_SERVER_NAME: &str = "lia-trust";
pub const MCP_SERVER_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    /// Absent on JSON-RPC notifications (e.g. `notifications/initialized`).
    #[serde(default)]
    pub id: Option<Value>,
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

/// Handle one JSON-RPC request body. Returns `Ok(None)` for notifications (no response).
pub fn handle_jsonrpc_opt(
    raw: &str,
    run_ctx: &RunContext,
    inspect_ctx: &InspectionContext,
) -> Result<Option<Value>, AdapterError> {
    let req: JsonRpcRequest =
        serde_json::from_str(raw).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    if req.jsonrpc != MCP_JSONRPC {
        let id = req.id.unwrap_or(Value::Null);
        return Ok(Some(rpc_error(id, -32600, "invalid jsonrpc version")));
    }

    // Notifications: no response body (JSON-RPC 2.0).
    if req.id.is_none() || req.method.starts_with("notifications/") {
        match req.method.as_str() {
            "notifications/initialized" | "notifications/cancelled" => return Ok(None),
            other if other.starts_with("notifications/") => return Ok(None),
            _ if req.id.is_none() => return Ok(None),
            _ => {}
        }
    }

    let id = req.id.clone().unwrap_or(Value::Null);
    match req.method.as_str() {
        "initialize" => Ok(Some(rpc_result(id, initialize_result()))),
        "ping" => Ok(Some(rpc_result(id, json!({})))),
        MCP_METHOD_LIST => Ok(Some(rpc_result(id, list_tools()))),
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
                return Ok(Some(rpc_result(id, out)));
            }
            let proxied = proxy_tool_call(id, name, &args, run_ctx)?;
            Ok(Some(proxied.response))
        }
        // Optional MCP surfaces: empty rather than hard-failing the session.
        "resources/list" => Ok(Some(rpc_result(id, json!({ "resources": [] })))),
        "prompts/list" => Ok(Some(rpc_result(id, json!({ "prompts": [] })))),
        other => Ok(Some(rpc_error(
            id,
            -32601,
            &format!("method not found: {other}"),
        ))),
    }
}

/// One-shot JSON-RPC (always returns a Value; notifications become `{"ok":true,"notification":true}`).
pub fn handle_jsonrpc(
    raw: &str,
    run_ctx: &RunContext,
    inspect_ctx: &InspectionContext,
) -> Result<Value, AdapterError> {
    match handle_jsonrpc_opt(raw, run_ctx, inspect_ctx)? {
        Some(v) => Ok(v),
        None => Ok(json!({ "ok": true, "notification": true })),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": MCP_SERVER_NAME,
            "version": MCP_SERVER_VERSION
        }
    })
}

/// Long-lived MCP stdio session: Content-Length framed request/response loop.
/// This is what Codex launches via `command` in `config.toml`.
pub fn serve_mcp_stdio(
    run_ctx: &RunContext,
    inspect_ctx: &InspectionContext,
) -> Result<(), AdapterError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    serve_mcp_stdio_io(&mut reader, &mut writer, run_ctx, inspect_ctx)
}

/// Testable stdio server loop over arbitrary reader/writer.
pub fn serve_mcp_stdio_io(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    run_ctx: &RunContext,
    inspect_ctx: &InspectionContext,
) -> Result<(), AdapterError> {
    while let Some(raw) = read_framed_message(reader)? {
        match handle_jsonrpc_opt(&raw, run_ctx, inspect_ctx)? {
            Some(resp) => {
                let body = serde_json::to_string(&resp)
                    .map_err(|e| AdapterError::Invalid(e.to_string()))?;
                write_framed_message(writer, &body)?;
            }
            None => {
                // notification — no response
            }
        }
    }
    Ok(())
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
        PROXY_TOOL_SHELL | "run_shell" | "Bash" => {
            // live tool-loop and some agents emit run_shell / Bash aliases
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_stdio::{frame_json, read_framed_message};
    use lia_gates::GateConfig;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn ctx_root(root: PathBuf) -> RunContext {
        RunContext {
            run_id: Uuid::new_v4(),
            config: GateConfig {
                allowed_roots: vec![root.clone()],
                home_dir: Some(PathBuf::from("/home/agent")),
                cwd: root,
                protected_paths: vec![],
                registry: BTreeMap::new(),
                env: BTreeMap::new(),
                run_id: None,
            },
            journal_path: None,
            secret_key_hex: None,
            key_id: None,
        }
    }

    fn inspect() -> InspectionContext {
        InspectionContext {
            journal_path: None,
            policy_path: None,
            bundle_path: None,
            probe_path: None,
            adapter: Some("codex".into()),
            last_denials: vec![],
        }
    }

    #[test]
    fn initialize_handshake_succeeds() {
        let root = tempfile::tempdir().unwrap();
        let ctx = ctx_root(root.path().to_path_buf());
        let insp = inspect();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "codex", "version": "0.144.5" }
            }
        })
        .to_string();
        let resp = handle_jsonrpc(&raw, &ctx, &insp).unwrap();
        assert!(resp.get("error").is_none(), "{resp}");
        assert_eq!(
            resp.pointer("/result/serverInfo/name").and_then(|v| v.as_str()),
            Some(MCP_SERVER_NAME)
        );
        assert_eq!(
            resp.pointer("/result/protocolVersion")
                .and_then(|v| v.as_str()),
            Some(MCP_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn notifications_initialized_no_error() {
        let root = tempfile::tempdir().unwrap();
        let ctx = ctx_root(root.path().to_path_buf());
        let insp = inspect();
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        .to_string();
        let opt = handle_jsonrpc_opt(&raw, &ctx, &insp).unwrap();
        assert!(opt.is_none());
    }

    #[test]
    fn framed_session_initialize_list_hard_deny() {
        let root = tempfile::tempdir().unwrap();
        let ctx = ctx_root(root.path().to_path_buf());
        let insp = inspect();

        let mut input = Vec::new();
        input.extend(
            frame_json(&json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"t","version":"0"}}
            }))
            .unwrap(),
        );
        input.extend(
            frame_json(&json!({
                "jsonrpc":"2.0","method":"notifications/initialized"
            }))
            .unwrap(),
        );
        input.extend(
            frame_json(&json!({
                "jsonrpc":"2.0","id":2,"method":"tools/list"
            }))
            .unwrap(),
        );
        input.extend(
            frame_json(&json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"delete_file","arguments":{"path":"/tmp/outside-lia-mcp-stdio"}}
            }))
            .unwrap(),
        );

        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        serve_mcp_stdio_io(&mut reader, &mut writer, &ctx, &insp).unwrap();

        let mut out = Cursor::new(writer);
        let init = read_framed_message(&mut out).unwrap().unwrap();
        let init_v: Value = serde_json::from_str(&init).unwrap();
        assert!(init_v.get("error").is_none(), "{init_v}");
        assert_eq!(
            init_v.pointer("/result/serverInfo/name").and_then(|v| v.as_str()),
            Some("lia-trust")
        );

        let list = read_framed_message(&mut out).unwrap().unwrap();
        let list_v: Value = serde_json::from_str(&list).unwrap();
        assert!(list_v
            .pointer("/result/tools")
            .and_then(|t| t.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false));

        let call = read_framed_message(&mut out).unwrap().unwrap();
        let call_v: Value = serde_json::from_str(&call).unwrap();
        assert_eq!(
            call_v.pointer("/result/isError").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            call_v.pointer("/result/lia/allowed").and_then(|v| v.as_bool()),
            Some(false)
        );
        // notifications produce no frames — only 3 responses
        assert!(read_framed_message(&mut out).unwrap().is_none());
    }
}
