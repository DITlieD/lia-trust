//! One-command LIA Trust Kernel install for Claude Code, Codex, Gemini CLI, and Cursor.
//!
//! Pure config-merge logic is separated from process I/O so unit tests cover
//! idempotent merge / uninstall without live agents. Default proof path uses
//! fixture config dirs; live user harness homes require explicit `--apply-live`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Marker embedded in generated hook commands so uninstall only removes LIA entries.
pub const LIA_HOOK_MARKER: &str = "lia-trust-kernel";
/// Codex MCP server table name.
pub const CODEX_MCP_SERVER: &str = "lia-trust";
/// Claude PreToolUse matcher covering gated tools.
pub const CLAUDE_PRETOOL_MATCHER: &str = "Bash|Write|Edit|Read|Delete|MultiEdit|NotebookEdit";
pub const GEMINI_BEFORETOOL_MATCHER: &str = "^(run_shell_command|write_file|replace|read_file)$";
/// Install manifest filename under lia home.
pub const MANIFEST_NAME: &str = "install-manifest.json";

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallPaths {
    pub lia_home: PathBuf,
    pub lia_bin: PathBuf,
    pub config_json: PathBuf,
    pub journal_db: PathBuf,
    pub secret_key_file: PathBuf,
    pub probe_json: PathBuf,
    pub claude_wrapper: PathBuf,
    pub codex_wrapper: PathBuf,
    pub gemini_wrapper: PathBuf,
    pub cursor_shell_wrapper: PathBuf,
    pub cursor_mcp_wrapper: PathBuf,
    pub claude_settings: PathBuf,
    pub codex_config: PathBuf,
    pub gemini_settings: PathBuf,
    pub cursor_hooks: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallReport {
    pub action: String,
    pub dry_run: bool,
    pub lia_home: PathBuf,
    pub claude_settings: PathBuf,
    pub codex_config: PathBuf,
    pub gemini_settings: PathBuf,
    pub cursor_hooks: PathBuf,
    pub claude_hook_installed: bool,
    pub codex_mcp_installed: bool,
    pub gemini_hook_installed: bool,
    pub cursor_hooks_installed: bool,
    pub kernel: KernelBoundary,
    pub notes: Vec<String>,
}

/// What Kernel means as product TCB (not commercial Harness/Canvas).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelBoundary {
    pub name: String,
    pub includes: Vec<String>,
    pub enforced_on: Vec<String>,
    pub cannot_observe: Vec<String>,
    pub assurance: String,
}

impl Default for KernelBoundary {
    fn default() -> Self {
        Self {
            name: "LIA Trust Kernel".into(),
            includes: vec![
                "protocol + event model".into(),
                "append-only journal + Ed25519 receipts".into(),
                "seven core gates (rules-as-data, fail-closed)".into(),
                "offline verify".into(),
                "thin adapters at harness tool boundaries".into(),
            ],
            enforced_on: vec![
                "configured surface: Claude Code PreToolUse hook (unprobed at install)".into(),
                "configured surface: Codex MCP/tool proxy (unprobed at install)".into(),
                "configured surface: Gemini CLI BeforeTool hook (unprobed at install)".into(),
                "configured surface: Cursor shell/MCP hooks (unprobed at install)".into(),
            ],
            cannot_observe: vec![
                "process/network CONFINE (v1 forbids CONFINE claim)".into(),
                "non-tool side effects and @-path reads outside hooks".into(),
                "credential brokering and egress enforcement (not observed)".into(),
            ],
            assurance: "UNMEASURED at install; run bench/probe_assurance.sh before assigning gate cells; never CONFINE/complete-mediation".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallRequest {
    pub lia_home: PathBuf,
    pub lia_bin: PathBuf,
    pub claude_home: PathBuf,
    pub codex_home: PathBuf,
    pub gemini_home: PathBuf,
    pub cursor_home: PathBuf,
    pub dry_run: bool,
    /// When false, refuse to write if paths look like the real user home configs
    /// without an explicit apply-live flag (caller enforces).
    pub apply_live: bool,
    pub allowed_roots: Vec<PathBuf>,
}

impl InstallPaths {
    pub fn resolve(
        lia_home: &Path,
        lia_bin: &Path,
        claude_home: &Path,
        codex_home: &Path,
        gemini_home: &Path,
        cursor_home: &Path,
    ) -> Self {
        Self {
            lia_home: lia_home.to_path_buf(),
            lia_bin: lia_bin.to_path_buf(),
            config_json: lia_home.join("config.json"),
            journal_db: lia_home.join("journal").join("default.db"),
            secret_key_file: lia_home.join("keys").join("signing.hex"),
            probe_json: lia_home.join("probe.json"),
            claude_wrapper: lia_home.join("bin").join("claude-pretool.sh"),
            codex_wrapper: lia_home.join("bin").join("codex-mcp.sh"),
            gemini_wrapper: lia_home.join("bin").join("gemini-beforetool.sh"),
            cursor_shell_wrapper: lia_home.join("bin").join("cursor-before-shell.sh"),
            cursor_mcp_wrapper: lia_home.join("bin").join("cursor-before-mcp.sh"),
            claude_settings: claude_home.join("settings.json"),
            codex_config: codex_home.join("config.toml"),
            gemini_settings: gemini_home.join("settings.json"),
            cursor_hooks: cursor_home.join("hooks.json"),
        }
    }
}

pub fn default_lia_home() -> PathBuf {
    std::env::var_os("LIA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs_home()
                .map(|h| h.join(".lia-trust"))
                .unwrap_or_else(|| PathBuf::from(".lia-trust"))
        })
}

pub fn default_claude_home() -> PathBuf {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|h| h.join(".claude")))
        .unwrap_or_else(|| PathBuf::from(".claude"))
}

pub fn default_codex_home() -> PathBuf {
    std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|h| h.join(".codex")))
        .unwrap_or_else(|| PathBuf::from(".codex"))
}

pub fn default_gemini_home() -> PathBuf {
    std::env::var_os("GEMINI_CLI_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|home| home.join(".gemini")))
        .unwrap_or_else(|| PathBuf::from(".gemini"))
}

pub fn default_cursor_home() -> PathBuf {
    std::env::var_os("CURSOR_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|home| home.join(".cursor")))
        .unwrap_or_else(|| PathBuf::from(".cursor"))
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Pure merge: inject LIA PreToolUse hook into Claude settings JSON object.
pub fn merge_claude_settings(existing: &Value, wrapper_cmd: &str) -> Result<Value, InstallError> {
    let mut root = match existing {
        Value::Object(m) => Value::Object(m.clone()),
        Value::Null => json!({}),
        other => {
            return Err(InstallError::Invalid(format!(
                "claude settings must be a JSON object, got {}",
                type_name(other)
            )))
        }
    };
    let hooks = root
        .as_object_mut()
        .ok_or_else(|| InstallError::Invalid("settings not object".into()))?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| InstallError::Invalid("hooks must be object".into()))?;
    let pre = hooks_obj.entry("PreToolUse").or_insert_with(|| json!([]));
    let arr = pre
        .as_array_mut()
        .ok_or_else(|| InstallError::Invalid("PreToolUse must be array".into()))?;

    // Remove prior LIA entries (idempotent reinstall).
    arr.retain(|entry| !entry_is_lia_hook(entry));

    arr.push(json!({
        "matcher": CLAUDE_PRETOOL_MATCHER,
        "hooks": [{
            "type": "command",
            "command": wrapper_cmd,
            "timeout": 30,
            "_lia_trust": true,
            "_lia_marker": LIA_HOOK_MARKER,
        }]
    }));
    Ok(root)
}

/// Pure remove of LIA hook entries from Claude settings.
pub fn unmerge_claude_settings(existing: &Value) -> Result<Value, InstallError> {
    let mut root = match existing {
        Value::Object(m) => Value::Object(m.clone()),
        Value::Null => json!({}),
        other => {
            return Err(InstallError::Invalid(format!(
                "claude settings must be object, got {}",
                type_name(other)
            )))
        }
    };
    if let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        if let Some(pre) = hooks.get_mut("PreToolUse").and_then(|p| p.as_array_mut()) {
            pre.retain(|entry| !entry_is_lia_hook(entry));
            if pre.is_empty() {
                hooks.remove("PreToolUse");
            }
        }
        if hooks.is_empty() {
            root.as_object_mut().map(|o| o.remove("hooks"));
        }
    }
    Ok(root)
}

pub fn claude_hook_present(settings: &Value) -> bool {
    settings
        .pointer("/hooks/PreToolUse")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().any(entry_is_lia_hook))
        .unwrap_or(false)
}

pub fn merge_gemini_settings(existing: &Value, wrapper_cmd: &str) -> Result<Value, InstallError> {
    let mut root = json_object(existing, "gemini settings")?;
    let hooks = root
        .as_object_mut()
        .ok_or_else(|| InstallError::Invalid("gemini settings not object".into()))?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let before = hooks
        .as_object_mut()
        .ok_or_else(|| InstallError::Invalid("Gemini hooks must be object".into()))?
        .entry("BeforeTool")
        .or_insert_with(|| json!([]));
    let entries = before
        .as_array_mut()
        .ok_or_else(|| InstallError::Invalid("Gemini BeforeTool must be array".into()))?;
    entries.retain(|entry| !gemini_entry_is_lia(entry));
    entries.push(json!({
        "matcher": GEMINI_BEFORETOOL_MATCHER,
        "sequential": true,
        "hooks": [{
            "type": "command",
            "command": wrapper_cmd,
            "name": "LIA Trust Kernel",
            "timeout": 30000,
            "description": "Fail-closed pre-action safety gate"
        }]
    }));
    Ok(root)
}

pub fn unmerge_gemini_settings(existing: &Value) -> Result<Value, InstallError> {
    let mut root = json_object(existing, "gemini settings")?;
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        if let Some(entries) = hooks.get_mut("BeforeTool").and_then(Value::as_array_mut) {
            entries.retain(|entry| !gemini_entry_is_lia(entry));
            if entries.is_empty() {
                hooks.remove("BeforeTool");
            }
        }
        if hooks.is_empty() {
            root.as_object_mut().map(|object| object.remove("hooks"));
        }
    }
    Ok(root)
}

pub fn gemini_hook_present(settings: &Value) -> bool {
    settings
        .pointer("/hooks/BeforeTool")
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.iter().any(gemini_entry_is_lia))
}

fn gemini_entry_is_lia(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|command| command.contains("gemini-beforetool"))
            })
        })
}

pub fn merge_cursor_hooks(
    existing: &Value,
    shell_wrapper: &str,
    mcp_wrapper: &str,
) -> Result<Value, InstallError> {
    let mut root = json_object(existing, "cursor hooks")?;
    root.as_object_mut()
        .ok_or_else(|| InstallError::Invalid("cursor hooks not object".into()))?
        .insert("version".into(), json!(1));
    let hooks = root
        .as_object_mut()
        .ok_or_else(|| InstallError::Invalid("cursor hooks not object".into()))?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| InstallError::Invalid("Cursor hooks must be object".into()))?;
    merge_cursor_hook_array(hooks, "beforeShellExecution", shell_wrapper)?;
    merge_cursor_hook_array(hooks, "beforeMCPExecution", mcp_wrapper)?;
    Ok(root)
}

pub fn unmerge_cursor_hooks(existing: &Value) -> Result<Value, InstallError> {
    let mut root = json_object(existing, "cursor hooks")?;
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        for event in ["beforeShellExecution", "beforeMCPExecution"] {
            if let Some(entries) = hooks.get_mut(event).and_then(Value::as_array_mut) {
                entries.retain(|entry| !cursor_entry_is_lia(entry));
                if entries.is_empty() {
                    hooks.remove(event);
                }
            }
        }
        if hooks.is_empty() {
            root.as_object_mut().map(|object| object.remove("hooks"));
        }
    }
    Ok(root)
}

pub fn cursor_hooks_present(hooks: &Value) -> bool {
    ["beforeShellExecution", "beforeMCPExecution"]
        .iter()
        .all(|event| {
            hooks
                .pointer(&format!("/hooks/{event}"))
                .and_then(Value::as_array)
                .is_some_and(|entries| entries.iter().any(cursor_entry_is_lia))
        })
}

fn merge_cursor_hook_array(
    hooks: &mut serde_json::Map<String, Value>,
    event: &str,
    wrapper: &str,
) -> Result<(), InstallError> {
    let entries = hooks.entry(event).or_insert_with(|| json!([]));
    let entries = entries
        .as_array_mut()
        .ok_or_else(|| InstallError::Invalid(format!("Cursor {event} must be array")))?;
    entries.retain(|entry| !cursor_entry_is_lia(entry));
    entries.push(json!({
        "command": wrapper,
        "timeout": 30,
        "failClosed": true
    }));
    Ok(())
}

fn cursor_entry_is_lia(entry: &Value) -> bool {
    entry
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.contains("cursor-before-"))
}

fn json_object(existing: &Value, label: &str) -> Result<Value, InstallError> {
    match existing {
        Value::Object(object) => Ok(Value::Object(object.clone())),
        Value::Null => Ok(json!({})),
        other => Err(InstallError::Invalid(format!(
            "{label} must be a JSON object, got {}",
            type_name(other)
        ))),
    }
}

fn entry_is_lia_hook(entry: &Value) -> bool {
    if entry.get("_lia_trust").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    if entry
        .get("_lia_marker")
        .and_then(|v| v.as_str())
        .map(|s| s.contains(LIA_HOOK_MARKER))
        .unwrap_or(false)
    {
        return true;
    }
    // Nested command string may contain marker / wrapper path.
    if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
        for h in hooks {
            if h.get("_lia_trust").and_then(|v| v.as_bool()) == Some(true) {
                return true;
            }
            if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                if cmd.contains(LIA_HOOK_MARKER) || cmd.contains("claude-pretool") {
                    return true;
                }
            }
        }
    }
    false
}

/// Pure merge of Codex config.toml text: upsert `[mcp_servers.lia-trust]`.
pub fn merge_codex_toml(existing: &str, command: &str, args: &[String]) -> String {
    let without = strip_codex_lia_section(existing);
    let mut out = without.trim_end().to_string();
    if !out.is_empty() {
        out.push('\n');
        out.push('\n');
    }
    out.push_str(&format!(
        "# {LIA_HOOK_MARKER} — managed by `lia install`; do not hand-edit\n"
    ));
    out.push_str(&format!("[mcp_servers.{CODEX_MCP_SERVER}]\n"));
    out.push_str(&format!("command = {}\n", toml_string(command)));
    out.push_str("args = [");
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&toml_string(a));
    }
    out.push_str("]\n");
    out.push_str("startup_timeout_sec = 30\n");
    out
}

/// Remove LIA MCP section from Codex config.toml.
pub fn unmerge_codex_toml(existing: &str) -> String {
    let s = strip_codex_lia_section(existing);
    if s.is_empty() {
        String::new()
    } else {
        format!("{}\n", s.trim_end())
    }
}

pub fn codex_mcp_present(toml_text: &str) -> bool {
    toml_text
        .lines()
        .any(|l| l.trim() == format!("[mcp_servers.{CODEX_MCP_SERVER}]"))
}

fn strip_codex_lia_section(existing: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    let header = format!("[mcp_servers.{CODEX_MCP_SERVER}]");
    let nested = format!("[mcp_servers.{CODEX_MCP_SERVER}.");
    let managed = format!("# {LIA_HOOK_MARKER}");
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&managed) {
            continue;
        }
        if trimmed == header || trimmed.starts_with(&nested) {
            skipping = true;
            continue;
        }
        if skipping {
            if trimmed.starts_with('[') {
                skipping = false;
            } else {
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Build shell wrapper for Claude PreToolUse (reads secret from file, not argv of settings).
pub fn claude_wrapper_script(paths: &InstallPaths) -> String {
    format!(
        r#"#!/usr/bin/env bash
# {marker}
set -euo pipefail
SECRET="$(tr -d '[:space:]' < "{secret}")"
exec "{bin}" hook --adapter claude-code \
  --config "{config}" \
  --journal "{journal}" \
  --secret-key-hex "$SECRET" \
  --key-id lia-install
"#,
        marker = LIA_HOOK_MARKER,
        secret = paths.secret_key_file.display(),
        bin = paths.lia_bin.display(),
        config = paths.config_json.display(),
        journal = paths.journal_db.display(),
    )
}

/// Build shell wrapper for Codex MCP stdio proxy.
///
/// Codex speaks **Content-Length framed** JSON-RPC on stdio and requires
/// `initialize` before tools/*. This wrapper execs `lia mcp` in long-lived
/// stdio mode (no `--request`); failures propagate (no `|| true`).
pub fn codex_wrapper_script(paths: &InstallPaths) -> String {
    format!(
        r#"#!/usr/bin/env bash
# {marker}
set -euo pipefail
SECRET="$(tr -d '[:space:]' < "{secret}")"
exec "{bin}" mcp \
  --config "{config}" \
  --journal "{journal}" \
  --secret-key-hex "$SECRET" \
  --key-id lia-install \
  --probe "{probe}" \
  --adapter codex
"#,
        marker = LIA_HOOK_MARKER,
        secret = paths.secret_key_file.display(),
        bin = paths.lia_bin.display(),
        config = paths.config_json.display(),
        journal = paths.journal_db.display(),
        probe = paths.probe_json.display(),
    )
}

pub fn gemini_wrapper_script(paths: &InstallPaths) -> String {
    hook_wrapper_script(paths, "gemini-cli")
}

pub fn cursor_shell_wrapper_script(paths: &InstallPaths) -> String {
    hook_wrapper_script(paths, "cursor-shell")
}

pub fn cursor_mcp_wrapper_script(paths: &InstallPaths) -> String {
    hook_wrapper_script(paths, "cursor-mcp")
}

fn hook_wrapper_script(paths: &InstallPaths, adapter: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# {marker}
set -euo pipefail
SECRET="$(tr -d '[:space:]' < "{secret}")"
exec "{bin}" hook --adapter {adapter} \
  --config "{config}" \
  --journal "{journal}" \
  --secret-key-hex "$SECRET" \
  --key-id lia-install
"#,
        marker = LIA_HOOK_MARKER,
        secret = paths.secret_key_file.display(),
        bin = paths.lia_bin.display(),
        config = paths.config_json.display(),
        journal = paths.journal_db.display(),
    )
}

pub fn default_gate_config_json(allowed_roots: &[PathBuf], cwd: &Path) -> Value {
    let roots: Vec<String> = if allowed_roots.is_empty() {
        vec![cwd.display().to_string()]
    } else {
        allowed_roots
            .iter()
            .map(|p| p.display().to_string())
            .collect()
    };
    json!({
        "allowed_roots": roots,
        "home_dir": dirs_home().map(|h| h.display().to_string()),
        "cwd": cwd.display().to_string(),
        "protected_paths": [
            // Keep LIA state outside agent rewrites when roots include home.
        ],
        "registry": {},
        "env": {},
    })
}

pub fn default_probe_json(adapter: &str) -> Value {
    let (keys, gate_cells, note) = match adapter {
        "claude-code" => (
            json!({
                "pre_write_block": false,
                "post_write_receipt": false,
                "shell_pre_block": false,
                "shell_result_capture": false,
                "network_control": false,
                "credential_broker": false,
                "completion_gate": false,
                "subagent_visibility": false,
                "immutable_journal": false,
                "offline_verification": false,
            }),
            json!({
                "test-integrity": "CANNOT-OBSERVE",
                "evidence-completeness": "CANNOT-OBSERVE",
                "filesystem-scope": "CANNOT-OBSERVE",
                "shell-irreversible": "CANNOT-OBSERVE",
                "dependency-reality": "CANNOT-OBSERVE",
                "secret-output": "CANNOT-OBSERVE",
                "journal-tamper": "CANNOT-OBSERVE"
            }),
            "install-time capability shape only; run bench/probe_assurance.sh before publishing cells",
        ),
        "codex" => (
            json!({
                "pre_write_block": false,
                "post_write_receipt": false,
                "shell_pre_block": false,
                "shell_result_capture": false,
                "network_control": false,
                "credential_broker": false,
                "completion_gate": false,
                "subagent_visibility": false,
                "immutable_journal": false,
                "offline_verification": false,
            }),
            json!({
                "test-integrity": "CANNOT-OBSERVE",
                "evidence-completeness": "CANNOT-OBSERVE",
                "filesystem-scope": "CANNOT-OBSERVE",
                "shell-irreversible": "CANNOT-OBSERVE",
                "dependency-reality": "CANNOT-OBSERVE",
                "secret-output": "CANNOT-OBSERVE",
                "journal-tamper": "CANNOT-OBSERVE"
            }),
            "install-time capability shape only; run bench/probe_assurance.sh before publishing cells",
        ),
        _ => (
            json!({
                "pre_write_block": false,
                "post_write_receipt": false,
                "shell_pre_block": false,
                "shell_result_capture": false,
                "network_control": false,
                "credential_broker": false,
                "completion_gate": false,
                "subagent_visibility": false,
                "immutable_journal": false,
                "offline_verification": false,
            }),
            json!({
                "test-integrity": "CANNOT-OBSERVE",
                "evidence-completeness": "CANNOT-OBSERVE",
                "filesystem-scope": "CANNOT-OBSERVE",
                "shell-irreversible": "CANNOT-OBSERVE",
                "dependency-reality": "CANNOT-OBSERVE",
                "secret-output": "CANNOT-OBSERVE",
                "journal-tamper": "CANNOT-OBSERVE"
            }),
            "install-time capability shape only; run bench/probe_assurance.sh before publishing cells",
        ),
    };
    json!({
        "adapter": adapter,
        "keys": keys,
        "gate_cells": gate_cells,
        "probed_at": null,
        "notes": [
            note,
            "network/credential CANNOT-OBSERVE",
            "not CONFINE; complete mediation not claimed"
        ],
    })
}

fn generate_secret_hex() -> Result<String, InstallError> {
    // OS CSPRNG only; fail hard if unavailable. A signing key derived from a predictable
    // source (time+pid) is guessable and silently breaks every signature it produces.
    lia_journal::random_secret_hex()
        .map_err(|e| InstallError::Invalid(format!("cannot generate signing key: {e}")))
}

/// Full install into paths (or dry-run report without writes).
pub fn install(req: &InstallRequest) -> Result<InstallReport, InstallError> {
    let paths = InstallPaths::resolve(
        &req.lia_home,
        &req.lia_bin,
        &req.claude_home,
        &req.codex_home,
        &req.gemini_home,
        &req.cursor_home,
    );
    let mut notes = vec![
        "Kernel = protocol + journal + Ed25519 + seven gates + offline verify + thin adapters"
            .into(),
        "Assurance: UNMEASURED at install; runtime probe required before PREVENT/DETECT claims"
            .into(),
    ];

    if !req.lia_bin.exists() && !req.dry_run {
        return Err(InstallError::Invalid(format!(
            "lia binary not found at {}",
            req.lia_bin.display()
        )));
    }

    let secret = if paths.secret_key_file.exists() {
        fs::read_to_string(&paths.secret_key_file)?
            .trim()
            .to_string()
    } else {
        generate_secret_hex()?
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = default_gate_config_json(&req.allowed_roots, &cwd);
    let probe = default_probe_json("claude-code");

    let claude_existing = read_json_or_empty(&paths.claude_settings)?;
    let claude_merged = merge_claude_settings(
        &claude_existing,
        &paths.claude_wrapper.display().to_string(),
    )?;

    let codex_existing = read_text_or_empty(&paths.codex_config)?;
    let codex_merged = merge_codex_toml(
        &codex_existing,
        &paths.codex_wrapper.display().to_string(),
        &[],
    );
    let gemini_existing = read_json_or_empty(&paths.gemini_settings)?;
    let gemini_merged = merge_gemini_settings(
        &gemini_existing,
        &paths.gemini_wrapper.display().to_string(),
    )?;
    let cursor_existing = read_json_or_empty(&paths.cursor_hooks)?;
    let cursor_merged = merge_cursor_hooks(
        &cursor_existing,
        &paths.cursor_shell_wrapper.display().to_string(),
        &paths.cursor_mcp_wrapper.display().to_string(),
    )?;

    if req.dry_run {
        notes.push("dry-run: no files written".into());
        return Ok(InstallReport {
            action: "install".into(),
            dry_run: true,
            lia_home: paths.lia_home,
            claude_settings: paths.claude_settings,
            codex_config: paths.codex_config,
            gemini_settings: paths.gemini_settings,
            cursor_hooks: paths.cursor_hooks,
            claude_hook_installed: claude_hook_present(&claude_merged),
            codex_mcp_installed: codex_mcp_present(&codex_merged),
            gemini_hook_installed: gemini_hook_present(&gemini_merged),
            cursor_hooks_installed: cursor_hooks_present(&cursor_merged),
            kernel: KernelBoundary::default(),
            notes,
        });
    }

    fs::create_dir_all(paths.lia_home.join("keys"))?;
    fs::create_dir_all(paths.lia_home.join("journal"))?;
    fs::create_dir_all(paths.lia_home.join("bin"))?;
    fs::create_dir_all(paths.lia_home.join("policy"))?;
    if let Some(parent) = paths.claude_settings.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = paths.codex_config.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = paths.gemini_settings.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = paths.cursor_hooks.parent() {
        fs::create_dir_all(parent)?;
    }

    write_secret(&paths.secret_key_file, &secret)?;
    write_pretty_json(&paths.config_json, &config)?;
    write_pretty_json(&paths.probe_json, &probe)?;
    // Also write a codex-labelled probe for status clarity.
    write_pretty_json(
        &paths.lia_home.join("probe-codex.json"),
        &default_probe_json("codex"),
    )?;
    write_pretty_json(
        &paths.lia_home.join("probe-gemini-cli.json"),
        &default_probe_json("gemini-cli"),
    )?;
    write_pretty_json(
        &paths.lia_home.join("probe-cursor.json"),
        &default_probe_json("cursor"),
    )?;

    write_script(&paths.claude_wrapper, &claude_wrapper_script(&paths))?;
    write_script(&paths.codex_wrapper, &codex_wrapper_script(&paths))?;
    write_script(&paths.gemini_wrapper, &gemini_wrapper_script(&paths))?;
    write_script(
        &paths.cursor_shell_wrapper,
        &cursor_shell_wrapper_script(&paths),
    )?;
    write_script(
        &paths.cursor_mcp_wrapper,
        &cursor_mcp_wrapper_script(&paths),
    )?;

    write_pretty_json(&paths.claude_settings, &claude_merged)?;
    fs::write(&paths.codex_config, &codex_merged)?;
    write_pretty_json(&paths.gemini_settings, &gemini_merged)?;
    write_pretty_json(&paths.cursor_hooks, &cursor_merged)?;

    let manifest = json!({
        "version": 1,
        "marker": LIA_HOOK_MARKER,
        "installed_at": chrono_now(),
        "paths": paths,
        "kernel": KernelBoundary::default(),
    });
    write_pretty_json(&paths.lia_home.join(MANIFEST_NAME), &manifest)?;

    notes.push(format!("wrote {}", paths.claude_settings.display()));
    notes.push(format!("wrote {}", paths.codex_config.display()));
    notes.push(format!("wrote {}", paths.gemini_settings.display()));
    notes.push(format!("wrote {}", paths.cursor_hooks.display()));
    notes.push(format!("state under {}", paths.lia_home.display()));

    Ok(InstallReport {
        action: "install".into(),
        dry_run: false,
        lia_home: paths.lia_home.clone(),
        claude_settings: paths.claude_settings.clone(),
        codex_config: paths.codex_config.clone(),
        gemini_settings: paths.gemini_settings.clone(),
        cursor_hooks: paths.cursor_hooks.clone(),
        claude_hook_installed: claude_hook_present(&claude_merged),
        codex_mcp_installed: codex_mcp_present(&codex_merged),
        gemini_hook_installed: gemini_hook_present(&gemini_merged),
        cursor_hooks_installed: cursor_hooks_present(&cursor_merged),
        kernel: KernelBoundary::default(),
        notes,
    })
}

pub fn uninstall(req: &InstallRequest) -> Result<InstallReport, InstallError> {
    let paths = InstallPaths::resolve(
        &req.lia_home,
        &req.lia_bin,
        &req.claude_home,
        &req.codex_home,
        &req.gemini_home,
        &req.cursor_home,
    );
    let mut notes = Vec::new();

    let claude_existing = read_json_or_empty(&paths.claude_settings)?;
    let claude_new = unmerge_claude_settings(&claude_existing)?;
    let codex_existing = read_text_or_empty(&paths.codex_config)?;
    let codex_new = unmerge_codex_toml(&codex_existing);
    let gemini_existing = read_json_or_empty(&paths.gemini_settings)?;
    let gemini_new = unmerge_gemini_settings(&gemini_existing)?;
    let cursor_existing = read_json_or_empty(&paths.cursor_hooks)?;
    let cursor_new = unmerge_cursor_hooks(&cursor_existing)?;

    if req.dry_run {
        notes.push("dry-run: no files written".into());
        return Ok(InstallReport {
            action: "uninstall".into(),
            dry_run: true,
            lia_home: paths.lia_home,
            claude_settings: paths.claude_settings,
            codex_config: paths.codex_config,
            gemini_settings: paths.gemini_settings,
            cursor_hooks: paths.cursor_hooks,
            claude_hook_installed: claude_hook_present(&claude_new),
            codex_mcp_installed: codex_mcp_present(&codex_new),
            gemini_hook_installed: gemini_hook_present(&gemini_new),
            cursor_hooks_installed: cursor_hooks_present(&cursor_new),
            kernel: KernelBoundary::default(),
            notes,
        });
    }

    if paths.claude_settings.exists() || claude_hook_present(&claude_existing) {
        if let Some(parent) = paths.claude_settings.parent() {
            fs::create_dir_all(parent)?;
        }
        write_pretty_json(&paths.claude_settings, &claude_new)?;
        notes.push(format!(
            "removed LIA hooks from {}",
            paths.claude_settings.display()
        ));
    }
    if paths.codex_config.exists() || codex_mcp_present(&codex_existing) {
        if let Some(parent) = paths.codex_config.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&paths.codex_config, &codex_new)?;
        notes.push(format!(
            "removed LIA MCP from {}",
            paths.codex_config.display()
        ));
    }
    if paths.gemini_settings.exists() || gemini_hook_present(&gemini_existing) {
        if let Some(parent) = paths.gemini_settings.parent() {
            fs::create_dir_all(parent)?;
        }
        write_pretty_json(&paths.gemini_settings, &gemini_new)?;
        notes.push(format!(
            "removed LIA hooks from {}",
            paths.gemini_settings.display()
        ));
    }
    if paths.cursor_hooks.exists() || cursor_hooks_present(&cursor_existing) {
        if let Some(parent) = paths.cursor_hooks.parent() {
            fs::create_dir_all(parent)?;
        }
        write_pretty_json(&paths.cursor_hooks, &cursor_new)?;
        notes.push(format!(
            "removed LIA hooks from {}",
            paths.cursor_hooks.display()
        ));
    }
    // Keep keys/journal by default (audit trail); only remove wrappers marker note.
    notes.push("LIA state dir retained (journal/keys); delete lia-home manually if desired".into());

    Ok(InstallReport {
        action: "uninstall".into(),
        dry_run: false,
        lia_home: paths.lia_home,
        claude_settings: paths.claude_settings,
        codex_config: paths.codex_config,
        gemini_settings: paths.gemini_settings,
        cursor_hooks: paths.cursor_hooks,
        claude_hook_installed: claude_hook_present(&claude_new),
        codex_mcp_installed: codex_mcp_present(&codex_new),
        gemini_hook_installed: gemini_hook_present(&gemini_new),
        cursor_hooks_installed: cursor_hooks_present(&cursor_new),
        kernel: KernelBoundary::default(),
        notes,
    })
}

pub fn status(req: &InstallRequest) -> Result<InstallReport, InstallError> {
    let paths = InstallPaths::resolve(
        &req.lia_home,
        &req.lia_bin,
        &req.claude_home,
        &req.codex_home,
        &req.gemini_home,
        &req.cursor_home,
    );
    let claude = read_json_or_empty(&paths.claude_settings)?;
    let codex = read_text_or_empty(&paths.codex_config)?;
    let gemini = read_json_or_empty(&paths.gemini_settings)?;
    let cursor = read_json_or_empty(&paths.cursor_hooks)?;
    let mut notes = Vec::new();
    if paths.lia_home.join(MANIFEST_NAME).exists() {
        notes.push("install-manifest present".into());
    } else {
        notes.push("no install-manifest (not installed via lia install, or wiped)".into());
    }
    if !paths.lia_bin.exists() {
        notes.push(format!(
            "WARNING: lia binary missing at {}",
            paths.lia_bin.display()
        ));
    }
    Ok(InstallReport {
        action: "status".into(),
        dry_run: false,
        lia_home: paths.lia_home,
        claude_settings: paths.claude_settings,
        codex_config: paths.codex_config,
        gemini_settings: paths.gemini_settings,
        cursor_hooks: paths.cursor_hooks,
        claude_hook_installed: claude_hook_present(&claude),
        codex_mcp_installed: codex_mcp_present(&codex),
        gemini_hook_installed: gemini_hook_present(&gemini),
        cursor_hooks_installed: cursor_hooks_present(&cursor),
        kernel: KernelBoundary::default(),
        notes,
    })
}

fn read_json_or_empty(path: &Path) -> Result<Value, InstallError> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let raw = fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(json!({}));
    }
    Ok(serde_json::from_str(&raw)?)
}

fn read_text_or_empty(path: &Path) -> Result<String, InstallError> {
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(fs::read_to_string(path)?)
}

fn write_pretty_json(path: &Path, value: &Value) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(value)?;
    fs::write(path, format!("{s}\n"))?;
    Ok(())
}

fn write_secret(path: &Path, secret: &str) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Create with 0600 ATOMICALLY (not create-then-chmod): a chmod-after-create leaves a
    // window where the signing key is world/group readable, and a failed chmod would
    // silently leave it exposed.
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut f = fs::File::create(path)?;
    f.write_all(secret.trim().as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

fn write_script(path: &Path, body: &str) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
    }
    Ok(())
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Resolve which home configs look "live" (real user dirs).
pub fn looks_like_live_user_home(
    claude_home: &Path,
    codex_home: &Path,
    gemini_home: &Path,
    cursor_home: &Path,
) -> bool {
    let Some(home) = dirs_home() else {
        return false;
    };
    claude_home == home.join(".claude")
        || codex_home == home.join(".codex")
        || gemini_home == home.join(".gemini")
        || cursor_home == home.join(".cursor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn claude_merge_idempotent_and_uninstall() {
        let existing = json!({"model": "x", "hooks": {"PreToolUse": [{"matcher": "Other", "hooks": [{"type": "command", "command": "echo hi"}]}]}});
        let m1 = merge_claude_settings(&existing, "/tmp/claude-pretool.sh").unwrap();
        assert!(claude_hook_present(&m1));
        let m2 = merge_claude_settings(&m1, "/tmp/claude-pretool.sh").unwrap();
        let arr = m2.pointer("/hooks/PreToolUse").unwrap().as_array().unwrap();
        let lia_count = arr.iter().filter(|e| entry_is_lia_hook(e)).count();
        assert_eq!(lia_count, 1, "reinstall must not duplicate LIA hooks");
        assert!(arr
            .iter()
            .any(|e| e.get("matcher").and_then(|m| m.as_str()) == Some("Other")));
        let u = unmerge_claude_settings(&m2).unwrap();
        assert!(!claude_hook_present(&u));
        assert!(u
            .pointer("/hooks/PreToolUse")
            .and_then(|a| a.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false));
        assert_eq!(u.get("model").and_then(|v| v.as_str()), Some("x"));
    }

    #[test]
    fn codex_merge_idempotent_and_uninstall() {
        let base = r#"
service_tier = "default"
model = "gpt"

[mcp_servers.other]
command = "/bin/true"
"#;
        let m1 = merge_codex_toml(base, "/tmp/codex-mcp.sh", &[]);
        assert!(codex_mcp_present(&m1));
        assert!(m1.contains("mcp_servers.other"));
        let m2 = merge_codex_toml(&m1, "/tmp/codex-mcp.sh", &[]);
        assert_eq!(
            m2.matches(&format!("[mcp_servers.{CODEX_MCP_SERVER}]"))
                .count(),
            1
        );
        let u = unmerge_codex_toml(&m2);
        assert!(!codex_mcp_present(&u));
        assert!(u.contains("mcp_servers.other"));
        assert!(u.contains("service_tier"));
    }

    #[test]
    fn gemini_and_cursor_merges_are_idempotent_and_cursor_fails_closed() {
        let gemini_base = json!({
            "theme": "dark",
            "hooks": {"BeforeTool": [{
                "matcher": "other_tool",
                "hooks": [{"type": "command", "command": "echo other"}]
            }]}
        });
        let gemini = merge_gemini_settings(&gemini_base, "/tmp/gemini-beforetool.sh").unwrap();
        let gemini_twice = merge_gemini_settings(&gemini, "/tmp/gemini-beforetool.sh").unwrap();
        assert!(gemini_hook_present(&gemini_twice));
        assert_eq!(
            gemini_twice
                .pointer("/hooks/BeforeTool")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .filter(|entry| gemini_entry_is_lia(entry))
                .count(),
            1
        );
        assert!(!gemini_hook_present(
            &unmerge_gemini_settings(&gemini_twice).unwrap()
        ));

        let cursor_base = json!({
            "version": 1,
            "hooks": {"beforeShellExecution": [{"command": "echo other"}]}
        });
        let cursor = merge_cursor_hooks(
            &cursor_base,
            "/tmp/cursor-before-shell.sh",
            "/tmp/cursor-before-mcp.sh",
        )
        .unwrap();
        let cursor_twice = merge_cursor_hooks(
            &cursor,
            "/tmp/cursor-before-shell.sh",
            "/tmp/cursor-before-mcp.sh",
        )
        .unwrap();
        assert!(cursor_hooks_present(&cursor_twice));
        for event in ["beforeShellExecution", "beforeMCPExecution"] {
            let entries = cursor_twice
                .pointer(&format!("/hooks/{event}"))
                .and_then(Value::as_array)
                .unwrap();
            let lia_entry = entries
                .iter()
                .find(|entry| cursor_entry_is_lia(entry))
                .unwrap();
            assert_eq!(
                lia_entry.get("failClosed").and_then(Value::as_bool),
                Some(true)
            );
            assert_eq!(
                entries
                    .iter()
                    .filter(|entry| cursor_entry_is_lia(entry))
                    .count(),
                1
            );
        }
        assert!(!cursor_hooks_present(
            &unmerge_cursor_hooks(&cursor_twice).unwrap()
        ));
    }

    #[test]
    fn install_status_uninstall_fixture_roundtrip() {
        let tmp = tempdir().unwrap();
        let lia_home = tmp.path().join("lia-home");
        let claude_home = tmp.path().join("claude");
        let codex_home = tmp.path().join("codex");
        let gemini_home = tmp.path().join("gemini");
        let cursor_home = tmp.path().join("cursor");
        // Fake binary path (must not collide with lia_home directory)
        let bin = tmp.path().join("lia-bin");
        fs::write(&bin, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let req = InstallRequest {
            lia_home: lia_home.clone(),
            lia_bin: bin.clone(),
            claude_home: claude_home.clone(),
            codex_home: codex_home.clone(),
            gemini_home: gemini_home.clone(),
            cursor_home: cursor_home.clone(),
            dry_run: false,
            apply_live: false,
            allowed_roots: vec![tmp.path().to_path_buf()],
        };
        let rep = install(&req).unwrap();
        assert!(rep.claude_hook_installed);
        assert!(rep.codex_mcp_installed);
        assert!(lia_home.join(MANIFEST_NAME).exists());
        assert!(claude_home.join("settings.json").exists());
        assert!(codex_home.join("config.toml").exists());
        assert!(gemini_home.join("settings.json").exists());
        assert!(cursor_home.join("hooks.json").exists());

        let st = status(&req).unwrap();
        assert!(st.claude_hook_installed);
        assert!(st.codex_mcp_installed);

        // idempotent reinstall
        let rep2 = install(&req).unwrap();
        assert!(rep2.claude_hook_installed);
        assert!(rep2.gemini_hook_installed);
        assert!(rep2.cursor_hooks_installed);
        let settings: Value =
            serde_json::from_str(&fs::read_to_string(claude_home.join("settings.json")).unwrap())
                .unwrap();
        let arr = settings
            .pointer("/hooks/PreToolUse")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(arr.iter().filter(|e| entry_is_lia_hook(e)).count(), 1);

        let un = uninstall(&req).unwrap();
        assert!(!un.claude_hook_installed);
        assert!(!un.codex_mcp_installed);
        assert!(!un.gemini_hook_installed);
        assert!(!un.cursor_hooks_installed);
        let st2 = status(&req).unwrap();
        assert!(!st2.claude_hook_installed);
        assert!(!st2.codex_mcp_installed);
        assert!(!st2.gemini_hook_installed);
        assert!(!st2.cursor_hooks_installed);
    }

    #[test]
    fn dry_run_writes_nothing() {
        let tmp = tempdir().unwrap();
        let bin = tmp.path().join("lia-bin");
        fs::write(&bin, b"x").unwrap();
        let req = InstallRequest {
            lia_home: tmp.path().join("lia-home"),
            lia_bin: bin,
            claude_home: tmp.path().join("claude"),
            codex_home: tmp.path().join("codex"),
            gemini_home: tmp.path().join("gemini"),
            cursor_home: tmp.path().join("cursor"),
            dry_run: true,
            apply_live: false,
            allowed_roots: vec![],
        };
        let rep = install(&req).unwrap();
        assert!(rep.dry_run);
        assert!(rep.claude_hook_installed);
        assert!(!req.lia_home.exists());
        assert!(!req.claude_home.join("settings.json").exists());
    }

    #[test]
    fn kernel_boundary_forbids_confine_claim() {
        let k = KernelBoundary::default();
        assert!(k.assurance.contains("UNMEASURED"));
        assert!(!k.assurance.contains("PREVENT"));
        assert!(
            k.assurance.contains("CONFINE")
                || k.cannot_observe.iter().any(|s| s.contains("CONFINE"))
        );
        assert!(!k.includes.is_empty());
    }
}
