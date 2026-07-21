use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

const SECRET_HEX: &str = "8888888888888888888888888888888888888888888888888888888888888888";

fn lia_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_lia")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lia"))
}

fn write_config(path: &Path, root: &Path) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "allowed_roots": [root],
            "home_dir": root.join("home"),
            "cwd": root,
            "protected_paths": [root.join(".lia")],
            "registry": {},
            "env": {"HOME": root.join("home")},
            "run_id": "33333333-3333-4333-8333-333333333333"
        }))
        .expect("config json"),
    )
    .expect("write config");
}

fn output_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "command emitted invalid JSON: {error}; status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn run_mcp(root: &Path, case: &str, tool: &str, arguments: Value) -> (Output, PathBuf) {
    let case_dir = root.parent().expect("root parent").join(case);
    fs::create_dir_all(&case_dir).expect("case dir");
    let config = case_dir.join("config.json");
    let journal = case_dir.join("journal.db");
    write_config(&config, root);
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    })
    .to_string();
    let output = Command::new(lia_bin())
        .args([
            "mcp",
            "--config",
            config.to_str().expect("config path"),
            "--journal",
            journal.to_str().expect("journal path"),
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "m2-production-test",
            "--request",
            &request,
        ])
        .output()
        .expect("run mcp");
    (output, journal)
}

fn assert_mcp_reason(output: &Output, is_error: bool, reason: &str) {
    let response = output_json(output);
    assert_eq!(
        response.pointer("/result/isError").and_then(Value::as_bool),
        Some(is_error),
        "response={response}"
    );
    assert!(
        response
            .pointer("/result/lia/outcomes")
            .and_then(Value::as_array)
            .is_some_and(|outcomes| outcomes.iter().any(|outcome| {
                outcome.get("reason_code").and_then(Value::as_str) == Some(reason)
            })),
        "missing reason {reason}: {response}"
    );
    assert!(
        response
            .pointer("/result/lia/journal_receipts")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty()),
        "missing production-path receipt: {response}"
    );
}

#[test]
fn generic_wrap_persists_a_signed_journal_outside_the_child_worktree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    let evidence = temp.path().join("evidence");
    let config = temp.path().join("config.json");
    fs::create_dir_all(&repo).expect("repo");
    fs::write(repo.join("base.txt"), "base\n").expect("base file");
    write_config(&config, &repo);

    let output = Command::new(lia_bin())
        .args([
            "wrap",
            "--repo",
            repo.to_str().expect("repo path"),
            "--evidence-dir",
            evidence.to_str().expect("evidence path"),
            "--config",
            config.to_str().expect("config path"),
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "generic-wrap-test",
            "--no-watch",
            "--",
            "sh",
            "-c",
            "printf wrapped > wrapped.txt",
        ])
        .output()
        .expect("run wrap");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = output_json(&output);
    let journal = PathBuf::from(report["journal_path"].as_str().expect("journal path"));
    let worktree = PathBuf::from(report["worktree"].as_str().expect("worktree"));
    let process_contract = PathBuf::from(
        report["process_contract_path"]
            .as_str()
            .expect("process contract path"),
    );
    let process_execution = PathBuf::from(
        report["process_execution_path"]
            .as_str()
            .expect("process execution path"),
    );
    assert!(journal.is_file(), "generic wrap did not create journal");
    assert!(!journal.starts_with(&worktree), "journal is child-writable");
    assert_eq!(report["process_validation"]["followed"], true);
    assert!(process_contract.is_file());
    assert!(process_execution.is_file());

    let verify = Command::new(lia_bin())
        .args(["journal-verify", journal.to_str().expect("journal path")])
        .output()
        .expect("verify generic journal");
    assert!(
        verify.status.success(),
        "verify stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let contract_verify = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            process_contract.to_str().expect("contract path"),
            "--execution",
            process_execution.to_str().expect("execution path"),
            "--journal",
            journal.to_str().expect("journal path"),
        ])
        .output()
        .expect("verify generic process contract");
    assert!(
        contract_verify.status.success(),
        "contract stderr={}",
        String::from_utf8_lossy(&contract_verify.stderr)
    );
}

#[test]
fn codex_write_path_enforces_ast_with_receipts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).expect("root");

    let (ast, _) = run_mcp(
        &root,
        "ast",
        "write_file",
        json!({"path": root.join("unsafe.py"), "content": "x = eval(user_input)\n"}),
    );
    assert_mcp_reason(&ast, true, "AST_EVAL");
}

#[test]
fn codex_write_path_enforces_supplied_taint_with_receipts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).expect("root");
    let (taint, _) = run_mcp(
        &root,
        "taint",
        "write_file",
        json!({
            "path": root.join("flow.py"),
            "content": "print('safe syntax')\n",
            "taint_graph": {
                "nodes": [
                    {"id": "input", "kind": "untrusted_source"},
                    {"id": "sink", "kind": "destructive_sink"}
                ],
                "edges": [{"from": "input", "to": "sink"}]
            }
        }),
    );
    assert_mcp_reason(&taint, true, "TAINT_UNTRUSTED_TO_DESTRUCTIVE_SINK");
}

#[test]
fn codex_malformed_taint_is_a_blocking_receipted_outcome() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).expect("root");
    let (taint, _) = run_mcp(
        &root,
        "taint-invalid",
        "write_file",
        json!({
            "path": root.join("flow.py"),
            "content": "print('safe syntax')\n",
            "taint_graph": {"nodes": [], "edges": []}
        }),
    );
    assert_mcp_reason(&taint, true, "TAINT_INVALID_INPUT");
}

#[test]
fn codex_ground_unknown_claim_is_a_blocking_production_tool() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).expect("root");

    let (ground, _) = run_mcp(
        &root,
        "ground",
        "ground_claim",
        json!({"claim": {"type": "not_registered"}}),
    );
    assert_mcp_reason(&ground, true, "GROUND_UNKNOWN_CLAIM_TYPE");
}

#[test]
fn codex_unsupported_agreement_is_a_blocking_production_tool() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).expect("root");
    let (syco, _) = run_mcp(
        &root,
        "syco",
        "check_agreement",
        json!({
            "exchange": {
                "user_assertion": "deleting the root is safe",
                "agent_response": "yes, agreed",
                "agent_agreed": true,
                "evidence_supports_assertion": false,
                "risk": "security"
            }
        }),
    );
    assert_mcp_reason(&syco, true, "SYCO_UNSUPPORTED_AGREEMENT");
}

#[test]
fn codex_incomplete_completion_is_blocking() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).expect("root");
    let (completion, _) = run_mcp(
        &root,
        "completion",
        "complete_task",
        json!({"modified_paths": ["src/lib.rs"], "has_test_result": false}),
    );
    assert_mcp_reason(&completion, true, "EVIDENCE_INCOMPLETE");
}

#[test]
fn assurance_report_accepts_probe_observed_per_gate_cells() {
    let temp = tempfile::tempdir().expect("tempdir");
    let probe = temp.path().join("claude.probe.json");
    fs::write(
        &probe,
        serde_json::to_vec_pretty(&json!({
            "adapter": "claude-code",
            "keys": {
                "pre_write_block": true,
                "post_write_receipt": true,
                "shell_pre_block": true,
                "shell_result_capture": false,
                "network_control": false,
                "credential_broker": false,
                "completion_gate": false,
                "subagent_visibility": true,
                "immutable_journal": true,
                "offline_verification": true
            },
            "gate_cells": {
                "test-integrity": "CANNOT-OBSERVE",
                "evidence-completeness": "CANNOT-OBSERVE",
                "filesystem-scope": "PREVENT",
                "shell-irreversible": "PREVENT",
                "dependency-reality": "CANNOT-OBSERVE",
                "secret-output": "PREVENT",
                "journal-tamper": "PREVENT"
            },
            "notes": ["fixture-observed PreToolUse boundary"]
        }))
        .expect("probe json"),
    )
    .expect("write probe");
    let output = Command::new(lia_bin())
        .args([
            "report",
            "--adapter",
            "claude-code",
            "--probe",
            probe.to_str().expect("probe path"),
            "--json",
        ])
        .output()
        .expect("run report");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = output_json(&output);
    let cells = report["gates"].as_array().expect("gate cells");
    assert!(cells
        .iter()
        .any(|cell| { cell["gate_id"] == "test-integrity" && cell["cell"] == "CANNOT-OBSERVE" }));
    assert!(cells.iter().any(|cell| {
        cell["gate_id"] == "evidence-completeness" && cell["cell"] == "CANNOT-OBSERVE"
    }));
}
