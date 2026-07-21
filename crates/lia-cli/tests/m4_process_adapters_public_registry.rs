use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SECRET_HEX: &str = "abababababababababababababababababababababababababababababababab";
const RUN_ID: &str = "44444444-4444-4444-8444-444444444444";
const ACTION_ID: &str = "55555555-5555-4555-8555-555555555555";
const EVIDENCE_ID: &str = "66666666-6666-4666-8666-666666666666";
const EXTRA_EVIDENCE_ID: &str = "88888888-8888-4888-8888-888888888888";

fn lia_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_lia")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lia"))
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

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).expect("json bytes")).expect("write json");
}

fn write_gate_config(path: &Path, root: &Path) {
    write_json(
        path,
        &json!({
            "allowed_roots": [root],
            "home_dir": root.join("home"),
            "cwd": root,
            "protected_paths": [],
            "registry": {},
            "env": {},
            "run_id": RUN_ID
        }),
    );
}

fn process_contract_sha256(value: &Value) -> String {
    let contract: lia_protocol::ProcessContract =
        serde_json::from_value(value.clone()).expect("typed process contract");
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&contract).expect("canonical contract bytes"));
    hex::encode(hasher.finalize())
}

fn process_execution_manifest_sha256(contract: &Value, execution: &Value) -> String {
    let contract: lia_protocol::ProcessContract =
        serde_json::from_value(contract.clone()).expect("typed process contract");
    let execution: lia_protocol::ProcessExecution =
        serde_json::from_value(execution.clone()).expect("typed process execution");
    lia_adapters::process_execution_manifest_sha256(&contract, &execution)
        .expect("execution manifest digest")
}

fn file_sha256(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fs::read(path).expect("file bytes"));
    hex::encode(hasher.finalize())
}

fn append_event(db: &Path, event: Value) -> String {
    let output = Command::new(lia_bin())
        .args([
            "journal-append",
            "--db",
            db.to_str().expect("db"),
            "--event",
            &event.to_string(),
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "m4-contract-test",
            "--run-id",
            RUN_ID,
        ])
        .output()
        .expect("journal append");
    assert!(
        output.status.success(),
        "append stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    output_json(&output)["receipt_id"]
        .as_str()
        .expect("receipt id")
        .to_string()
}

#[test]
fn process_contract_requires_verified_journal_evidence_before_completion() {
    let temp = tempfile::tempdir().expect("tempdir");
    let journal = temp.path().join("journal.db");
    let contract_path = temp.path().join("contract.json");
    let execution_path = temp.path().join("execution.json");

    let contract = json!({
        "contract_version": "lia-process-contract-v1",
        "contract_id": "77777777-7777-4777-8777-777777777777",
        "run_id": RUN_ID,
        "objective": "Run the declared test command and admit completion only from its receipt.",
        "assumptions": [{
            "id": "tests-are-applicable",
            "statement": "The repository exposes the declared test target.",
            "required_evidence": ["test-result"]
        }],
        "required_evidence": [{
            "id": "test-result",
            "kind": "test_result",
            "description": "Wrapper-observed test evidence",
            "required": true
        }],
        "allowed_actions": ["run_test"],
        "completion_predicate": {
            "all_evidence": ["test-result"],
            "require_all_assumptions_supported": true,
            "require_no_unresolved_claims": true
        },
        "honest_stop_conditions": [{
            "code": "test-runner-unavailable",
            "description": "The declared runner cannot be executed."
        }]
    });
    write_json(&contract_path, &contract);
    let contract_receipt = append_event(
        &journal,
        json!({
            "family": "process_contract_declared",
            "contract_id": "77777777-7777-4777-8777-777777777777",
            "contract_version": "lia-process-contract-v1",
            "contract_sha256": process_contract_sha256(&contract),
            "timestamp": "2026-07-21T23:59:59Z"
        }),
    );

    let action_receipt = append_event(
        &journal,
        json!({
            "family": "action_attempted",
            "action_id": ACTION_ID,
            "kind": "run_test",
            "payload": {
                "command": "cargo test",
                "path": null,
                "content_sha256": null,
                "argv": ["cargo", "test"],
                "cwd": "/repo",
                "package": null,
                "version": null,
                "claim": null
            },
            "timestamp": "2026-07-22T00:00:00Z"
        }),
    );
    let evidence_receipt = append_event(
        &journal,
        json!({
            "family": "evidence_captured",
            "evidence_id": EVIDENCE_ID,
            "kind": "test_result",
            "path": "/evidence/test.json",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bytes": 42,
            "timestamp": "2026-07-22T00:00:01Z"
        }),
    );
    let extra_evidence_receipt = append_event(
        &journal,
        json!({
            "family": "evidence_captured",
            "evidence_id": EXTRA_EVIDENCE_ID,
            "kind": "test_result",
            "path": "/evidence/extra-test.json",
            "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bytes": 43,
            "timestamp": "2026-07-22T00:00:01Z"
        }),
    );
    let mut execution = json!({
        "contract_id": "77777777-7777-4777-8777-777777777777",
        "contract_receipt_id": contract_receipt,
        "performed_actions": [{
            "action_id": ACTION_ID,
            "kind": "run_test",
            "receipt_id": action_receipt
        }],
        "evidence": [{
            "requirement_id": "test-result",
            "evidence_id": EVIDENCE_ID,
            "receipt_id": evidence_receipt,
            "kind": "test_result",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }],
        "supported_assumptions": ["tests-are-applicable"],
        "unresolved_claims": [],
        "outcome": {
            "kind": "complete",
            "receipt_id": "00000000-0000-0000-0000-000000000000"
        }
    });
    let completion_manifest = process_execution_manifest_sha256(&contract, &execution);
    let completion_receipt = append_event(
        &journal,
        json!({
            "family": "gate_verdict",
            "action_id": ACTION_ID,
            "gate_id": "evidence-completeness",
            "verdict": "verified",
            "reason_code": "EVIDENCE_COMPLETE",
            "risk_tier": "quality",
            "detail": "required test evidence observed",
            "evidence_sha256": completion_manifest,
            "timestamp": "2026-07-22T00:00:02Z"
        }),
    );
    execution["outcome"]["receipt_id"] = json!(completion_receipt);
    write_json(&execution_path, &execution);

    let valid = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            contract_path.to_str().expect("contract"),
            "--execution",
            execution_path.to_str().expect("execution"),
            "--journal",
            journal.to_str().expect("journal"),
        ])
        .output()
        .expect("validate contract");
    assert!(
        valid.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&valid.stderr)
    );
    let valid_report = output_json(&valid);
    assert_eq!(valid_report["followed"], true);
    assert_eq!(valid_report["status"], "complete");
    assert_eq!(valid_report["reason_code"], "PROCESS_CONTRACT_FOLLOWED");

    let mut relabelled_evidence = execution.clone();
    relabelled_evidence["evidence"][0]["kind"] = json!("unrelated_kind");
    write_json(&execution_path, &relabelled_evidence);
    let relabelled = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            contract_path.to_str().expect("contract"),
            "--execution",
            execution_path.to_str().expect("execution"),
            "--journal",
            journal.to_str().expect("journal"),
        ])
        .output()
        .expect("reject relabelled evidence");
    assert!(!relabelled.status.success());
    assert_eq!(
        output_json(&relabelled)["reason_code"],
        "PROCESS_EVIDENCE_RECEIPT_MISMATCH"
    );

    let mut unbound_execution = execution.clone();
    unbound_execution["evidence"]
        .as_array_mut()
        .expect("evidence list")
        .push(json!({
            "requirement_id": "test-result",
            "evidence_id": EXTRA_EVIDENCE_ID,
            "receipt_id": extra_evidence_receipt,
            "kind": "test_result",
            "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }));
    write_json(&execution_path, &unbound_execution);
    let unbound = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            contract_path.to_str().expect("contract"),
            "--execution",
            execution_path.to_str().expect("execution"),
            "--journal",
            journal.to_str().expect("journal"),
        ])
        .output()
        .expect("reject unbound execution manifest");
    assert!(!unbound.status.success());
    assert_eq!(
        output_json(&unbound)["reason_code"],
        "PROCESS_COMPLETION_RECEIPT_INVALID"
    );
    write_json(&execution_path, &execution);

    let mut rewritten_contract = contract.clone();
    rewritten_contract["objective"] = json!("A different objective written after execution.");
    write_json(&contract_path, &rewritten_contract);
    let rewritten = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            contract_path.to_str().expect("contract"),
            "--execution",
            execution_path.to_str().expect("execution"),
            "--journal",
            journal.to_str().expect("journal"),
        ])
        .output()
        .expect("reject rewritten contract");
    assert!(!rewritten.status.success());
    assert_eq!(
        output_json(&rewritten)["reason_code"],
        "PROCESS_CONTRACT_RECEIPT_INVALID"
    );
    write_json(&contract_path, &contract);

    let mut incomplete: Value =
        serde_json::from_slice(&fs::read(&execution_path).expect("execution bytes"))
            .expect("execution json");
    incomplete["evidence"] = json!([]);
    write_json(&execution_path, &incomplete);
    let invalid = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            contract_path.to_str().expect("contract"),
            "--execution",
            execution_path.to_str().expect("execution"),
            "--journal",
            journal.to_str().expect("journal"),
        ])
        .output()
        .expect("reject incomplete contract");
    assert!(!invalid.status.success(), "missing evidence must block");
    assert_eq!(
        output_json(&invalid)["reason_code"],
        "PROCESS_REQUIRED_EVIDENCE_MISSING"
    );

    incomplete["outcome"] = json!({
        "kind": "honest_stop",
        "condition_code": "test-runner-unavailable",
        "receipt_id": "00000000-0000-0000-0000-000000000000",
        "unblocks": [{
            "tried": ["located cargo", "inspected repository test metadata"],
            "missing": "an executable test runner",
            "route": "install the pinned toolchain and rerun"
        }]
    });
    let stop_manifest = process_execution_manifest_sha256(&contract, &incomplete);
    let stop_receipt = append_event(
        &journal,
        json!({
            "family": "gate_verdict",
            "action_id": ACTION_ID,
            "gate_id": "process-contract",
            "verdict": "incomplete",
            "reason_code": "test-runner-unavailable",
            "risk_tier": "quality",
            "detail": "test runner unavailable",
            "evidence_sha256": stop_manifest,
            "timestamp": "2026-07-22T00:00:03Z"
        }),
    );
    incomplete["outcome"]["receipt_id"] = json!(stop_receipt);
    write_json(&execution_path, &incomplete);
    let honest_stop = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            contract_path.to_str().expect("contract"),
            "--execution",
            execution_path.to_str().expect("execution"),
            "--journal",
            journal.to_str().expect("journal"),
        ])
        .output()
        .expect("validate honest stop");
    assert!(honest_stop.status.success());
    let stop_report = output_json(&honest_stop);
    assert_eq!(stop_report["status"], "honest_stop");
    assert_eq!(stop_report["reason_code"], "PROCESS_HONEST_STOP_VALID");

    incomplete["outcome"]["unblocks"] = json!([]);
    write_json(&execution_path, &incomplete);
    let unblockless = Command::new(lia_bin())
        .args([
            "process-contract-validate",
            "--contract",
            contract_path.to_str().expect("contract"),
            "--execution",
            execution_path.to_str().expect("execution"),
            "--journal",
            journal.to_str().expect("journal"),
        ])
        .output()
        .expect("reject unblockless stop");
    assert!(!unblockless.status.success());
    assert_eq!(
        output_json(&unblockless)["reason_code"],
        "PROCESS_UNBLOCK_INVALID"
    );
}

fn run_hook(adapter: &str, raw: Value, config: &Path, journal: &Path) -> Output {
    let mut child = Command::new(lia_bin())
        .args([
            "hook",
            "--adapter",
            adapter,
            "--config",
            config.to_str().expect("config"),
            "--journal",
            journal.to_str().expect("journal"),
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "m4-hook-test",
            "--run-id",
            RUN_ID,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(raw.to_string().as_bytes())
        .expect("write hook input");
    child.wait_with_output().expect("hook output")
}

#[test]
fn gemini_and_cursor_native_pre_action_hooks_deny_and_receipt_destructive_shell() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    let config = temp.path().join("config.json");
    write_gate_config(&config, &repo);

    let gemini_journal = temp.path().join("gemini.db");
    let gemini = run_hook(
        "gemini-cli",
        json!({
            "session_id": "gemini-session",
            "transcript_path": "/tmp/gemini-transcript.json",
            "cwd": repo,
            "hook_event_name": "BeforeTool",
            "timestamp": "2026-07-22T00:00:00Z",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "rm -rf /"},
            "future_additive_field": {"accepted": true}
        }),
        &config,
        &gemini_journal,
    );
    assert_eq!(gemini.status.code(), Some(2));
    assert_eq!(output_json(&gemini)["decision"], "deny");

    let cursor_journal = temp.path().join("cursor.db");
    let cursor = run_hook(
        "cursor-shell",
        json!({
            "command": "rm -rf /",
            "cwd": repo,
            "sandbox": false,
            "future_additive_field": {"accepted": true}
        }),
        &config,
        &cursor_journal,
    );
    assert_eq!(cursor.status.code(), Some(2));
    assert_eq!(output_json(&cursor)["permission"], "deny");

    let gemini_benign = run_hook(
        "gemini-cli",
        json!({
            "session_id": "gemini-benign",
            "transcript_path": "/tmp/gemini-benign.json",
            "cwd": repo,
            "hook_event_name": "BeforeTool",
            "timestamp": "2026-07-22T00:00:01Z",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "printf safe"}
        }),
        &config,
        &gemini_journal,
    );
    assert!(gemini_benign.status.success());
    assert_eq!(output_json(&gemini_benign)["decision"], "allow");

    let cursor_benign = run_hook(
        "cursor-shell",
        json!({
            "command": "printf safe",
            "cwd": repo,
            "sandbox": false
        }),
        &config,
        &cursor_journal,
    );
    assert!(cursor_benign.status.success());
    assert_eq!(output_json(&cursor_benign)["permission"], "allow");

    let cursor_unknown = run_hook(
        "cursor-mcp",
        json!({
            "tool_name": "future_external_tool",
            "tool_input": {},
            "url": "https://mcp.example.test",
            "future_additive_field": true
        }),
        &config,
        &cursor_journal,
    );
    assert!(cursor_unknown.status.success());
    assert_eq!(output_json(&cursor_unknown)["permission"], "ask");

    for journal in [&gemini_journal, &cursor_journal] {
        let verify = Command::new(lia_bin())
            .args(["journal-verify", journal.to_str().expect("journal")])
            .output()
            .expect("verify hook journal");
        assert!(
            verify.status.success(),
            "journal did not carry a verifiable receipt: {}",
            String::from_utf8_lossy(&verify.stderr)
        );
    }
}

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod executable");
}

#[test]
#[cfg(unix)]
fn optional_cosign_verifier_pins_identity_and_issuer_and_reports_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifact = temp.path().join("artifact.bin");
    let bundle = temp.path().join("artifact.sigstore.json");
    let args_log = temp.path().join("args.txt");
    let fake = temp.path().join("fake-cosign");
    fs::write(&artifact, b"artifact").expect("artifact");
    fs::write(&bundle, b"{}").expect("bundle");
    write_executable(
        &fake,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho verified\nexit 0\n",
            args_log.display()
        ),
    );
    let verifier_sha256 = file_sha256(&fake);

    let success = Command::new(lia_bin())
        .args([
            "public-verify",
            "--artifact",
            artifact.to_str().expect("artifact"),
            "--bundle",
            bundle.to_str().expect("bundle"),
            "--certificate-identity",
            "release@example.com",
            "--certificate-oidc-issuer",
            "https://accounts.example.com",
            "--cosign-bin",
            fake.to_str().expect("fake cosign"),
            "--expected-cosign-sha256",
            &verifier_sha256,
            "--timeout-seconds",
            "2",
        ])
        .output()
        .expect("public verify");
    assert!(
        success.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&success.stderr)
    );
    let report = output_json(&success);
    assert_eq!(report["accepted"], true);
    assert_eq!(report["reason_code"], "SIGSTORE_VERIFIED");
    assert_eq!(report["verifier_sha256"], verifier_sha256);
    assert_eq!(report["artifact_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(report["bundle_sha256"].as_str().unwrap().len(), 64);
    let args = fs::read_to_string(&args_log).expect("args log");
    assert!(args.contains("verify-blob"));
    assert!(args.contains("--certificate-identity=release@example.com"));
    assert!(args.contains("--certificate-oidc-issuer=https://accounts.example.com"));

    let unpinned = Command::new(lia_bin())
        .args([
            "public-verify",
            "--artifact",
            artifact.to_str().expect("artifact"),
            "--bundle",
            bundle.to_str().expect("bundle"),
            "--certificate-identity",
            "release@example.com",
            "--certificate-oidc-issuer",
            "https://accounts.example.com",
            "--cosign-bin",
            fake.to_str().expect("fake cosign"),
            "--expected-cosign-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .output()
        .expect("reject unpinned verifier");
    assert!(!unpinned.status.success());
    assert!(String::from_utf8_lossy(&unpinned.stderr).contains("SIGSTORE_VERIFIER_DIGEST_MISMATCH"));

    write_executable(&fake, "#!/bin/sh\necho rejected >&2\nexit 1\n");
    let verifier_sha256 = file_sha256(&fake);
    let failure = Command::new(lia_bin())
        .args([
            "public-verify",
            "--artifact",
            artifact.to_str().expect("artifact"),
            "--bundle",
            bundle.to_str().expect("bundle"),
            "--certificate-identity",
            "release@example.com",
            "--certificate-oidc-issuer",
            "https://accounts.example.com",
            "--cosign-bin",
            fake.to_str().expect("fake cosign"),
            "--expected-cosign-sha256",
            &verifier_sha256,
            "--timeout-seconds",
            "2",
        ])
        .output()
        .expect("rejected public verify");
    assert!(!failure.status.success());
    assert_eq!(
        output_json(&failure)["reason_code"],
        "SIGSTORE_VERIFICATION_FAILED"
    );

    write_executable(&fake, "#!/bin/sh\nsleep 5 &\nexit 0\n");
    let verifier_sha256 = file_sha256(&fake);
    let timeout_started = std::time::Instant::now();
    let timeout = Command::new(lia_bin())
        .args([
            "public-verify",
            "--artifact",
            artifact.to_str().expect("artifact"),
            "--bundle",
            bundle.to_str().expect("bundle"),
            "--certificate-identity",
            "release@example.com",
            "--certificate-oidc-issuer",
            "https://accounts.example.com",
            "--cosign-bin",
            fake.to_str().expect("fake cosign"),
            "--expected-cosign-sha256",
            &verifier_sha256,
            "--timeout-seconds",
            "1",
        ])
        .output()
        .expect("timed out public verify");
    assert!(!timeout.status.success());
    assert!(timeout_started.elapsed().as_secs() < 4);
    assert_eq!(
        output_json(&timeout)["reason_code"],
        "SIGSTORE_VERIFIER_TIMEOUT"
    );
}

#[test]
#[cfg(unix)]
fn registry_evidence_is_bounded_hashed_and_offline_cache_is_tamper_evident() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fake = temp.path().join("fake-curl");
    let cache = temp.path().join("cache");
    write_executable(
        &fake,
        r#"#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    out="$1"
  fi
  shift
done
printf '%s\n' '{"name":"serde","vers":"1.0.0","deps":[],"cksum":"abc","features":{},"yanked":false}' > "$out"
printf '200'
"#,
    );
    let client_sha256 = file_sha256(&fake);

    let custom_origin = Command::new(lia_bin())
        .args([
            "registry-evidence",
            "--ecosystem",
            "crates-io",
            "--package",
            "serde",
            "--cache-dir",
            cache.to_str().expect("cache"),
            "--http-client",
            fake.to_str().expect("fake curl"),
            "--expected-http-client-sha256",
            &client_sha256,
            "--base-url",
            "https://registry.example.test",
        ])
        .output()
        .expect("reject custom registry origin");
    assert!(!custom_origin.status.success());
    assert!(String::from_utf8_lossy(&custom_origin.stderr)
        .contains("custom registry origins cannot produce VERIFIED evidence"));

    let live = Command::new(lia_bin())
        .args([
            "registry-evidence",
            "--ecosystem",
            "crates-io",
            "--package",
            "serde",
            "--version",
            "1.0.0",
            "--cache-dir",
            cache.to_str().expect("cache"),
            "--http-client",
            fake.to_str().expect("fake curl"),
            "--expected-http-client-sha256",
            &client_sha256,
            "--timeout-seconds",
            "2",
        ])
        .output()
        .expect("live registry evidence");
    assert!(
        live.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&live.stderr)
    );
    let live_report = output_json(&live);
    assert_eq!(live_report["accepted"], true);
    assert_eq!(live_report["source"], "live");
    assert_eq!(live_report["reason_code"], "REGISTRY_VERSION_VERIFIED");
    assert_eq!(
        live_report["response_sha256"]
            .as_str()
            .expect("response sha")
            .len(),
        64
    );
    let cache_body = PathBuf::from(
        live_report["cache_body_path"]
            .as_str()
            .expect("cache body path"),
    );
    let cache_metadata = PathBuf::from(
        live_report["cache_metadata_path"]
            .as_str()
            .expect("cache metadata path"),
    );
    assert!(cache_body.is_file());
    let response_sha256 = live_report["response_sha256"]
        .as_str()
        .expect("response sha")
        .to_string();
    let cache_manifest_sha256 = live_report["cache_manifest_sha256"]
        .as_str()
        .expect("cache manifest sha")
        .to_string();

    let offline = Command::new(lia_bin())
        .args([
            "registry-evidence",
            "--ecosystem",
            "crates-io",
            "--package",
            "serde",
            "--version",
            "1.0.0",
            "--cache-dir",
            cache.to_str().expect("cache"),
            "--offline",
            "--expected-response-sha256",
            &response_sha256,
            "--expected-cache-manifest-sha256",
            &cache_manifest_sha256,
        ])
        .output()
        .expect("offline registry evidence");
    assert!(
        offline.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&offline.stderr)
    );
    assert_eq!(output_json(&offline)["source"], "cache");

    let original_metadata = fs::read(&cache_metadata).expect("original cache metadata");
    let mut stale_metadata: Value =
        serde_json::from_slice(&original_metadata).expect("cache metadata json");
    stale_metadata["fetched_at"] = json!("2000-01-01T00:00:00Z");
    write_json(&cache_metadata, &stale_metadata);
    let stale_manifest_sha256 = file_sha256(&cache_metadata);
    let stale = Command::new(lia_bin())
        .args([
            "registry-evidence",
            "--ecosystem",
            "crates-io",
            "--package",
            "serde",
            "--version",
            "1.0.0",
            "--cache-dir",
            cache.to_str().expect("cache"),
            "--offline",
            "--expected-response-sha256",
            &response_sha256,
            "--expected-cache-manifest-sha256",
            &stale_manifest_sha256,
            "--max-cache-age-seconds",
            "1",
        ])
        .output()
        .expect("stale registry evidence");
    assert!(!stale.status.success());
    assert_eq!(output_json(&stale)["reason_code"], "REGISTRY_CACHE_STALE");
    fs::write(&cache_metadata, &original_metadata).expect("restore cache metadata");

    fs::write(&cache_body, b"tampered").expect("tamper cache");
    let tampered = Command::new(lia_bin())
        .args([
            "registry-evidence",
            "--ecosystem",
            "crates-io",
            "--package",
            "serde",
            "--version",
            "1.0.0",
            "--cache-dir",
            cache.to_str().expect("cache"),
            "--offline",
            "--expected-response-sha256",
            &response_sha256,
            "--expected-cache-manifest-sha256",
            &cache_manifest_sha256,
        ])
        .output()
        .expect("tampered registry evidence");
    assert!(
        !tampered.status.success(),
        "tampered cache must fail closed"
    );
    assert_eq!(
        output_json(&tampered)["reason_code"],
        "REGISTRY_CACHE_HASH_MISMATCH"
    );

    let mut forged_metadata: Value =
        serde_json::from_slice(&original_metadata).expect("cache metadata json");
    forged_metadata["response_sha256"] = json!(file_sha256(&cache_body));
    forged_metadata["response_bytes"] = json!(8);
    write_json(&cache_metadata, &forged_metadata);
    let forged = Command::new(lia_bin())
        .args([
            "registry-evidence",
            "--ecosystem",
            "crates-io",
            "--package",
            "serde",
            "--version",
            "1.0.0",
            "--cache-dir",
            cache.to_str().expect("cache"),
            "--offline",
            "--expected-response-sha256",
            &response_sha256,
            "--expected-cache-manifest-sha256",
            &cache_manifest_sha256,
        ])
        .output()
        .expect("forged adjacent cache metadata");
    assert!(!forged.status.success());
    assert_eq!(
        output_json(&forged)["reason_code"],
        "REGISTRY_CACHE_MANIFEST_PIN_MISMATCH"
    );

    let slow = temp.path().join("slow-curl");
    write_executable(&slow, "#!/bin/sh\nsleep 5 &\nexit 0\n");
    let slow_sha256 = file_sha256(&slow);
    let timeout_started = std::time::Instant::now();
    let timed_out = Command::new(lia_bin())
        .args([
            "registry-evidence",
            "--ecosystem",
            "crates-io",
            "--package",
            "tokio",
            "--cache-dir",
            cache.to_str().expect("cache"),
            "--http-client",
            slow.to_str().expect("slow curl"),
            "--expected-http-client-sha256",
            &slow_sha256,
            "--timeout-seconds",
            "1",
        ])
        .output()
        .expect("registry timeout");
    assert!(!timed_out.status.success());
    assert!(timeout_started.elapsed().as_secs() < 4);
    assert_eq!(
        output_json(&timed_out)["reason_code"],
        "REGISTRY_FETCH_TIMEOUT"
    );
}
