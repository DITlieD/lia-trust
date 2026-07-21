#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use lia_journal::Journal;
use lia_protocol::Event;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SECRET_HEX: &str = "9999999999999999999999999999999999999999999999999999999999999999";

fn lia_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_lia")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lia"))
}

fn unshare_bin() -> PathBuf {
    PathBuf::from("/usr/bin/unshare")
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read helper");
    hex::encode(Sha256::digest(bytes))
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
            "run_id": "55555555-5555-4555-8555-555555555555"
        }))
        .expect("config json"),
    )
    .expect("write config");
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    let evidence = temp.path().join("evidence");
    let config = temp.path().join("config.json");
    fs::create_dir_all(&repo).expect("repo");
    fs::write(repo.join("base.txt"), "base\n").expect("base");
    write_config(&config, &repo);
    (temp, repo, evidence, config)
}

fn base_wrap(repo: &Path, evidence: &Path, config: &Path) -> Command {
    let mut command = Command::new(lia_bin());
    command.args([
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
        "m5-confinement-test",
        "--no-watch",
        "--linux-confine",
        "--unshare-bin",
        unshare_bin().to_str().expect("unshare path"),
    ]);
    command
}

fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}; status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_signed_confinement_evidence(report: &Value) {
    let journal = report["journal_path"].as_str().expect("journal path");
    let verify = Command::new(lia_bin())
        .args(["journal-verify", journal])
        .output()
        .expect("verify journal");
    assert!(
        verify.status.success(),
        "verify stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let contract: Value = serde_json::from_slice(
        &fs::read(
            report["process_contract_path"]
                .as_str()
                .expect("contract path"),
        )
        .expect("contract"),
    )
    .expect("contract json");
    assert!(contract["required_evidence"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| {
            row["id"] == "linux-confinement" && row["kind"] == "generic-linux-confinement"
        })));
    let execution: Value = serde_json::from_slice(
        &fs::read(
            report["process_execution_path"]
                .as_str()
                .expect("execution path"),
        )
        .expect("execution"),
    )
    .expect("execution json");
    assert!(execution["evidence"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| {
            row["requirement_id"] == "linux-confinement"
                && row["kind"] == "generic-linux-confinement"
        })));
    let report_path = report["confinement_report_path"]
        .as_str()
        .expect("confinement report path");
    let report_bytes = fs::read(report_path).expect("persisted confinement report");
    let persisted: Value = serde_json::from_slice(&report_bytes).expect("confinement report json");
    assert_eq!(persisted, report["confinement"]);
    let digest = hex::encode(Sha256::digest(&report_bytes));
    assert!(execution["evidence"].as_array().is_some_and(|rows| rows
        .iter()
        .any(|row| { row["requirement_id"] == "linux-confinement" && row["sha256"] == digest })));
    let rows = Journal::open_readonly(journal)
        .expect("open journal")
        .load_rows()
        .expect("load journal rows");
    assert!(rows.iter().any(|row| matches!(
        &row.event,
        Event::ConfinementApplied(event) if event.attestation_sha256 == digest
    )));
    assert!(rows.iter().any(|row| matches!(
        &row.event,
        Event::EvidenceCaptured(event)
            if event.kind == "generic-linux-confinement"
                && event.sha256 == digest
                && event.path.as_deref() == Some(report_path)
    )));
}

fn unavailable(output: &Output) -> bool {
    !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("CONFINEMENT_UNAVAILABLE")
}

#[test]
fn linux_confinement_requires_an_exact_helper_digest() {
    let (_temp, repo, evidence, config) = fixture();
    let output = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &"0".repeat(64),
            "--",
            "/bin/sh",
            "-c",
            "printf escaped > should-not-run",
        ])
        .output()
        .expect("run wrap");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CONFINEMENT_HELPER_DIGEST_MISMATCH"));
    assert!(!repo.join("should-not-run").exists());
}

#[test]
fn linux_backend_proves_namespace_and_egress_or_fails_closed_as_unavailable() {
    let (_temp, repo, evidence, config) = fixture();
    let host_net = fs::read_link("/proc/self/ns/net")
        .expect("host net namespace")
        .display()
        .to_string();
    let script = format!(
        "test \"$(readlink /proc/self/ns/net)\" != '{}' && \
         python3 -c 'import socket; s=socket.socket(); s.settimeout(1);\ntry: s.connect((\"1.1.1.1\",443)); raise SystemExit(9)\nexcept OSError: pass' && \
         if chmod 000 '{1}/base.txt'; then exit 10; fi; \
         printf confined > confined.txt",
        host_net,
        repo.display()
    );
    let output = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &sha256_file(&unshare_bin()),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .output()
        .expect("run wrap");
    if unavailable(&output) {
        assert!(!repo.join("confined.txt").exists());
        return;
    }
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json_output(&output);
    assert_eq!(
        report["confinement"]["backend"],
        "linux-namespaces-landlock"
    );
    assert_eq!(report["confinement"]["ip_egress_blocked"], true);
    assert_eq!(report["confinement"]["host_path_writes_blocked"], true);
    assert_eq!(
        report["confinement"]["evidence_artifacts_write_blocked"],
        true
    );
    assert_eq!(
        report["confinement"]["host_filesystem_reads_confined"],
        false
    );
    assert!(report["confinement"]["landlock_abi"].as_u64().unwrap() >= 3);
    let worktree = PathBuf::from(report["worktree"].as_str().expect("worktree"));
    assert_eq!(
        fs::read_to_string(worktree.join("confined.txt")).unwrap(),
        "confined"
    );
    assert_signed_confinement_evidence(&report);

    let first_report_path = PathBuf::from(
        report["confinement_report_path"]
            .as_str()
            .expect("first report path"),
    );
    let first_report_bytes = fs::read(&first_report_path).expect("first report bytes");
    let second = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &sha256_file(&unshare_bin()),
            "--",
            "/bin/true",
        ])
        .output()
        .expect("second wrap in same evidence directory");
    assert!(
        second.status.success(),
        "second stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_report = json_output(&second);
    assert_ne!(
        second_report["confinement_report_path"].as_str(),
        report["confinement_report_path"].as_str()
    );
    assert_eq!(
        fs::read(&first_report_path).expect("first report after second run"),
        first_report_bytes
    );
    assert_signed_confinement_evidence(&second_report);
}

#[test]
fn evidence_is_read_only_and_scoped_credential_uses_an_expiring_fd_broker() {
    let (temp, repo, evidence, config) = fixture();
    let source = temp.path().join("api-token");
    fs::write(&source, "super-secret-token").expect("credential");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("chmod credential");
    let lia = lia_bin();
    let script = format!(
        "if printf tamper > '{0}/child-write'; then exit 41; fi; \
         if test -s '{1}'; then exit 42; fi; \
         if env | grep -q 'super-secret-token'; then exit 43; fi; \
         if test -n \"${{CARGO_HOME+x}}\" -o -n \"${{RUSTUP_HOME+x}}\"; then exit 45; fi; \
         '{2}' credential-read --name api > credential.bin; \
         if '{2}' credential-read --name api > second-credential.bin; then exit 44; fi; \
         sha256sum credential.bin | cut -d' ' -f1 > credential.sha256",
        evidence.display(),
        source.display(),
        lia.display()
    );
    let output = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &sha256_file(&unshare_bin()),
            "--credential",
            &format!("api={}", source.display()),
            "--credential-ttl-seconds",
            "5",
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .output()
        .expect("run wrap");
    if unavailable(&output) {
        assert!(!evidence.join("child-write").exists());
        return;
    }
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json_output(&output);
    let worktree = PathBuf::from(report["worktree"].as_str().expect("worktree"));
    assert_eq!(
        fs::read_to_string(worktree.join("credential.sha256"))
            .unwrap()
            .trim(),
        hex::encode(Sha256::digest(b"super-secret-token"))
    );
    assert!(!evidence.join("child-write").exists());
    assert_eq!(report["confinement"]["credential_names"], json!(["api"]));
    assert_eq!(
        fs::metadata(worktree.join("second-credential.bin"))
            .expect("second redirection")
            .len(),
        0
    );
    assert_signed_confinement_evidence(&report);
}

#[test]
fn credential_sources_with_broad_permissions_fail_before_spawn() {
    let (temp, repo, evidence, config) = fixture();
    let source = temp.path().join("api-token");
    fs::write(&source, "secret").expect("credential");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).expect("chmod credential");
    let output = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &sha256_file(&unshare_bin()),
            "--credential",
            &format!("api={}", source.display()),
            "--credential-ttl-seconds",
            "1",
            "--",
            "/bin/sh",
            "-c",
            "printf escaped > should-not-run",
        ])
        .output()
        .expect("run wrap");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CREDENTIAL_SOURCE_PERMISSIONS"));
    assert!(!repo.join("should-not-run").exists());
}

#[test]
fn duplicate_normalized_credential_names_fail_before_spawn() {
    let (temp, repo, evidence, config) = fixture();
    let first = temp.path().join("first-token");
    let second = temp.path().join("second-token");
    fs::write(&first, "first").expect("first credential");
    fs::write(&second, "second").expect("second credential");
    fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).expect("chmod first");
    fs::set_permissions(&second, fs::Permissions::from_mode(0o600)).expect("chmod second");
    let output = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &sha256_file(&unshare_bin()),
            "--credential",
            &format!("api={}", first.display()),
            "--credential",
            &format!("API={}", second.display()),
            "--",
            "/bin/sh",
            "-c",
            "printf escaped > should-not-run",
        ])
        .output()
        .expect("run wrap");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CREDENTIAL_DUPLICATE"));
    assert!(!repo.join("should-not-run").exists());
}

#[test]
fn credential_broker_refuses_delivery_after_ttl() {
    let (temp, repo, evidence, config) = fixture();
    let source = temp.path().join("api-token");
    fs::write(&source, "expired-secret").expect("credential");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("chmod credential");
    let lia = lia_bin();
    let script = format!(
        "sleep 2; '{0}' credential-read --name api > credential.tmp && mv credential.tmp should-not-exist",
        lia.display()
    );
    let output = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &sha256_file(&unshare_bin()),
            "--credential",
            &format!("api={}", source.display()),
            "--credential-ttl-seconds",
            "1",
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .output()
        .expect("run wrap");
    if unavailable(&output) {
        return;
    }
    assert!(
        !output.status.success(),
        "expired credential unexpectedly issued"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("CREDENTIAL_EXPIRED_OR_USED"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json_output(&output);
    assert_eq!(report["process_validation"]["followed"], true);
    let worktree = PathBuf::from(report["worktree"].as_str().expect("worktree"));
    assert!(!worktree.join("should-not-exist").exists());
    assert_eq!(
        fs::metadata(worktree.join("credential.tmp"))
            .expect("empty redirection target")
            .len(),
        0
    );
}

#[test]
fn malformed_credential_request_terminalizes_as_an_honest_stop() {
    let (temp, repo, evidence, config) = fixture();
    let source = temp.path().join("api-token");
    fs::write(&source, "secret").expect("credential");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("chmod credential");
    let script = "python3 -c 'import os,socket; s=socket.socket(fileno=int(os.environ[\"LIA_CREDENTIAL_FD_API\"])); s.sendall(b\"GET wrong\\n\"); s.close()'";
    let output = base_wrap(&repo, &evidence, &config)
        .args([
            "--expected-unshare-sha256",
            &sha256_file(&unshare_bin()),
            "--credential",
            &format!("api={}", source.display()),
            "--credential-ttl-seconds",
            "5",
            "--",
            "/bin/sh",
            "-c",
            script,
        ])
        .output()
        .expect("run malformed broker request");
    if unavailable(&output) {
        return;
    }
    assert!(!output.status.success());
    let report = json_output(&output);
    assert_eq!(report["agent_exit"], 0);
    assert_eq!(report["trust_boundary_failed"], true);
    assert_eq!(report["reason_code"], "CREDENTIAL_BROKER_FAILED");
    assert_eq!(report["process_validation"]["followed"], true);
    let execution: Value = serde_json::from_slice(
        &fs::read(
            report["process_execution_path"]
                .as_str()
                .expect("execution path"),
        )
        .expect("execution"),
    )
    .expect("execution json");
    assert_eq!(
        execution["outcome"]["condition_code"],
        "credential-broker-failed"
    );
    assert_signed_confinement_evidence(&report);
}
