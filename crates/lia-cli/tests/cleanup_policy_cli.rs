use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

const SECRET_HEX: &str = "7777777777777777777777777777777777777777777777777777777777777777";

fn lia_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_lia")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lia"))
}

fn config(root: &Path, approved_targets: Option<&[PathBuf]>) -> Value {
    let mut value = json!({
        "allowed_roots": [root],
        "home_dir": root.join("home"),
        "cwd": root,
        "protected_paths": [root.join(".lia")],
        "registry": {},
        "env": {
            "HOME": root.join("home"),
            "BUILD_DIR": root.join("target")
        },
        "run_id": "11111111-1111-4111-8111-111111111111"
    });
    if let Some(targets) = approved_targets {
        value["cleanup_policy"] = json!({
            "version": 1,
            "approved_targets": targets,
        });
    }
    value
}

fn run_gate(tmp: &Path, name: &str, cfg: &Value, command: &str) -> (Output, PathBuf) {
    let case = tmp.join(name);
    fs::create_dir_all(&case).expect("create case");
    let cfg_path = case.join("config.json");
    let req_path = case.join("request.json");
    let journal = case.join("journal.db");
    fs::write(
        &cfg_path,
        serde_json::to_vec_pretty(cfg).expect("config json"),
    )
    .expect("write config");
    fs::write(
        &req_path,
        serde_json::to_vec_pretty(&json!({
            "gate_id": "shell-irreversible",
            "action_id": "22222222-2222-4222-8222-222222222222",
            "kind": "shell",
            "payload": {"command": command}
        }))
        .expect("request json"),
    )
    .expect("write request");
    let output = Command::new(lia_bin())
        .args([
            "gate",
            "--config",
            cfg_path.to_str().expect("config path"),
            "--request",
            req_path.to_str().expect("request path"),
            "--journal",
            journal.to_str().expect("journal path"),
            "--secret-key-hex",
            SECRET_HEX,
            "--key-id",
            "cleanup-policy-test",
        ])
        .output()
        .expect("run lia gate");
    (output, journal)
}

fn outcome(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "gate did not emit JSON: {error}; status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_case(output: &Output, expected_exit: i32, verdict: &str, reason: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = outcome(output);
    assert_eq!(value["outcomes"][0]["verdict"], verdict);
    assert_eq!(value["outcomes"][0]["reason_code"], reason);
    assert!(
        value["journal_receipts"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "missing signed receipt: {value}"
    );
}

#[test]
fn approved_in_root_cleanup_reaches_cli_journal_and_offline_verifier() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    let target = root.join("target");
    fs::create_dir_all(&target).expect("target");
    let (output, journal) = run_gate(
        temp.path(),
        "approved",
        &config(&root, Some(std::slice::from_ref(&target))),
        "rm -rf ./target",
    );
    assert_case(&output, 0, "allow", "SHELL_CLEANUP_APPROVED");

    let verified = Command::new(lia_bin())
        .args(["journal-verify", journal.to_str().expect("journal path")])
        .output()
        .expect("run separate verifier process");
    assert!(
        verified.status.success(),
        "journal verification failed: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn cleanup_policy_adversarial_matrix_fails_closed_with_stable_reasons() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    let target = root.join("target");
    let cache = root.join("cache");
    let protected = root.join(".lia/cache");
    let home = root.join("home");
    for path in [&target, &cache, &protected, &home] {
        fs::create_dir_all(path).expect("fixture dir");
    }
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).expect("outside");

    let cases = vec![
        (
            "missing-policy",
            config(&root, None),
            "rm -rf ./target".to_string(),
            "SHELL_CLEANUP_APPROVAL_REQUIRED",
        ),
        (
            "absolute-root",
            config(&root, Some(std::slice::from_ref(&PathBuf::from("/")))),
            "rm -rf /".to_string(),
            "SHELL_DESTRUCTIVE",
        ),
        (
            "home-wide",
            config(&root, Some(std::slice::from_ref(&home))),
            "rm -rf $HOME/*".to_string(),
            "SHELL_DESTRUCTIVE",
        ),
        (
            "outside-root",
            config(&root, Some(std::slice::from_ref(&outside))),
            format!("rm -rf {}", outside.display()),
            "SHELL_CLEANUP_OUT_OF_SCOPE",
        ),
        (
            "parent-escape",
            config(&root, Some(std::slice::from_ref(&outside))),
            "rm -rf ../outside".to_string(),
            "SHELL_CLEANUP_OUT_OF_SCOPE",
        ),
        (
            "protected",
            config(&root, Some(std::slice::from_ref(&protected))),
            "rm -rf ./.lia/cache".to_string(),
            "SHELL_CLEANUP_PROTECTED_TARGET",
        ),
        (
            "glob",
            config(&root, Some(std::slice::from_ref(&target))),
            "rm -rf ./target/*".to_string(),
            "SHELL_CLEANUP_AMBIGUOUS",
        ),
        (
            "mixed-targets",
            config(&root, Some(std::slice::from_ref(&target))),
            "rm -rf ./target ./cache".to_string(),
            "SHELL_CLEANUP_APPROVAL_REQUIRED",
        ),
        (
            "compound-shell",
            config(&root, Some(std::slice::from_ref(&target))),
            "rm -rf ./target && echo done".to_string(),
            "SHELL_CLEANUP_AMBIGUOUS",
        ),
        (
            "nested-shell",
            config(&root, Some(std::slice::from_ref(&target))),
            "sh -c 'rm -rf ./target'".to_string(),
            "SHELL_CLEANUP_AMBIGUOUS",
        ),
        (
            "missing-env",
            config(&root, Some(std::slice::from_ref(&target))),
            "rm -rf $MISSING_BUILD_DIR".to_string(),
            "SHELL_CLEANUP_AMBIGUOUS",
        ),
        (
            "command-substitution",
            config(&root, Some(std::slice::from_ref(&target))),
            "rm -rf $(pwd)/target".to_string(),
            "SHELL_COMMAND_SUBSTITUTION",
        ),
    ];

    for (name, cfg, command, reason) in cases {
        let (output, _) = run_gate(temp.path(), name, &cfg, &command);
        assert_case(&output, 2, "deny", reason);
    }
}

#[cfg(unix)]
#[test]
fn cleanup_policy_rejects_symlink_target_even_when_lexically_approved() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    let outside = temp.path().join("outside");
    let link = root.join("target");
    fs::create_dir_all(&root).expect("root");
    fs::create_dir_all(&outside).expect("outside");
    symlink(&outside, &link).expect("symlink");
    let (output, _) = run_gate(
        temp.path(),
        "symlink",
        &config(&root, Some(std::slice::from_ref(&link))),
        "rm -rf ./target",
    );
    assert_case(&output, 2, "deny", "SHELL_CLEANUP_OUT_OF_SCOPE");
}

#[test]
fn cleanup_normalization_matrix_has_one_policy_owned_outcome() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    let target = root.join("target");
    fs::create_dir_all(&target).expect("target");
    let cfg = config(&root, Some(std::slice::from_ref(&target)));

    for (index, command) in [
        "rm -rf target",
        "rm -fr ./target",
        "rm --recursive --force ./a/../target",
        "rm -r -f ./target",
        "rm -f -r ./target",
        "rm -rf $BUILD_DIR",
    ]
    .into_iter()
    .enumerate()
    {
        let (output, _) = run_gate(temp.path(), &format!("normalized-{index}"), &cfg, command);
        assert_case(&output, 0, "allow", "SHELL_CLEANUP_APPROVED");
    }
}
