//! V3 CLI entrypoints: doctor fail-closed, spawn gate allow/deny with journal verify.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn lia_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lia"))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_string_pretty(value).unwrap() + "\n").unwrap();
}

#[test]
fn doctor_fails_nonzero_on_bad_fixture_install() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(lia_bin())
        .args([
            "doctor",
            "--lia-home",
            tmp.path().join("missing-lia").to_str().unwrap(),
            "--lia-bin",
            tmp.path().join("no-bin").to_str().unwrap(),
            "--claude-home",
            tmp.path().join("claude").to_str().unwrap(),
            "--codex-home",
            tmp.path().join("codex").to_str().unwrap(),
            "--gemini-home",
            tmp.path().join("gemini").to_str().unwrap(),
            "--cursor-home",
            tmp.path().join("cursor").to_str().unwrap(),
        ])
        .output()
        .expect("run doctor");
    assert_ne!(
        out.status.code(),
        Some(0),
        "doctor must fail bad install; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("FAILED")
            || text.contains("binary")
            || text.contains("manifest")
            || text.contains("missing"),
        "human-readable failure expected: {text}"
    );
}

#[test]
fn doctor_ok_after_fixture_install() {
    let tmp = tempfile::tempdir().unwrap();
    let lia_home = tmp.path().join("lia-home");
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let install = Command::new(lia_bin())
        .args([
            "install",
            "--lia-home",
            lia_home.to_str().unwrap(),
            "--lia-bin",
            lia_bin().to_str().unwrap(),
            "--claude-home",
            tmp.path().join("claude").to_str().unwrap(),
            "--codex-home",
            tmp.path().join("codex").to_str().unwrap(),
            "--gemini-home",
            tmp.path().join("gemini").to_str().unwrap(),
            "--cursor-home",
            tmp.path().join("cursor").to_str().unwrap(),
            "--allowed-root",
            home.to_str().unwrap(),
        ])
        .output()
        .expect("install");
    assert!(
        install.status.success(),
        "install: {}",
        String::from_utf8_lossy(&install.stderr)
    );

    let doctor = Command::new(lia_bin())
        .args([
            "doctor",
            "--lia-home",
            lia_home.to_str().unwrap(),
            "--lia-bin",
            lia_bin().to_str().unwrap(),
            "--claude-home",
            tmp.path().join("claude").to_str().unwrap(),
            "--codex-home",
            tmp.path().join("codex").to_str().unwrap(),
            "--gemini-home",
            tmp.path().join("gemini").to_str().unwrap(),
            "--cursor-home",
            tmp.path().join("cursor").to_str().unwrap(),
        ])
        .env("HOME", &home)
        .output()
        .expect("doctor");
    assert!(
        doctor.status.success(),
        "doctor should pass: stdout={} stderr={}",
        String::from_utf8_lossy(&doctor.stdout),
        String::from_utf8_lossy(&doctor.stderr)
    );
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(stdout.contains("mediated_tools") || stdout.contains("Bash"));
}

#[test]
fn spawn_hook_allow_and_deny_with_signed_journal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let journal = tmp.path().join("j.db");
    let config = tmp.path().join("config.json");
    let secret = lia_journal::random_secret_hex().unwrap();

    write_json(
        &config,
        &serde_json::json!({
            "allowed_roots": [root.to_string_lossy()],
            "home_dir": root.to_string_lossy(),
            "cwd": root.to_string_lossy(),
            "protected_paths": [],
            "registry": {},
            "env": {},
            "spawn_policy": { "allow": true }
        }),
    );

    let allow_stdin = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Task",
        "tool_input": {"prompt": "explore", "subagent_type": "explore"},
        "session_id": "s-child",
        "parent_session_id": "s-parent",
        "cwd": root.to_string_lossy(),
    })
    .to_string();

    let allow = Command::new(lia_bin())
        .args([
            "hook",
            "--adapter",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
            "--journal",
            journal.to_str().unwrap(),
            "--secret-key-hex",
            &secret,
            "--key-id",
            "v3-test",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn allow");
    {
        use std::io::Write;
        allow.stdin.as_ref().unwrap().write_all(allow_stdin.as_bytes()).unwrap();
    }
    let allow_out = allow.wait_with_output().unwrap();
    assert!(
        allow_out.status.success(),
        "spawn allow: stdout={} stderr={}",
        String::from_utf8_lossy(&allow_out.stdout),
        String::from_utf8_lossy(&allow_out.stderr)
    );

    // Deny under policy
    write_json(
        &config,
        &serde_json::json!({
            "allowed_roots": [root.to_string_lossy()],
            "home_dir": root.to_string_lossy(),
            "cwd": root.to_string_lossy(),
            "protected_paths": [],
            "registry": {},
            "env": {},
            "spawn_policy": { "allow": false }
        }),
    );
    let deny_stdin = serde_json::json!({
        "toolName": "spawn_subagent",
        "toolInput": {"prompt": "nope", "subagent_type": "general-purpose"},
        "hookEventName": "pre_tool_use",
        "cwd": root.to_string_lossy(),
    })
    .to_string();
    let mut deny = Command::new(lia_bin())
        .args([
            "hook",
            "--adapter",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
            "--journal",
            journal.to_str().unwrap(),
            "--secret-key-hex",
            &secret,
            "--key-id",
            "v3-test",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn deny");
    {
        use std::io::Write;
        deny.stdin
            .as_mut()
            .unwrap()
            .write_all(deny_stdin.as_bytes())
            .unwrap();
    }
    let deny_out = deny.wait_with_output().unwrap();
    assert_ne!(
        deny_out.status.code(),
        Some(0),
        "deny must block; stdout={}",
        String::from_utf8_lossy(&deny_out.stdout)
    );
    let err = String::from_utf8_lossy(&deny_out.stderr);
    assert!(
        err.contains("SPAWN_DENIED") || err.contains("spawn") || err.contains("denied"),
        "stderr should mention spawn deny: {err}"
    );

    // Offline journal verify
    let verify = Command::new(lia_bin())
        .args(["journal-verify", journal.to_str().unwrap()])
        .output()
        .expect("verify");
    assert!(
        verify.status.success(),
        "journal-verify: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn grok_envelope_home_allow_oos_deny_via_hook() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join("proj")).unwrap();
    let config = tmp.path().join("config.json");
    write_json(
        &config,
        &serde_json::json!({
            "allowed_roots": [home.to_string_lossy()],
            "home_dir": home.to_string_lossy(),
            "cwd": home.to_string_lossy(),
            "protected_paths": [],
            "registry": {},
            "env": {},
        }),
    );
    let in_scope = serde_json::json!({
        "toolName": "run_terminal_command",
        "toolInput": {"command": format!("ls {}", home.display())},
        "hookEventName": "pre_tool_use",
        "cwd": home.to_string_lossy(),
    })
    .to_string();
    let allow = Command::new(lia_bin())
        .args([
            "hook",
            "--adapter",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        allow.stdin.as_ref().unwrap().write_all(in_scope.as_bytes()).unwrap();
    }
    let allow_out = allow.wait_with_output().unwrap();
    assert!(
        allow_out.status.success(),
        "Grok in-scope allow failed: {}",
        String::from_utf8_lossy(&allow_out.stderr)
    );

    let oos = serde_json::json!({
        "toolName": "read_file",
        "toolInput": {"target_file": "/etc/passwd"},
        "hookEventName": "pre_tool_use",
        "cwd": home.to_string_lossy(),
    })
    .to_string();
    let deny = Command::new(lia_bin())
        .args([
            "hook",
            "--adapter",
            "claude-code",
            "--config",
            config.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        deny.stdin.as_ref().unwrap().write_all(oos.as_bytes()).unwrap();
    }
    let deny_out = deny.wait_with_output().unwrap();
    assert_ne!(deny_out.status.code(), Some(0), "OOS must deny");
}
