use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const SECRET_HEX: &str = "9999999999999999999999999999999999999999999999999999999999999999";

fn lia_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_lia")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lia"))
}

fn write_config(path: &Path, root: &Path) {
    fs::write(
        path,
        serde_json::to_vec(&json!({
            "allowed_roots": [root],
            "home_dir": root.join("home"),
            "cwd": root,
            "protected_paths": [],
            "registry": {},
            "env": {"HOME": root.join("home")}
        }))
        .expect("config"),
    )
    .expect("write config");
}

#[test]
fn generic_wrap_kills_timed_out_child_and_preserves_verified_evidence() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    let evidence = temp.path().join("evidence");
    let config = temp.path().join("config.json");
    fs::create_dir_all(&repo).expect("repo");
    fs::write(repo.join("base.txt"), "base\n").expect("base");
    write_config(&config, &repo);

    let started = Instant::now();
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
            "timeout-test",
            "--timeout-seconds",
            "1",
            "--",
            "sleep",
            "10",
        ])
        .output()
        .expect("run wrap");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "child was not killed"
    );
    assert_eq!(
        output.status.code(),
        Some(124),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("report json");
    assert_eq!(report["timed_out"], true);
    assert_eq!(report["reason_code"], "GENERIC_AGENT_TIMEOUT");
    let journal = report["journal_path"].as_str().expect("journal path");
    let verify = Command::new(lia_bin())
        .args(["journal-verify", journal])
        .output()
        .expect("verify");
    assert!(
        verify.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn generic_wrap_fails_closed_when_watcher_loses_the_worktree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    let evidence = temp.path().join("evidence");
    let config = temp.path().join("config.json");
    fs::create_dir_all(&repo).expect("repo");
    fs::write(repo.join("base.txt"), "base\n").expect("base");
    write_config(&config, &repo);

    let started = Instant::now();
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
            "--timeout-seconds",
            "5",
            "--",
            "sh",
            "-c",
            "work=$(pwd); cd /; rm -rf \"$work\"; sleep 2",
        ])
        .output()
        .expect("run wrap");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(
        !output.status.success(),
        "watcher failure was reported as success"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("GENERIC_OBSERVATION_INCOMPLETE"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let journal = evidence.join("journal.db");
    let verify = Command::new(lia_bin())
        .args(["journal-verify", journal.to_str().expect("journal")])
        .output()
        .expect("verify");
    assert!(
        verify.status.success(),
        "failure evidence was not verifiable"
    );
}
