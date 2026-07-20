//! Integration: `lia install` CLI drives pure merge + HARD deny via installed wrappers.
//! Uses fixture homes only (never live ~/.claude / ~/.codex).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn lia_bin() -> PathBuf {
    // Prefer release if present; fall back to CARGO_BIN_EXE
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_lia") {
        return PathBuf::from(p);
    }
    let mut candidates = vec![
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/lia"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lia"),
    ];
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        candidates.insert(0, PathBuf::from(&td).join("release/lia"));
        candidates.insert(1, PathBuf::from(&td).join("debug/lia"));
    }
    candidates
        .into_iter()
        .find(|p| p.exists())
        .expect("lia binary built")
}

#[test]
fn install_cli_fixture_wires_and_uninstalls() {
    let tmp = tempfile::tempdir().expect("tmp");
    let lia = lia_bin();
    let lia_home = tmp.path().join("lia-home");
    let claude = tmp.path().join("claude");
    let codex = tmp.path().join("codex");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();

    let out = Command::new(&lia)
        .args([
            "install",
            "--lia-home",
            lia_home.to_str().unwrap(),
            "--lia-bin",
            lia.to_str().unwrap(),
            "--claude-home",
            claude.to_str().unwrap(),
            "--codex-home",
            codex.to_str().unwrap(),
            "--allowed-root",
            repo.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("install");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["claude_hook_installed"], true);
    assert_eq!(report["codex_mcp_installed"], true);
    assert!(report["kernel"]["assurance"]
        .as_str()
        .unwrap_or("")
        .contains("GATE"));
    assert!(!report["kernel"]["assurance"]
        .as_str()
        .unwrap_or("")
        .contains("complete-mediation")
        || report["kernel"]["assurance"]
            .as_str()
            .unwrap_or("")
            .contains("never CONFINE"));

    let settings = fs::read_to_string(claude.join("settings.json")).unwrap();
    assert!(settings.contains("lia-trust-kernel") || settings.contains("claude-pretool"));
    let toml = fs::read_to_string(codex.join("config.toml")).unwrap();
    assert!(toml.contains("[mcp_servers.lia-trust]"));

    // refuse live without flag (only if default homes would be live — smoke dry-run)
    let dry = Command::new(&lia)
        .args(["install", "--dry-run", "--json"])
        .output()
        .expect("dry");
    assert!(dry.status.success());

    let un = Command::new(&lia)
        .args([
            "uninstall",
            "--lia-home",
            lia_home.to_str().unwrap(),
            "--claude-home",
            claude.to_str().unwrap(),
            "--codex-home",
            codex.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("uninstall");
    assert!(un.status.success(), "stderr={}", String::from_utf8_lossy(&un.stderr));
    let urep: serde_json::Value = serde_json::from_slice(&un.stdout).unwrap();
    assert_eq!(urep["claude_hook_installed"], false);
    assert_eq!(urep["codex_mcp_installed"], false);
}
