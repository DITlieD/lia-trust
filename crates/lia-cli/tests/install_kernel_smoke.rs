//! Integration: `lia install` CLI drives pure merge + HARD deny via installed wrappers.
//! Uses fixture homes only (never live ~/.claude / ~/.codex).
//! Codex path: Content-Length framed initialize → tools/list → tools/call HARD deny
//! against the installed `codex-mcp.sh` (real MCP client session shape).

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

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

    // Point gate config at fixture repo for OOS deny.
    let cfg = serde_json::json!({
        "allowed_roots": [repo],
        "home_dir": "/home/agent",
        "cwd": repo,
        "protected_paths": [],
        "registry": {},
        "env": {}
    });
    fs::write(lia_home.join("config.json"), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

    let wrap = lia_home.join("bin/codex-mcp.sh");
    assert!(wrap.exists(), "installed codex wrapper missing");
    drive_installed_codex_mcp_session(&wrap);

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

fn frame_msg(v: &serde_json::Value) -> Vec<u8> {
    let body = serde_json::to_vec(v).unwrap();
    let mut out = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(&body);
    out
}

fn read_framed(stdout: &mut impl Read) -> serde_json::Value {
    let mut headers = String::new();
    loop {
        let mut buf = [0u8; 1];
        let n = stdout.read(&mut buf).expect("read header byte");
        assert!(n == 1, "EOF mid MCP headers");
        headers.push(buf[0] as char);
        if headers.ends_with("\r\n\r\n") {
            break;
        }
        // also accept bare \n\n
        if headers.ends_with("\n\n") && !headers.ends_with("\r\n\n") {
            break;
        }
        assert!(headers.len() < 4096, "headers too long");
    }
    let mut content_length = None;
    for line in headers.lines() {
        if let Some(rest) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            content_length = Some(rest.trim().parse::<usize>().unwrap());
        }
    }
    let len = content_length.expect("Content-Length");
    let mut body = vec![0u8; len];
    stdout.read_exact(&mut body).expect("read body");
    serde_json::from_slice(&body).expect("json body")
}

fn drive_installed_codex_mcp_session(wrap: &std::path::Path) {
    let mut child = Command::new(wrap)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn codex-mcp.sh");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    stdin
        .write_all(&frame_msg(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "install_kernel_smoke", "version": "0"}
            }
        })))
        .unwrap();
    stdin.flush().unwrap();
    let init = read_framed(&mut stdout);
    assert!(init.get("error").is_none(), "initialize failed: {init}");
    assert_eq!(
        init.pointer("/result/serverInfo/name").and_then(|v| v.as_str()),
        Some("lia-trust")
    );

    stdin
        .write_all(&frame_msg(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })))
        .unwrap();
    stdin.flush().unwrap();

    stdin
        .write_all(&frame_msg(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        })))
        .unwrap();
    stdin.flush().unwrap();
    let list = read_framed(&mut stdout);
    assert!(
        list.pointer("/result/tools")
            .and_then(|t| t.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "tools/list empty: {list}"
    );

    stdin
        .write_all(&frame_msg(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "delete_file",
                "arguments": {"path": "/tmp/outside-lia-cli-install-smoke"}
            }
        })))
        .unwrap();
    stdin.flush().unwrap();
    let deny = read_framed(&mut stdout);
    assert_eq!(
        deny.pointer("/result/isError").and_then(|v| v.as_bool()),
        Some(true),
        "expected HARD deny: {deny}"
    );
    assert_eq!(
        deny.pointer("/result/lia/allowed").and_then(|v| v.as_bool()),
        Some(false)
    );

    drop(stdin);
    let _ = child.wait_timeout_or_kill(Duration::from_secs(3));
}

trait WaitTimeout {
    fn wait_timeout_or_kill(&mut self, d: Duration) -> std::io::Result<std::process::ExitStatus>;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout_or_kill(&mut self, d: Duration) -> std::io::Result<std::process::ExitStatus> {
        let start = std::time::Instant::now();
        loop {
            match self.try_wait()? {
                Some(st) => return Ok(st),
                None if start.elapsed() > d => {
                    let _ = self.kill();
                    return self.wait();
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}
