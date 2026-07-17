use lia_protocol::{RiskTier, Verdict};
use regex::Regex;
use serde_json::json;

use crate::expand::{expand_command_paths, ExpandError};
use crate::filesystem::check_filesystem_scope;
use crate::{make_outcome, GateConfig, GateError, GateOutcome, GatePayload, GateRequest};

pub fn check_shell_irreversible(
    request: &GateRequest,
    config: &GateConfig,
) -> Result<GateOutcome, GateError> {
    let command = request
        .payload
        .command
        .as_deref()
        .ok_or_else(|| GateError::Invalid("shell-irreversible requires command".into()))?;

    let evidence = json!({ "command": command });

    match expand_command_paths(
        command,
        config.home_dir.as_deref(),
        &config.env,
        &config.cwd,
    ) {
        Err(ExpandError::CommandSubstitution(s)) => {
            return Ok(make_outcome(
                "shell-irreversible",
                request.action_id,
                Verdict::Deny,
                "SHELL_COMMAND_SUBSTITUTION",
                RiskTier::Irreversible,
                Some("command substitution refused before scope check".into()),
                Some(s),
                &evidence,
            ));
        }
        Err(e) => return Err(GateError::Expand(e)),
        Ok(expanded) => {
            if is_destructive(command, &expanded.tokens) {
                return Ok(make_outcome(
                    "shell-irreversible",
                    request.action_id,
                    Verdict::Deny,
                    "SHELL_DESTRUCTIVE",
                    RiskTier::Irreversible,
                    Some("destructive/irreversible shell pattern".into()),
                    Some(command.to_string()),
                    &evidence,
                ));
            }

            for path in &expanded.path_tokens {
                let mut fs_req = request.clone();
                fs_req.gate_id = "filesystem-scope".into();
                fs_req.payload = GatePayload {
                    path: Some(path.expanded.clone()),
                    command: None,
                    cwd: Some(config.cwd.to_string_lossy().into_owned()),
                    ..GatePayload::default()
                };
                let fs = check_filesystem_scope(&fs_req, config)?;
                if !matches!(fs.verdict, Verdict::Allow) {
                    return Ok(make_outcome(
                        "shell-irreversible",
                        request.action_id,
                        Verdict::Deny,
                        "SHELL_OUT_OF_SCOPE",
                        RiskTier::Irreversible,
                        Some(format!(
                            "post-expansion path out of scope: {}",
                            path.expanded
                        )),
                        Some(path.expanded.clone()),
                        &json!({
                            "command": command,
                            "expanded_path": path.expanded,
                            "fs_reason": fs.reason_code,
                        }),
                    ));
                }
            }

            Ok(make_outcome(
                "shell-irreversible",
                request.action_id,
                Verdict::Allow,
                "GATE_ALLOW",
                RiskTier::Irreversible,
                Some("shell command passed expansion + scope checks".into()),
                None,
                &json!({
                    "command": command,
                    "tokens": expanded.tokens,
                    "paths": expanded.path_tokens.iter().map(|p| &p.expanded).collect::<Vec<_>>(),
                }),
            ))
        }
    }
}

fn is_destructive(command: &str, tokens: &[String]) -> bool {
    let lower = command.to_ascii_lowercase();
    let joined = tokens
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    let patterns: &[(&str, bool)] = &[
        (r"\brm\b.*\s(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive)", true),
        (r"\bgit\s+clean\b", true),
        (r"\bgit\s+reset\s+--hard\b", true),
        (r"\bgit\s+push\s+.*--force\b", true),
        (r"\bnpm\s+publish\b", true),
        (r"\bpip\s+publish\b", true),
        (r"\bcargo\s+publish\b", true),
        (r"\bdrop\s+(table|database)\b", true),
        (r"\bshred\b", true),
        (r"\bmkfs\b", true),
        (r"\bdd\b.*\bof=", true),
        (r"\bchmod\s+-r\s+777\s+/", true),
        (r"\bchown\s+-r\b.*/", true),
        (r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?", true),
        (r"\btruncate\b.*--size\s*0", true),
        (r"\bfind\b.*-delete\b", true),
        (r"\bunlink\b", true),
        (r"\bri\b.*\.remove\(", true),
    ];

    for (pat, _) in patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(&lower) || re.is_match(&joined) {
                return true;
            }
        }
    }

    if tokens.iter().any(|t| t == "rm") {
        let has_r = tokens.iter().any(|t| t.starts_with('-') && t.contains('r'));
        let has_f = tokens.iter().any(|t| t.starts_with('-') && t.contains('f'));
        if has_r && has_f {
            return true;
        }
    }

    if lower.contains("fs.rm")
        || lower.contains("rmsync")
        || lower.contains("rimraf")
        || lower.contains("rmtree")
        || lower.contains("shutil.rmtree")
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GateConfig;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn destructive_fixture_commands() -> Vec<&'static str> {
        vec![
            "rm -rf /",
            "rm -rf ~/*",
            "rm -rf $HOME/*",
            "rm -rf ../../etc",
            "rm -rf ~/project",
            "git clean -fdx",
            "git reset --hard",
            "git push --force origin main",
            "npm publish",
            "cargo publish",
            "DROP TABLE users;",
            "shred -u secret.key",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            "chmod -R 777 /",
            "find / -name '*.pem' -delete",
            "node -e \"require('fs').rmSync('/tmp/out',{recursive:true,force:true})\"",
            "python -c \"import shutil; shutil.rmtree('/var/lib/db')\"",
            "rm -rf $(pwd)/..",
            "echo `rm -rf /tmp/x`",
        ]
    }

    fn cfg() -> GateConfig {
        GateConfig {
            allowed_roots: vec![PathBuf::from("/work/repo")],
            home_dir: Some(PathBuf::from("/home/agent")),
            cwd: PathBuf::from("/work/repo"),
            protected_paths: vec![PathBuf::from("/work/repo/.lia")],
            registry: BTreeMap::new(),
            env: BTreeMap::from([("HOME".into(), "/home/agent".into())]),
            run_id: None,
        }
    }

    #[test]
    fn twenty_destructive_fixtures_deny() {
        let config = cfg();
        let cmds = destructive_fixture_commands();
        assert!(cmds.len() >= 20);
        for cmd in cmds {
            let req = GateRequest {
                gate_id: "shell-irreversible".into(),
                action_id: Uuid::new_v4(),
                kind: Some(lia_protocol::ActionKind::Shell),
                payload: GatePayload {
                    command: Some(cmd.into()),
                    ..GatePayload::default()
                },
            };
            let out = check_shell_irreversible(&req, &config).expect("eval");
            assert!(
                matches!(out.verdict, Verdict::Deny),
                "expected DENY for {cmd}, got {:?} {}",
                out.verdict,
                out.reason_code
            );
        }
    }
}
