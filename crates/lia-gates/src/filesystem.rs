use std::path::{Path, PathBuf};

use lia_protocol::{RiskTier, Verdict};
use serde_json::json;

use crate::expand::{expand_path_token, normalize_lexical};
use crate::{make_outcome, GateConfig, GateError, GateOutcome, GateRequest};

pub fn check_filesystem_scope(
    request: &GateRequest,
    config: &GateConfig,
) -> Result<GateOutcome, GateError> {
    let raw = request
        .payload
        .path
        .clone()
        .or_else(|| request.payload.command.clone())
        .ok_or_else(|| GateError::Invalid("filesystem-scope requires path".into()))?;

    let cwd = request
        .payload
        .cwd
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| config.cwd.clone());

    let expanded = expand_path_token(&raw, config.home_dir.as_deref(), &config.env, &cwd)?;
    let target = PathBuf::from(&expanded.expanded);
    let smallest = smallest_affected_path(&target);

    let evidence = json!({
        "raw": raw,
        "expanded": expanded.expanded,
        "smallest": smallest,
    });

    if is_protected(&smallest, &config.protected_paths) {
        return Ok(make_outcome(
            request,
            Verdict::Deny,
            "FS_PROTECTED_PATH",
            RiskTier::Irreversible,
            Some("in-run edit to hook/policy/verifier path refused".into()),
            Some(smallest.clone()),
            &evidence,
        ));
    }

    if let Some(real) = resolve_existing_symlink_target(&smallest) {
        if !path_inside_any(&real, &config.allowed_roots) {
            return Ok(make_outcome(
                request,
                Verdict::Deny,
                "FS_SYMLINK_ESCAPE",
                RiskTier::Irreversible,
                Some("symlink resolves outside allowed roots".into()),
                Some(real.to_string_lossy().into_owned()),
                &evidence,
            ));
        }
    }

    if !path_inside_any(Path::new(&smallest), &config.allowed_roots) {
        return Ok(make_outcome(
            request,
            Verdict::Deny,
            "FS_OUT_OF_SCOPE",
            RiskTier::Irreversible,
            Some("path outside allowed roots".into()),
            Some(smallest),
            &evidence,
        ));
    }

    Ok(make_outcome(
        request,
        Verdict::Allow,
        "GATE_ALLOW",
        RiskTier::Irreversible,
        Some("path inside allowed roots".into()),
        None,
        &evidence,
    ))
}

fn smallest_affected_path(path: &Path) -> String {
    normalize_lexical(path).to_string_lossy().into_owned()
}

fn path_inside_any(path: &Path, roots: &[PathBuf]) -> bool {
    let norm = normalize_lexical(path);
    for root in roots {
        let root_n = normalize_lexical(root);
        if norm.starts_with(&root_n) {
            return true;
        }
    }
    false
}

/// Protect LIA / harness policy surfaces — not ordinary project paths like
/// git `hooks/post-receive` under a task workspace (those are in-scope work).
fn is_protected(path: &str, protected: &[PathBuf]) -> bool {
    let p = normalize_lexical(Path::new(path));
    let ps = p.to_string_lossy();

    // Explicit configured protected paths (prefix match).
    for prot in protected {
        let n = normalize_lexical(prot);
        if p == n || p.starts_with(&n) {
            return true;
        }
    }

    // LIA / agent-harness control plane only (not generic ".../hooks/...").
    if ps.contains("/.lia/")
        || ps.ends_with("policy.frozen.yaml")
        || ps.contains("gate-manifest")
        || ps.contains("/.claude/hooks/")
        || ps.contains("/.codex/hooks/")
        || ps.contains("/.cursor/hooks/")
        || ps.contains("/lia/policy/")
        || ps.contains("/lia/hooks/")
    {
        return true;
    }

    // "verifier" binary / module at path end under control dirs
    if (ps.contains("/.lia/") || ps.contains("/policy/")) && ps.ends_with("verifier") {
        return true;
    }

    false
}

fn resolve_existing_symlink_target(path: &str) -> Option<PathBuf> {
    let p = Path::new(path);
    if p.symlink_metadata().ok()?.file_type().is_symlink() {
        let target = std::fs::read_link(p).ok()?;
        let parent = p.parent().unwrap_or_else(|| Path::new("/"));
        Some(normalize_lexical(&parent.join(target)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GateConfig, GatePayload, GateRequest};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn cfg(roots: &[&str]) -> GateConfig {
        GateConfig {
            allowed_roots: roots.iter().map(PathBuf::from).collect(),
            home_dir: Some(PathBuf::from("/home/agent")),
            cwd: PathBuf::from(roots[0]),
            protected_paths: vec![PathBuf::from(format!("{}/.lia", roots[0]))],
            registry: BTreeMap::new(),
            env: BTreeMap::new(),
            run_id: None,
            cleanup_policy: None,
            spawn_policy: None,
        }
    }

    fn eval_path(path: &str, config: &GateConfig) -> crate::GateOutcome {
        let req = GateRequest {
            gate_id: "filesystem-scope".into(),
            action_id: Uuid::new_v4(),
            kind: None,
            payload: GatePayload {
                path: Some(path.into()),
                ..GatePayload::default()
            },
        };
        check_filesystem_scope(&req, config).expect("eval")
    }

    #[test]
    fn git_hooks_under_workspace_allow() {
        use lia_protocol::Verdict;
        let config = cfg(&["/app", "/git", "/testbed"]);
        for p in [
            "/app/git/server/hooks/post-receive",
            "/git/server/hooks/post-receive",
            "/testbed/hooks/post-receive",
        ] {
            let out = eval_path(p, &config);
            assert!(
                matches!(out.verdict, Verdict::Allow),
                "expected ALLOW for git hook path {p}, got {:?} {}",
                out.verdict,
                out.reason_code
            );
        }
    }

    #[test]
    fn lia_control_plane_hooks_deny() {
        use lia_protocol::Verdict;
        let config = cfg(&["/app"]);
        for p in [
            "/app/.lia/policy.yaml",
            "/app/.claude/hooks/PreToolUse.sh",
            "/app/.lia/hooks/block.sh",
        ] {
            let out = eval_path(p, &config);
            assert!(
                matches!(out.verdict, Verdict::Deny),
                "expected DENY for control plane {p}, got {:?} {}",
                out.verdict,
                out.reason_code
            );
        }
    }
}
