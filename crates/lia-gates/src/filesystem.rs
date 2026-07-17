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

    let expanded = expand_path_token(
        &raw,
        config.home_dir.as_deref(),
        &config.env,
        &cwd,
    )?;
    let target = PathBuf::from(&expanded.expanded);
    let smallest = smallest_affected_path(&target);

    let evidence = json!({
        "raw": raw,
        "expanded": expanded.expanded,
        "smallest": smallest,
    });

    if is_protected(&smallest, &config.protected_paths) {
        return Ok(make_outcome(
            "filesystem-scope",
            request.action_id,
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
                "filesystem-scope",
                request.action_id,
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
            "filesystem-scope",
            request.action_id,
            Verdict::Deny,
            "FS_OUT_OF_SCOPE",
            RiskTier::Irreversible,
            Some("path outside allowed roots".into()),
            Some(smallest),
            &evidence,
        ));
    }

    Ok(make_outcome(
        "filesystem-scope",
        request.action_id,
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

fn is_protected(path: &str, protected: &[PathBuf]) -> bool {
    let p = normalize_lexical(Path::new(path));
    for prot in protected {
        let n = normalize_lexical(prot);
        if p == n || p.starts_with(&n) {
            return true;
        }
        let ps = p.to_string_lossy();
        let ns = n.to_string_lossy();
        if ps.contains("/hooks/")
            || ps.contains("/policy/")
            || ps.ends_with("verifier")
            || ps.contains("gate-manifest")
            || ns.contains("hooks") && ps.contains(ns.as_ref())
        {
            return true;
        }
    }
    let ps = p.to_string_lossy();
    ps.contains("/.lia/")
        || ps.ends_with("policy.frozen.yaml")
        || ps.contains("/hooks/")
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
