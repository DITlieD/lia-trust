use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use lia_protocol::{RiskTier, Verdict};
use regex::Regex;
use serde_json::json;

use crate::expand::{expand_path_token, normalize_lexical, PathKind};
use crate::filesystem::check_filesystem_scope;
use crate::{make_outcome, GateConfig, GateError, GateOutcome, GatePayload, GateRequest};

const CLEANUP_POLICY_VERSION: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CleanupParse {
    NotCleanup,
    Ambiguous,
    Targets(Vec<String>),
}

pub(super) fn parse_recursive_cleanup(command: &str, tokens: &[String]) -> CleanupParse {
    let recursive_force_shape = has_recursive_force_rm(command, tokens);
    if tokens.first().map(String::as_str) != Some("rm") {
        return if recursive_force_shape {
            CleanupParse::Ambiguous
        } else {
            CleanupParse::NotCleanup
        };
    }

    let mut recursive = false;
    let mut force = false;
    let mut after_double_dash = false;
    let mut saw_target = false;
    let mut targets = Vec::new();

    for token in &tokens[1..] {
        if matches!(token.as_str(), ";" | "|" | "&" | "&&" | "||" | "<" | ">") {
            return if recursive_force_shape {
                CleanupParse::Ambiguous
            } else {
                CleanupParse::NotCleanup
            };
        }
        if !after_double_dash && token == "--" {
            after_double_dash = true;
            continue;
        }
        if !after_double_dash && token.starts_with("--") {
            if saw_target {
                return CleanupParse::Ambiguous;
            }
            match token.as_str() {
                "--recursive" => recursive = true,
                "--force" => force = true,
                "--preserve-root" | "--one-file-system" => {}
                _ => return CleanupParse::Ambiguous,
            }
            continue;
        }
        if !after_double_dash && token.starts_with('-') && token != "-" {
            if saw_target {
                return CleanupParse::Ambiguous;
            }
            for flag in token[1..].chars() {
                match flag {
                    'r' | 'R' => recursive = true,
                    'f' => force = true,
                    _ => return CleanupParse::Ambiguous,
                }
            }
            continue;
        }
        saw_target = true;
        targets.push(token.clone());
    }

    if recursive && force {
        if targets.is_empty() {
            CleanupParse::Ambiguous
        } else {
            CleanupParse::Targets(targets)
        }
    } else {
        CleanupParse::NotCleanup
    }
}

pub(super) fn check_recursive_cleanup(
    request: &GateRequest,
    config: &GateConfig,
    command: &str,
    raw_targets: &[String],
) -> Result<GateOutcome, GateError> {
    let mut normalized_targets = Vec::with_capacity(raw_targets.len());

    for raw in raw_targets {
        if is_home_reference(raw) {
            return Ok(make_outcome(
                request,
                Verdict::Deny,
                "SHELL_DESTRUCTIVE",
                RiskTier::Irreversible,
                Some(
                    "recursive cleanup through a home-relative target is not policy eligible"
                        .into(),
                ),
                Some(raw.clone()),
                &json!({"command": command, "target": raw}),
            ));
        }
        if references_unknown_env(raw, &config.env) {
            return Ok(cleanup_outcome(
                request,
                Verdict::Deny,
                "SHELL_CLEANUP_AMBIGUOUS",
                "cleanup target contains an unknown or malformed environment reference",
                Some(raw.clone()),
                &json!({"command": command, "target": raw}),
            ));
        }
        let expanded =
            expand_path_token(raw, config.home_dir.as_deref(), &config.env, &config.cwd)?;
        let target = normalize_lexical(Path::new(&expanded.expanded));

        if is_hard_cleanup_target(&target, &expanded.kind, config) {
            return Ok(make_outcome(
                request,
                Verdict::Deny,
                "SHELL_DESTRUCTIVE",
                RiskTier::Irreversible,
                Some(
                    "recursive cleanup targets a filesystem, home, or allowed-root boundary".into(),
                ),
                Some(target.to_string_lossy().into_owned()),
                &json!({"command": command, "target": raw, "expanded": target}),
            ));
        }
        if matches!(expanded.kind, PathKind::GlobBase) {
            return Ok(cleanup_outcome(
                request,
                Verdict::Deny,
                "SHELL_CLEANUP_AMBIGUOUS",
                "recursive cleanup globs are not eligible for policy approval",
                Some(raw.clone()),
                &json!({"command": command, "target": raw, "glob_base": target}),
            ));
        }

        let mut fs_request = request.clone();
        fs_request.gate_id = "filesystem-scope".into();
        fs_request.payload = GatePayload {
            path: Some(target.to_string_lossy().into_owned()),
            command: None,
            cwd: Some(config.cwd.to_string_lossy().into_owned()),
            ..GatePayload::default()
        };
        let fs_outcome = check_filesystem_scope(&fs_request, config)?;
        if !matches!(fs_outcome.verdict, Verdict::Allow) {
            let (reason, detail) = if fs_outcome.reason_code == "FS_PROTECTED_PATH" {
                (
                    "SHELL_CLEANUP_PROTECTED_TARGET",
                    "recursive cleanup targets a protected policy/evidence path",
                )
            } else {
                (
                    "SHELL_CLEANUP_OUT_OF_SCOPE",
                    "recursive cleanup resolves outside the declared allowed roots",
                )
            };
            return Ok(cleanup_outcome(
                request,
                Verdict::Deny,
                reason,
                detail,
                Some(target.to_string_lossy().into_owned()),
                &json!({
                    "command": command,
                    "target": raw,
                    "expanded": target,
                    "filesystem_reason": fs_outcome.reason_code,
                }),
            ));
        }

        match path_contains_symlink(&target) {
            Ok(true) => {
                return Ok(cleanup_outcome(
                    request,
                    Verdict::Deny,
                    "SHELL_CLEANUP_AMBIGUOUS",
                    "recursive cleanup target traverses a symbolic link",
                    Some(target.to_string_lossy().into_owned()),
                    &json!({"command": command, "target": raw, "expanded": target}),
                ));
            }
            Ok(false) => {}
            Err(error) => {
                return Ok(cleanup_outcome(
                    request,
                    Verdict::Deny,
                    "SHELL_CLEANUP_AMBIGUOUS",
                    "recursive cleanup target metadata could not be verified",
                    Some(target.to_string_lossy().into_owned()),
                    &json!({
                        "command": command,
                        "target": raw,
                        "error_kind": format!("{:?}", error.kind()),
                    }),
                ));
            }
        }
        normalized_targets.push(target);
    }

    let Some(policy) = config.cleanup_policy.as_ref() else {
        return Ok(cleanup_outcome(
            request,
            Verdict::Deny,
            "SHELL_CLEANUP_APPROVAL_REQUIRED",
            "recursive cleanup needs an explicit target policy",
            normalized_targets
                .first()
                .map(|p| p.to_string_lossy().into_owned()),
            &json!({"command": command, "targets": normalized_targets}),
        ));
    };
    if policy.version != CLEANUP_POLICY_VERSION || policy.approved_targets.is_empty() {
        return Ok(cleanup_outcome(
            request,
            Verdict::Deny,
            "SHELL_CLEANUP_APPROVAL_REQUIRED",
            "cleanup policy version or target set is invalid",
            normalized_targets
                .first()
                .map(|p| p.to_string_lossy().into_owned()),
            &json!({
                "command": command,
                "targets": normalized_targets,
                "policy_version": policy.version,
            }),
        ));
    }

    let approved: Vec<PathBuf> = policy
        .approved_targets
        .iter()
        .filter(|path| path.is_absolute())
        .map(|path| normalize_lexical(path))
        .collect();
    if normalized_targets
        .iter()
        .any(|target| !approved.contains(target))
    {
        return Ok(cleanup_outcome(
            request,
            Verdict::Deny,
            "SHELL_CLEANUP_APPROVAL_REQUIRED",
            "one or more recursive cleanup targets are not explicitly approved",
            normalized_targets
                .first()
                .map(|p| p.to_string_lossy().into_owned()),
            &json!({
                "command": command,
                "targets": normalized_targets,
                "policy_version": policy.version,
                "approved_targets": approved,
            }),
        ));
    }

    Ok(cleanup_outcome(
        request,
        Verdict::Allow,
        "SHELL_CLEANUP_APPROVED",
        "recursive cleanup targets exactly match the explicit in-root policy",
        None,
        &json!({
            "command": command,
            "targets": normalized_targets,
            "policy_version": policy.version,
            "approved_targets": approved,
        }),
    ))
}

pub(super) fn cleanup_outcome(
    request: &GateRequest,
    verdict: Verdict,
    reason_code: &str,
    detail: &str,
    offending: Option<String>,
    evidence: &serde_json::Value,
) -> GateOutcome {
    make_outcome(
        request,
        verdict,
        reason_code,
        RiskTier::Irreversible,
        Some(detail.to_string()),
        offending,
        evidence,
    )
}

fn is_hard_cleanup_target(target: &Path, kind: &PathKind, config: &GateConfig) -> bool {
    let root = Path::new("/");
    if target == root {
        return true;
    }
    if config.home_dir.as_deref().map(normalize_lexical).as_ref()
        == Some(&normalize_lexical(target))
    {
        return true;
    }
    if config
        .allowed_roots
        .iter()
        .map(|path| normalize_lexical(path))
        .any(|allowed| allowed == normalize_lexical(target))
    {
        return true;
    }
    matches!(kind, PathKind::GlobBase)
        && config.home_dir.as_deref().map(normalize_lexical).as_ref()
            == Some(&normalize_lexical(target))
}

fn path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn is_home_reference(raw: &str) -> bool {
    raw == "~"
        || raw.starts_with("~/")
        || raw == "$HOME"
        || raw.starts_with("$HOME/")
        || raw == "${HOME}"
        || raw.starts_with("${HOME}/")
}

fn references_unknown_env(raw: &str, env: &BTreeMap<String, String>) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        if index + 1 >= bytes.len() {
            return true;
        }
        if bytes[index + 1] == b'{' {
            let Some(relative_end) = raw[index + 2..].find('}') else {
                return true;
            };
            let end = index + 2 + relative_end;
            let name = &raw[index + 2..end];
            if name.is_empty() || !env.contains_key(name) {
                return true;
            }
            index = end + 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len()
            && (bytes[end] == b'_' || bytes[end].is_ascii_alphanumeric())
            && !(end == start && bytes[end].is_ascii_digit())
        {
            end += 1;
        }
        if end == start {
            return true;
        }
        if !env.contains_key(&raw[start..end]) {
            return true;
        }
        index = end;
    }
    false
}

pub(super) fn has_recursive_force_rm(command: &str, tokens: &[String]) -> bool {
    let lower = command.to_ascii_lowercase();
    let pattern = r"\brm\b.*\s(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b";
    match Regex::new(pattern) {
        Ok(regex) if regex.is_match(&lower) => return true,
        Ok(_) => {}
        // A classifier construction failure cannot justify allowing a recursive-force shape.
        Err(_) => return true,
    }
    let has_rm = tokens.iter().any(|token| token == "rm") || lower.contains("rm --recursive");
    let has_recursive = tokens.iter().any(|token| {
        token == "--recursive"
            || (token.starts_with('-') && (token.contains('r') || token.contains('R')))
    });
    let has_force = tokens
        .iter()
        .any(|token| token == "--force" || (token.starts_with('-') && token.contains('f')));
    has_rm && has_recursive && has_force
}
