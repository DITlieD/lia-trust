use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::BenchError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsLintFinding {
    pub path: String,
    pub line: usize,
    pub excerpt: String,
    pub reason: String,
}

pub fn claims_lint(root: &Path) -> Result<Vec<ClaimsLintFinding>, BenchError> {
    let mut findings = Vec::new();
    if !root.exists() {
        return Ok(findings);
    }
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !(matches!(ext, "md" | "txt" | "json" | "tsv") || name == "CLAIMS") {
            continue;
        }
        let text = fs::read_to_string(path)?;
        if ext == "json" {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                lint_json_value(path, &v, &mut findings);
                continue;
            }
        }
        for (idx, line) in text.lines().enumerate() {
            if line_has_untagged_rate_claim(line) {
                findings.push(ClaimsLintFinding {
                    path: path.display().to_string(),
                    line: idx + 1,
                    excerpt: line.chars().take(160).collect(),
                    reason: "numeric claim lacks [MEASURED]/[EXTERNAL] tag".into(),
                });
            }
        }
    }
    Ok(findings)
}

fn lint_json_value(path: &Path, v: &serde_json::Value, findings: &mut Vec<ClaimsLintFinding>) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(claims) = map.get("claims").and_then(|c| c.as_array()) {
                for (i, claim) in claims.iter().enumerate() {
                    let text = claim
                        .get("text")
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let tags = claim
                        .get("tags")
                        .and_then(|t| t.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let tagged = tags.iter().any(|t| *t == "MEASURED" || *t == "EXTERNAL");
                    if looks_like_rate_claim(text) && !tagged {
                        findings.push(ClaimsLintFinding {
                            path: path.display().to_string(),
                            line: i + 1,
                            excerpt: text.chars().take(160).collect(),
                            reason: "claim missing MEASURED/EXTERNAL tag".into(),
                        });
                    }
                }
                return;
            }
            for (k, child) in map {
                if k == "catch_rate" || k == "false_block_rate" || k.ends_with("_rate") {
                    // machine result bundles are verified by lia verify recompute, not claims-lint prose
                    continue;
                }
                lint_json_value(path, child, findings);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                lint_json_value(path, child, findings);
            }
        }
        _ => {}
    }
}

fn looks_like_rate_claim(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // Word-boundary match for "rate" so Strategy/Generated/operate do not trip the lint.
    let has_rate_word = lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_').any(|w| {
        w == "rate" || w.ends_with("-rate") || w.starts_with("rate-") || w.contains("catch-rate")
            || w == "catch_rate" || w == "false_block_rate" || w.ends_with("_rate")
    }) || lower.contains("catch-rate")
        || lower.contains("false-block")
        || lower.contains("false_block");
    if !(has_rate_word
        || lower.contains("percent")
        || lower.contains('%')
        || lower.contains("trust-integrity"))
    {
        return false;
    }
    text.chars().any(|c| c.is_ascii_digit())
}

fn line_has_untagged_rate_claim(line: &str) -> bool {
    if line.contains("[MEASURED]") || line.contains("[EXTERNAL]") {
        return false;
    }
    if line.trim_start().starts_with('#') {
        return false;
    }
    looks_like_rate_claim(line)
}
