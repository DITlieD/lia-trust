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
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| !is_ignored_tree(entry))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !(matches!(ext, "md" | "txt" | "json" | "tsv" | "rst" | "html" | "htm")
            || name == "CLAIMS"
            || name == "README")
        {
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

fn is_ignored_tree(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    if matches!(name.as_ref(), "datasets" | "runs")
        && entry
            .path()
            .ancestors()
            .any(|ancestor| ancestor.ends_with(Path::new("bench/harbor")))
    {
        return true;
    }
    matches!(
        name.as_ref(),
        ".git"
            | ".venv"
            | "venv"
            | "target"
            | "node_modules"
            | ".tox"
            | ".mypy_cache"
            | ".pytest_cache"
            | "__pycache__"
            | "docs-internal"
    )
}

fn lint_json_value(path: &Path, v: &serde_json::Value, findings: &mut Vec<ClaimsLintFinding>) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(claims) = map.get("claims").and_then(|c| c.as_array()) {
                for (i, claim) in claims.iter().enumerate() {
                    let text = claim.get("text").and_then(|t| t.as_str()).unwrap_or("");
                    let tags = claim
                        .get("tags")
                        .and_then(|t| t.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
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
        // any string leaf can carry a claim ("summary":"99% catch rate"), not only claims[].text
        serde_json::Value::String(s) => {
            if looks_like_rate_claim(s) && !is_tagged(s) {
                findings.push(ClaimsLintFinding {
                    path: path.display().to_string(),
                    line: 0,
                    excerpt: s.chars().take(160).collect(),
                    reason: "JSON string carries an untagged numeric/superlative claim".into(),
                });
            }
        }
        _ => {}
    }
}

/// Superlatives banned without evidence (K-1/KD-1): a marketing claim of being best/fastest/
/// unbreakable is a claim like any number and needs a tag or must be dropped.
const SUPERLATIVES: &[&str] = &[
    "best-in-class",
    "state-of-the-art",
    "world-class",
    "industry-leading",
    "unmatched",
    "unbreakable",
    "bulletproof",
    "military-grade",
    "bank-grade",
    "the fastest",
    "the most secure",
    "the most accurate",
    "100% secure",
    "completely secure",
    "guaranteed secure",
    "cannot be bypassed",
    "impossible to",
];

/// Metric nouns that make a nearby bare number a quantitative claim even without "rate"/"%".
const METRIC_NOUNS: &[&str] = &[
    "catch",
    "catches",
    "caught",
    "block",
    "blocks",
    "blocked",
    "false-open",
    "false open",
    "false-block",
    "false block",
    "hallucination",
    "wire-dark",
    "detection",
    "attacks",
    "insecure",
    "residual",
    "speedup",
    "faster",
    "fewer",
    "reduction",
];

fn has_number(lower: &str) -> bool {
    // a digit anywhere, OR a spelled-out cardinal used as a percentage ("ninety-nine
    // percent"). Spelled-out words are ONLY counted next to "percent" so ordinals like
    // "layer-two" / "phase-one" do not read as numeric claims.
    if lower.chars().any(|c| c.is_ascii_digit()) {
        return true;
    }
    if lower.contains("percent") {
        const NUM_WORDS: &[&str] = &[
            "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
            "hundred", "thousand", "ninety", "half",
        ];
        return lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|w| NUM_WORDS.contains(&w));
    }
    false
}

fn looks_like_rate_claim(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // any banned superlative is a claim regardless of numbers
    if SUPERLATIVES.iter().any(|s| lower.contains(s)) {
        return true;
    }
    // Word-boundary match for "rate" so Strategy/Generated/operate do not trip the lint.
    let has_rate_word = lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .any(|w| {
            w == "rate"
                || w.ends_with("-rate")
                || w.starts_with("rate-")
                || w.contains("catch-rate")
                || w == "catch_rate"
                || w == "false_block_rate"
                || w.ends_with("_rate")
        })
        || lower.contains("catch-rate")
        || lower.contains("false-block")
        || lower.contains("false_block");
    // strong rate/percent context: any number is a claim
    let strong_context = has_rate_word
        || lower.contains("percent")
        || lower.contains('%')
        || lower.contains("trust-integrity");
    if strong_context && has_number(&lower) {
        return true;
    }
    // weaker context (a metric noun, a multiplier): require a CLAIM-shaped number so a
    // list ordinal ("5.") or a spec table cell ("| 2 |") does not trip the lint.
    let weak_context = has_metric_noun(&lower) || has_multiplier(&lower);
    weak_context && claimish_number(&lower)
}

fn has_metric_noun(lower: &str) -> bool {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .any(|word| METRIC_NOUNS.contains(&word))
        || ["false open", "false block"]
            .iter()
            .any(|phrase| lower.contains(phrase))
}

/// A digit immediately followed by 'x' ("3x", "2.45x") — a multiplier claim. NOT any 'x'.
fn has_multiplier(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    bytes.windows(2).enumerate().any(|(index, pair)| {
        if !pair[0].is_ascii_digit() || pair[1] != b'x' {
            return false;
        }
        let mut start = index;
        while start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
            start -= 1;
        }
        let begins_number = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let ends_number = index + 2 == bytes.len() || !bytes[index + 2].is_ascii_alphanumeric();
        begins_number && ends_number
    })
}

/// A number shaped like a quantitative claim: a decimal (0.97), a percent (99%), a
/// multiplier (3x), or an "N of M" / "N out of M" / "N/M" ratio. A bare integer alone
/// (a list ordinal, a table cell, a version) does NOT qualify.
fn claimish_number(lower: &str) -> bool {
    let b = lower.as_bytes();
    for i in 0..b.len() {
        if !b[i].is_ascii_digit() {
            continue;
        }
        // decimal a.b
        if i + 1 < b.len() && b[i + 1] == b'.' && i + 2 < b.len() && b[i + 2].is_ascii_digit() {
            return true;
        }
        // percent or multiplier suffix
        if i + 1 < b.len() && (b[i + 1] == b'%' || b[i + 1] == b'x') {
            return true;
        }
    }
    lower.contains(" of ") && lower.chars().any(|c| c.is_ascii_digit())
        || lower.contains(" out of ")
        || regex_ratio(lower)
}

/// N/M with digits on both sides (e.g. "44/551").
fn regex_ratio(lower: &str) -> bool {
    let b = lower.as_bytes();
    b.windows(3)
        .any(|w| w[0].is_ascii_digit() && w[1] == b'/' && w[2].is_ascii_digit())
}

/// A claim is tagged when it carries [MEASURED...] or [EXTERNAL...]; the honest-wording
/// style attaches a recompute pointer inside the brackets ("[MEASURED, signed bundle]"),
/// so match the opening prefix, not only the bare "[MEASURED]".
fn is_tagged(text: &str) -> bool {
    text.contains("[MEASURED") || text.contains("[EXTERNAL") || text.contains("[DESIGN")
}

fn line_has_untagged_rate_claim(line: &str) -> bool {
    if is_tagged(line) {
        return false;
    }
    // headers are NOT exempt: "## Catch rate: 99%" is a claim like any other line.
    looks_like_rate_claim(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_previously_missed_claim_classes() {
        // superlatives, spelled-out percent, bare N-of-M, N/M, multiplier, markdown headers
        for s in [
            "LIA is best-in-class.",
            "It is unbreakable.",
            "Catch rate of ninety-nine percent.",
            "We catch 1247 of 1250 attacks.",
            "Detection improved 44/551.",
            "Tokens rose 2.45x under gating.",
            "## Catch rate: 99%",
        ] {
            assert!(looks_like_rate_claim(s), "should flag: {s}");
        }
    }

    #[test]
    fn does_not_flag_benign_or_structural_lines() {
        // list ordinals, spec table cells, ordinals-as-words, tagged claims
        for s in [
            "5. Do not pool recorded and live catch metrics.",
            "| Block exit code | 2 |",
            "That is intentional for TRUST-INTEGRITY (plan layer-two list).",
            "catch rate 1.0 at false-block 0 [MEASURED, signed bundle]",
            "See the roadmap for phase-one work.",
            "burntsushi__ripgrep-2576__zpqr8XR",
            "crack-7z-hash__hegne7x",
            "release blocker v0.1.0",
        ] {
            assert!(!line_has_untagged_rate_claim(s), "should NOT flag: {s}");
        }
    }

    #[test]
    fn skips_dependency_and_build_trees_but_lints_project_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let ignored = temp.path().join("bench/harbor/.venv/pkg");
        let tracked = temp.path().join("docs");
        std::fs::create_dir_all(&ignored).expect("ignored dir");
        std::fs::create_dir_all(&tracked).expect("tracked dir");
        std::fs::write(ignored.join("README.md"), "catch rate 99%").expect("ignored claim");
        std::fs::write(tracked.join("claim.md"), "catch rate 98%").expect("tracked claim");
        let generated = temp.path().join("bench/harbor/runs/run-1");
        std::fs::create_dir_all(&generated).expect("generated dir");
        std::fs::write(
            generated.join("trajectory.json"),
            r#"{"note":"catch rate 97%"}"#,
        )
        .expect("generated claim");
        let internal = temp.path().join("docs-internal");
        std::fs::create_dir_all(&internal).expect("internal dir");
        std::fs::write(internal.join("session.md"), "catch rate 96%").expect("internal claim");

        let findings = claims_lint(temp.path()).expect("lint");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].path.ends_with("docs/claim.md"));
    }
}
