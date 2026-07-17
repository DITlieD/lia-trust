use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireCheckError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("regex: {0}")]
    Regex(#[from] regex::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum Verdict {
    Wired,
    Internal,
    Dark,
    RegisteredDark,
    UnsoundName,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: String,
    pub symbol: String,
    pub kind: String,
    pub line: usize,
    pub verdict: Verdict,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct AllowRow {
    pub unit: String,
    pub path: String,
    pub symbol: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct PubDef {
    kind: String,
    name: String,
    line: usize,
    wire_dark_unit: Option<String>,
}

const COMMON_FN_NAMES: &[&str] = &[
    "new", "default", "from", "into", "build", "run", "init", "get", "set", "len",
    "name", "kind", "id", "fmt", "clone", "next", "read", "write", "open", "close",
    "start", "stop", "call", "apply", "check", "emit", "push", "pop",
];

pub fn load_allowlist(path: &Path) -> Result<Vec<AllowRow>, WireCheckError> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut rows = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let ln = raw.trim();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = ln.split('\t').collect();
        if parts.len() < 3 {
            return Err(WireCheckError::Config(format!(
                "allowlist {}:{}: need unit\\tpath\\tsymbol[\\treason]",
                path.display(),
                i + 1
            )));
        }
        rows.push(AllowRow {
            unit: parts[0].to_string(),
            path: parts[1].replace('\\', "/"),
            symbol: parts[2].to_string(),
            reason: parts.get(3).unwrap_or(&"").to_string(),
        });
    }
    Ok(rows)
}

pub fn pub_def_re() -> Result<Regex, WireCheckError> {
    Ok(Regex::new(
        r#"(?m)^[ \t]*pub(?:[ \t]*\((?:crate|super|self|in[ \t]+[^)]*)\))?[ \t]+(?:async[ \t]+|unsafe[ \t]+|const[ \t]+|extern[ \t]+"[^"]*"[ \t]+)*(fn|struct|enum|trait|type|const|static)[ \t]+([A-Za-z_][A-Za-z0-9_]*)"#,
    )?)
}

pub fn wire_dark_re() -> Result<Regex, WireCheckError> {
    Ok(Regex::new(r"WIRE-DARK\[([^\]]+)\]")?)
}

fn is_test_path(path: &Path) -> bool {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(|s| s.to_ascii_lowercase()))
        .collect();
    if parts.iter().any(|p| p == "tests" || p == "benches" || p == "examples") {
        return true;
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    stem.ends_with("_test") || stem.ends_with("_tests") || path.file_name().and_then(|s| s.to_str()) == Some("build.rs")
}

fn strip_comments_preserve_newlines(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < bytes.len() {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    break;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn line_of(text: &str, byte_idx: usize) -> usize {
    text[..byte_idx.min(text.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

fn wire_dark_near(lines: &[&str], def_line: usize, re: &Regex) -> Option<String> {
    let start = def_line.saturating_sub(5).max(1);
    for ln in start..=def_line {
        if let Some(line) = lines.get(ln - 1) {
            if let Some(c) = re.captures(line) {
                return Some(c[1].to_string());
            }
        }
    }
    None
}

pub(crate) fn extract_pub_defs(_path: &Path, text: &str) -> Result<Vec<PubDef>, WireCheckError> {
    let re = pub_def_re()?;
    let dark_re = wire_dark_re()?;
    let lines: Vec<&str> = text.lines().collect();
    let cleaned = strip_comments_preserve_newlines(text);
    let mut out = Vec::new();
    for caps in re.captures_iter(&cleaned) {
        let kind = caps[1].to_string();
        let name = caps[2].to_string();
        let line = line_of(&cleaned, caps.get(0).map(|m| m.start()).unwrap_or(0));
        let wire_dark_unit = wire_dark_near(&lines, line, &dark_re);
        out.push(PubDef {
            kind,
            name,
            line,
            wire_dark_unit,
        });
    }
    Ok(out)
}

pub fn files_from_changeset(root: &Path, changeset: &str) -> Result<Vec<PathBuf>, WireCheckError> {
    let p = Path::new(changeset);
    if p.is_file() {
        let text = fs::read_to_string(p)?;
        return paths_from_diff_text(root, &text);
    }
    if changeset == "-" || changeset == "HEAD" || changeset.starts_with("git:") {
        let base = changeset.strip_prefix("git:").unwrap_or("HEAD");
        let output = Command::new("git")
            .args(["diff", "-U0", base, "--", "*.rs"])
            .current_dir(root)
            .output()
            .map_err(|e| WireCheckError::Config(format!("git diff failed: {e}")))?;
        if !output.status.success() {
            return Err(WireCheckError::Config(format!(
                "git diff exit {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        return paths_from_diff_text(root, &String::from_utf8_lossy(&output.stdout));
    }
    paths_from_diff_text(root, changeset)
}

fn paths_from_diff_text(root: &Path, text: &str) -> Result<Vec<PathBuf>, WireCheckError> {
    let mut set = HashSet::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            if rest.ends_with(".rs") {
                set.insert(root.join(rest));
            }
        } else if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some((_, b)) = rest.split_once(' ') {
                let path = b.strip_prefix("b/").unwrap_or(b);
                if path.ends_with(".rs") {
                    set.insert(root.join(path));
                }
            }
        }
    }
    let mut v: Vec<_> = set.into_iter().collect();
    v.sort();
    Ok(v)
}

fn cfg_test_line_mask(text: &str) -> Vec<bool> {
    let lines: Vec<&str> = text.lines().collect();
    let mut mask = vec![false; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg( test )]") {
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            if j < lines.len() && lines[j].contains('{') {
                let mut depth = 0i32;
                let start = i;
                while j < lines.len() {
                    for ch in lines[j].chars() {
                        if ch == '{' {
                            depth += 1;
                        } else if ch == '}' {
                            depth -= 1;
                        }
                    }
                    j += 1;
                    if depth <= 0 {
                        break;
                    }
                }
                for k in start..j {
                    mask[k] = true;
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    mask
}

fn production_refs(root: &Path, symbol: &str, defining: &Path) -> Result<(usize, usize), WireCheckError> {
    let mut prod = 0usize;
    let mut same_file_non_def = 0usize;
    let word = Regex::new(&format!(r"\b{}\b", regex::escape(symbol)))?;
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
    {
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(path);
        let parts: Vec<_> = rel.components().filter_map(|c| c.as_os_str().to_str()).collect();
        if parts.iter().any(|p| *p == "target" || *p == ".git") {
            continue;
        }
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let cleaned = strip_comments_preserve_newlines(&text);
        let in_cfg_test = cfg_test_line_mask(&cleaned);
        for (idx, line) in cleaned.lines().enumerate() {
            if in_cfg_test.get(idx).copied().unwrap_or(false) {
                continue;
            }
            if line.trim_start().starts_with("use ") {
                continue;
            }
            if !word.is_match(line) {
                continue;
            }
            if pub_def_re()?.is_match(line) && line.contains(symbol) {
                continue;
            }
            if path == defining {
                same_file_non_def += 1;
                continue;
            }
            if is_test_path(path) || line.contains("#[test]") {
                continue;
            }
            prod += 1;
        }
    }
    Ok((prod, same_file_non_def))
}

fn allowlisted(rows: &[AllowRow], path: &Path, root: &Path, symbol: &str, unit: &str) -> bool {
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    rows.iter().any(|r| r.path == rel && r.symbol == symbol && r.unit == unit)
}

pub fn check_files(
    root: &Path,
    files: &[PathBuf],
    allow: &[AllowRow],
) -> Result<Vec<Finding>, WireCheckError> {
    let mut findings = Vec::new();
    for path in files {
        if !path.exists() || is_test_path(path) {
            continue;
        }
        let text = fs::read_to_string(path)?;
        let defs = extract_pub_defs(path, &text)?;
        for def in defs {
            if def.kind != "fn" {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if let Some(unit) = &def.wire_dark_unit {
                if allowlisted(allow, path, root, &def.name, unit) {
                    findings.push(Finding {
                        path: rel,
                        symbol: def.name,
                        kind: def.kind,
                        line: def.line,
                        verdict: Verdict::RegisteredDark,
                        detail: format!("WIRE-DARK[{unit}] + allowlist row"),
                    });
                    continue;
                }
                findings.push(Finding {
                    path: rel.clone(),
                    symbol: def.name.clone(),
                    kind: def.kind.clone(),
                    line: def.line,
                    verdict: Verdict::Dark,
                    detail: format!(
                        "WIRE-DARK[{unit}] present but no allowlist row for {rel}::{}" ,
                        def.name
                    ),
                });
                continue;
            }
            if COMMON_FN_NAMES.contains(&def.name.as_str()) || def.name.len() < 4 {
                findings.push(Finding {
                    path: rel,
                    symbol: def.name,
                    kind: def.kind,
                    line: def.line,
                    verdict: Verdict::UnsoundName,
                    detail: "name too common for name-grep; Layer 3 coverage is authoritative".into(),
                });
                continue;
            }
            let (prod, same) = production_refs(root, &def.name, path)?;
            let verdict = if prod > 0 {
                Verdict::Wired
            } else if same > 0 {
                Verdict::Internal
            } else {
                Verdict::Dark
            };
            findings.push(Finding {
                path: rel,
                symbol: def.name,
                kind: def.kind,
                line: def.line,
                verdict,
                detail: format!("production_refs={prod} same_file_refs={same}"),
            });
        }
    }
    Ok(findings)
}

pub fn exit_code(findings: &[Finding]) -> i32 {
    if findings.iter().any(|f| f.verdict == Verdict::Dark) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn dark_when_only_test_caller() {
        let dir = tempfile_dir();
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        let lib = src.join("lib.rs");
        fs::write(
            &lib,
            "pub fn seed_unwired_dark() {}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn t() { seed_unwired_dark(); }\n}\n",
        )
        .unwrap();
        let findings = check_files(&dir, &[lib], &[]).unwrap();
        assert!(
            findings.iter().any(|f| f.symbol == "seed_unwired_dark" && f.verdict == Verdict::Dark),
            "{findings:?}"
        );
        assert_eq!(exit_code(&findings), 1);
    }

    fn tempfile_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("lia_wire_check_{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        let mut marker = fs::File::create(p.join(".lia_wire_check_tmp")).unwrap();
        let _ = writeln!(marker, "tmp");
        p
    }
}
