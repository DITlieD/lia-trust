use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tree_sitter::{Node, Parser};

pub const AST_GATE_ID: &str = "ast-gate";

pub const AST_REASON_CODES: &[&str] = &[
    "AST_ALLOW",
    "AST_AUTHZ_REMOVED",
    "AST_DANGEROUS_DESER",
    "AST_EVAL",
    "AST_IMPORT_NO_MANIFEST",
    "AST_SQL_INTERP",
    "AST_TEST_UNCONDITIONAL",
    "AST_UNTRUSTED_CMD",
];

pub const PINNED_GRAMMAR_VERSIONS: &[(&str, &str)] = &[
    ("tree-sitter", "0.24.7"),
    ("tree-sitter-python", "0.23.6"),
    ("tree-sitter-rust", "0.23.3"),
    ("tree-sitter-javascript", "0.23.1"),
];

#[derive(Debug, Error)]
pub enum AstError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Language {
    Python,
    Rust,
    Javascript,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Predicate {
    SqlInterp,
    UntrustedCmd,
    DangerousDeser,
    Eval,
    ImportNoManifest,
    TestUnconditional,
    AuthzRemoved,
}

impl Predicate {
    pub fn reason_code(self) -> &'static str {
        match self {
            Predicate::SqlInterp => "AST_SQL_INTERP",
            Predicate::UntrustedCmd => "AST_UNTRUSTED_CMD",
            Predicate::DangerousDeser => "AST_DANGEROUS_DESER",
            Predicate::Eval => "AST_EVAL",
            Predicate::ImportNoManifest => "AST_IMPORT_NO_MANIFEST",
            Predicate::TestUnconditional => "AST_TEST_UNCONDITIONAL",
            Predicate::AuthzRemoved => "AST_AUTHZ_REMOVED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AstHit {
    pub predicate: Predicate,
    pub language: Language,
    pub line: usize,
    pub excerpt: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AstReport {
    pub verdict: String,
    pub reason_code: String,
    pub hits: Vec<AstHit>,
    pub grammar_pins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ScanOptions {
    #[serde(default)]
    pub manifest_packages: Vec<String>,
    #[serde(default)]
    pub language: Option<Language>,
}

pub fn scan_source(
    source: &str,
    lang: Language,
    opts: &ScanOptions,
) -> Result<AstReport, AstError> {
    let mut hits = Vec::new();
    match lang {
        Language::Python => scan_python(source, opts, &mut hits)?,
        Language::Rust => scan_rust(source, opts, &mut hits)?,
        Language::Javascript => scan_javascript(source, opts, &mut hits)?,
    }
    Ok(finalize(hits))
}

pub fn scan_file(path: impl AsRef<Path>, opts: &ScanOptions) -> Result<AstReport, AstError> {
    let path = path.as_ref();
    let source = fs::read_to_string(path)?;
    let lang = opts.language.unwrap_or_else(|| infer_language(path));
    scan_source(&source, lang, opts)
}

pub fn scan_diff(diff: &str, opts: &ScanOptions) -> Result<AstReport, AstError> {
    let mut hits = Vec::new();
    let lang = opts.language.unwrap_or(Language::Python);
    let added = collect_diff_lines(diff, true);
    let removed = collect_diff_lines(diff, false);
    let added_src = added.join("\n");
    if !added_src.trim().is_empty() {
        match lang {
            Language::Python => scan_python(&added_src, opts, &mut hits)?,
            Language::Rust => scan_rust(&added_src, opts, &mut hits)?,
            Language::Javascript => scan_javascript(&added_src, opts, &mut hits)?,
        }
    }
    check_authz_removed(&added, &removed, lang, &mut hits);
    check_test_unconditional_lines(&added, lang, &mut hits);
    Ok(finalize(hits))
}

pub fn ast_report_to_outcome(report: &AstReport, action_id: uuid::Uuid) -> lia_gates::GateOutcome {
    let evidence = serde_json::json!({
        "hits": report.hits,
        "grammar_pins": report.grammar_pins,
    });
    let evidence_sha256 = {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(&evidence).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    };
    let verdict = if report.hits.is_empty() {
        lia_protocol::Verdict::Allow
    } else {
        lia_protocol::Verdict::Deny
    };
    lia_gates::GateOutcome {
        gate_id: AST_GATE_ID.to_string(),
        action_id,
        verdict,
        reason_code: report.reason_code.clone(),
        risk_tier: lia_protocol::RiskTier::Security,
        detail: report.hits.first().map(|h| h.detail.clone()),
        offending: report.hits.first().map(|h| h.excerpt.clone()),
        evidence_sha256,
        timestamp: chrono::Utc::now(),
        hl4: None,
        shareable: None,
    }
}

fn finalize(mut hits: Vec<AstHit>) -> AstReport {
    hits.sort_by(|a, b| {
        a.predicate
            .cmp(&b.predicate)
            .then(a.line.cmp(&b.line))
            .then(a.excerpt.cmp(&b.excerpt))
    });
    hits.dedup_by(|a, b| a.predicate == b.predicate && a.line == b.line && a.excerpt == b.excerpt);
    let reason_code = hits
        .first()
        .map(|h| h.predicate.reason_code().to_string())
        .unwrap_or_else(|| "AST_ALLOW".to_string());
    let verdict = if hits.is_empty() {
        "allow".to_string()
    } else {
        "deny".to_string()
    };
    AstReport {
        verdict,
        reason_code,
        hits,
        grammar_pins: PINNED_GRAMMAR_VERSIONS
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect(),
    }
}

fn infer_language(path: &Path) -> Language {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "py" => Language::Python,
        "rs" => Language::Rust,
        "js" | "mjs" | "cjs" | "jsx" => Language::Javascript,
        _ => Language::Python,
    }
}

fn parse_tree(source: &str, lang: Language) -> Result<tree_sitter::Tree, AstError> {
    let mut parser = Parser::new();
    let language = match lang {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Javascript => tree_sitter_javascript::LANGUAGE.into(),
    };
    parser
        .set_language(&language)
        .map_err(|e| AstError::Parse(format!("set_language: {e}")))?;
    parser
        .parse(source, None)
        .ok_or_else(|| AstError::Parse("tree-sitter returned no tree".into()))
}

fn scan_python(source: &str, opts: &ScanOptions, hits: &mut Vec<AstHit>) -> Result<(), AstError> {
    let tree = parse_tree(source, Language::Python)?;
    walk_python(tree.root_node(), source.as_bytes(), opts, hits);
    check_test_unconditional_lines(
        &source.lines().map(|l| l.to_string()).collect::<Vec<_>>(),
        Language::Python,
        hits,
    );
    Ok(())
}

fn walk_python(node: Node, src: &[u8], opts: &ScanOptions, hits: &mut Vec<AstHit>) {
    let kind = node.kind();
    let text = node_text(node, src);

    if kind == "call" {
        let callee = call_callee_python(node, src);
        let line = node.start_position().row + 1;
        if (callee.ends_with("execute") || callee.ends_with("executemany"))
            && looks_sql_interpolated(node, src)
        {
            hits.push(AstHit {
                predicate: Predicate::SqlInterp,
                language: Language::Python,
                line,
                excerpt: trim_excerpt(&text),
                detail: "SQL executed with interpolated string".into(),
            });
        }
        if callee == "eval" || callee == "exec" {
            hits.push(AstHit {
                predicate: Predicate::Eval,
                language: Language::Python,
                line,
                excerpt: trim_excerpt(&text),
                detail: format!("dangerous call {callee}"),
            });
        }
        if text.contains("pickle.loads") || text.contains("marshal.loads") {
            hits.push(AstHit {
                predicate: Predicate::DangerousDeser,
                language: Language::Python,
                line,
                excerpt: trim_excerpt(&text),
                detail: "dangerous deserialization".into(),
            });
        }
        if text.contains("yaml.load(") && !text.contains("yaml.safe_load(") {
            hits.push(AstHit {
                predicate: Predicate::DangerousDeser,
                language: Language::Python,
                line,
                excerpt: trim_excerpt(&text),
                detail: "yaml.load without SafeLoader".into(),
            });
        }
        if (text.contains("os.system")
            || (text.contains("subprocess") && text.contains("shell=True")))
            && !arg_is_string_literal(node, src)
        {
            hits.push(AstHit {
                predicate: Predicate::UntrustedCmd,
                language: Language::Python,
                line,
                excerpt: trim_excerpt(&text),
                detail: "untrusted data flows into command execution".into(),
            });
        }
    }

    if kind == "import_statement" || kind == "import_from_statement" {
        let line = node.start_position().row + 1;
        for name in import_names_python(node, src) {
            if !opts.manifest_packages.is_empty()
                && !opts
                    .manifest_packages
                    .iter()
                    .any(|p| p == &name || name.starts_with(&format!("{p}.")))
            {
                hits.push(AstHit {
                    predicate: Predicate::ImportNoManifest,
                    language: Language::Python,
                    line,
                    excerpt: trim_excerpt(&text),
                    detail: format!("import {name} has no manifest entry"),
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_python(child, src, opts, hits);
    }
}

fn scan_rust(source: &str, opts: &ScanOptions, hits: &mut Vec<AstHit>) -> Result<(), AstError> {
    let tree = parse_tree(source, Language::Rust)?;
    walk_rust(tree.root_node(), source.as_bytes(), opts, hits);
    check_test_unconditional_lines(
        &source.lines().map(|l| l.to_string()).collect::<Vec<_>>(),
        Language::Rust,
        hits,
    );
    Ok(())
}

fn walk_rust(node: Node, src: &[u8], opts: &ScanOptions, hits: &mut Vec<AstHit>) {
    let kind = node.kind();
    let text = node_text(node, src);
    let line = node.start_position().row + 1;

    if kind == "macro_invocation" && text.contains("sqlx::query") && text.contains("format!") {
        hits.push(AstHit {
            predicate: Predicate::SqlInterp,
            language: Language::Rust,
            line,
            excerpt: trim_excerpt(&text),
            detail: "SQL query built via format interpolation".into(),
        });
    }

    if kind == "call_expression" {
        if text.contains("bincode::deserialize") {
            hits.push(AstHit {
                predicate: Predicate::DangerousDeser,
                language: Language::Rust,
                line,
                excerpt: trim_excerpt(&text),
                detail: "dangerous deserialization".into(),
            });
        }
        if text.contains("Command::new") && text.contains("arg(&input)") {
            hits.push(AstHit {
                predicate: Predicate::UntrustedCmd,
                language: Language::Rust,
                line,
                excerpt: trim_excerpt(&text),
                detail: "command args from non-literal".into(),
            });
        }
    }

    if kind == "use_declaration" && !opts.manifest_packages.is_empty() {
        if let Some(name) = rust_use_root(&text) {
            if !opts.manifest_packages.iter().any(|p| p == &name) {
                hits.push(AstHit {
                    predicate: Predicate::ImportNoManifest,
                    language: Language::Rust,
                    line,
                    excerpt: trim_excerpt(&text),
                    detail: format!("use {name} has no manifest entry"),
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_rust(child, src, opts, hits);
    }
}

fn scan_javascript(
    source: &str,
    opts: &ScanOptions,
    hits: &mut Vec<AstHit>,
) -> Result<(), AstError> {
    let tree = parse_tree(source, Language::Javascript)?;
    walk_js(tree.root_node(), source.as_bytes(), opts, hits);
    Ok(())
}

fn walk_js(node: Node, src: &[u8], opts: &ScanOptions, hits: &mut Vec<AstHit>) {
    let kind = node.kind();
    let text = node_text(node, src);
    let line = node.start_position().row + 1;

    if kind == "call_expression" {
        if text.starts_with("eval(") || text.contains("= eval(") {
            hits.push(AstHit {
                predicate: Predicate::Eval,
                language: Language::Javascript,
                line,
                excerpt: trim_excerpt(&text),
                detail: "eval call".into(),
            });
        }
        if (text.contains("execSync(") || text.contains("exec("))
            && (text.contains("${") || text.contains("+ req") || text.contains("+ input"))
        {
            hits.push(AstHit {
                predicate: Predicate::UntrustedCmd,
                language: Language::Javascript,
                line,
                excerpt: trim_excerpt(&text),
                detail: "untrusted data into command".into(),
            });
        }
    }

    if kind == "import_statement" && !opts.manifest_packages.is_empty() {
        if let Some(name) = js_import_root(&text) {
            if !opts.manifest_packages.iter().any(|p| p == &name) {
                hits.push(AstHit {
                    predicate: Predicate::ImportNoManifest,
                    language: Language::Javascript,
                    line,
                    excerpt: trim_excerpt(&text),
                    detail: format!("import {name} has no manifest entry"),
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_js(child, src, opts, hits);
    }
}

fn call_callee_python(call: Node, src: &[u8]) -> String {
    let mut cursor = call.walk();
    for child in call.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "attribute" {
            return node_text(child, src);
        }
    }
    String::new()
}

fn looks_sql_interpolated(call: Node, src: &[u8]) -> bool {
    let mut cursor = call.walk();
    for child in call.children(&mut cursor) {
        if child.kind() != "argument_list" {
            continue;
        }
        let mut ac = child.walk();
        for arg in child.children(&mut ac) {
            if !arg.is_named() {
                continue;
            }
            let at = node_text(arg, src);
            if at.starts_with('f') && (at.starts_with("f\"") || at.starts_with("f'")) {
                return true;
            }
            if at.contains(".format(") || arg.kind() == "binary_operator" {
                return true;
            }
            if arg.kind() == "concatenated_string" {
                return true;
            }
        }
    }
    false
}

fn arg_is_string_literal(call: Node, src: &[u8]) -> bool {
    let mut cursor = call.walk();
    for child in call.children(&mut cursor) {
        if child.kind() != "argument_list" {
            continue;
        }
        let mut ac = child.walk();
        let args: Vec<Node> = child.children(&mut ac).filter(|n| n.is_named()).collect();
        if args.len() == 1 && args[0].kind() == "string" {
            let t = node_text(args[0], src);
            return !t.starts_with('f');
        }
        return false;
    }
    false
}

fn import_names_python(node: Node, src: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "dotted_name" {
            let t = node_text(child, src);
            if let Some(root) = t.split('.').next() {
                if !root.is_empty() {
                    names.push(root.to_string());
                }
            }
        }
        if child.kind() == "aliased_import" {
            if let Some(dn) = named_child(child, "dotted_name") {
                let t = node_text(dn, src);
                if let Some(root) = t.split('.').next() {
                    if !root.is_empty() {
                        names.push(root.to_string());
                    }
                }
            }
        }
    }
    names
}

fn named_child<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let mut found = None;
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            found = Some(child);
            break;
        }
    }
    found
}

fn rust_use_root(text: &str) -> Option<String> {
    let t = text.trim().trim_start_matches("use ").trim_end_matches(';');
    let root = t.split("::").next()?.trim();
    if root.is_empty() || matches!(root, "crate" | "super" | "self" | "std" | "core" | "alloc") {
        return None;
    }
    Some(root.to_string())
}

fn js_import_root(text: &str) -> Option<String> {
    let q = text.find('\'').or_else(|| text.find('"'))?;
    let rest = &text[q + 1..];
    let end = rest.find('\'').or_else(|| rest.find('"'))?;
    let spec = &rest[..end];
    if spec.starts_with('.') || spec.starts_with('/') {
        return None;
    }
    Some(spec.split('/').next().unwrap_or(spec).to_string())
}

fn check_test_unconditional_lines(lines: &[String], lang: Language, hits: &mut Vec<AstHit>) {
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        let bad = match lang {
            Language::Python => {
                t == "assert True"
                    || t.starts_with("assert True ")
                    || t == "self.assertTrue(True)"
                    || t == "return True  # always pass"
            }
            Language::Rust => t.contains("assert!(true)") || t.contains("assert_eq!((), ())"),
            Language::Javascript => {
                t.contains("expect(true).toBe(true)") || t.contains("assert.ok(true)")
            }
        };
        if bad {
            hits.push(AstHit {
                predicate: Predicate::TestUnconditional,
                language: lang,
                line: i + 1,
                excerpt: trim_excerpt(t),
                detail: "test converted to unconditional success".into(),
            });
        }
    }
}

fn check_authz_removed(
    added: &[String],
    removed: &[String],
    lang: Language,
    hits: &mut Vec<AstHit>,
) {
    const AUTHZ: &[&str] = &[
        "check_auth",
        "require_auth",
        "authorize",
        "require_permission",
        "assert_permission",
        "ensure_admin",
        "verify_token",
    ];
    let removed_authz: Vec<&str> = removed
        .iter()
        .filter(|l| AUTHZ.iter().any(|a| l.contains(a)))
        .map(|l| l.as_str())
        .collect();
    if removed_authz.is_empty() {
        return;
    }
    let sensitive_context = added.iter().chain(removed.iter()).any(|l| {
        let t = l.to_ascii_lowercase();
        t.contains("admin")
            || t.contains("delete_user")
            || t.contains("transfer")
            || t.contains("sensitive")
            || t.contains("payment")
    });
    let still_present = added.iter().any(|l| AUTHZ.iter().any(|a| l.contains(a)));
    if sensitive_context && !still_present {
        hits.push(AstHit {
            predicate: Predicate::AuthzRemoved,
            language: lang,
            line: 1,
            excerpt: trim_excerpt(removed_authz[0]),
            detail: "authz check removed from sensitive function".into(),
        });
    }
}

fn collect_diff_lines(diff: &str, added: bool) -> Vec<String> {
    let mut out = Vec::new();
    for line in diff.lines() {
        if added {
            if let Some(rest) = line.strip_prefix('+') {
                if !rest.starts_with("++") {
                    out.push(rest.to_string());
                }
            }
        } else if let Some(rest) = line.strip_prefix('-') {
            if !rest.starts_with("--") {
                out.push(rest.to_string());
            }
        }
    }
    out
}

fn node_text(node: Node, src: &[u8]) -> String {
    match node.utf8_text(src) {
        Ok(t) => t.to_string(),
        Err(_) => String::new(),
    }
}

fn trim_excerpt(s: &str) -> String {
    let t = s.trim();
    if t.len() > 160 {
        format!("{}…", &t[..160])
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts_with_manifest(pkgs: &[&str]) -> ScanOptions {
        ScanOptions {
            manifest_packages: pkgs.iter().map(|s| s.to_string()).collect(),
            language: Some(Language::Python),
        }
    }

    #[test]
    fn sql_interp_positive_and_negative() {
        let bad = r#"
def q(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
"#;
        let r = scan_source(bad, Language::Python, &ScanOptions::default()).unwrap();
        assert!(r.hits.iter().any(|h| h.predicate == Predicate::SqlInterp));

        let good = r#"
def q(cur, name):
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
"#;
        let r2 = scan_source(good, Language::Python, &ScanOptions::default()).unwrap();
        assert!(!r2.hits.iter().any(|h| h.predicate == Predicate::SqlInterp));
    }

    #[test]
    fn eval_positive_negative() {
        let bad = "x = eval(user_input)\n";
        let r = scan_source(bad, Language::Python, &ScanOptions::default()).unwrap();
        assert!(r.hits.iter().any(|h| h.predicate == Predicate::Eval));
        let good = "x = int(user_input)\n";
        let r2 = scan_source(good, Language::Python, &ScanOptions::default()).unwrap();
        assert!(!r2.hits.iter().any(|h| h.predicate == Predicate::Eval));
    }

    #[test]
    fn dangerous_deser_positive_negative() {
        let bad = "import pickle\ndata = pickle.loads(blob)\n";
        let r = scan_source(bad, Language::Python, &ScanOptions::default()).unwrap();
        assert!(r
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::DangerousDeser));
        let good = "import json\ndata = json.loads(blob)\n";
        let r2 = scan_source(good, Language::Python, &ScanOptions::default()).unwrap();
        assert!(!r2
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::DangerousDeser));
    }

    #[test]
    fn untrusted_cmd_positive_negative() {
        let bad = "import os\nos.system(user_cmd)\n";
        let r = scan_source(bad, Language::Python, &ScanOptions::default()).unwrap();
        assert!(r
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::UntrustedCmd));
        let good = "import os\nos.system('ls')\n";
        let r2 = scan_source(good, Language::Python, &ScanOptions::default()).unwrap();
        assert!(!r2
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::UntrustedCmd));
    }

    #[test]
    fn import_manifest_positive_negative() {
        let src = "import phantomlib\nimport json\n";
        let opts = opts_with_manifest(&["json"]);
        let r = scan_source(src, Language::Python, &opts).unwrap();
        assert!(r
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::ImportNoManifest));
        let opts2 = opts_with_manifest(&["json", "phantomlib"]);
        let r2 = scan_source(src, Language::Python, &opts2).unwrap();
        assert!(!r2
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::ImportNoManifest));
    }

    #[test]
    fn test_unconditional_positive_negative() {
        let bad = "def test_login():\n    assert True\n";
        let r = scan_source(bad, Language::Python, &ScanOptions::default()).unwrap();
        assert!(r
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::TestUnconditional));
        let good = "def test_login():\n    assert client.login('a','b')\n";
        let r2 = scan_source(good, Language::Python, &ScanOptions::default()).unwrap();
        assert!(!r2
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::TestUnconditional));
    }

    #[test]
    fn authz_removed_positive_negative() {
        let bad_diff = r#"
@@ def delete_user @@
-    check_auth(user)
-    delete_user(user_id)
+    delete_user(user_id)
"#;
        let r = scan_diff(bad_diff, &ScanOptions::default()).unwrap();
        assert!(r
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::AuthzRemoved));

        let good_diff = r#"
@@ def delete_user @@
-    check_auth(user)
-    delete_user(user_id)
+    check_auth(user)
+    delete_user(user_id)
"#;
        let r2 = scan_diff(good_diff, &ScanOptions::default()).unwrap();
        assert!(!r2
            .hits
            .iter()
            .any(|h| h.predicate == Predicate::AuthzRemoved));
    }

    #[test]
    fn grammar_pins_present() {
        let r = scan_source("x=1\n", Language::Python, &ScanOptions::default()).unwrap();
        assert!(r.grammar_pins.iter().any(|p| p.starts_with("tree-sitter=")));
    }
}
