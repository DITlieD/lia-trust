use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use lia_gates::{GateConfig, WrapperObservation};
use lia_protocol::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const GROUND_GATE_ID: &str = "ground";

pub const GROUND_REASON_CODES: &[&str] = &[
    "GROUND_API_SCHEMA_MISS",
    "GROUND_API_SCHEMA_OK",
    "GROUND_DEP_MISSING",
    "GROUND_DEP_OK",
    "GROUND_FILE_MISSING",
    "GROUND_FILE_OK",
    "GROUND_SOURCE_HASH_MISMATCH",
    "GROUND_SOURCE_NO_CITATION",
    "GROUND_SOURCE_SPAN_MISS",
    "GROUND_SOURCE_SUPPORTED",
    "GROUND_SOURCE_TOKEN_ONLY",
    "GROUND_SYMBOL_MISSING",
    "GROUND_SYMBOL_OK",
    "GROUND_TEST_NO_RECEIPT",
    "GROUND_TEST_OK",
    "GROUND_TEST_REFUTED",
    "GROUND_UNKNOWN_CLAIM_TYPE",
];

#[derive(Debug, Error)]
pub enum GroundError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid claim: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ClaimKind {
    FileExists,
    SymbolExists,
    TestsPassed,
    DependencyExists,
    SourceSupports,
    ApiSchemaContains,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    #[serde(rename = "type")]
    pub kind: ClaimKind,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub schema_path: Option<String>,
    #[serde(default)]
    pub schema_key: Option<String>,
    #[serde(default)]
    pub claim_text: Option<String>,
    #[serde(default)]
    pub citations: Option<Vec<Citation>>,
    #[serde(default)]
    pub sources: Option<Vec<FetchedSource>>,
    #[serde(default)]
    pub wrapper: Option<WrapperObservation>,
    #[serde(default)]
    pub claimed_pass: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub source_id: String,
    pub span_start: usize,
    pub span_end: usize,
    pub excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FetchedSource {
    pub source_id: String,
    pub body: String,
    pub body_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroundContext {
    #[serde(default)]
    pub root: Option<PathBuf>,
    #[serde(default)]
    pub registry: BTreeMap<String, Vec<String>>,
}

impl GroundContext {
    pub fn from_gate_config(config: &GateConfig) -> Self {
        Self {
            root: config.allowed_roots.first().cloned(),
            registry: config.registry.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroundResult {
    pub claim_type: String,
    pub verdict: Verdict,
    pub reason_code: String,
    pub detail: Option<String>,
    pub checked_location: Option<String>,
    pub evidence_sha256: String,
    pub timestamp: DateTime<Utc>,
    pub action_id: Uuid,
}

pub fn parse_claim(json: &str) -> Result<Claim, GroundError> {
    Ok(serde_json::from_str(json)?)
}

pub fn load_claim(path: impl AsRef<Path>) -> Result<Claim, GroundError> {
    let bytes = fs::read(path.as_ref())?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn load_context(path: impl AsRef<Path>) -> Result<GroundContext, GroundError> {
    let bytes = fs::read(path.as_ref())?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn verify_claim(claim: &Claim, ctx: &GroundContext) -> Result<GroundResult, GroundError> {
    verify_claim_with_id(claim, ctx, Uuid::new_v4())
}

pub fn verify_claim_with_id(
    claim: &Claim,
    ctx: &GroundContext,
    action_id: Uuid,
) -> Result<GroundResult, GroundError> {
    let evidence = serde_json::to_value(claim).unwrap_or(Value::Null);
    let result = match claim.kind {
        ClaimKind::FileExists => check_file_exists(claim, ctx, action_id, &evidence)?,
        ClaimKind::SymbolExists => check_symbol_exists(claim, ctx, action_id, &evidence)?,
        ClaimKind::TestsPassed => check_tests_passed(claim, action_id, &evidence)?,
        ClaimKind::DependencyExists => check_dependency(claim, ctx, action_id, &evidence)?,
        ClaimKind::SourceSupports => check_source_supports(claim, action_id, &evidence)?,
        ClaimKind::ApiSchemaContains => check_api_schema(claim, ctx, action_id, &evidence)?,
        ClaimKind::Unknown => make_result(
            "unknown",
            action_id,
            Verdict::Unsupported,
            "GROUND_UNKNOWN_CLAIM_TYPE",
            Some("unregistered claim type returns unsupported (fail-closed)".into()),
            None,
            &evidence,
        ),
    };
    Ok(result)
}

pub fn ground_result_to_outcome(
    result: &GroundResult,
) -> lia_gates::GateOutcome {
    lia_gates::GateOutcome {
        gate_id: GROUND_GATE_ID.to_string(),
        action_id: result.action_id,
        verdict: result.verdict.clone(),
        reason_code: result.reason_code.clone(),
        risk_tier: lia_protocol::RiskTier::Security,
        detail: result.detail.clone(),
        offending: result.checked_location.clone(),
        evidence_sha256: result.evidence_sha256.clone(),
        timestamp: result.timestamp,
        hl4: None,
        shareable: None,
    }
}

fn check_file_exists(
    claim: &Claim,
    ctx: &GroundContext,
    action_id: Uuid,
    evidence: &Value,
) -> Result<GroundResult, GroundError> {
    let rel = claim
        .path
        .as_deref()
        .ok_or_else(|| GroundError::Invalid("file_exists requires path".into()))?;
    let path = resolve_path(ctx, rel);
    let loc = path.display().to_string();
    if path.is_file() {
        Ok(make_result(
            "file_exists",
            action_id,
            Verdict::Verified,
            "GROUND_FILE_OK",
            Some(format!("file present at {loc}")),
            Some(loc),
            evidence,
        ))
    } else {
        Ok(make_result(
            "file_exists",
            action_id,
            Verdict::Refuted,
            "GROUND_FILE_MISSING",
            Some(format!("file absent at {loc}")),
            Some(loc),
            evidence,
        ))
    }
}

fn check_symbol_exists(
    claim: &Claim,
    ctx: &GroundContext,
    action_id: Uuid,
    evidence: &Value,
) -> Result<GroundResult, GroundError> {
    let rel = claim
        .path
        .as_deref()
        .ok_or_else(|| GroundError::Invalid("symbol_exists requires path".into()))?;
    let symbol = claim
        .symbol
        .as_deref()
        .ok_or_else(|| GroundError::Invalid("symbol_exists requires symbol".into()))?;
    let path = resolve_path(ctx, rel);
    let loc = format!("{}::{symbol}", path.display());
    if !path.is_file() {
        return Ok(make_result(
            "symbol_exists",
            action_id,
            Verdict::Refuted,
            "GROUND_SYMBOL_MISSING",
            Some(format!("file absent for symbol check: {}", path.display())),
            Some(loc),
            evidence,
        ));
    }
    let body = fs::read_to_string(&path)?;
    if symbol_present(&body, symbol) {
        Ok(make_result(
            "symbol_exists",
            action_id,
            Verdict::Verified,
            "GROUND_SYMBOL_OK",
            Some(format!("symbol {symbol} found")),
            Some(loc),
            evidence,
        ))
    } else {
        Ok(make_result(
            "symbol_exists",
            action_id,
            Verdict::Refuted,
            "GROUND_SYMBOL_MISSING",
            Some(format!("symbol {symbol} not found in {}", path.display())),
            Some(loc),
            evidence,
        ))
    }
}

fn check_tests_passed(
    claim: &Claim,
    action_id: Uuid,
    evidence: &Value,
) -> Result<GroundResult, GroundError> {
    let claimed = claim.claimed_pass.unwrap_or(true);
    if !claimed {
        return Ok(make_result(
            "tests_passed",
            action_id,
            Verdict::Unsupported,
            "GROUND_TEST_NO_RECEIPT",
            Some("tests_passed claim with claimed_pass=false is unsupported".into()),
            None,
            evidence,
        ));
    }
    let Some(wrapper) = claim.wrapper.as_ref() else {
        return Ok(make_result(
            "tests_passed",
            action_id,
            Verdict::Unsupported,
            "GROUND_TEST_NO_RECEIPT",
            Some("no gate-1 wrapper receipt backs tests_passed".into()),
            None,
            evidence,
        ));
    };
    if !hl4_complete(wrapper) {
        return Ok(make_result(
            "tests_passed",
            action_id,
            Verdict::Unsupported,
            "GROUND_TEST_NO_RECEIPT",
            Some("wrapper receipt missing HL-4 fields".into()),
            None,
            evidence,
        ));
    }
    if wrapper.exit_code != 0 {
        return Ok(make_result(
            "tests_passed",
            action_id,
            Verdict::Refuted,
            "GROUND_TEST_REFUTED",
            Some(format!(
                "wrapper exit_code={} refutes tests_passed",
                wrapper.exit_code
            )),
            Some(format!("exit_code={}", wrapper.exit_code)),
            evidence,
        ));
    }
    Ok(make_result(
        "tests_passed",
        action_id,
        Verdict::Verified,
        "GROUND_TEST_OK",
        Some("gate-1 wrapper receipt binds a real pass".into()),
        None,
        evidence,
    ))
}

fn check_dependency(
    claim: &Claim,
    ctx: &GroundContext,
    action_id: Uuid,
    evidence: &Value,
) -> Result<GroundResult, GroundError> {
    let package = claim
        .package
        .as_deref()
        .ok_or_else(|| GroundError::Invalid("dependency_exists requires package".into()))?;
    let version = claim.version.as_deref();
    let loc = match version {
        Some(v) => format!("{package}@{v}"),
        None => package.to_string(),
    };
    let Some(versions) = ctx.registry.get(package) else {
        return Ok(make_result(
            "dependency_exists",
            action_id,
            Verdict::Refuted,
            "GROUND_DEP_MISSING",
            Some("package absent from registry snapshot".into()),
            Some(loc),
            evidence,
        ));
    };
    if let Some(ver) = version {
        if !versions.iter().any(|v| v == ver) {
            return Ok(make_result(
                "dependency_exists",
                action_id,
                Verdict::Refuted,
                "GROUND_DEP_MISSING",
                Some(format!("version {ver} not in registry for {package}")),
                Some(loc),
                evidence,
            ));
        }
    }
    Ok(make_result(
        "dependency_exists",
        action_id,
        Verdict::Verified,
        "GROUND_DEP_OK",
        Some("package present in registry snapshot".into()),
        Some(loc),
        evidence,
    ))
}

fn check_source_supports(
    claim: &Claim,
    action_id: Uuid,
    evidence: &Value,
) -> Result<GroundResult, GroundError> {
    let claim_text = claim
        .claim_text
        .as_deref()
        .ok_or_else(|| GroundError::Invalid("source_supports requires claim_text".into()))?
        .trim();
    if claim_text.is_empty() {
        return Err(GroundError::Invalid(
            "source_supports claim_text must be non-empty".into(),
        ));
    }
    let sources = claim.sources.as_deref().unwrap_or(&[]);
    let citations = claim.citations.as_deref().unwrap_or(&[]);

    if sources.is_empty() {
        return Ok(make_result(
            "source_supports",
            action_id,
            Verdict::Unsupported,
            "GROUND_SOURCE_NO_CITATION",
            Some("no hashed fetched sources supplied".into()),
            None,
            evidence,
        ));
    }

    for src in sources {
        let actual = blake3::hash(src.body.as_bytes()).to_hex().to_string();
        if actual != src.body_blake3 {
            return Ok(make_result(
                "source_supports",
                action_id,
                Verdict::Refuted,
                "GROUND_SOURCE_HASH_MISMATCH",
                Some(format!(
                    "fetched source {} blake3 mismatch (tampered or mis-hashed)",
                    src.source_id
                )),
                Some(src.source_id.clone()),
                evidence,
            ));
        }
    }

    if citations.is_empty() {
        if token_only_present(claim_text, sources) {
            return Ok(make_result(
                "source_supports",
                action_id,
                Verdict::Unsupported,
                "GROUND_SOURCE_TOKEN_ONLY",
                Some(
                    "token-only containment is banned; span + closed-set citation required"
                        .into(),
                ),
                None,
                evidence,
            ));
        }
        return Ok(make_result(
            "source_supports",
            action_id,
            Verdict::Unsupported,
            "GROUND_SOURCE_NO_CITATION",
            Some("no citing span from the fetched hashed set".into()),
            None,
            evidence,
        ));
    }

    let mut closed: BTreeMap<&str, &FetchedSource> = BTreeMap::new();
    for src in sources {
        closed.insert(src.source_id.as_str(), src);
    }

    let mut bound_spans: Vec<&str> = Vec::new();
    for cite in citations {
        let Some(src) = closed.get(cite.source_id.as_str()) else {
            return Ok(make_result(
                "source_supports",
                action_id,
                Verdict::Unsupported,
                "GROUND_SOURCE_NO_CITATION",
                Some(format!(
                    "citation source_id {} not in closed fetched set",
                    cite.source_id
                )),
                Some(cite.source_id.clone()),
                evidence,
            ));
        };
        if cite.span_end < cite.span_start || cite.span_end > src.body.len() {
            return Ok(make_result(
                "source_supports",
                action_id,
                Verdict::Unsupported,
                "GROUND_SOURCE_SPAN_MISS",
                Some(format!(
                    "citation span [{}, {}) out of bounds for {}",
                    cite.span_start, cite.span_end, cite.source_id
                )),
                Some(cite.source_id.clone()),
                evidence,
            ));
        }
        let actual = &src.body[cite.span_start..cite.span_end];
        if actual != cite.excerpt {
            return Ok(make_result(
                "source_supports",
                action_id,
                Verdict::Unsupported,
                "GROUND_SOURCE_SPAN_MISS",
                Some(format!(
                    "citation excerpt does not match hashed source span in {}",
                    cite.source_id
                )),
                Some(cite.source_id.clone()),
                evidence,
            ));
        }
        bound_spans.push(actual);
    }

    let supported = bound_spans.iter().any(|span| span_contains_claim(span, claim_text));
    if supported {
        Ok(make_result(
            "source_supports",
            action_id,
            Verdict::Verified,
            "GROUND_SOURCE_SUPPORTED",
            Some("claim text contained in a closed-set cited span".into()),
            None,
            evidence,
        ))
    } else {
        Ok(make_result(
            "source_supports",
            action_id,
            Verdict::Unsupported,
            "GROUND_SOURCE_SPAN_MISS",
            Some("cited spans do not contain the claim text (not token-matched)".into()),
            None,
            evidence,
        ))
    }
}

fn check_api_schema(
    claim: &Claim,
    ctx: &GroundContext,
    action_id: Uuid,
    evidence: &Value,
) -> Result<GroundResult, GroundError> {
    let schema_rel = claim
        .schema_path
        .as_deref()
        .ok_or_else(|| GroundError::Invalid("api_schema_contains requires schema_path".into()))?;
    let key = claim
        .schema_key
        .as_deref()
        .ok_or_else(|| GroundError::Invalid("api_schema_contains requires schema_key".into()))?;
    let path = resolve_path(ctx, schema_rel);
    let loc = format!("{}#{}", path.display(), key);
    if !path.is_file() {
        return Ok(make_result(
            "api_schema_contains",
            action_id,
            Verdict::Refuted,
            "GROUND_API_SCHEMA_MISS",
            Some(format!("schema file absent: {}", path.display())),
            Some(loc),
            evidence,
        ));
    }
    let bytes = fs::read(&path)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if json_path_exists(&value, key) {
        Ok(make_result(
            "api_schema_contains",
            action_id,
            Verdict::Verified,
            "GROUND_API_SCHEMA_OK",
            Some(format!("schema contains key path {key}")),
            Some(loc),
            evidence,
        ))
    } else {
        Ok(make_result(
            "api_schema_contains",
            action_id,
            Verdict::Refuted,
            "GROUND_API_SCHEMA_MISS",
            Some(format!("schema missing key path {key}")),
            Some(loc),
            evidence,
        ))
    }
}

fn resolve_path(ctx: &GroundContext, rel: &str) -> PathBuf {
    let p = PathBuf::from(rel);
    if p.is_absolute() {
        return p;
    }
    match ctx.root.as_ref() {
        Some(root) => root.join(p),
        None => p,
    }
}

fn symbol_present(body: &str, symbol: &str) -> bool {
    // Prefer declaration-shaped matches (AST-lite / word-boundary) over bare
    // substring hits so false symbol misses drop on fixture languages (P2-16).
    if symbol_declaration_present(body, symbol) {
        return true;
    }
    let patterns = [
        format!("fn {symbol}"),
        format!("fn {symbol}<"),
        format!("fn {symbol}("),
        format!("def {symbol}"),
        format!("def {symbol}("),
        format!("class {symbol}"),
        format!("struct {symbol}"),
        format!("enum {symbol}"),
        format!("type {symbol}"),
        format!("const {symbol}"),
        format!("let {symbol}"),
        format!("function {symbol}"),
        format!(" {symbol} ="),
        format!("\t{symbol} ="),
    ];
    patterns.iter().any(|p| body.contains(p.as_str()))
        || body.lines().any(|line| {
            let t = line.trim();
            t == symbol || t.starts_with(&format!("{symbol}(")) || t.starts_with(&format!("{symbol} ="))
        })
}

/// Declaration-shaped patterns for Rust/Python/JS (not full AST; reduces
/// token-only false positives like matching `foo` inside `foobar`).
fn symbol_declaration_present(body: &str, symbol: &str) -> bool {
    let esc = regex_escape(symbol);
    let decls = [
        format!(r"(?m)^\s*(pub\s+)?(async\s+)?fn\s+{esc}\s*[<(]"),
        format!(r"(?m)^\s*(pub\s+)?(struct|enum|type|const|trait|mod)\s+{esc}\b"),
        format!(r"(?m)^\s*(async\s+)?def\s+{esc}\s*\("),
        format!(r"(?m)^\s*class\s+{esc}\b"),
        format!(r"(?m)^\s*(export\s+)?(async\s+)?function\s+{esc}\s*\("),
        format!(r"(?m)^\s*(export\s+)?(const|let|var)\s+{esc}\s*="),
    ];
    decls.iter().any(|pat| {
        regex::Regex::new(pat)
            .map(|re| re.is_match(body))
            .unwrap_or(false)
    })
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn hl4_complete(w: &WrapperObservation) -> bool {
    !w.stdout_sha256.is_empty()
        && !w.stderr_sha256.is_empty()
        && !w.argv.is_empty()
        && !w.cwd.is_empty()
        && !w.coverage_profraw_sha256.is_empty()
        && !w.wrapper_digest_sha256.is_empty()
}

fn span_contains_claim(span: &str, claim_text: &str) -> bool {
    span.contains(claim_text)
}

fn token_only_present(claim_text: &str, sources: &[FetchedSource]) -> bool {
    let tokens: Vec<&str> = claim_text
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|t| t.len() >= 3)
        .collect();
    if tokens.is_empty() {
        return false;
    }
    let combined: String = sources.iter().map(|s| s.body.as_str()).collect();
    tokens.iter().all(|t| {
        combined
            .to_ascii_lowercase()
            .contains(&t.to_ascii_lowercase())
    })
}

fn json_path_exists(value: &Value, path: &str) -> bool {
    let mut cur = value;
    for part in path.split('.').filter(|p| !p.is_empty()) {
        match cur {
            Value::Object(map) => match map.get(part) {
                Some(next) => cur = next,
                None => return false,
            },
            Value::Array(arr) => match part.parse::<usize>() {
                Ok(i) => match arr.get(i) {
                    Some(next) => cur = next,
                    None => return false,
                },
                Err(_) => return false,
            },
            _ => return false,
        }
    }
    true
}

fn make_result(
    claim_type: &str,
    action_id: Uuid,
    verdict: Verdict,
    reason_code: &str,
    detail: Option<String>,
    checked_location: Option<String>,
    evidence: &Value,
) -> GroundResult {
    GroundResult {
        claim_type: claim_type.to_string(),
        verdict,
        reason_code: reason_code.to_string(),
        detail,
        checked_location,
        evidence_sha256: sha256_hex(&serde_json::to_vec(evidence).unwrap_or_default()),
        timestamp: Utc::now(),
        action_id,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn unknown_claim_type_is_unsupported() {
        let claim: Claim = serde_json::from_str(r#"{"type":"made_up_claim"}"#).unwrap();
        assert!(matches!(claim.kind, ClaimKind::Unknown));
        let ctx = GroundContext {
            root: None,
            registry: BTreeMap::new(),
        };
        let r = verify_claim(&claim, &ctx).unwrap();
        assert_eq!(r.verdict, Verdict::Unsupported);
        assert_eq!(r.reason_code, "GROUND_UNKNOWN_CLAIM_TYPE");
    }

    #[test]
    fn file_exists_verified_and_refuted() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("present.txt");
        fs::write(&f, b"ok").unwrap();
        let ctx = GroundContext {
            root: Some(dir.path().to_path_buf()),
            registry: BTreeMap::new(),
        };
        let ok = Claim {
            kind: ClaimKind::FileExists,
            path: Some("present.txt".into()),
            symbol: None,
            package: None,
            version: None,
            schema_path: None,
            schema_key: None,
            claim_text: None,
            citations: None,
            sources: None,
            wrapper: None,
            claimed_pass: None,
        };
        let r = verify_claim(&ok, &ctx).unwrap();
        assert_eq!(r.verdict, Verdict::Verified);
        let miss = Claim {
            path: Some("absent.txt".into()),
            ..ok
        };
        let r2 = verify_claim(&miss, &ctx).unwrap();
        assert_eq!(r2.verdict, Verdict::Refuted);
    }

    #[test]
    fn source_supports_refuses_token_only() {
        let body = "The registry lists serde at version 1.0.0 and tokio at 1.37.";
        let hash = blake3::hash(body.as_bytes()).to_hex().to_string();
        let claim = Claim {
            kind: ClaimKind::SourceSupports,
            path: None,
            symbol: None,
            package: None,
            version: None,
            schema_path: None,
            schema_key: None,
            claim_text: Some("serde tokio".into()),
            citations: None,
            sources: Some(vec![FetchedSource {
                source_id: "doc1".into(),
                body: body.into(),
                body_blake3: hash,
            }]),
            wrapper: None,
            claimed_pass: None,
        };
        let r = verify_claim(
            &claim,
            &GroundContext {
                root: None,
                registry: BTreeMap::new(),
            },
        )
        .unwrap();
        assert_eq!(r.verdict, Verdict::Unsupported);
        assert_eq!(r.reason_code, "GROUND_SOURCE_TOKEN_ONLY");
    }

    #[test]
    fn source_supports_span_citation_verifies() {
        let body = "Package phantom-crate-xyz does not exist in crates.io.";
        let hash = blake3::hash(body.as_bytes()).to_hex().to_string();
        let excerpt = "phantom-crate-xyz does not exist";
        let start = body.find(excerpt).unwrap();
        let end = start + excerpt.len();
        let claim = Claim {
            kind: ClaimKind::SourceSupports,
            path: None,
            symbol: None,
            package: None,
            version: None,
            schema_path: None,
            schema_key: None,
            claim_text: Some(excerpt.into()),
            citations: Some(vec![Citation {
                source_id: "doc1".into(),
                span_start: start,
                span_end: end,
                excerpt: excerpt.into(),
            }]),
            sources: Some(vec![FetchedSource {
                source_id: "doc1".into(),
                body: body.into(),
                body_blake3: hash,
            }]),
            wrapper: None,
            claimed_pass: None,
        };
        let r = verify_claim(
            &claim,
            &GroundContext {
                root: None,
                registry: BTreeMap::new(),
            },
        )
        .unwrap();
        assert_eq!(r.verdict, Verdict::Verified);
        assert_eq!(r.reason_code, "GROUND_SOURCE_SUPPORTED");
    }

    #[test]
    fn tests_passed_without_receipt_unsupported() {
        let claim = Claim {
            kind: ClaimKind::TestsPassed,
            path: None,
            symbol: None,
            package: None,
            version: None,
            schema_path: None,
            schema_key: None,
            claim_text: None,
            citations: None,
            sources: None,
            wrapper: None,
            claimed_pass: Some(true),
        };
        let r = verify_claim(
            &claim,
            &GroundContext {
                root: None,
                registry: BTreeMap::new(),
            },
        )
        .unwrap();
        assert_eq!(r.verdict, Verdict::Unsupported);
        assert_eq!(r.reason_code, "GROUND_TEST_NO_RECEIPT");
    }

    #[test]
    fn dependency_phantom_refuted() {
        let mut registry = BTreeMap::new();
        registry.insert("serde".into(), vec!["1.0.0".into()]);
        let claim = Claim {
            kind: ClaimKind::DependencyExists,
            path: None,
            symbol: None,
            package: Some("phantom-crate-xyz".into()),
            version: Some("9.9.9".into()),
            schema_path: None,
            schema_key: None,
            claim_text: None,
            citations: None,
            sources: None,
            wrapper: None,
            claimed_pass: None,
        };
        let r = verify_claim(
            &claim,
            &GroundContext {
                root: None,
                registry,
            },
        )
        .unwrap();
        assert_eq!(r.verdict, Verdict::Refuted);
        assert_eq!(r.reason_code, "GROUND_DEP_MISSING");
    }

    #[test]
    fn api_schema_contains() {
        let dir = tempfile::tempdir().unwrap();
        let schema = dir.path().join("openapi.json");
        let mut f = fs::File::create(&schema).unwrap();
        f.write_all(br#"{"paths":{"/health":{"get":{}}}}"#).unwrap();
        let ctx = GroundContext {
            root: Some(dir.path().to_path_buf()),
            registry: BTreeMap::new(),
        };
        let claim = Claim {
            kind: ClaimKind::ApiSchemaContains,
            path: None,
            symbol: None,
            package: None,
            version: None,
            schema_path: Some("openapi.json".into()),
            schema_key: Some("paths./health.get".into()),
            claim_text: None,
            citations: None,
            sources: None,
            wrapper: None,
            claimed_pass: None,
        };
        let r = verify_claim(&claim, &ctx).unwrap();
        assert_eq!(r.verdict, Verdict::Verified);
    }
}
