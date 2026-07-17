use std::fs;
use std::path::{Path, PathBuf};

use lia_gates::{GatePayload, GateRequest};
use lia_protocol::ActionKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::BenchError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum CaseClass {
    FabricatedPass,
    OosWrite,
    OosDelete,
    HallucinatedDep,
    UnsupportedClaim,
    UnsupportedAgreement,
    SecretLeak,
    JournalTamper,
    Benign,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum CaseRole {
    Adversarial,
    Benign,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum EntryKind {
    Action,
    Request,
    Ground,
    Syco,
    Hook,
    Mcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CorpusCase {
    pub id: String,
    pub class: CaseClass,
    pub role: CaseRole,
    pub entry: EntryKind,
    #[serde(default)]
    pub action: Option<ActionSpec>,
    #[serde(default)]
    pub request: Option<GateRequest>,
    #[serde(default)]
    pub claim: Option<ValueOrRaw>,
    #[serde(default)]
    pub exchange: Option<ValueOrRaw>,
    #[serde(default)]
    pub hook: Option<serde_json::Value>,
    #[serde(default)]
    pub mcp: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ValueOrRaw {
    Value(serde_json::Value),
    Raw(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub kind: ActionKind,
    pub action_id: Uuid,
    pub payload: GatePayload,
}

pub fn assert_corpus_hardened(corpus: &Path) -> Result<(), BenchError> {
    if !corpus.is_dir() {
        return Err(BenchError::Abort(format!(
            "corpus {} is not a directory",
            corpus.display()
        )));
    }
    for entry in WalkDir::new(corpus) {
        let entry = entry.map_err(|e| BenchError::Io(e.into()))?;
        let name = entry.file_name().to_string_lossy();
        if name == ".git" || name.ends_with(".git") {
            return Err(BenchError::Abort(format!(
                "corpus carries git metadata at {}; STOP (git-STRIP required)",
                entry.path().display()
            )));
        }
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "patch" | "fix" | "rej") {
                return Err(BenchError::Abort(format!(
                    "corpus carries fix metadata {}; STOP",
                    path.display()
                )));
            }
        }
        let lower = name.to_ascii_lowercase();
        if lower.contains("fixme") || lower == "solution" || lower == "answer.key" {
            return Err(BenchError::Abort(format!(
                "corpus carries fix metadata {}; STOP",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn load_corpus(corpus: &Path) -> Result<Vec<CorpusCase>, BenchError> {
    assert_corpus_hardened(corpus)?;
    let mut cases = Vec::new();
    for entry in WalkDir::new(corpus).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) != Some("case.json") {
            continue;
        }
        let bytes = fs::read(path)?;
        let case: CorpusCase = serde_json::from_slice(&bytes)?;
        cases.push(case);
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    if cases.is_empty() {
        return Err(BenchError::Invalid(format!(
            "no case.json under {}",
            corpus.display()
        )));
    }
    Ok(cases)
}

pub fn corpus_sha256(corpus: &Path) -> Result<String, BenchError> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(corpus).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            paths.push(entry.path().to_path_buf());
        }
    }
    paths.sort();
    let mut hasher = Sha256::new();
    for p in paths {
        let rel = p.strip_prefix(corpus).unwrap_or(&p);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(&fs::read(&p)?);
        hasher.update(b"\0");
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn assert_skill_free(repo: &Path) -> Result<(), BenchError> {
    let banned = [
        ".claude",
        ".cursor",
        ".codex",
        "AGENTS.md",
        "CLAUDE.md",
        ".lia-skills",
    ];
    for b in banned {
        let p = repo.join(b);
        if p.exists() {
            return Err(BenchError::Abort(format!(
                "repo not skill-free: {} present",
                p.display()
            )));
        }
    }
    Ok(())
}

pub fn make_throwaway_repo(parent: &Path) -> Result<PathBuf, BenchError> {
    let repo = parent.join("repo");
    fs::create_dir_all(repo.join("src"))?;
    fs::write(repo.join("src/main.rs"), "fn main() {}\n")?;
    fs::write(repo.join("README"), "empty-harness throwaway\n")?;
    assert_skill_free(&repo)?;
    Ok(repo)
}
