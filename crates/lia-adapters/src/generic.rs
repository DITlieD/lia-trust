use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lia_gates::GateConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::dispatch::RunContext;
use crate::AdapterError;

const DEFAULT_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TERM",
    "TMPDIR",
    "TMP",
    "TEMP",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "SSH_AUTH_SOCK",
    "DISPLAY",
    "XDG_RUNTIME_DIR",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapOptions {
    pub repo: PathBuf,
    pub evidence_dir: PathBuf,
    pub run_id: Uuid,
    pub config: GateConfig,
    pub secret_key_hex: String,
    pub key_id: String,
    #[serde(default)]
    pub env_allowlist: Option<Vec<String>>,
    #[serde(default)]
    pub watch: bool,
    pub agent_argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapReport {
    pub run_id: Uuid,
    pub worktree: PathBuf,
    pub journal_path: PathBuf,
    pub agent_exit: i32,
    pub detect_events: Vec<DetectEvent>,
    pub final_diff_sha256: Option<String>,
    pub mediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectEvent {
    pub path: String,
    pub kind: String,
}

pub fn wrap(opts: WrapOptions) -> Result<WrapReport, AdapterError> {
    if opts.agent_argv.is_empty() {
        return Err(AdapterError::Invalid("wrap requires agent argv".into()));
    }
    fs::create_dir_all(&opts.evidence_dir).map_err(|e| AdapterError::Invalid(e.to_string()))?;

    let evidence_canon = canonicalize_path(&opts.evidence_dir)?;
    let repo_canon = canonicalize_path(&opts.repo)?;
    if evidence_canon.starts_with(&repo_canon) {
        return Err(AdapterError::Invalid(
            "evidence_dir must be outside the agent writable repo/worktree".into(),
        ));
    }

    let worktree = opts.evidence_dir.join(format!("worktree-{}", opts.run_id));
    create_isolated_worktree(&repo_canon, &worktree)?;

    let journal_path = opts.evidence_dir.join("journal.db");
    if journal_path.exists() {
        let jp = canonicalize_path(&journal_path)?;
        if jp.starts_with(&worktree) {
            return Err(AdapterError::Invalid(
                "journal must remain outside child writable area".into(),
            ));
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let detect_log = opts.evidence_dir.join("detect_events.jsonl");
    let watcher = if opts.watch {
        let stop_c = Arc::clone(&stop);
        let root = worktree.clone();
        let log_path = detect_log.clone();
        Some(thread::spawn(move || watch_detect_only(root, log_path, stop_c)))
    } else {
        None
    };

    let allow = opts
        .env_allowlist
        .clone()
        .unwrap_or_else(|| DEFAULT_ENV_ALLOWLIST.iter().map(|s| (*s).to_string()).collect());
    let child_env = filter_env(&allow);

    let mut cmd = Command::new(&opts.agent_argv[0]);
    if opts.agent_argv.len() > 1 {
        cmd.args(&opts.agent_argv[1..]);
    }
    cmd.current_dir(&worktree)
        .env_clear()
        .envs(child_env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| AdapterError::Invalid(format!("failed to spawn agent: {e}")))?;
    let agent_exit = status.code().unwrap_or(1);

    stop.store(true, Ordering::SeqCst);
    if let Some(handle) = watcher {
        let _ = handle.join();
    }

    let detect_events = read_detect_events(&detect_log);
    let final_diff_sha256 = compute_worktree_diff_sha(&repo_canon, &worktree).ok();

    let _ctx = RunContext {
        run_id: opts.run_id,
        config: opts.config,
        journal_path: Some(journal_path.clone()),
        secret_key_hex: Some(opts.secret_key_hex),
        key_id: Some(opts.key_id),
    };
    let _ = _ctx;

    Ok(WrapReport {
        run_id: opts.run_id,
        worktree,
        journal_path,
        agent_exit,
        detect_events,
        final_diff_sha256,
        mediation: "mediation: incomplete — an out-of-band process can bypass LIA on this harness; native ELAI's process-isolation closes this".into(),
    })
}

fn create_isolated_worktree(repo: &Path, worktree: &Path) -> Result<(), AdapterError> {
    if worktree.exists() {
        return Err(AdapterError::Invalid(format!(
            "worktree already exists: {}",
            worktree.display()
        )));
    }
    if repo.join(".git").exists() {
        let status = Command::new("git")
            .args([
                "-C",
                repo.to_str().ok_or_else(|| AdapterError::Invalid("repo path".into()))?,
                "worktree",
                "add",
                "--detach",
                worktree
                    .to_str()
                    .ok_or_else(|| AdapterError::Invalid("worktree path".into()))?,
            ])
            .status()
            .map_err(|e| AdapterError::Invalid(e.to_string()))?;
        if status.success() {
            return Ok(());
        }
    }
    copy_dir_recursive(repo, worktree)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), AdapterError> {
    fs::create_dir_all(dst).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    for entry in fs::read_dir(src).map_err(|e| AdapterError::Invalid(e.to_string()))? {
        let entry = entry.map_err(|e| AdapterError::Invalid(e.to_string()))?;
        let ty = entry
            .file_type()
            .map_err(|e| AdapterError::Invalid(e.to_string()))?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            if entry.file_name() == ".git" {
                continue;
            }
            copy_dir_recursive(&entry.path(), &to)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), &to).map_err(|e| AdapterError::Invalid(e.to_string()))?;
        }
    }
    Ok(())
}

fn filter_env(allowlist: &[String]) -> BTreeMap<String, String> {
    let allow: BTreeSet<String> = allowlist.iter().cloned().collect();
    std::env::vars()
        .filter(|(k, _)| allow.contains(k))
        .collect()
}

fn watch_detect_only(root: PathBuf, log_path: PathBuf, stop: Arc<AtomicBool>) {
    let mut baseline = snapshot_paths(&root);
    while !stop.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
        let now = snapshot_paths(&root);
        for p in now.difference(&baseline) {
            let _ = append_detect(&log_path, p, "created_or_modified");
        }
        for p in baseline.difference(&now) {
            let _ = append_detect(&log_path, p, "deleted");
        }
        baseline = now;
    }
}

fn snapshot_paths(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(rel) = path.strip_prefix(root) {
                out.insert(rel.to_string_lossy().to_string());
            }
        }
    }
    out
}

fn append_detect(log_path: &Path, path: &str, kind: &str) -> Result<(), AdapterError> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let line = serde_json::json!({"path": path, "kind": kind});
    writeln!(f, "{line}").map_err(|e| AdapterError::Invalid(e.to_string()))?;
    Ok(())
}

fn read_detect_events(path: &Path) -> Vec<DetectEvent> {
    let mut out = Vec::new();
    let Ok(mut f) = fs::File::open(path) else {
        return out;
    };
    let mut buf = String::new();
    let _ = f.read_to_string(&mut buf);
    for line in buf.lines() {
        if let Ok(ev) = serde_json::from_str::<DetectEvent>(line) {
            out.push(ev);
        }
    }
    out
}

fn compute_worktree_diff_sha(repo: &Path, worktree: &Path) -> Result<String, AdapterError> {
    let mut hasher = Sha256::new();
    let paths = snapshot_paths(worktree);
    let base = snapshot_paths(repo);
    for p in paths.union(&base) {
        hasher.update(p.as_bytes());
        let a = worktree.join(p);
        let b = repo.join(p);
        let a_bytes = fs::read(&a).unwrap_or_default();
        let b_bytes = fs::read(&b).unwrap_or_default();
        if a_bytes != b_bytes {
            hasher.update(&a_bytes);
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

fn canonicalize_path(path: &Path) -> Result<PathBuf, AdapterError> {
    fs::create_dir_all(path).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    fs::canonicalize(path).map_err(|e| AdapterError::Invalid(e.to_string()))
}

pub fn admit_final_diff(
    repo: &Path,
    worktree: &Path,
    allow: bool,
) -> Result<Option<String>, AdapterError> {
    if !allow {
        return Ok(None);
    }
    let sha = compute_worktree_diff_sha(repo, worktree)?;
    Ok(Some(sha))
}
