use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use lia_gates::GateConfig;
use lia_journal::{append_signed, Journal, SigningIdentity};
use lia_protocol::{
    ActionAttempted, ActionKind, ActionObserved, ActionPayload, Event, EvidenceCaptured,
    GateVerdictEvent, HonestStopCondition, ProcessActionRef, ProcessCompletionPredicate,
    ProcessContract, ProcessContractDeclared, ProcessEvidenceRef, ProcessEvidenceRequirement,
    ProcessExecution, ProcessOutcome, RawHarnessEvent, RiskTier, TypedUnblockCondition, Verdict,
    PROCESS_CONTRACT_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AdapterError;
use crate::{
    process_contract_sha256, process_execution_manifest_sha256, validate_process_contract,
    ProcessValidationReport,
};

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

fn default_timeout_seconds() -> u64 {
    900
}

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
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    pub agent_argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapReport {
    pub run_id: Uuid,
    pub worktree: PathBuf,
    pub journal_path: PathBuf,
    pub agent_exit: i32,
    pub timed_out: bool,
    pub reason_code: String,
    pub detect_events: Vec<DetectEvent>,
    pub final_diff_sha256: Option<String>,
    pub mediation: String,
    pub process_contract_path: PathBuf,
    pub process_execution_path: PathBuf,
    pub process_validation: ProcessValidationReport,
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
    let identity = SigningIdentity::from_secret_key_hex(opts.key_id.clone(), &opts.secret_key_hex)?;
    let journal = if journal_path.exists() {
        Journal::open(&journal_path)?
    } else {
        Journal::create(&journal_path)?
    };
    let contract_id = Uuid::new_v4();
    let contract = ProcessContract {
        contract_version: PROCESS_CONTRACT_VERSION.into(),
        contract_id,
        run_id: opts.run_id,
        objective: "Run the wrapped agent process and admit only wrapper-observed completion"
            .into(),
        assumptions: Vec::new(),
        required_evidence: vec![
            ProcessEvidenceRequirement {
                id: "agent-exit".into(),
                kind: "generic-agent-exit".into(),
                description: "Exit status observed by the generic wrapper".into(),
                required: true,
            },
            ProcessEvidenceRequirement {
                id: "final-diff".into(),
                kind: "generic-final-diff".into(),
                description: "Final worktree diff hashed outside the child process".into(),
                required: true,
            },
        ],
        allowed_actions: vec![ActionKind::Other],
        completion_predicate: ProcessCompletionPredicate {
            all_evidence: vec!["agent-exit".into(), "final-diff".into()],
            require_all_assumptions_supported: true,
            require_no_unresolved_claims: true,
        },
        honest_stop_conditions: vec![
            HonestStopCondition {
                code: "wrapped-process-failed".into(),
                description: "The wrapped process exited nonzero".into(),
            },
            HonestStopCondition {
                code: "wrapped-process-timeout".into(),
                description: "The wrapper deadline expired".into(),
            },
        ],
    };
    let process_contract_path = opts.evidence_dir.join("process-contract.json");
    write_json_file(&process_contract_path, &contract)?;
    let contract_row = append_signed(
        &journal,
        opts.run_id,
        Event::ProcessContractDeclared(ProcessContractDeclared {
            contract_id,
            contract_version: contract.contract_version.clone(),
            contract_sha256: process_contract_sha256(&contract)
                .map_err(|error| AdapterError::Invalid(error.to_string()))?,
            timestamp: Utc::now(),
        }),
        &identity,
    )?;
    let action_id = Uuid::new_v4();
    let action_row = append_signed(
        &journal,
        opts.run_id,
        Event::ActionAttempted(ActionAttempted {
            action_id,
            kind: ActionKind::Other,
            payload: ActionPayload {
                command: None,
                path: None,
                content_sha256: None,
                argv: Some(opts.agent_argv.clone()),
                cwd: Some(worktree.display().to_string()),
                package: None,
                version: None,
                claim: Some("generic wrapped agent process".into()),
            },
            timestamp: Utc::now(),
        }),
        &identity,
    )?;

    let stop = Arc::new(AtomicBool::new(false));
    let detect_log = opts.evidence_dir.join("detect_events.jsonl");
    let mut watcher = if opts.watch {
        fs::File::create(&detect_log).map_err(|error| AdapterError::Invalid(error.to_string()))?;
        let stop_c = Arc::clone(&stop);
        let root = worktree.clone();
        let log_path = detect_log.clone();
        Some(thread::spawn(move || {
            watch_detect_only(root, log_path, stop_c)
        }))
    } else {
        None
    };

    let allow = opts.env_allowlist.clone().unwrap_or_else(|| {
        DEFAULT_ENV_ALLOWLIST
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    });
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

    let status_result = match cmd.spawn() {
        Ok(mut child) => {
            let timeout = Duration::from_secs(opts.timeout_seconds);
            let started = Instant::now();
            loop {
                if watcher.as_ref().is_some_and(|handle| handle.is_finished()) {
                    let (status, cleanup_error) = terminate_and_reap(&mut child);
                    let detail = cleanup_error.unwrap_or_else(|| {
                        "detect watcher stopped before the wrapped child exited".into()
                    });
                    break Ok((
                        status,
                        false,
                        Some(("GENERIC_OBSERVATION_INCOMPLETE", detail)),
                    ));
                }
                match child.try_wait() {
                    Ok(Some(status)) => break Ok((Some(status), false, None)),
                    Ok(None) if started.elapsed() >= timeout => {
                        let (status, cleanup_error) = terminate_and_reap(&mut child);
                        let failure =
                            cleanup_error.map(|detail| ("GENERIC_AGENT_CLEANUP_FAILED", detail));
                        break Ok((status, true, failure));
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(10)),
                    Err(error) => {
                        let (status, cleanup_error) = terminate_and_reap(&mut child);
                        let mut detail = format!("child status check failed: {error}");
                        if let Some(cleanup_error) = cleanup_error {
                            detail.push_str(&format!("; cleanup failed: {cleanup_error}"));
                        }
                        break Ok((
                            status,
                            false,
                            Some(("GENERIC_AGENT_CLEANUP_FAILED", detail)),
                        ));
                    }
                }
            }
        }
        Err(error) => Err(error),
    };

    stop.store(true, Ordering::SeqCst);
    let watcher_failure = if let Some(handle) = watcher.take() {
        match handle.join() {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(_) => Some("detect watcher panicked".into()),
        }
    } else {
        None
    };
    let (status, timed_out, execution_failure) = match status_result {
        Ok(result) => result,
        Err(error) => {
            append_signed(
                &journal,
                opts.run_id,
                Event::RawHarness(RawHarnessEvent {
                    harness: "generic".into(),
                    raw: serde_json::json!({
                        "action_id": action_id,
                        "reason_code": "GENERIC_AGENT_SPAWN_FAILED",
                        "error": error.to_string(),
                    }),
                    timestamp: Utc::now(),
                }),
                &identity,
            )?;
            return Err(AdapterError::Invalid(format!(
                "failed to spawn agent: {error}"
            )));
        }
    };
    let observation_failure = watcher_failure.filter(|_| {
        !matches!(
            execution_failure.as_ref(),
            Some((reason_code, _)) if *reason_code == "GENERIC_OBSERVATION_INCOMPLETE"
        )
    });
    let agent_exit = if timed_out {
        append_signed(
            &journal,
            opts.run_id,
            Event::RawHarness(RawHarnessEvent {
                harness: "generic".into(),
                raw: serde_json::json!({
                    "action_id": action_id,
                    "reason_code": "GENERIC_AGENT_TIMEOUT",
                    "timeout_seconds": opts.timeout_seconds,
                }),
                timestamp: Utc::now(),
            }),
            &identity,
        )?;
        124
    } else {
        status.as_ref().and_then(ExitStatus::code).unwrap_or(1)
    };
    let reason_code = if timed_out {
        "GENERIC_AGENT_TIMEOUT"
    } else {
        "GENERIC_AGENT_EXITED"
    };
    if let Some((reason_code, detail)) = &execution_failure {
        append_signed(
            &journal,
            opts.run_id,
            Event::RawHarness(RawHarnessEvent {
                harness: "generic".into(),
                raw: serde_json::json!({
                    "action_id": action_id,
                    "reason_code": reason_code,
                    "detail": detail,
                }),
                timestamp: Utc::now(),
            }),
            &identity,
        )?;
    }
    if let Some(detail) = &observation_failure {
        append_signed(
            &journal,
            opts.run_id,
            Event::RawHarness(RawHarnessEvent {
                harness: "generic".into(),
                raw: serde_json::json!({
                    "action_id": action_id,
                    "reason_code": "GENERIC_OBSERVATION_INCOMPLETE",
                    "detail": detail,
                }),
                timestamp: Utc::now(),
            }),
            &identity,
        )?;
    }
    append_signed(
        &journal,
        opts.run_id,
        Event::ActionObserved(ActionObserved {
            action_id,
            exit_code: Some(agent_exit),
            stdout_sha256: None,
            stderr_sha256: None,
            coverage_profraw_sha256: None,
            wrapper_digest_sha256: None,
            timestamp: Utc::now(),
        }),
        &identity,
    )?;

    if let Some((reason_code, detail)) = execution_failure {
        return Err(AdapterError::Invalid(format!(
            "{reason_code}: {detail}; evidence journal={}",
            journal_path.display()
        )));
    }
    if let Some(detail) = observation_failure {
        return Err(AdapterError::Invalid(format!(
            "GENERIC_OBSERVATION_INCOMPLETE: {detail}; evidence journal={}",
            journal_path.display()
        )));
    }

    let detect_events = read_detect_events(&detect_log, opts.watch)?;
    let final_diff_sha256 = compute_worktree_diff_sha(&repo_canon, &worktree)?;
    let exit_evidence_id = Uuid::new_v4();
    let exit_bytes = serde_json::to_vec(&serde_json::json!({
        "agent_exit": agent_exit,
        "timed_out": timed_out,
        "reason_code": reason_code,
    }))
    .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    let exit_sha256 = sha256_bytes(&exit_bytes);
    let exit_evidence_row = append_signed(
        &journal,
        opts.run_id,
        Event::EvidenceCaptured(EvidenceCaptured {
            evidence_id: exit_evidence_id,
            kind: "generic-agent-exit".into(),
            path: None,
            sha256: exit_sha256.clone(),
            bytes: None,
            timestamp: Utc::now(),
        }),
        &identity,
    )?;
    let diff_evidence_id = Uuid::new_v4();
    let diff_evidence_row = append_signed(
        &journal,
        opts.run_id,
        Event::EvidenceCaptured(EvidenceCaptured {
            evidence_id: diff_evidence_id,
            kind: "generic-final-diff".into(),
            path: Some(worktree.display().to_string()),
            sha256: final_diff_sha256.clone(),
            bytes: None,
            timestamp: Utc::now(),
        }),
        &identity,
    )?;
    let contract_receipt = receipt_id(&contract_row)?;
    let action_receipt = receipt_id(&action_row)?;
    let exit_receipt = receipt_id(&exit_evidence_row)?;
    let diff_receipt = receipt_id(&diff_evidence_row)?;
    let outcome = if agent_exit == 0 && !timed_out {
        ProcessOutcome::Complete {
            receipt_id: Uuid::nil(),
        }
    } else {
        ProcessOutcome::HonestStop {
            condition_code: if timed_out {
                "wrapped-process-timeout"
            } else {
                "wrapped-process-failed"
            }
            .into(),
            receipt_id: Uuid::nil(),
            unblocks: vec![TypedUnblockCondition {
                tried: vec![format!("executed {}", opts.agent_argv.join(" "))],
                missing: if timed_out {
                    "a completion within the configured deadline"
                } else {
                    "a zero exit status from the wrapped process"
                }
                .into(),
                route: "inspect the signed journal and rerun with corrected inputs or policy"
                    .into(),
            }],
        }
    };
    let mut execution = ProcessExecution {
        contract_id,
        contract_receipt_id: contract_receipt,
        performed_actions: vec![ProcessActionRef {
            action_id,
            kind: ActionKind::Other,
            receipt_id: action_receipt,
        }],
        evidence: vec![
            ProcessEvidenceRef {
                requirement_id: "agent-exit".into(),
                evidence_id: exit_evidence_id,
                receipt_id: exit_receipt,
                kind: "generic-agent-exit".into(),
                sha256: exit_sha256,
            },
            ProcessEvidenceRef {
                requirement_id: "final-diff".into(),
                evidence_id: diff_evidence_id,
                receipt_id: diff_receipt,
                kind: "generic-final-diff".into(),
                sha256: final_diff_sha256.clone(),
            },
        ],
        supported_assumptions: Vec::new(),
        unresolved_claims: Vec::new(),
        outcome,
    };
    let execution_manifest_sha256 = process_execution_manifest_sha256(&contract, &execution)
        .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    let completion_row = append_signed(
        &journal,
        opts.run_id,
        Event::GateVerdict(GateVerdictEvent {
            action_id,
            gate_id: "process-contract".into(),
            verdict: if agent_exit == 0 && !timed_out {
                Verdict::Verified
            } else {
                Verdict::Incomplete
            },
            reason_code: if agent_exit == 0 && !timed_out {
                "PROCESS_WRAPPER_COMPLETED"
            } else if timed_out {
                "wrapped-process-timeout"
            } else {
                "wrapped-process-failed"
            }
            .into(),
            risk_tier: RiskTier::Quality,
            detail: Some(format!(
                "wrapper observed exit={agent_exit} timed_out={timed_out}"
            )),
            evidence_sha256: Some(execution_manifest_sha256),
            timestamp: Utc::now(),
        }),
        &identity,
    )?;
    let completion_receipt = receipt_id(&completion_row)?;
    match &mut execution.outcome {
        ProcessOutcome::Complete { receipt_id } | ProcessOutcome::HonestStop { receipt_id, .. } => {
            *receipt_id = completion_receipt
        }
        ProcessOutcome::InProgress => {
            return Err(AdapterError::Invalid(
                "generic wrapper produced a non-terminal process outcome".into(),
            ))
        }
    }
    let process_execution_path = opts.evidence_dir.join("process-execution.json");
    write_json_file(&process_execution_path, &execution)?;
    let process_validation = validate_process_contract(&contract, &execution, &journal_path)
        .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    if !process_validation.followed {
        return Err(AdapterError::Invalid(format!(
            "generic process contract rejected: {}",
            process_validation.reason_code
        )));
    }

    Ok(WrapReport {
        run_id: opts.run_id,
        worktree,
        journal_path,
        agent_exit,
        timed_out,
        reason_code: reason_code.into(),
        detect_events,
        final_diff_sha256: Some(final_diff_sha256),
        mediation: "mediation: incomplete — an out-of-band process can bypass LIA on this harness; native ELAI's process-isolation closes this".into(),
        process_contract_path,
        process_execution_path,
        process_validation,
    })
}

fn receipt_id(row: &lia_protocol::JournalRow) -> Result<Uuid, AdapterError> {
    row.receipt
        .as_ref()
        .map(|receipt| receipt.receipt_id)
        .ok_or_else(|| AdapterError::Invalid("signed journal row missing receipt".into()))
}

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), AdapterError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| AdapterError::Invalid(error.to_string()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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
                repo.to_str()
                    .ok_or_else(|| AdapterError::Invalid("repo path".into()))?,
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

#[derive(Default)]
struct CleanupErrorSummary {
    count: u64,
    first: Option<String>,
    last: Option<String>,
}

impl CleanupErrorSummary {
    fn record(&mut self, message: String) {
        self.count = self.count.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(message.clone());
        }
        self.last = Some(message);
    }

    fn render(&self) -> Option<String> {
        let first = self.first.as_deref()?;
        if self.count == 1 {
            return Some(first.to_owned());
        }
        Some(format!(
            "cleanup errors={} first={first}; last={}",
            self.count,
            self.last.as_deref().unwrap_or(first)
        ))
    }
}

fn terminate_and_reap(child: &mut std::process::Child) -> (Option<ExitStatus>, Option<String>) {
    let mut cleanup_errors = CleanupErrorSummary::default();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (Some(status), cleanup_errors.render()),
            Ok(None) => {}
            Err(error) => cleanup_errors.record(format!("status check failed: {error}")),
        }
        match child.kill() {
            Ok(()) => break,
            Err(error) => {
                cleanup_errors.record(format!("kill failed: {error}"));
                // Never release a child that may still be executing. A kernel-level refusal to
                // terminate is fail-stop: keep observation alive and retry instead of returning.
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    loop {
        match child.wait() {
            Ok(status) => return (Some(status), cleanup_errors.render()),
            Err(error) => {
                cleanup_errors.record(format!("reap failed: {error}"));
                match child.try_wait() {
                    Ok(Some(status)) => return (Some(status), cleanup_errors.render()),
                    Ok(None) | Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        }
    }
}

fn watch_detect_only(
    root: PathBuf,
    log_path: PathBuf,
    stop: Arc<AtomicBool>,
) -> Result<(), AdapterError> {
    let mut baseline = snapshot_paths(&root)?;
    loop {
        thread::sleep(Duration::from_millis(200));
        let now = snapshot_paths(&root)?;
        for p in now.difference(&baseline) {
            append_detect(&log_path, p, "created_or_modified")?;
        }
        for p in baseline.difference(&now) {
            append_detect(&log_path, p, "deleted")?;
        }
        baseline = now;
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
    }
}

fn snapshot_paths(root: &Path) -> Result<BTreeSet<String>, AdapterError> {
    let mut out = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|error| {
            AdapterError::Invalid(format!(
                "snapshot read failed at {}: {error}",
                dir.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| AdapterError::Invalid(error.to_string()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| AdapterError::Invalid(error.to_string()))?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let rel = path.strip_prefix(root).map_err(|error| {
                    AdapterError::Invalid(format!("snapshot path escaped root: {error}"))
                })?;
                out.insert(rel.to_string_lossy().to_string());
            }
        }
    }
    Ok(out)
}

fn append_detect(log_path: &Path, path: &str, kind: &str) -> Result<(), AdapterError> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let line = serde_json::json!({"path": path, "kind": kind});
    writeln!(f, "{line}").map_err(|e| AdapterError::Invalid(e.to_string()))?;
    f.sync_data()
        .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    Ok(())
}

fn read_detect_events(path: &Path, required: bool) -> Result<Vec<DetectEvent>, AdapterError> {
    let mut out = Vec::new();
    let mut f = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(error) => return Err(AdapterError::Invalid(error.to_string())),
    };
    let mut buf = String::new();
    f.read_to_string(&mut buf)
        .map_err(|error| AdapterError::Invalid(error.to_string()))?;
    for line in buf.lines() {
        let event = serde_json::from_str::<DetectEvent>(line)
            .map_err(|error| AdapterError::Invalid(error.to_string()))?;
        out.push(event);
    }
    Ok(out)
}

fn compute_worktree_diff_sha(repo: &Path, worktree: &Path) -> Result<String, AdapterError> {
    let mut hasher = Sha256::new();
    let paths = snapshot_paths(worktree)?;
    let base = snapshot_paths(repo)?;
    for p in paths.union(&base) {
        hasher.update(p.as_bytes());
        let a = worktree.join(p);
        let b = repo.join(p);
        let a_bytes = if a.is_file() {
            fs::read(&a).map_err(|error| AdapterError::Invalid(error.to_string()))?
        } else {
            Vec::new()
        };
        let b_bytes = if b.is_file() {
            fs::read(&b).map_err(|error| AdapterError::Invalid(error.to_string()))?
        } else {
            Vec::new()
        };
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
