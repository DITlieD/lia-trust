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
    ActionAttempted, ActionKind, ActionObserved, ActionPayload, ConfinementApplied, Event,
    EvidenceCaptured, GateVerdictEvent, HonestStopCondition, ProcessActionRef, ProcessAssumption,
    ProcessCompletionPredicate, ProcessContract, ProcessContractDeclared, ProcessEvidenceRef,
    ProcessEvidenceRequirement, ProcessExecution, ProcessOutcome, RawHarnessEvent, RiskTier,
    TypedUnblockCondition, Verdict, PROCESS_CONTRACT_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AdapterError;
use crate::{
    process_contract_sha256, process_execution_manifest_sha256, spawn_linux_confined,
    validate_process_contract, ConfinementReport, LinuxConfinementOptions, ProcessValidationReport,
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
    #[serde(default)]
    pub confinement: Option<LinuxConfinementOptions>,
    pub agent_argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapReport {
    pub run_id: Uuid,
    pub worktree: PathBuf,
    pub journal_path: PathBuf,
    pub agent_exit: i32,
    pub timed_out: bool,
    pub trust_boundary_failed: bool,
    pub reason_code: String,
    pub detect_events: Vec<DetectEvent>,
    pub final_diff_sha256: Option<String>,
    pub mediation: String,
    pub process_contract_path: PathBuf,
    pub process_execution_path: PathBuf,
    pub process_validation: ProcessValidationReport,
    pub confinement_report_path: Option<PathBuf>,
    pub confinement: Option<ConfinementReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectEvent {
    pub path: String,
    pub kind: String,
}

enum ManagedChild {
    Direct(std::process::Child),
    #[cfg(target_os = "linux")]
    Confined(Box<crate::confinement::ConfinedChild>),
}

impl ManagedChild {
    fn child_mut(&mut self) -> &mut std::process::Child {
        match self {
            Self::Direct(child) => child,
            #[cfg(target_os = "linux")]
            Self::Confined(child) => child.child_mut(),
        }
    }

    fn finish_auxiliaries(&mut self) -> Result<(), AdapterError> {
        match self {
            Self::Direct(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::Confined(child) => child.finish_brokers(),
        }
    }
}

pub fn wrap(opts: WrapOptions) -> Result<WrapReport, AdapterError> {
    if opts.agent_argv.is_empty() {
        return Err(AdapterError::Invalid("wrap requires agent argv".into()));
    }
    fs::create_dir_all(&opts.evidence_dir).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    make_evidence_private(&opts.evidence_dir)?;

    let evidence_canon = canonicalize_directory(&opts.evidence_dir)?;
    let repo_canon = canonicalize_directory(&opts.repo)?;
    if evidence_canon.starts_with(&repo_canon) {
        return Err(AdapterError::Invalid(
            "evidence_dir must be outside the agent writable repo/worktree".into(),
        ));
    }

    let worktree_path = evidence_canon.join(format!("worktree-{}", opts.run_id));
    create_isolated_worktree(&repo_canon, &worktree_path)?;
    let worktree = canonicalize_directory(&worktree_path)?;

    let journal_path = evidence_canon.join("journal.db");
    if journal_path.exists() {
        let jp = fs::canonicalize(&journal_path)
            .map_err(|error| AdapterError::Invalid(error.to_string()))?;
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
    let confinement_requested = opts.confinement.is_some();
    let mut required_evidence = vec![
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
    ];
    let mut all_evidence = vec!["agent-exit".into(), "final-diff".into()];
    let mut assumptions = Vec::new();
    if confinement_requested {
        required_evidence.push(ProcessEvidenceRequirement {
            id: "linux-confinement".into(),
            kind: "generic-linux-confinement".into(),
            description: "Wrapper-observed namespace and Landlock readiness attestation".into(),
            required: true,
        });
        all_evidence.push("linux-confinement".into());
        assumptions.push(ProcessAssumption {
            id: "linux-confinement-active".into(),
            statement: "The wrapped child executes only after the Linux confinement handshake"
                .into(),
            required_evidence: vec!["linux-confinement".into()],
        });
    }
    let contract_id = Uuid::new_v4();
    let contract = ProcessContract {
        contract_version: PROCESS_CONTRACT_VERSION.into(),
        contract_id,
        run_id: opts.run_id,
        objective: "Run the wrapped agent process and admit only wrapper-observed completion"
            .into(),
        assumptions,
        required_evidence,
        allowed_actions: vec![ActionKind::Other],
        completion_predicate: ProcessCompletionPredicate {
            all_evidence,
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
            HonestStopCondition {
                code: "wrapped-process-observation-incomplete".into(),
                description: "The wrapper could not complete its required observation boundary"
                    .into(),
            },
            HonestStopCondition {
                code: "credential-broker-failed".into(),
                description: "A scoped credential broker rejected or lost its request channel"
                    .into(),
            },
        ],
    };
    let process_contract_path =
        evidence_canon.join(format!("process-contract-{}.json", opts.run_id));
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
    let detect_log = evidence_canon.join("detect_events.jsonl");
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
    let child_env = if confinement_requested {
        confined_env(&worktree, &allow)?
    } else {
        filter_env(&allow)
    };
    let mut confinement_report = None;
    let mut confinement_report_path = None;
    let mut confinement_evidence: Option<(Uuid, Uuid, String)> = None;
    let spawn_result: Result<ManagedChild, AdapterError> = if let Some(options) = &opts.confinement
    {
        #[cfg(target_os = "linux")]
        {
            spawn_linux_confined(
                options,
                &worktree,
                &evidence_canon,
                &opts.agent_argv,
                &child_env,
            )
            .and_then(|mut confined| {
                let report = confined.report.clone();
                let report_bytes = serde_json::to_vec(&report)
                    .map_err(|error| AdapterError::Invalid(error.to_string()))?;
                let report_sha256 = sha256_bytes(&report_bytes);
                let report_path =
                    evidence_canon.join(format!("confinement-report-{}.json", opts.run_id));
                write_private_bytes_new(&report_path, &report_bytes)?;
                append_signed(
                    &journal,
                    opts.run_id,
                    Event::ConfinementApplied(ConfinementApplied {
                        backend: report.backend.clone(),
                        helper_sha256: report.helper_sha256.clone(),
                        network_namespace: report.network_namespace.clone(),
                        mount_namespace: report.mount_namespace.clone(),
                        pid_namespace: report.pid_namespace.clone(),
                        landlock_abi: report.landlock_abi,
                        ip_egress_blocked: report.ip_egress_blocked,
                        host_path_writes_blocked: report.host_path_writes_blocked,
                        evidence_artifacts_write_blocked: report.evidence_artifacts_write_blocked,
                        attestation_sha256: report_sha256.clone(),
                        credential_names: report.credential_names.clone(),
                        timestamp: Utc::now(),
                    }),
                    &identity,
                )?;
                let evidence_id = Uuid::new_v4();
                let evidence_row = append_signed(
                    &journal,
                    opts.run_id,
                    Event::EvidenceCaptured(EvidenceCaptured {
                        evidence_id,
                        kind: "generic-linux-confinement".into(),
                        path: Some(report_path.display().to_string()),
                        sha256: report_sha256.clone(),
                        bytes: Some(report_bytes.len() as u64),
                        timestamp: Utc::now(),
                    }),
                    &identity,
                )?;
                let evidence_receipt = receipt_id(&evidence_row)?;
                confined.release()?;
                confinement_report = Some(report);
                confinement_report_path = Some(report_path);
                confinement_evidence = Some((evidence_id, evidence_receipt, report_sha256));
                Ok(ManagedChild::Confined(Box::new(confined)))
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = options;
            Err(AdapterError::Invalid(
                "CONFINEMENT_UNAVAILABLE: Linux namespace backend requires Linux".into(),
            ))
        }
    } else {
        let mut cmd = Command::new(&opts.agent_argv[0]);
        if opts.agent_argv.len() > 1 {
            cmd.args(&opts.agent_argv[1..]);
        }
        cmd.current_dir(&worktree)
            .env_clear()
            .envs(&child_env)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        cmd.spawn()
            .map(ManagedChild::Direct)
            .map_err(|error| AdapterError::Invalid(error.to_string()))
    };

    let status_result: Result<_, AdapterError> = match spawn_result {
        Ok(mut managed) => {
            let timeout = Duration::from_secs(opts.timeout_seconds);
            let started = Instant::now();
            let result = loop {
                if watcher.as_ref().is_some_and(|handle| handle.is_finished()) {
                    let (status, cleanup_error) = terminate_and_reap(managed.child_mut());
                    let detail = cleanup_error.unwrap_or_else(|| {
                        "detect watcher stopped before the wrapped child exited".into()
                    });
                    break Ok((
                        status,
                        false,
                        Some(("GENERIC_OBSERVATION_INCOMPLETE", detail)),
                    ));
                }
                match managed.child_mut().try_wait() {
                    Ok(Some(status)) => break Ok((Some(status), false, None)),
                    Ok(None) if started.elapsed() >= timeout => {
                        let (status, cleanup_error) = terminate_and_reap(managed.child_mut());
                        let failure =
                            cleanup_error.map(|detail| ("GENERIC_AGENT_CLEANUP_FAILED", detail));
                        break Ok((status, true, failure));
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(10)),
                    Err(error) => {
                        let (status, cleanup_error) = terminate_and_reap(managed.child_mut());
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
            };
            match managed.finish_auxiliaries() {
                Ok(()) => result,
                Err(error) => match result {
                    Ok((status, timed_out, _)) => Ok((
                        status,
                        timed_out,
                        Some(("CREDENTIAL_BROKER_FAILED", error.to_string())),
                    )),
                    Err(existing) => Err(existing),
                },
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
            return Err(error);
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
    let credential_broker_failed = matches!(
        execution_failure.as_ref(),
        Some(("CREDENTIAL_BROKER_FAILED", _))
    );
    let trust_boundary_failed = credential_broker_failed;
    let reason_code = if timed_out {
        "GENERIC_AGENT_TIMEOUT"
    } else if let Some((failure_code, _)) = &execution_failure {
        *failure_code
    } else if observation_failure.is_some() {
        "GENERIC_OBSERVATION_INCOMPLETE"
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

    if let Some((reason_code, detail)) = &execution_failure {
        if !credential_broker_failed {
            return Err(AdapterError::Invalid(format!(
                "{reason_code}: {detail}; evidence journal={}",
                journal_path.display()
            )));
        }
    }
    if let Some(detail) = &observation_failure {
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
        "trust_boundary_failed": trust_boundary_failed,
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
    let completed = agent_exit == 0 && !timed_out && !trust_boundary_failed;
    let honest_stop_code = if timed_out {
        "wrapped-process-timeout"
    } else if matches!(
        execution_failure.as_ref(),
        Some(("CREDENTIAL_BROKER_FAILED", _))
    ) {
        "credential-broker-failed"
    } else if trust_boundary_failed {
        "wrapped-process-observation-incomplete"
    } else {
        "wrapped-process-failed"
    };
    let outcome = if completed {
        ProcessOutcome::Complete {
            receipt_id: Uuid::nil(),
        }
    } else {
        ProcessOutcome::HonestStop {
            condition_code: honest_stop_code.into(),
            receipt_id: Uuid::nil(),
            unblocks: vec![TypedUnblockCondition {
                tried: vec![format!("executed {}", opts.agent_argv.join(" "))],
                missing: if timed_out {
                    "a completion within the configured deadline"
                } else if trust_boundary_failed {
                    "a complete wrapper observation and credential-broker lifecycle"
                } else {
                    "a zero exit status from the wrapped process"
                }
                .into(),
                route: "inspect the signed journal and rerun with corrected inputs or policy"
                    .into(),
            }],
        }
    };
    let mut execution_evidence = vec![
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
    ];
    let mut supported_assumptions = Vec::new();
    if let Some((evidence_id, receipt_id, sha256)) = confinement_evidence {
        execution_evidence.push(ProcessEvidenceRef {
            requirement_id: "linux-confinement".into(),
            evidence_id,
            receipt_id,
            kind: "generic-linux-confinement".into(),
            sha256,
        });
        supported_assumptions.push("linux-confinement-active".into());
    }
    let mut execution = ProcessExecution {
        contract_id,
        contract_receipt_id: contract_receipt,
        performed_actions: vec![ProcessActionRef {
            action_id,
            kind: ActionKind::Other,
            receipt_id: action_receipt,
        }],
        evidence: execution_evidence,
        supported_assumptions,
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
            verdict: if completed {
                Verdict::Verified
            } else {
                Verdict::Incomplete
            },
            reason_code: if completed {
                "PROCESS_WRAPPER_COMPLETED"
            } else {
                honest_stop_code
            }
            .into(),
            risk_tier: RiskTier::Quality,
            detail: Some(format!(
                "wrapper observed exit={agent_exit} timed_out={timed_out} trust_boundary_failed={trust_boundary_failed}"
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
    let process_execution_path =
        evidence_canon.join(format!("process-execution-{}.json", opts.run_id));
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
        trust_boundary_failed,
        reason_code: reason_code.into(),
        detect_events,
        final_diff_sha256: Some(final_diff_sha256),
        mediation: if confinement_report.is_some() {
            "scoped Linux confinement: IP egress and host path writes are blocked for this wrapped process; host reads, pathname Unix sockets, pre-opened descriptors, out-of-band processes, and a separate OS principal are not covered".into()
        } else {
            "mediation: incomplete — an out-of-band process can bypass LIA on this harness; use the opt-in Linux confinement backend where supported".into()
        },
        process_contract_path,
        process_execution_path,
        process_validation,
        confinement_report_path,
        confinement: confinement_report,
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

fn write_private_bytes_new(path: &Path, bytes: &[u8]) -> Result<(), AdapterError> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| AdapterError::Invalid(format!("evidence write failed: {error}")))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| AdapterError::Invalid(format!("evidence sync failed: {error}")))?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| AdapterError::Invalid(format!("evidence dir sync failed: {error}")))?;
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn make_evidence_private(path: &Path) -> Result<(), AdapterError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            AdapterError::Invalid(format!("EVIDENCE_DIRECTORY_PERMISSIONS: {error}"))
        })?;
    }
    Ok(())
}

fn confined_env(
    worktree: &Path,
    requested_allowlist: &[String],
) -> Result<BTreeMap<String, String>, AdapterError> {
    const SAFE_PASSTHROUGH: &[&str] = &["USER", "LANG", "LC_ALL", "TERM"];
    let requested: BTreeSet<&str> = requested_allowlist.iter().map(String::as_str).collect();
    let mut env: BTreeMap<String, String> = std::env::vars()
        .filter(|(name, _)| {
            requested.contains(name.as_str()) && SAFE_PASSTHROUGH.contains(&name.as_str())
        })
        .collect();
    let private_home = worktree.join(".lia-home");
    let private_tmp = worktree.join(".lia-tmp");
    let target = worktree.join(".lia-target");
    fs::create_dir_all(&private_home).map_err(|error| AdapterError::Invalid(error.to_string()))?;
    fs::create_dir_all(&private_tmp).map_err(|error| AdapterError::Invalid(error.to_string()))?;
    fs::create_dir_all(&target).map_err(|error| AdapterError::Invalid(error.to_string()))?;
    env.insert(
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
    );
    env.insert("HOME".into(), private_home.display().to_string());
    env.insert("TMPDIR".into(), private_tmp.display().to_string());
    env.insert("TMP".into(), private_tmp.display().to_string());
    env.insert("TEMP".into(), private_tmp.display().to_string());
    env.insert("CARGO_TARGET_DIR".into(), target.display().to_string());
    Ok(env)
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

fn canonicalize_directory(path: &Path) -> Result<PathBuf, AdapterError> {
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
