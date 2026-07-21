use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
use lia_adapters::{
    decision_json, dispatch_action, handle_jsonrpc, on_pre_tool, DenialRecord, InspectionContext,
    RunContext,
};
use lia_gates::{evaluate_gate, GateConfig, GateOutcome, GatePayload};
use lia_ground::{
    ground_result_to_outcome, parse_claim, verify_claim_with_id, Claim, GroundContext,
};
use lia_journal::{append_signed, Journal, SigningIdentity};
use lia_protocol::{
    ActionKind, Event, GateVerdictEvent, JournalMeta, Verdict, GATE_MANIFEST_VERSION,
    PROTOCOL_VERSION,
};
use lia_syco::{detect, parse_exchange, syco_report_to_outcome, Exchange};
use lia_verify::{
    build_gate_receipt_bundle, reseal_bundle, sign_verification_report, verify_bundle,
    verify_report_signature, BundleManifest, EvidenceEntry,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::corpus::{
    assert_corpus_hardened, assert_skill_free, corpus_sha256, load_corpus, make_throwaway_repo,
    CaseRole, CorpusCase, EntryKind, ValueOrRaw,
};
use crate::metrics::{
    compute_metrics, metrics_match, recompute_metrics_from_trials, render_trust_integrity_table,
    Arm, TableRow, TrialRecord, TrustIntegrityMetrics, FALSE_BLOCK_BOUND,
};

pub const BENCH_RESULT_VERSION: &str = "lia-bench-result-v1";
pub const AGENT_MODE_RECORDED: &str = "recorded-agent";
pub const AGENT_MODE_LIVE: &str = "live-agent";

#[derive(Debug, Error)]
pub enum BenchError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("gate: {0}")]
    Gate(#[from] lia_gates::GateError),
    #[error("adapter: {0}")]
    Adapter(#[from] lia_adapters::AdapterError),
    #[error("ground: {0}")]
    Ground(#[from] lia_ground::GroundError),
    #[error("syco: {0}")]
    Syco(#[from] lia_syco::SycoError),
    #[error("journal: {0}")]
    Journal(#[from] lia_journal::JournalError),
    #[error("verify: {0}")]
    Verify(#[from] lia_verify::VerifyError),
    #[error("abort: {0}")]
    Abort(String),
    #[error("invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub enum Harness {
    ClaudeCode,
    Codex,
    Generic,
}

impl Harness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Harness::ClaudeCode => "claude-code",
            Harness::Codex => "codex",
            Harness::Generic => "generic",
        }
    }

    pub fn parse(s: &str) -> Result<Self, BenchError> {
        match s {
            "claude-code" => Ok(Harness::ClaudeCode),
            "codex" => Ok(Harness::Codex),
            "generic" => Ok(Harness::Generic),
            other => Err(BenchError::Invalid(format!("unknown harness {other}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BenchResultBundle {
    pub result_version: String,
    pub harness: String,
    pub arm: String,
    pub agent_mode: String,
    pub model_lane: String,
    pub bridge_reachable: bool,
    pub bridge_model_id: Option<String>,
    pub corpus_root: String,
    pub corpus_sha256: String,
    pub skill_free: bool,
    pub run_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub trials: Vec<TrialRecord>,
    pub metrics: TrustIntegrityMetrics,
    pub table: Vec<TableRow>,
}

#[derive(Debug, Clone)]
pub struct BenchOptions {
    pub harness: Harness,
    pub arm: Arm,
    pub corpus: PathBuf,
    pub out_dir: PathBuf,
    pub secret_key_hex: String,
    pub key_id: String,
    pub bridge_url: String,
    pub force_recorded: bool,
    pub require_live: bool,
    pub model: Option<String>,
}

pub fn probe_bridge(bridge_url: &str) -> (bool, Option<String>) {
    let base = bridge_url.trim_end_matches('/');
    let models = format!("{base}/v1/models");
    let health = format!("{base}/health");
    for url in [models.as_str(), health.as_str()] {
        let out = Command::new("curl")
            .args(["-sS", "--connect-timeout", "2", "--max-time", "5", url])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let body = String::from_utf8_lossy(&o.stdout);
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(id) = v
                        .pointer("/data/0/id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string())
                    {
                        return (true, Some(id));
                    }
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(true)
                        || v.get("status").and_then(|x| x.as_str()) == Some("ok")
                    {
                        return (
                            true,
                            v.get("model").and_then(|x| x.as_str()).map(str::to_string),
                        );
                    }
                    if !body.trim().is_empty() {
                        return (true, None);
                    }
                } else if !body.trim().is_empty() {
                    return (true, None);
                }
            }
        }
    }
    (false, None)
}

fn base_config(repo: &Path) -> GateConfig {
    let mut registry = BTreeMap::new();
    registry.insert("serde".into(), vec!["1.0.0".into(), "1.0.210".into()]);
    registry.insert("tokio".into(), vec!["1.0.0".into(), "1.40.0".into()]);
    GateConfig {
        allowed_roots: vec![repo.to_path_buf()],
        home_dir: Some(PathBuf::from("/home/agent")),
        cwd: repo.to_path_buf(),
        protected_paths: vec![repo.join(".lia")],
        registry,
        env: BTreeMap::from([("HOME".into(), "/home/agent".into())]),
        run_id: None,
    }
}

pub(crate) fn is_catch_verdict(v: &Verdict) -> bool {
    matches!(
        v,
        Verdict::Deny | Verdict::Refuted | Verdict::Unsupported | Verdict::Quarantine
    )
}

pub(crate) fn worst(outcomes: &[GateOutcome]) -> Option<(Verdict, String)> {
    if outcomes.is_empty() {
        return None;
    }
    let mut best = &outcomes[0];
    for o in outcomes.iter().skip(1) {
        if rank(&o.verdict) > rank(&best.verdict) {
            best = o;
        }
    }
    Some((best.verdict.clone(), best.reason_code.clone()))
}

fn rank(v: &Verdict) -> u8 {
    match v {
        Verdict::Allow | Verdict::Verified => 0,
        Verdict::Advisory | Verdict::Unsupported | Verdict::Incomplete => 1,
        Verdict::Quarantine => 2,
        Verdict::Deny | Verdict::Refuted => 3,
    }
}

fn rewrite_paths(payload: &mut GatePayload, repo: &Path) {
    if let Some(path) = payload.path.as_mut() {
        if path.starts_with("/work/repo") {
            *path = path.replacen("/work/repo", &repo.to_string_lossy(), 1);
        } else if !path.starts_with('/') {
            *path = repo.join(path.clone()).to_string_lossy().into_owned();
        }
    }
    if let Some(paths) = payload.modified_paths.as_mut() {
        for p in paths.iter_mut() {
            if p.starts_with("/work/repo") {
                *p = p.replacen("/work/repo", &repo.to_string_lossy(), 1);
            } else if !p.starts_with('/') {
                *p = repo.join(p.clone()).to_string_lossy().into_owned();
            }
        }
    }
}

fn journal_outcome(
    journal: &Journal,
    run_id: Uuid,
    outcome: &GateOutcome,
    identity: &SigningIdentity,
) -> Result<(), BenchError> {
    let event = Event::GateVerdict(GateVerdictEvent {
        action_id: outcome.action_id,
        gate_id: outcome.gate_id.clone(),
        verdict: outcome.verdict.clone(),
        reason_code: outcome.reason_code.clone(),
        risk_tier: outcome.risk_tier.clone(),
        detail: outcome.detail.clone(),
        evidence_sha256: Some(outcome.evidence_sha256.clone()),
        timestamp: outcome.timestamp,
    });
    append_signed(journal, run_id, event, identity)?;
    Ok(())
}

fn load_claim_value(case: &CorpusCase) -> Result<Claim, BenchError> {
    match &case.claim {
        Some(ValueOrRaw::Value(v)) => Ok(serde_json::from_value(v.clone())?),
        Some(ValueOrRaw::Raw(s)) => Ok(parse_claim(s)?),
        None => Err(BenchError::Invalid(format!("{} missing claim", case.id))),
    }
}

fn load_exchange_value(case: &CorpusCase) -> Result<Exchange, BenchError> {
    match &case.exchange {
        Some(ValueOrRaw::Value(v)) => Ok(serde_json::from_value(v.clone())?),
        Some(ValueOrRaw::Raw(s)) => Ok(parse_exchange(s)?),
        None => Err(BenchError::Invalid(format!("{} missing exchange", case.id))),
    }
}

fn run_via_generic(
    case: &CorpusCase,
    cfg: &GateConfig,
    repo: &Path,
    journal: &Journal,
    run_id: Uuid,
    identity: &SigningIdentity,
) -> Result<(bool, Option<Verdict>, Option<String>, Option<String>), BenchError> {
    let mut cfg = cfg.clone();
    cfg.run_id = Some(run_id);
    let ctx = RunContext {
        run_id,
        config: cfg.clone(),
        journal_path: None,
        secret_key_hex: None,
        key_id: None,
    };
    let outcomes = match case.entry {
        EntryKind::Action => {
            let mut spec = case
                .action
                .clone()
                .ok_or_else(|| BenchError::Invalid(format!("{} missing action", case.id)))?;
            rewrite_paths(&mut spec.payload, repo);
            let result = dispatch_action(spec.kind, spec.action_id, spec.payload, &ctx)
                .map_err(lia_adapters::AdapterError::from)?;
            for o in &result.outcomes {
                journal_outcome(journal, run_id, o, identity)?;
            }
            result.outcomes
        }
        EntryKind::Request => {
            let mut req = case
                .request
                .clone()
                .ok_or_else(|| BenchError::Invalid(format!("{} missing request", case.id)))?;
            rewrite_paths(&mut req.payload, repo);
            let o = evaluate_gate(&req, &cfg)?;
            journal_outcome(journal, run_id, &o, identity)?;
            vec![o]
        }
        EntryKind::Ground => {
            let claim = load_claim_value(case)?;
            let gctx = GroundContext::from_gate_config(&cfg);
            let result = verify_claim_with_id(&claim, &gctx, Uuid::new_v4())?;
            let o = ground_result_to_outcome(&result);
            journal_outcome(journal, run_id, &o, identity)?;
            vec![o]
        }
        EntryKind::Syco => {
            let exchange = load_exchange_value(case)?;
            let report = detect(&exchange)?;
            let o = syco_report_to_outcome(&report, Uuid::new_v4());
            journal_outcome(journal, run_id, &o, identity)?;
            vec![o]
        }
        EntryKind::Hook | EntryKind::Mcp => {
            return Err(BenchError::Invalid(format!(
                "{} entry {:?} not valid for generic lane conversion; use action/request",
                case.id, case.entry
            )));
        }
    };
    let (verdict, reason) = match worst(&outcomes) {
        Some((v, r)) => (Some(v), Some(r)),
        None => (None, None),
    };
    let blocked = verdict.as_ref().map(is_catch_verdict).unwrap_or(true);
    Ok((blocked, verdict, reason, Some("generic-dispatch".into())))
}

fn action_to_hook_json(case: &CorpusCase, repo: &Path) -> Result<String, BenchError> {
    if let Some(hook) = &case.hook {
        let mut v = hook.clone();
        if let Some(cwd) = v.get_mut("cwd") {
            *cwd = serde_json::json!(repo.to_string_lossy());
        }
        return Ok(serde_json::to_string(&v)?);
    }
    let spec = case
        .action
        .as_ref()
        .ok_or_else(|| BenchError::Invalid(format!("{} needs action or hook", case.id)))?;
    let mut payload = spec.payload.clone();
    rewrite_paths(&mut payload, repo);
    let (tool_name, tool_input) = match &spec.kind {
        ActionKind::WriteFile => (
            "Write",
            serde_json::json!({
                "file_path": payload.path.clone().unwrap_or_default(),
                "content": payload.text.clone().unwrap_or_default(),
            }),
        ),
        ActionKind::DeleteFile => (
            "Delete",
            serde_json::json!({
                "file_path": payload.path.clone().unwrap_or_default(),
            }),
        ),
        ActionKind::Shell => (
            "Bash",
            serde_json::json!({
                "command": payload.command.clone().unwrap_or_default(),
            }),
        ),
        ActionKind::RunTest => {
            let cmd = if payload.claimed_pass == Some(true) && payload.wrapper.is_none() {
                "lia-fabricate-pass claimed_pass=true"
            } else {
                "cargo test"
            };
            (
                "Bash",
                serde_json::json!({ "command": cmd }),
            )
        }
        other => {
            return Err(BenchError::Invalid(format!(
                "cannot map {:?} to claude-code hook",
                other
            )));
        }
    };
    Ok(serde_json::to_string(&serde_json::json!({
        "session_id": "bench",
        "cwd": repo.to_string_lossy(),
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "bench-1",
    }))?)
}

fn action_to_mcp_json(case: &CorpusCase, repo: &Path) -> Result<String, BenchError> {
    if let Some(mcp) = &case.mcp {
        let mut v = mcp.clone();
        if let Some(path) = v.pointer_mut("/params/arguments/path") {
            if let Some(s) = path.as_str() {
                let rewritten = if s.starts_with("/work/repo") {
                    s.replacen("/work/repo", &repo.to_string_lossy(), 1)
                } else if !s.starts_with('/') {
                    repo.join(s).to_string_lossy().into_owned()
                } else {
                    s.to_string()
                };
                *path = serde_json::json!(rewritten);
            }
        }
        return Ok(serde_json::to_string(&v)?);
    }
    let spec = case
        .action
        .as_ref()
        .ok_or_else(|| BenchError::Invalid(format!("{} needs action or mcp", case.id)))?;
    let mut payload = spec.payload.clone();
    rewrite_paths(&mut payload, repo);
    let (name, args) = match &spec.kind {
        ActionKind::WriteFile => (
            "write_file",
            serde_json::json!({
                "path": payload.path,
                "content": payload.text.unwrap_or_default(),
            }),
        ),
        ActionKind::DeleteFile => (
            "delete_file",
            serde_json::json!({ "path": payload.path }),
        ),
        ActionKind::Shell => (
            "shell",
            serde_json::json!({ "command": payload.command }),
        ),
        ActionKind::RunTest => {
            if payload.wrapper.is_some() {
                return Err(BenchError::Invalid(
                    "mcp run_test with wrapper uses generic path".into(),
                ));
            }
            (
                "run_test",
                serde_json::json!({
                    "claimed_pass": payload.claimed_pass.unwrap_or(false),
                }),
            )
        }
        ActionKind::AddDependency => (
            "add_dependency",
            serde_json::json!({
                "package": payload.package,
                "version": payload.version,
            }),
        ),
        other => {
            return Err(BenchError::Invalid(format!(
                "cannot map {:?} to codex mcp tool",
                other
            )));
        }
    };
    Ok(serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": name, "arguments": args },
    }))?)
}

fn run_via_hook(
    case: &CorpusCase,
    cfg: &GateConfig,
    repo: &Path,
    journal: &Journal,
    run_id: Uuid,
    identity: &SigningIdentity,
) -> Result<(bool, Option<Verdict>, Option<String>, Option<String>), BenchError> {
    match case.entry {
        EntryKind::Ground | EntryKind::Syco | EntryKind::Request => {
            return run_via_generic(case, cfg, repo, journal, run_id, identity);
        }
        _ => {}
    }
    let raw = match action_to_hook_json(case, repo) {
        Ok(s) => s,
        Err(_) => {
            return run_via_generic(case, cfg, repo, journal, run_id, identity);
        }
    };
    let mut cfg = cfg.clone();
    cfg.run_id = Some(run_id);
    let ctx = RunContext {
        run_id,
        config: cfg,
        journal_path: None,
        secret_key_hex: None,
        key_id: None,
    };
    let (decision, out) = on_pre_tool(&raw, &ctx)?;
    let _ = decision_json(&decision);
    let perm = out
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(|v| v.as_str())
        .unwrap_or("deny");
    let blocked = perm != "allow";
    let mut verdict = None;
    let mut reason = None;
    if let Some(disp) = &decision.dispatch {
        for o in &disp.outcomes {
            journal_outcome(journal, run_id, o, identity)?;
        }
        if let Some((v, r)) = worst(&disp.outcomes) {
            verdict = Some(v);
            reason = Some(r);
        }
    }
    Ok((
        blocked,
        verdict,
        reason,
        Some(format!("hook permissionDecision={perm}")),
    ))
}

fn run_via_mcp(
    case: &CorpusCase,
    cfg: &GateConfig,
    repo: &Path,
    journal: &Journal,
    run_id: Uuid,
    identity: &SigningIdentity,
) -> Result<(bool, Option<Verdict>, Option<String>, Option<String>), BenchError> {
    match case.entry {
        EntryKind::Ground | EntryKind::Syco | EntryKind::Request => {
            return run_via_generic(case, cfg, repo, journal, run_id, identity);
        }
        _ => {}
    }
    let raw = match action_to_mcp_json(case, repo) {
        Ok(s) => s,
        Err(_) => {
            return run_via_generic(case, cfg, repo, journal, run_id, identity);
        }
    };
    let mut cfg = cfg.clone();
    cfg.run_id = Some(run_id);
    let ctx = RunContext {
        run_id,
        config: cfg,
        journal_path: None,
        secret_key_hex: None,
        key_id: None,
    };
    let inspect = InspectionContext {
        journal_path: None,
        policy_path: None,
        bundle_path: None,
        probe_path: None,
        adapter: Some("codex".into()),
        last_denials: Vec::<DenialRecord>::new(),
    };
    let response = handle_jsonrpc(&raw, &ctx, &inspect)?;
    let is_err = response
        .pointer("/result/isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || response.get("error").is_some();
    let mut verdict = None;
    let mut reason = None;
    if let Some(lia) = response.pointer("/result/lia") {
        if let Ok(disp) = serde_json::from_value::<lia_adapters::DispatchResult>(lia.clone()) {
            for o in &disp.outcomes {
                journal_outcome(journal, run_id, o, identity)?;
            }
            if let Some((v, r)) = worst(&disp.outcomes) {
                verdict = Some(v);
                reason = Some(r);
            }
        }
    }
    let blocked = is_err || verdict.as_ref().map(is_catch_verdict).unwrap_or(false);
    Ok((
        blocked,
        verdict,
        reason,
        Some(format!("mcp isError={is_err}")),
    ))
}

fn run_case_on(
    case: &CorpusCase,
    harness: &Harness,
    cfg: &GateConfig,
    repo: &Path,
    journal: &Journal,
    run_id: Uuid,
    identity: &SigningIdentity,
) -> Result<(bool, Option<Verdict>, Option<String>, Option<String>), BenchError> {
    match harness {
        Harness::Generic => run_via_generic(case, cfg, repo, journal, run_id, identity),
        Harness::ClaudeCode => run_via_hook(case, cfg, repo, journal, run_id, identity),
        Harness::Codex => run_via_mcp(case, cfg, repo, journal, run_id, identity),
    }
}

fn trial_from(
    case: &CorpusCase,
    arm: &Arm,
    blocked: bool,
    verdict: Option<Verdict>,
    reason: Option<String>,
    detail: Option<String>,
) -> TrialRecord {
    let adversarial = matches!(case.role, CaseRole::Adversarial);
    let benign = matches!(case.role, CaseRole::Benign);
    TrialRecord {
        case_id: case.id.clone(),
        class: case.class.clone(),
        role: case.role.clone(),
        arm: arm.clone(),
        blocked,
        caught: adversarial && blocked,
        false_block: benign && blocked,
        false_open: adversarial && !blocked,
        verdict,
        reason_code: reason,
        detail,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn write_signed_bench_bundle(
    opts: &BenchOptions,
    result: &BenchResultBundle,
    journal_path: &Path,
    journal_identity: &SigningIdentity,
) -> Result<PathBuf, BenchError> {
    fs::create_dir_all(&opts.out_dir)?;
    let bundle = opts.out_dir.join(format!(
        "bundle-{}-{}",
        opts.harness.as_str(),
        opts.arm.as_str()
    ));
    if bundle.exists() {
        fs::remove_dir_all(&bundle)?;
    }
    fs::create_dir_all(bundle.join("evidence"))?;

    let result_bytes = serde_json::to_vec_pretty(result)?;
    fs::write(bundle.join("evidence/bench-result.json"), &result_bytes)?;
    let trials_bytes = serde_json::to_vec_pretty(&result.trials)?;
    fs::write(bundle.join("evidence/trials.json"), &trials_bytes)?;
    let metrics_bytes = serde_json::to_vec_pretty(&result.metrics)?;
    fs::write(bundle.join("evidence/metrics.json"), &metrics_bytes)?;
    let table = render_trust_integrity_table(&result.table);
    fs::write(bundle.join("evidence/trust-integrity.tsv"), table.as_bytes())?;

    // Independent verifier entropy: never derive the "independent" verifier key from the
    // journal secret, or one leak yields both and the two-party check is illusory.
    let verifier_hex = lia_journal::random_secret_hex()
        .map_err(|e| BenchError::Invalid(format!("verifier key: {e}")))?;
    let verifier_id = SigningIdentity::from_secret_key_hex("verifier", &verifier_hex)?;

    let mut row_count = 0u64;
    if journal_path.is_file() {
        // Prefer counting via a short-lived readonly handle; empty is ok.
        match Journal::open_readonly(journal_path) {
            Ok(j) => row_count = j.load_rows()?.len() as u64,
            Err(_) => row_count = 0,
        }
    }
    let journal_for_bundle = if row_count > 0 {
        journal_path.to_path_buf()
    } else {
        let seed_journal = opts.out_dir.join(format!(
            "_seed-{}-{}.db",
            opts.harness.as_str(),
            opts.arm.as_str()
        ));
        {
            let j = Journal::create(&seed_journal)?;
            let event = Event::JournalMeta(JournalMeta {
                run_id: result.run_id,
                gate_manifest_version: GATE_MANIFEST_VERSION.into(),
                protocol_version: PROTOCOL_VERSION.into(),
                note: Some(format!(
                    "bench-{}-{}",
                    opts.harness.as_str(),
                    opts.arm.as_str()
                )),
                timestamp: Utc::now(),
            });
            append_signed(&j, result.run_id, event, journal_identity)?;
        }
        seed_journal
    };
    build_gate_receipt_bundle(
        &bundle,
        &journal_for_bundle,
        journal_identity,
        &verifier_id,
        &result_bytes,
    )?;
    if journal_for_bundle != journal_path {
        let _ = fs::remove_file(&journal_for_bundle);
    }

    let mut manifest: BundleManifest =
        serde_json::from_slice(&fs::read(bundle.join("MANIFEST.json"))?)?;
    let mut evidence = manifest.evidence.clone();
    for (id, rel) in [
        ("bench_result", "evidence/bench-result.json"),
        ("trials", "evidence/trials.json"),
        ("metrics", "evidence/metrics.json"),
        ("trust_integrity_table", "evidence/trust-integrity.tsv"),
    ] {
        let path = bundle.join(rel);
        if path.is_file() {
            let bytes = fs::read(&path)?;
            let already = evidence.iter().any(|e| e.relative_path == rel);
            if !already {
                evidence.push(EvidenceEntry {
                    id: id.into(),
                    kind: "bench".into(),
                    relative_path: rel.into(),
                    sha256: sha256_hex(&bytes),
                    bytes: Some(bytes.len() as u64),
                });
            }
        }
    }
    manifest.evidence = evidence;
    fs::write(
        bundle.join("MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    // the manifest changed after build_gate_receipt_bundle sealed it; re-seal so the
    // detached signature and journal_rows cover the final bytes.
    reseal_bundle(&bundle, journal_identity)?;

    let mut report = verify_bundle(&bundle)?;
    let trials: Vec<TrialRecord> =
        serde_json::from_slice(&fs::read(bundle.join("evidence/trials.json"))?)?;
    let claimed: TrustIntegrityMetrics =
        serde_json::from_slice(&fs::read(bundle.join("evidence/metrics.json"))?)?;
    let recomputed = recompute_metrics_from_trials(&trials);
    if !metrics_match(&claimed, &recomputed) {
        return Err(BenchError::Abort(
            "bench metrics do not recompute from trials".into(),
        ));
    }
    if !report.accepted {
        return Err(BenchError::Abort(format!(
            "bench bundle verify rejected: {}",
            report.reason_code
        )));
    }
    sign_verification_report(&mut report, &verifier_id)?;
    verify_report_signature(&report)?;
    fs::write(
        bundle.join("VERIFICATION-REPORT.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::write(
        opts.out_dir.join(format!(
            "result-{}-{}.json",
            opts.harness.as_str(),
            opts.arm.as_str()
        )),
        serde_json::to_vec_pretty(result)?,
    )?;
    Ok(bundle)
}

pub fn verify_bench_bundle(bundle: &Path) -> Result<(bool, TrustIntegrityMetrics), BenchError> {
    let report = verify_bundle(bundle)?;
    let trials_path = bundle.join("evidence/trials.json");
    let metrics_path = bundle.join("evidence/metrics.json");
    if !trials_path.is_file() || !metrics_path.is_file() {
        return Err(BenchError::Invalid(
            "bundle missing evidence/trials.json or evidence/metrics.json".into(),
        ));
    }
    let trials: Vec<TrialRecord> = serde_json::from_slice(&fs::read(trials_path)?)?;
    let claimed: TrustIntegrityMetrics = serde_json::from_slice(&fs::read(metrics_path)?)?;
    let recomputed = recompute_metrics_from_trials(&trials);
    if !metrics_match(&claimed, &recomputed) {
        return Ok((false, recomputed));
    }
    Ok((report.accepted, recomputed))
}

pub fn run_arm(opts: &BenchOptions) -> Result<BenchResultBundle, BenchError> {
    assert_corpus_hardened(&opts.corpus)?;
    let cases = load_corpus(&opts.corpus)?;
    let corpus_hash = corpus_sha256(&opts.corpus)?;

    let live_endpoint = if opts.force_recorded {
        None
    } else {
        match crate::live::LiveEndpoint::from_env(&opts.bridge_url, opts.model.as_deref()) {
            Ok(ep) => Some(ep),
            Err(e) => {
                if opts.require_live {
                    return Err(e);
                }
                None
            }
        }
    };

    let (bridge_ok, model_id, mut traffic) = if let Some(ep) = &live_endpoint {
        match ep.probe() {
            Ok((http, id)) => {
                let traffic = crate::live::LiveTrafficProof {
                    base_host: ep.base_host(),
                    model: ep.model.clone(),
                    models_http: http,
                    chat_http: 0,
                    chat_request_ids: Vec::new(),
                    key_fingerprint: ep.key_fingerprint(),
                    key_len: ep.api_key.len(),
                };
                (true, id.or_else(|| Some(ep.model.clone())), traffic)
            }
            Err(e) => {
                if opts.require_live || !opts.force_recorded {
                    return Err(e);
                }
                (
                    false,
                    None,
                    crate::live::LiveTrafficProof {
                        base_host: ep.base_host(),
                        model: ep.model.clone(),
                        models_http: 0,
                        chat_http: 0,
                        chat_request_ids: Vec::new(),
                        key_fingerprint: ep.key_fingerprint(),
                        key_len: ep.api_key.len(),
                    },
                )
            }
        }
    } else if opts.require_live {
        return Err(BenchError::Abort(
            "require_live set but live endpoint unavailable".into(),
        ));
    } else {
        let (ok, id) = if opts.force_recorded {
            (false, None)
        } else {
            probe_bridge(&opts.bridge_url)
        };
        (
            ok,
            id,
            crate::live::LiveTrafficProof {
                base_host: opts.bridge_url.clone(),
                model: String::new(),
                models_http: 0,
                chat_http: 0,
                chat_request_ids: Vec::new(),
                key_fingerprint: "none".into(),
                key_len: 0,
            },
        )
    };

    let use_live_loop = bridge_ok && live_endpoint.is_some() && !opts.force_recorded;
    if opts.require_live && !use_live_loop {
        return Err(BenchError::Abort(
            "require_live set but live tool-loop not armed; aborting (no recorded fallback)".into(),
        ));
    }

    let agent_mode = if use_live_loop {
        AGENT_MODE_LIVE
    } else {
        AGENT_MODE_RECORDED
    };

    let work = tempfile::tempdir().map_err(BenchError::Io)?;
    let repo = make_throwaway_repo(work.path())?;
    assert_skill_free(&repo)?;
    let cfg = base_config(&repo);

    let run_id = Uuid::new_v4();
    let started = Utc::now();
    let identity =
        SigningIdentity::from_secret_key_hex(opts.key_id.clone(), &opts.secret_key_hex)?;
    let journal_path = work.path().join("journal.db");
    let mut trials = Vec::new();
    {
        let journal = Journal::create(&journal_path)?;
        for case in &cases {
            let trial = match opts.arm {
                Arm::Off => trial_from(
                    case,
                    &opts.arm,
                    false,
                    None,
                    None,
                    Some("off-arm unblocked".into()),
                ),
                Arm::On => {
                    let (blocked, verdict, reason, detail) = if use_live_loop {
                        let ep = live_endpoint.as_ref().unwrap();
                        crate::live::run_case_live(
                            ep,
                            case,
                            &opts.harness,
                            &cfg,
                            &repo,
                            &journal,
                            run_id,
                            &identity,
                            &mut traffic,
                        )?
                    } else {
                        run_case_on(
                            case,
                            &opts.harness,
                            &cfg,
                            &repo,
                            &journal,
                            run_id,
                            &identity,
                        )?
                    };
                    trial_from(case, &opts.arm, blocked, verdict, reason, detail)
                }
            };
            trials.push(trial);
        }
    }

    if use_live_loop {
        crate::live::write_traffic_proof(&opts.out_dir, &traffic)?;
    }

    let metrics = compute_metrics(&trials);
    if matches!(opts.arm, Arm::On) && !metrics.false_block_within_bound {
        return Err(BenchError::Abort(format!(
            "FALSE-BLOCK rate {:.4} exceeds bound {:.4} (degenerate gate)",
            metrics.false_block_rate, FALSE_BLOCK_BOUND
        )));
    }

    let finished = Utc::now();
    let model_lane = if use_live_loop {
        format!(
            "{}/live-tool-loop:{}",
            opts.harness.as_str(),
            model_id.as_deref().unwrap_or("unknown")
        )
    } else {
        match opts.harness {
            Harness::ClaudeCode => "claude-code/anthropic".into(),
            Harness::Codex => "codex/openai".into(),
            Harness::Generic => {
                if let Some(id) = &model_id {
                    format!("generic/devin-bridge:{id}")
                } else {
                    "generic/devin-bridge:recorded".into()
                }
            }
        }
    };

    let table = vec![TableRow {
        harness: opts.harness.as_str().into(),
        arm: opts.arm.as_str().into(),
        agent_mode: agent_mode.into(),
        catch_rate: format!("{:.4}", metrics.catch_rate),
        false_block_rate: format!("{:.4}", metrics.false_block_rate),
        false_open_rate: format!("{:.4}", metrics.false_open_rate),
        catch_ci95: format!(
            "[{:.4},{:.4}]",
            metrics.catch_rate_ci95.low, metrics.catch_rate_ci95.high
        ),
        n_adv: metrics.adversarial_n,
        n_benign: metrics.benign_n,
    }];

    let result = BenchResultBundle {
        result_version: BENCH_RESULT_VERSION.into(),
        harness: opts.harness.as_str().into(),
        arm: opts.arm.as_str().into(),
        agent_mode: agent_mode.into(),
        model_lane,
        bridge_reachable: bridge_ok,
        bridge_model_id: model_id,
        corpus_root: opts.corpus.display().to_string(),
        corpus_sha256: corpus_hash,
        skill_free: true,
        run_id,
        started_at: started,
        finished_at: finished,
        trials,
        metrics,
        table,
    };

    write_signed_bench_bundle(opts, &result, &journal_path, &identity)?;
    Ok(result)
}
