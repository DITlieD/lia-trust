use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use lia_gates::GateConfig;
use lia_protocol::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::assurance::{AssuranceLevel, AssuranceReport, CapabilityProbe, GateCell};
use crate::claude_code::on_pre_tool;
use crate::codex::handle_jsonrpc;
use crate::contracts::{
    ADAPTER_CLAUDE_CODE, ADAPTER_CODEX, ADAPTER_CURSOR, ADAPTER_GEMINI_CLI, ADAPTER_GENERIC,
    CAP_COMPLETION_GATE, CAP_IMMUTABLE_JOURNAL, CAP_OFFLINE_VERIFICATION, CAP_POST_WRITE_RECEIPT,
    CAP_PRE_WRITE_BLOCK, CAP_SHELL_PRE_BLOCK, CAP_SHELL_RESULT_CAPTURE, CAP_SUBAGENT_VISIBILITY,
};
use crate::cursor::on_cursor_before_shell;
use crate::dispatch::RunContext;
use crate::gemini_cli::on_gemini_before_tool;
use crate::mcp_inspection::{inspection_tool_names, refuse_mutation, InspectionContext};
use crate::{evaluate_generic_action, AdapterError, GenericAction};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuiteManifest {
    pub suite_id: String,
    pub frozen: bool,
    pub assurance_truth: String,
    pub cases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaseExpect {
    #[serde(default)]
    pub permission_decision: Option<String>,
    #[serde(default)]
    pub allowed: Option<bool>,
    #[serde(default)]
    pub any_verdict: Option<String>,
    #[serde(default)]
    pub match_truth: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConformanceCase {
    pub id: String,
    pub adapter: String,
    pub kind: String,
    pub input: Value,
    pub expect: CaseExpect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseResult {
    pub id: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConformanceReport {
    pub suite_id: String,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<CaseResult>,
}

pub fn load_suite(suite_path: impl AsRef<Path>) -> Result<SuiteManifest, AdapterError> {
    let bytes = fs::read(suite_path.as_ref()).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AdapterError::Invalid(e.to_string()))
}

pub fn assert_adapter(
    suite_root: impl AsRef<Path>,
    adapter_filter: Option<&str>,
) -> Result<ConformanceReport, AdapterError> {
    let suite_root = suite_root.as_ref();
    let suite = load_suite(suite_root.join("SUITE.json"))?;
    if !suite.frozen {
        return Err(AdapterError::Invalid(
            "conformance suite must be frozen".into(),
        ));
    }
    let truth_path = resolve_truth(suite_root, &suite.assurance_truth)?;
    let mut results = Vec::new();
    for rel in &suite.cases {
        let case_path = suite_root.join(rel);
        let case: ConformanceCase = serde_json::from_slice(
            &fs::read(&case_path).map_err(|e| AdapterError::Invalid(e.to_string()))?,
        )
        .map_err(|e| AdapterError::Invalid(format!("{}: {e}", case_path.display())))?;
        if let Some(filter) = adapter_filter {
            if case.adapter != "all" && case.adapter != filter {
                continue;
            }
        }
        let result = run_case(suite_root, &case, &truth_path)?;
        results.push(result);
    }
    let passed = results.iter().filter(|r| r.ok).count();
    let failed = results.len() - passed;
    Ok(ConformanceReport {
        suite_id: suite.suite_id,
        passed,
        failed,
        results,
    })
}

fn resolve_truth(suite_root: &Path, rel: &str) -> Result<PathBuf, AdapterError> {
    let candidates = [
        suite_root.join(rel),
        suite_root.parent().unwrap_or(suite_root).join(rel),
    ];
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }
    Err(AdapterError::Invalid(format!(
        "assurance truth not found: {rel}"
    )))
}

fn run_case(
    suite_root: &Path,
    case: &ConformanceCase,
    truth_path: &Path,
) -> Result<CaseResult, AdapterError> {
    match case.kind.as_str() {
        "hook" => run_hook_case(case),
        "mcp" => run_mcp_case(case),
        "action" => run_action_case(case),
        "assurance" => run_assurance_case(suite_root, case, truth_path),
        "inspection_read_only" => run_inspection_read_only_case(case),
        other => Ok(CaseResult {
            id: case.id.clone(),
            ok: false,
            detail: format!("unknown case kind {other}"),
        }),
    }
}

fn run_inspection_read_only_case(case: &ConformanceCase) -> Result<CaseResult, AdapterError> {
    let names = inspection_tool_names();
    let mutation_names = [
        "delete_receipts",
        "rewrite_policy",
        "append_journal",
        "approve_action",
    ];
    let names_are_inspection = names.iter().all(|name| {
        name.starts_with("verify_")
            || name.starts_with("inspect_")
            || name.starts_with("explain_")
            || name.starts_with("show_")
    });
    let mutations_refused = mutation_names
        .iter()
        .all(|name| refuse_mutation(name).is_err());
    let ok = case.expect.allowed == Some(false) && names_are_inspection && mutations_refused;
    Ok(CaseResult {
        id: case.id.clone(),
        ok,
        detail: if ok {
            "inspection surface exposes no mutation and rejects mutation names".into()
        } else {
            "inspection surface admitted mutation or case expectation was not deny".into()
        },
    })
}

fn temp_cfg() -> Result<(tempfile::TempDir, GateConfig), AdapterError> {
    let dir = tempfile::tempdir().map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let root = dir.path().to_path_buf();
    fs::create_dir_all(root.join("src")).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let cfg = GateConfig {
        allowed_roots: vec![root.clone()],
        home_dir: Some(PathBuf::from("/home/agent")),
        cwd: root,
        protected_paths: vec![],
        registry: BTreeMap::new(),
        env: BTreeMap::from([("HOME".into(), "/home/agent".into())]),
        run_id: None,
        cleanup_policy: None,
        spawn_policy: None,
    };
    Ok((dir, cfg))
}

fn run_hook_case(case: &ConformanceCase) -> Result<CaseResult, AdapterError> {
    let (_dir, cfg) = temp_cfg()?;
    let mut input = case.input.clone();
    if let Some(obj) = input.as_object_mut() {
        obj.entry("cwd")
            .or_insert_with(|| Value::String(cfg.cwd.display().to_string()));
    }
    let ctx = RunContext {
        run_id: Uuid::new_v4(),
        config: cfg,
        journal_path: None,
        secret_key_hex: None,
        key_id: None,
    };
    let raw = serde_json::to_string(&input).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let (permission, dispatch) = match case.adapter.as_str() {
        ADAPTER_CLAUDE_CODE => {
            let (decision, _) = on_pre_tool(&raw, &ctx)?;
            (decision.permission_decision, decision.dispatch)
        }
        ADAPTER_GEMINI_CLI => {
            let decision = on_gemini_before_tool(&raw, &ctx)?;
            (decision.decision, decision.dispatch)
        }
        ADAPTER_CURSOR => {
            let decision = on_cursor_before_shell(&raw, &ctx)?;
            (decision.permission, decision.dispatch)
        }
        other => {
            return Ok(CaseResult {
                id: case.id.clone(),
                ok: false,
                detail: format!("hook conformance unsupported for adapter {other}"),
            })
        }
    };
    let mut ok = true;
    let mut detail = String::new();
    if let Some(exp) = &case.expect.permission_decision {
        if permission != *exp {
            ok = false;
            detail.push_str(&format!(
                "permission_decision got {} want {exp}; ",
                permission
            ));
        }
    }
    if let Some(v) = &case.expect.any_verdict {
        let want = parse_verdict(v)?;
        let hit = dispatch
            .as_ref()
            .map(|d| d.outcomes.iter().any(|o| o.verdict == want))
            .unwrap_or(false);
        if !hit {
            ok = false;
            detail.push_str(&format!("missing verdict {v}; "));
        }
    }
    if ok {
        detail = "ok".into();
    }
    Ok(CaseResult {
        id: case.id.clone(),
        ok,
        detail,
    })
}

fn run_mcp_case(case: &ConformanceCase) -> Result<CaseResult, AdapterError> {
    let (_dir, cfg) = temp_cfg()?;
    let ctx = RunContext {
        run_id: Uuid::new_v4(),
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
        adapter: Some(ADAPTER_CODEX.into()),
        last_denials: vec![],
    };
    let raw =
        serde_json::to_string(&case.input).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let response = handle_jsonrpc(&raw, &ctx, &inspect)?;
    let lia = response.pointer("/result/lia");
    let allowed = lia.and_then(|v| v.get("allowed")).and_then(|v| v.as_bool());
    let mut ok = true;
    let mut detail = String::new();
    if let Some(exp) = case.expect.allowed {
        if allowed != Some(exp) {
            ok = false;
            detail.push_str(&format!("allowed got {allowed:?} want {exp}; "));
        }
    }
    if let Some(v) = &case.expect.any_verdict {
        let want = parse_verdict(v)?;
        let hit = lia
            .and_then(|x| x.get("outcomes"))
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter().any(|o| {
                    o.get("verdict")
                        .and_then(|vv| vv.as_str())
                        .map(|s| parse_verdict(s).ok() == Some(want.clone()))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if !hit {
            ok = false;
            detail.push_str(&format!("missing verdict {v}; "));
        }
    }
    if ok {
        detail = "ok".into();
    }
    Ok(CaseResult {
        id: case.id.clone(),
        ok,
        detail,
    })
}

fn run_action_case(case: &ConformanceCase) -> Result<CaseResult, AdapterError> {
    let (_dir, cfg) = temp_cfg()?;
    let kind = case
        .input
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AdapterError::Invalid("action case needs kind".into()))?;
    let payload = case
        .input
        .get("payload")
        .cloned()
        .ok_or_else(|| AdapterError::Invalid("action case needs payload".into()))?;
    let action = GenericAction {
        kind: serde_json::from_value(Value::String(kind.into()))
            .map_err(|e| AdapterError::Invalid(e.to_string()))?,
        action_id: Uuid::new_v4(),
        payload: serde_json::from_value(payload)
            .map_err(|e| AdapterError::Invalid(e.to_string()))?,
    };
    let outcomes = evaluate_generic_action(&action, &cfg)?;
    let mut ok = true;
    let mut detail = String::new();
    if let Some(v) = &case.expect.any_verdict {
        let want = parse_verdict(v)?;
        if !outcomes.iter().any(|o| o.verdict == want) {
            ok = false;
            detail.push_str(&format!("missing verdict {v}; "));
        }
    }
    if ok {
        detail = "ok".into();
    }
    Ok(CaseResult {
        id: case.id.clone(),
        ok,
        detail,
    })
}

fn run_assurance_case(
    _suite_root: &Path,
    case: &ConformanceCase,
    truth_path: &Path,
) -> Result<CaseResult, AdapterError> {
    let truth: Value = serde_json::from_slice(
        &fs::read(truth_path).map_err(|e| AdapterError::Invalid(e.to_string()))?,
    )
    .map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let mut ok = true;
    let mut detail = String::new();
    for adapter in [
        ADAPTER_CLAUDE_CODE,
        ADAPTER_CODEX,
        ADAPTER_GENERIC,
        ADAPTER_GEMINI_CLI,
        ADAPTER_CURSOR,
    ] {
        let probe = frozen_probe(adapter);
        let report = AssuranceReport::from_probe(&probe)?;
        let expected = truth
            .get(adapter)
            .ok_or_else(|| AdapterError::Invalid(format!("truth missing {adapter}")))?;
        let want_level = expected.get("level").and_then(|v| v.as_str()).unwrap_or("");
        let got_level = match report.level {
            AssuranceLevel::Audit => "AUDIT",
            AssuranceLevel::Observe => "OBSERVE",
            AssuranceLevel::Gate => "GATE",
            AssuranceLevel::Confine => "CONFINE",
        };
        if got_level != want_level {
            ok = false;
            detail.push_str(&format!("{adapter} level {got_level}!={want_level}; "));
        }
        if let Some(gates) = expected.get("gates").and_then(|g| g.as_object()) {
            for (gate_id, cell) in gates {
                let want = cell.as_str().unwrap_or("");
                let got = report
                    .gates
                    .iter()
                    .find(|g| g.gate_id == *gate_id)
                    .map(|g| match g.cell {
                        GateCell::Prevent => "PREVENT",
                        GateCell::Detect => "DETECT",
                        GateCell::CannotObserve => "CANNOT-OBSERVE",
                    })
                    .unwrap_or("MISSING");
                if got != want {
                    ok = false;
                    detail.push_str(&format!("{adapter}/{gate_id} {got}!={want}; "));
                }
            }
        }
    }
    if case.expect.match_truth != Some(true) {
        ok = false;
        detail.push_str("match_truth required; ");
    }
    if ok {
        detail = "ok".into();
    }
    Ok(CaseResult {
        id: case.id.clone(),
        ok,
        detail,
    })
}

fn frozen_probe(adapter: &str) -> CapabilityProbe {
    let mut keys = BTreeMap::new();
    let mut gate_cells = BTreeMap::new();
    match adapter {
        ADAPTER_CLAUDE_CODE => {
            keys.insert(CAP_PRE_WRITE_BLOCK.into(), true);
            keys.insert(CAP_POST_WRITE_RECEIPT.into(), true);
            keys.insert(CAP_SHELL_PRE_BLOCK.into(), true);
            keys.insert(CAP_SHELL_RESULT_CAPTURE.into(), false);
            keys.insert(CAP_COMPLETION_GATE.into(), false);
            keys.insert(CAP_SUBAGENT_VISIBILITY.into(), true);
            keys.insert(CAP_IMMUTABLE_JOURNAL.into(), true);
            keys.insert(CAP_OFFLINE_VERIFICATION.into(), true);
            for gate in [
                "test-integrity",
                "evidence-completeness",
                "dependency-reality",
            ] {
                gate_cells.insert(gate.into(), GateCell::CannotObserve);
            }
            for gate in [
                "filesystem-scope",
                "shell-irreversible",
                "secret-output",
                "journal-tamper",
            ] {
                gate_cells.insert(gate.into(), GateCell::Prevent);
            }
        }
        ADAPTER_CODEX => {
            keys.insert(CAP_PRE_WRITE_BLOCK.into(), true);
            keys.insert(CAP_POST_WRITE_RECEIPT.into(), true);
            keys.insert(CAP_SHELL_PRE_BLOCK.into(), true);
            keys.insert(CAP_SHELL_RESULT_CAPTURE.into(), false);
            keys.insert(CAP_COMPLETION_GATE.into(), true);
            keys.insert(CAP_SUBAGENT_VISIBILITY.into(), false);
            keys.insert(CAP_IMMUTABLE_JOURNAL.into(), true);
            keys.insert(CAP_OFFLINE_VERIFICATION.into(), true);
            gate_cells.insert("test-integrity".into(), GateCell::CannotObserve);
            for gate in [
                "evidence-completeness",
                "filesystem-scope",
                "shell-irreversible",
                "dependency-reality",
                "secret-output",
                "journal-tamper",
            ] {
                gate_cells.insert(gate.into(), GateCell::Prevent);
            }
        }
        ADAPTER_GEMINI_CLI => {
            keys.insert(CAP_PRE_WRITE_BLOCK.into(), true);
            keys.insert(CAP_POST_WRITE_RECEIPT.into(), true);
            keys.insert(CAP_SHELL_PRE_BLOCK.into(), true);
            keys.insert(CAP_SHELL_RESULT_CAPTURE.into(), false);
            keys.insert(CAP_COMPLETION_GATE.into(), false);
            keys.insert(CAP_SUBAGENT_VISIBILITY.into(), false);
            keys.insert(CAP_IMMUTABLE_JOURNAL.into(), true);
            keys.insert(CAP_OFFLINE_VERIFICATION.into(), true);
            for gate in [
                "test-integrity",
                "evidence-completeness",
                "dependency-reality",
            ] {
                gate_cells.insert(gate.into(), GateCell::CannotObserve);
            }
            for gate in [
                "filesystem-scope",
                "shell-irreversible",
                "secret-output",
                "journal-tamper",
            ] {
                gate_cells.insert(gate.into(), GateCell::Prevent);
            }
        }
        ADAPTER_CURSOR => {
            keys.insert(CAP_PRE_WRITE_BLOCK.into(), false);
            keys.insert(CAP_POST_WRITE_RECEIPT.into(), false);
            keys.insert(CAP_SHELL_PRE_BLOCK.into(), true);
            keys.insert(CAP_SHELL_RESULT_CAPTURE.into(), false);
            keys.insert(CAP_COMPLETION_GATE.into(), false);
            keys.insert(CAP_SUBAGENT_VISIBILITY.into(), false);
            keys.insert(CAP_IMMUTABLE_JOURNAL.into(), true);
            keys.insert(CAP_OFFLINE_VERIFICATION.into(), true);
            for gate in [
                "test-integrity",
                "evidence-completeness",
                "filesystem-scope",
                "dependency-reality",
                "secret-output",
            ] {
                gate_cells.insert(gate.into(), GateCell::CannotObserve);
            }
            gate_cells.insert("shell-irreversible".into(), GateCell::Prevent);
            gate_cells.insert("journal-tamper".into(), GateCell::Prevent);
        }
        _ => {
            keys.insert(CAP_POST_WRITE_RECEIPT.into(), true);
            keys.insert(CAP_IMMUTABLE_JOURNAL.into(), true);
            keys.insert(CAP_OFFLINE_VERIFICATION.into(), true);
            for gate in [
                "test-integrity",
                "evidence-completeness",
                "shell-irreversible",
                "dependency-reality",
                "secret-output",
            ] {
                gate_cells.insert(gate.into(), GateCell::CannotObserve);
            }
            gate_cells.insert("filesystem-scope".into(), GateCell::Detect);
            gate_cells.insert("journal-tamper".into(), GateCell::Prevent);
        }
    }
    CapabilityProbe {
        adapter: adapter.into(),
        keys,
        gate_cells,
        probed_at: None,
        notes: vec!["conformance frozen probe".into()],
    }
}

fn parse_verdict(s: &str) -> Result<Verdict, AdapterError> {
    match s {
        "allow" => Ok(Verdict::Allow),
        "deny" => Ok(Verdict::Deny),
        "quarantine" => Ok(Verdict::Quarantine),
        "advisory" => Ok(Verdict::Advisory),
        "refuted" => Ok(Verdict::Refuted),
        "verified" => Ok(Verdict::Verified),
        "unsupported" => Ok(Verdict::Unsupported),
        "incomplete" => Ok(Verdict::Incomplete),
        other => Err(AdapterError::Invalid(format!("unknown verdict {other}"))),
    }
}
