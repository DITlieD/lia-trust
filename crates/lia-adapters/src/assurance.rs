use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::contracts::{
    ADAPTER_CLAUDE_CODE, ADAPTER_CODEX, ADAPTER_GENERIC, ALL_CAPABILITY_KEYS, CAP_COMPLETION_GATE,
    CAP_CREDENTIAL_BROKER, CAP_IMMUTABLE_JOURNAL, CAP_NETWORK_CONTROL, CAP_OFFLINE_VERIFICATION,
    CAP_POST_WRITE_RECEIPT, CAP_PRE_WRITE_BLOCK, CAP_SHELL_PRE_BLOCK, CAP_SHELL_RESULT_CAPTURE,
    CAP_SUBAGENT_VISIBILITY,
};
use crate::AdapterError;
use lia_gates::CORE_GATE_IDS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum GateCell {
    Prevent,
    Detect,
    #[serde(rename = "CANNOT-OBSERVE")]
    CannotObserve,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceLevel {
    Audit,
    Observe,
    Gate,
    Confine,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityProbe {
    pub adapter: String,
    pub keys: BTreeMap<String, bool>,
    #[serde(default)]
    pub probed_at: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateAssuranceCell {
    pub gate_id: String,
    pub cell: GateCell,
    pub limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceReport {
    pub adapter: String,
    pub level: AssuranceLevel,
    pub gates: Vec<GateAssuranceCell>,
    pub capability_keys: BTreeMap<String, bool>,
    pub mediation: String,
    pub network: String,
    pub notes: Vec<String>,
}

impl AssuranceReport {
    pub fn from_probe(probe: &CapabilityProbe) -> Result<Self, AdapterError> {
        let keys = normalize_keys(&probe.keys);
        let mut gates = Vec::new();
        for gate_id in CORE_GATE_IDS {
            let (cell, limit) = cell_for_gate(gate_id, &keys);
            gates.push(GateAssuranceCell {
                gate_id: (*gate_id).to_string(),
                cell,
                limit,
            });
        }

        let level = rollup_level(&keys);
        let mediation = if cap(&keys, CAP_PRE_WRITE_BLOCK) || cap(&keys, CAP_SHELL_PRE_BLOCK) {
            if probe.adapter == ADAPTER_GENERIC {
                "mediation: incomplete — an out-of-band process can bypass LIA on this harness; native ELAI's process-isolation closes this".into()
            } else if probe.adapter == ADAPTER_CODEX {
                "mediation: incomplete — only tools routed through the MCP proxy are gated; native FS/shell/network can bypass".into()
            } else {
                "mediation: hook-path complete for matched tools; @-path reads and non-tool side effects are outside PreToolUse".into()
            }
        } else {
            "mediation: incomplete — no pre-execution block capability observed on this harness".into()
        };
        let network = if cap(&keys, CAP_NETWORK_CONTROL) {
            "network confinement: PREVENT".into()
        } else {
            "network confinement: CANNOT-GUARANTEE (this harness has no egress hook)".into()
        };

        Ok(Self {
            adapter: probe.adapter.clone(),
            level,
            gates,
            capability_keys: keys,
            mediation,
            network,
            notes: probe.notes.clone(),
        })
    }

    pub fn one_line(&self) -> String {
        let cells: Vec<String> = self
            .gates
            .iter()
            .map(|g| format!("{}: {:?}", g.gate_id, g.cell).replace("Prevent", "PREVENT").replace("Detect", "DETECT").replace("CannotObserve", "CANNOT-OBSERVE"))
            .collect();
        format!(
            "adapter={} | {} | {} | assurance level: {:?}",
            self.adapter,
            cells.join(" | "),
            self.network,
            self.level
        )
        .replace("Audit", "AUDIT")
        .replace("Observe", "OBSERVE")
        .replace("Gate", "GATE")
        .replace("Confine", "CONFINE")
    }

    pub fn render_table(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("adapter: {}", self.adapter));
        for g in &self.gates {
            lines.push(format!(
                "{}: {} | {}",
                g.gate_id,
                cell_str(g.cell),
                g.limit
            ));
        }
        lines.push(self.network.clone());
        lines.push(self.mediation.clone());
        lines.push(format!("assurance level: {}", level_str(self.level)));
        lines.join("\n")
    }
}

fn cell_str(c: GateCell) -> &'static str {
    match c {
        GateCell::Prevent => "PREVENT",
        GateCell::Detect => "DETECT",
        GateCell::CannotObserve => "CANNOT-OBSERVE",
    }
}

fn level_str(l: AssuranceLevel) -> &'static str {
    match l {
        AssuranceLevel::Audit => "AUDIT",
        AssuranceLevel::Observe => "OBSERVE",
        AssuranceLevel::Gate => "GATE",
        AssuranceLevel::Confine => "CONFINE",
    }
}

fn normalize_keys(input: &BTreeMap<String, bool>) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for key in ALL_CAPABILITY_KEYS {
        out.insert((*key).to_string(), input.get(*key).copied().unwrap_or(false));
    }
    out
}

fn cap(keys: &BTreeMap<String, bool>, name: &str) -> bool {
    keys.get(name).copied().unwrap_or(false)
}

fn cell_for_gate(gate_id: &str, keys: &BTreeMap<String, bool>) -> (GateCell, String) {
    match gate_id {
        "test-integrity" => {
            if cap(keys, CAP_SHELL_RESULT_CAPTURE) && cap(keys, CAP_COMPLETION_GATE) {
                (
                    GateCell::Prevent,
                    "wrapper-captured test evidence required before pass".into(),
                )
            } else if cap(keys, CAP_SHELL_RESULT_CAPTURE) || cap(keys, CAP_POST_WRITE_RECEIPT) {
                (
                    GateCell::Detect,
                    "can record test claims; cannot always block pre-claim".into(),
                )
            } else {
                (
                    GateCell::CannotObserve,
                    "no test result capture on this harness".into(),
                )
            }
        }
        "evidence-completeness" => {
            if cap(keys, CAP_COMPLETION_GATE) {
                (GateCell::Prevent, "completion gated on required evidence".into())
            } else if cap(keys, CAP_POST_WRITE_RECEIPT) {
                (GateCell::Detect, "completion evidence inspected post-hoc".into())
            } else {
                (
                    GateCell::CannotObserve,
                    "no completion observation channel".into(),
                )
            }
        }
        "filesystem-scope" => {
            if cap(keys, CAP_PRE_WRITE_BLOCK) {
                (GateCell::Prevent, "pre-write path scope enforced".into())
            } else if cap(keys, CAP_POST_WRITE_RECEIPT) {
                (
                    GateCell::Detect,
                    "file watcher / diff admission detect-only; not pre-write prevention".into(),
                )
            } else {
                (
                    GateCell::CannotObserve,
                    "no filesystem observation channel".into(),
                )
            }
        }
        "shell-irreversible" => {
            if cap(keys, CAP_SHELL_PRE_BLOCK) {
                (GateCell::Prevent, "shell pre-exec block via hook/proxy".into())
            } else if cap(keys, CAP_SHELL_RESULT_CAPTURE) {
                (GateCell::Detect, "shell results captured after exec".into())
            } else {
                (
                    GateCell::CannotObserve,
                    "shell interception unavailable on this harness".into(),
                )
            }
        }
        "dependency-reality" => {
            if cap(keys, CAP_PRE_WRITE_BLOCK) || cap(keys, CAP_COMPLETION_GATE) {
                (GateCell::Prevent, "dependency add gated before apply".into())
            } else if cap(keys, CAP_POST_WRITE_RECEIPT) {
                (GateCell::Detect, "dependency claims checked post-hoc".into())
            } else {
                (
                    GateCell::CannotObserve,
                    "no dependency observation channel".into(),
                )
            }
        }
        "secret-output" => {
            if cap(keys, CAP_PRE_WRITE_BLOCK) {
                (GateCell::Prevent, "secret-bearing content inspectable pre-write".into())
            } else if cap(keys, CAP_POST_WRITE_RECEIPT) || cap(keys, CAP_SHELL_RESULT_CAPTURE) {
                (GateCell::Detect, "secrets scanned in captured outputs".into())
            } else {
                (
                    GateCell::CannotObserve,
                    "no output capture for secret scanning".into(),
                )
            }
        }
        "journal-tamper" => {
            if cap(keys, CAP_IMMUTABLE_JOURNAL) && cap(keys, CAP_OFFLINE_VERIFICATION) {
                (
                    GateCell::Prevent,
                    "tampered journal fails offline verify / append-only store".into(),
                )
            } else if cap(keys, CAP_IMMUTABLE_JOURNAL) || cap(keys, CAP_OFFLINE_VERIFICATION) {
                (GateCell::Detect, "partial journal integrity signal".into())
            } else {
                (
                    GateCell::CannotObserve,
                    "journal integrity not available".into(),
                )
            }
        }
        other => (
            GateCell::CannotObserve,
            format!("unknown gate {other}"),
        ),
    }
}

fn rollup_level(keys: &BTreeMap<String, bool>) -> AssuranceLevel {
    let confine_shape = cap(keys, CAP_NETWORK_CONTROL)
        && cap(keys, CAP_CREDENTIAL_BROKER)
        && cap(keys, CAP_PRE_WRITE_BLOCK)
        && cap(keys, CAP_SHELL_PRE_BLOCK);
    if confine_shape {
        return AssuranceLevel::Gate;
    }
    if cap(keys, CAP_PRE_WRITE_BLOCK)
        || cap(keys, CAP_SHELL_PRE_BLOCK)
        || cap(keys, CAP_COMPLETION_GATE)
    {
        return AssuranceLevel::Gate;
    }
    if cap(keys, CAP_POST_WRITE_RECEIPT)
        || cap(keys, CAP_SHELL_RESULT_CAPTURE)
        || cap(keys, CAP_SUBAGENT_VISIBILITY)
        || cap(keys, CAP_IMMUTABLE_JOURNAL)
    {
        return AssuranceLevel::Observe;
    }
    if cap(keys, CAP_OFFLINE_VERIFICATION) {
        return AssuranceLevel::Audit;
    }
    AssuranceLevel::Audit
}

pub fn load_assurance_from_probe_file(path: impl AsRef<Path>) -> Result<AssuranceReport, AdapterError> {
    let bytes = fs::read(path.as_ref()).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    let probe: CapabilityProbe =
        serde_json::from_slice(&bytes).map_err(|e| AdapterError::Invalid(e.to_string()))?;
    AssuranceReport::from_probe(&probe)
}

pub fn report_for_adapter(
    adapter: &str,
    probe_path: Option<&Path>,
) -> Result<AssuranceReport, AdapterError> {
    match probe_path {
        Some(p) => {
            let report = load_assurance_from_probe_file(p)?;
            if report.adapter != adapter {
                return Err(AdapterError::Invalid(format!(
                    "probe adapter {} does not match --adapter {adapter}",
                    report.adapter
                )));
            }
            Ok(report)
        }
        None => Err(AdapterError::Invalid(
            "assurance report requires --probe <file> (probe-derived; never hard-coded)".into(),
        )),
    }
}

pub fn known_adapters() -> &'static [&'static str] {
    &[ADAPTER_CLAUDE_CODE, ADAPTER_CODEX, ADAPTER_GENERIC]
}
