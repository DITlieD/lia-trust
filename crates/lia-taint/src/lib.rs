use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TaintError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid flow: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum NodeKind {
    UntrustedSource,
    Intermediate,
    DestructiveSink,
    Declassifier,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaintNode {
    pub id: String,
    pub kind: NodeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaintEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaintGraph {
    pub nodes: Vec<TaintNode>,
    pub edges: Vec<TaintEdge>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum TaintVerdict {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaintFinding {
    pub source: String,
    pub sink: String,
    pub path: Vec<String>,
    pub declassified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaintReport {
    pub verdict: TaintVerdict,
    pub reason_code: String,
    pub findings: Vec<TaintFinding>,
}

pub const TAINT_REASON_OK: &str = "TAINT_OK";
pub const TAINT_REASON_UNTRUSTED_TO_SINK: &str = "TAINT_UNTRUSTED_TO_DESTRUCTIVE_SINK";

pub fn parse_graph(json: &str) -> Result<TaintGraph, TaintError> {
    Ok(serde_json::from_str(json)?)
}

pub fn check_flows(graph: &TaintGraph) -> Result<TaintReport, TaintError> {
    if graph.nodes.is_empty() {
        return Err(TaintError::Invalid("taint graph has no nodes".into()));
    }
    let mut kinds: BTreeMap<&str, NodeKind> = BTreeMap::new();
    for n in &graph.nodes {
        if kinds.insert(n.id.as_str(), n.kind).is_some() {
            return Err(TaintError::Invalid(format!("duplicate node id {}", n.id)));
        }
    }
    for e in &graph.edges {
        if !kinds.contains_key(e.from.as_str()) || !kinds.contains_key(e.to.as_str()) {
            return Err(TaintError::Invalid(format!(
                "edge {} -> {} references unknown node",
                e.from, e.to
            )));
        }
    }

    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in &graph.edges {
        adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
    }

    let sources: Vec<&str> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::UntrustedSource)
        .map(|n| n.id.as_str())
        .collect();
    let sinks: BTreeSet<&str> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::DestructiveSink)
        .map(|n| n.id.as_str())
        .collect();

    let mut findings = Vec::new();
    for src in sources {
        let paths = paths_to_sinks(src, &adj, &sinks, &kinds);
        for (path, declassified) in paths {
            let sink = path.last().copied().unwrap_or(src).to_string();
            findings.push(TaintFinding {
                source: src.to_string(),
                sink,
                path: path.into_iter().map(|s| s.to_string()).collect(),
                declassified,
            });
        }
    }

    let bad: Vec<&TaintFinding> = findings.iter().filter(|f| !f.declassified).collect();
    if bad.is_empty() {
        Ok(TaintReport {
            verdict: TaintVerdict::Allow,
            reason_code: TAINT_REASON_OK.to_string(),
            findings,
        })
    } else {
        Ok(TaintReport {
            verdict: TaintVerdict::Deny,
            reason_code: TAINT_REASON_UNTRUSTED_TO_SINK.to_string(),
            findings,
        })
    }
}

fn paths_to_sinks<'a>(
    start: &'a str,
    adj: &BTreeMap<&'a str, Vec<&'a str>>,
    sinks: &BTreeSet<&'a str>,
    kinds: &BTreeMap<&'a str, NodeKind>,
) -> Vec<(Vec<&'a str>, bool)> {
    let mut out = Vec::new();
    let mut q: VecDeque<(Vec<&'a str>, bool)> = VecDeque::new();
    q.push_back((vec![start], false));
    let mut seen_edges: BTreeSet<(usize, &'a str, bool)> = BTreeSet::new();

    while let Some((path, decl)) = q.pop_front() {
        let cur = match path.last().copied() {
            Some(c) => c,
            None => continue,
        };
        if sinks.contains(cur) && path.len() > 1 {
            out.push((path.clone(), decl));
        }
        if let Some(nexts) = adj.get(cur) {
            for nxt in nexts {
                let mut next_decl = decl;
                if kinds.get(nxt) == Some(&NodeKind::Declassifier) {
                    next_decl = true;
                }
                let key = (path.len(), *nxt, next_decl);
                if !seen_edges.insert(key) {
                    continue;
                }
                if path.contains(nxt) {
                    continue;
                }
                let mut np = path.clone();
                np.push(*nxt);
                q.push_back((np, next_decl));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_to_sink_denied() {
        let g = TaintGraph {
            nodes: vec![
                TaintNode {
                    id: "req.body".into(),
                    kind: NodeKind::UntrustedSource,
                },
                TaintNode {
                    id: "fs.delete".into(),
                    kind: NodeKind::DestructiveSink,
                },
            ],
            edges: vec![TaintEdge {
                from: "req.body".into(),
                to: "fs.delete".into(),
            }],
        };
        let r = check_flows(&g).unwrap();
        assert_eq!(r.verdict, TaintVerdict::Deny);
        assert_eq!(r.reason_code, TAINT_REASON_UNTRUSTED_TO_SINK);
        assert!(!r.findings[0].declassified);
    }

    #[test]
    fn explicit_declassification_allows() {
        let g = TaintGraph {
            nodes: vec![
                TaintNode {
                    id: "req.body".into(),
                    kind: NodeKind::UntrustedSource,
                },
                TaintNode {
                    id: "sanitize".into(),
                    kind: NodeKind::Declassifier,
                },
                TaintNode {
                    id: "fs.delete".into(),
                    kind: NodeKind::DestructiveSink,
                },
            ],
            edges: vec![
                TaintEdge {
                    from: "req.body".into(),
                    to: "sanitize".into(),
                },
                TaintEdge {
                    from: "sanitize".into(),
                    to: "fs.delete".into(),
                },
            ],
        };
        let r = check_flows(&g).unwrap();
        assert_eq!(r.verdict, TaintVerdict::Allow);
        assert!(r.findings.iter().all(|f| f.declassified));
    }
}
