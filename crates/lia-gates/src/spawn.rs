//! Spawn-agent GATE (V3-A): Task / spawn_subagent / Agent policy + signed verdict.

use lia_protocol::{RiskTier, Verdict};
use serde_json::json;

use crate::{make_outcome, GateConfig, GateOutcome, GateRequest, SpawnPolicy};

pub fn check_spawn_agent(
    request: &GateRequest,
    config: &GateConfig,
) -> Result<GateOutcome, crate::GateError> {
    let policy = config
        .spawn_policy
        .clone()
        .unwrap_or_else(SpawnPolicy::default);
    let agent_type = request
        .payload
        .spawn_agent_type
        .clone()
        .unwrap_or_else(|| "unspecified".into());
    let session_id = request.payload.session_id.clone();
    let parent_session_id = request.payload.parent_session_id.clone();
    let agent_id = request.payload.agent_id.clone();
    let prompt_preview = request
        .payload
        .text
        .as_deref()
        .map(|t| {
            let t = t.trim();
            if t.len() > 200 {
                format!("{}…", &t[..200])
            } else {
                t.to_string()
            }
        })
        .unwrap_or_default();

    let evidence = json!({
        "action": "spawn_agent",
        "allow": policy.allow,
        "agent_type": agent_type,
        "session_id": session_id,
        "parent_session_id": parent_session_id,
        "agent_id": agent_id,
        "prompt_preview": prompt_preview,
        "cwd": request.payload.cwd,
    });

    // Human- and journal-recoverable linkage (V3-11): ids must appear in GateVerdict
    // detail, not only inside evidence_sha256 of the evidence blob.
    let detail = spawn_detail_line(
        policy.allow,
        &agent_type,
        session_id.as_deref(),
        parent_session_id.as_deref(),
        agent_id.as_deref(),
    );

    if policy.allow {
        Ok(make_outcome(
            request,
            Verdict::Allow,
            "SPAWN_ALLOWED",
            RiskTier::Productivity,
            Some(detail),
            None,
            &evidence,
        ))
    } else {
        Ok(make_outcome(
            request,
            Verdict::Deny,
            "SPAWN_DENIED",
            RiskTier::Security,
            Some(detail),
            Some(agent_type),
            &evidence,
        ))
    }
}

/// Stable journal/operator detail for spawn decisions, including parent/child linkage.
pub fn spawn_detail_line(
    allow: bool,
    agent_type: &str,
    session_id: Option<&str>,
    parent_session_id: Option<&str>,
    agent_id: Option<&str>,
) -> String {
    let verb = if allow { "allowed" } else { "denied by spawn_policy" };
    let session = session_id.unwrap_or("-");
    let parent = parent_session_id.unwrap_or("-");
    let agent = agent_id.unwrap_or("-");
    format!(
        "spawn_agent {verb} (agent_type={agent_type}; session_id={session}; parent_session_id={parent}; agent_id={agent}); child tools not automatically mediated"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GateConfig, GatePayload};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn cfg(allow: bool) -> GateConfig {
        GateConfig {
            allowed_roots: vec![PathBuf::from("/tmp")],
            home_dir: None,
            cwd: PathBuf::from("/tmp"),
            protected_paths: vec![],
            registry: BTreeMap::new(),
            env: BTreeMap::new(),
            run_id: None,
            cleanup_policy: None,
            spawn_policy: Some(SpawnPolicy { allow }),
        }
    }

    fn req() -> GateRequest {
        GateRequest {
            gate_id: "spawn-agent".into(),
            action_id: Uuid::new_v4(),
            kind: Some(lia_protocol::ActionKind::SpawnAgent),
            payload: GatePayload {
                text: Some("do the thing".into()),
                spawn_agent_type: Some("explore".into()),
                session_id: Some("child-1".into()),
                parent_session_id: Some("parent-0".into()),
                agent_id: Some("agent-9".into()),
                action_label: Some("spawn_agent".into()),
                cwd: Some("/tmp".into()),
                ..GatePayload::default()
            },
        }
    }

    #[test]
    fn allow_default_and_explicit() {
        let out = check_spawn_agent(&req(), &cfg(true)).unwrap();
        assert_eq!(out.verdict, Verdict::Allow);
        assert_eq!(out.reason_code, "SPAWN_ALLOWED");
        assert_eq!(out.gate_id, "spawn-agent");
    }

    #[test]
    fn deny_when_policy_disallows() {
        let out = check_spawn_agent(&req(), &cfg(false)).unwrap();
        assert_eq!(out.verdict, Verdict::Deny);
        assert_eq!(out.reason_code, "SPAWN_DENIED");
    }

    #[test]
    fn missing_policy_defaults_to_allow() {
        let mut c = cfg(true);
        c.spawn_policy = None;
        let out = check_spawn_agent(&req(), &c).unwrap();
        assert_eq!(out.reason_code, "SPAWN_ALLOWED");
    }

    #[test]
    fn detail_embeds_parent_child_and_agent_ids() {
        let out = check_spawn_agent(&req(), &cfg(true)).unwrap();
        let detail = out.detail.expect("detail");
        assert!(detail.contains("session_id=child-1"), "{detail}");
        assert!(detail.contains("parent_session_id=parent-0"), "{detail}");
        assert!(detail.contains("agent_id=agent-9"), "{detail}");
        assert!(detail.contains("agent_type=explore"), "{detail}");
        assert!(detail.contains("spawn_agent allowed"), "{detail}");
    }

    #[test]
    fn deny_detail_also_embeds_linkage_ids() {
        let out = check_spawn_agent(&req(), &cfg(false)).unwrap();
        let detail = out.detail.expect("detail");
        assert!(detail.contains("parent_session_id=parent-0"), "{detail}");
        assert!(detail.contains("session_id=child-1"), "{detail}");
        assert!(detail.contains("agent_id=agent-9"), "{detail}");
        assert!(detail.contains("denied"), "{detail}");
    }
}
