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

    if policy.allow {
        Ok(make_outcome(
            request,
            Verdict::Allow,
            "SPAWN_ALLOWED",
            RiskTier::Productivity,
            Some(format!(
                "spawn_agent allowed (agent_type={agent_type}); child tools not automatically mediated"
            )),
            None,
            &evidence,
        ))
    } else {
        Ok(make_outcome(
            request,
            Verdict::Deny,
            "SPAWN_DENIED",
            RiskTier::Security,
            Some(format!(
                "spawn_agent denied by spawn_policy (agent_type={agent_type})"
            )),
            Some(agent_type),
            &evidence,
        ))
    }
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
}
