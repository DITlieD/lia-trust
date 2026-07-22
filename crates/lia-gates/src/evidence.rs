use lia_protocol::{RiskTier, Verdict};
use serde_json::json;

use crate::{make_outcome, GateError, GateOutcome, GateRequest};

pub fn check_evidence_completeness(request: &GateRequest) -> Result<GateOutcome, GateError> {
    let modified = request.payload.modified_paths.clone().unwrap_or_default();
    let new_deps = request.payload.new_dependencies.clone().unwrap_or_default();
    let has_test = request.payload.has_test_result.unwrap_or(false);
    let unsupported = request.payload.test_unsupported.unwrap_or(false);
    let deps_ok = request.payload.deps_registry_evidence.unwrap_or(false);

    let evidence = json!({
        "modified_paths": modified,
        "new_dependencies": new_deps,
        "has_test_result": has_test,
        "test_unsupported": unsupported,
        "deps_registry_evidence": deps_ok,
    });

    if !modified.is_empty() && !has_test && !unsupported {
        return Ok(make_outcome(
            request,
            Verdict::Incomplete,
            "EVIDENCE_INCOMPLETE",
            RiskTier::Security,
            Some("modified code requires test-result or unsupported-test verdict".into()),
            Some(modified.join(",")),
            &evidence,
        ));
    }

    if !new_deps.is_empty() && !deps_ok {
        return Ok(make_outcome(
            request,
            Verdict::Incomplete,
            "EVIDENCE_INCOMPLETE",
            RiskTier::Security,
            Some("new dependency requires registry evidence".into()),
            Some(new_deps.join(",")),
            &evidence,
        ));
    }

    Ok(make_outcome(
        request,
        Verdict::Allow,
        "GATE_ALLOW",
        RiskTier::Security,
        Some("required completion evidence present".into()),
        None,
        &evidence,
    ))
}
