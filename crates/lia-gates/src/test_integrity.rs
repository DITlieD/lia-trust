use lia_protocol::{RiskTier, Verdict};
use serde_json::json;

use crate::{make_outcome, GateError, GateOutcome, GateRequest};

pub fn check_test_integrity(request: &GateRequest) -> Result<GateOutcome, GateError> {
    let claimed = request.payload.claimed_pass.ok_or_else(|| {
        GateError::Invalid("test-integrity requires claimed_pass".into())
    })?;
    let evidence = json!({
        "claimed_pass": claimed,
        "wrapper": request.payload.wrapper,
    });

    if !claimed {
        let mut out = make_outcome(
            "test-integrity",
            request.action_id,
            Verdict::Allow,
            "TEST_INTEGRITY_OK",
            RiskTier::Security,
            Some("claimed failure needs no wrapper pass receipt".into()),
            None,
            &evidence,
        );
        out.hl4 = request.payload.wrapper.clone();
        return Ok(out);
    }

    let Some(wrapper) = request.payload.wrapper.as_ref() else {
        return Ok(make_outcome(
            "test-integrity",
            request.action_id,
            Verdict::Refuted,
            "TEST_FABRICATED_PASS",
            RiskTier::Security,
            Some("claimed_pass=true with no wrapper-captured observation".into()),
            Some("claimed_pass".into()),
            &evidence,
        ));
    };

    if !hl4_complete(wrapper) {
        return Ok(make_outcome(
            "test-integrity",
            request.action_id,
            Verdict::Deny,
            "TEST_MISSING_HL4_FIELDS",
            RiskTier::Security,
            Some("wrapper observation missing HL-4 field set".into()),
            Some("wrapper".into()),
            &evidence,
        ));
    }

    if wrapper.exit_code != 0 {
        return Ok(make_outcome(
            "test-integrity",
            request.action_id,
            Verdict::Refuted,
            "TEST_FABRICATED_PASS",
            RiskTier::Security,
            Some(format!(
                "claimed_pass=true but wrapper exit_code={}",
                wrapper.exit_code
            )),
            Some(format!("exit_code={}", wrapper.exit_code)),
            &evidence,
        ));
    }

    let mut out = make_outcome(
        "test-integrity",
        request.action_id,
        Verdict::Allow,
        "TEST_INTEGRITY_OK",
        RiskTier::Security,
        Some("wrapper-observed pass binds HL-4 fields".into()),
        None,
        &evidence,
    );
    out.hl4 = Some(wrapper.clone());
    Ok(out)
}

fn hl4_complete(w: &crate::WrapperObservation) -> bool {
    !w.stdout_sha256.is_empty()
        && !w.stderr_sha256.is_empty()
        && !w.argv.is_empty()
        && !w.cwd.is_empty()
        && !w.coverage_profraw_sha256.is_empty()
        && !w.wrapper_digest_sha256.is_empty()
        && w.stdout_sha256.len() == 64
        && w.stderr_sha256.len() == 64
        && w.coverage_profraw_sha256.len() == 64
        && w.wrapper_digest_sha256.len() == 64
}
