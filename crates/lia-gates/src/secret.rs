use lia_protocol::{RiskTier, Verdict};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{blake3_hex, make_outcome, GateError, GateOutcome, GateRequest};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShareableProjection {
    pub content_blake3: String,
    pub byte_len: u64,
    pub redaction_count: u64,
    pub has_secret_material: bool,
}

pub fn check_secret_output(request: &GateRequest) -> Result<GateOutcome, GateError> {
    let text = request
        .payload
        .text
        .as_deref()
        .ok_or_else(|| GateError::Invalid("secret-output requires text".into()))?;

    let hits = detect_secrets(text);
    let projection = ShareableProjection {
        content_blake3: blake3_hex(text.as_bytes()),
        byte_len: text.len() as u64,
        redaction_count: hits.len() as u64,
        has_secret_material: !hits.is_empty(),
    };

    let evidence = json!({
        "shareable": projection,
        "hit_kinds": hits,
    });

    if !hits.is_empty() {
        let mut out = make_outcome(
            "secret-output",
            request.action_id,
            Verdict::Deny,
            "SECRET_IN_OUTPUT",
            RiskTier::Secret,
            Some(format!("sensitive material detected: {}", hits.join(","))),
            Some(hits.join(",")),
            &evidence,
        );
        out.shareable = Some(projection);
        return Ok(out);
    }

    let mut out = make_outcome(
        "secret-output",
        request.action_id,
        Verdict::Allow,
        "GATE_ALLOW",
        RiskTier::Secret,
        Some("no secret patterns; shareable projection carries hashes only".into()),
        None,
        &evidence,
    );
    out.shareable = Some(projection);
    Ok(out)
}

fn detect_secrets(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let patterns: &[(&str, &str)] = &[
        (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key"),
        (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
        (r"(?i)aws_secret_access_key\s*=\s*\S+", "aws_secret"),
        (r"ghp_[A-Za-z0-9]{36}", "github_pat"),
        (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
        (r"(?i)api[_-]?key\s*[:=]\s*\S{16,}", "api_key"),
        (r"(?i)password\s*[:=]\s*\S{8,}", "password"),
    ];
    for (pat, kind) in patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(text) {
                hits.push((*kind).to_string());
            }
        }
    }
    hits
}
