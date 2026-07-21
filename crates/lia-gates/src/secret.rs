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
        // any PEM private key header (RSA/EC/DSA/OPENSSH/ENCRYPTED/PGP ... PRIVATE KEY)
        (r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY", "private_key"),
        // AWS long-term (AKIA) and STS temporary (ASIA) access-key ids
        (r"A[KS]IA[0-9A-Z]{16}", "aws_access_key"),
        (r"(?i)aws_secret_access_key\s*=\s*\S+", "aws_secret"),
        // GitHub PAT (ghp_), oauth (gho_), user (ghu_), server (ghs_), refresh (ghr_), fine-grained
        (r"gh[opsur]_[A-Za-z0-9]{36}", "github_token"),
        (r"github_pat_[A-Za-z0-9_]{22,}", "github_fine_grained_pat"),
        (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
        (r"(?i)api[_-]?key\s*[:=]\s*\S{16,}", "api_key"),
        (r"(?i)password\s*[:=]\s*\S{8,}", "password"),
        // OpenAI project / user / service keys
        (r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b", "openai_project_key"),
        (r"\bsk-[A-Za-z0-9]{20,}\b", "openai_api_key"),
        // Anthropic
        (r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "anthropic_api_key"),
        // Google / Gemini API keys
        (r"\bAIza[0-9A-Za-z_\-]{20,}\b", "google_api_key"),
        // HuggingFace
        (r"\bhf_[A-Za-z0-9]{20,}\b", "huggingface_token"),
        // Stripe live secret / restricted keys
        (r"\b[sr]k_live_[A-Za-z0-9]{20,}\b", "stripe_key"),
        // JWT (three base64url segments, header begins eyJ = {"…)
        (r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "jwt"),
        // credentials embedded in a URI (scheme://user:pass@host)
        (r"://[^/\s:@]+:[^/\s@]+@", "uri_credentials"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn detects_sk_proj_openai_project_key() {
        let req = GateRequest {
            gate_id: "secret-output".into(),
            action_id: Uuid::new_v4(),
            kind: None,
            payload: crate::GatePayload {
                text: Some(
                    "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD".into(),
                ),
                ..crate::GatePayload::default()
            },
        };
        let out = check_secret_output(&req).expect("eval");
        assert!(matches!(out.verdict, Verdict::Deny));
        assert_eq!(out.reason_code, "SECRET_IN_OUTPUT");
    }

    #[test]
    fn detects_additional_secret_shapes() {
        // each of these leaked ALLOW before the coverage fix. token-shaped fixtures are
        // split with concat! so the committed source never contains a contiguous
        // secret-shaped literal (push-protection scans the blob, not the runtime value).
        for s in [
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            concat!("AS", "IAY34FZKBOKMUTVV7A"),
            concat!("gh", "o_", "16C7e42F292c6912E7710c838347Ae178B4a"),
            concat!("gh", "u_", "16C7e42F292c6912E7710c838347Ae178B4a"),
            concat!("github", "_pat_", "11ABCDEFG0abcdefghijkl_MNOPQRSTUVWXYZ0123456789"),
            concat!("eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".abcDEFghiJKLmnop"),
            "postgres://admin:S3cr3tPass@db.internal/prod",
            concat!("sk", "_live_", "abcdefghijklmnopqrstuvwx"),
        ] {
            let req = GateRequest {
                gate_id: "secret-output".into(),
                action_id: Uuid::new_v4(),
                kind: None,
                payload: crate::GatePayload {
                    text: Some(s.into()),
                    ..crate::GatePayload::default()
                },
            };
            let out = check_secret_output(&req).expect("eval");
            assert!(
                matches!(out.verdict, Verdict::Deny),
                "expected DENY for secret shape: {s}"
            );
        }
    }

    #[test]
    fn clean_text_allows() {
        let req = GateRequest {
            gate_id: "secret-output".into(),
            action_id: Uuid::new_v4(),
            kind: None,
            payload: crate::GatePayload {
                text: Some("hello world no secrets here".into()),
                ..crate::GatePayload::default()
            },
        };
        let out = check_secret_output(&req).expect("eval");
        assert!(matches!(out.verdict, Verdict::Allow));
    }
}
