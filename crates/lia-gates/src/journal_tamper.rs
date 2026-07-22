use lia_protocol::{RiskTier, Verdict};
use serde_json::json;

use crate::{make_outcome, GateConfig, GateError, GateOutcome, GateRequest};

// SCOPE: this gate is a STRUCTURAL chain probe over supplied row summaries (seq continuity,
// prev_hash linkage, cross-session run_id, duplicate row_hash). It does NOT recompute
// row_hash from event bytes or verify Ed25519 signatures — those live in
// `lia_journal::verify_chain` (driven by `lia journal-verify` / `lia verify`), which is the
// cryptographic, un-forgeable check. Do not read a pass here as "content-tamper detected";
// it detects reorder/gap/dup/cross-session, a strictly weaker property than the real verify.
pub fn check_journal_tamper(
    request: &GateRequest,
    config: &GateConfig,
) -> Result<GateOutcome, GateError> {
    let rows = request
        .payload
        .journal_rows
        .as_ref()
        .ok_or_else(|| GateError::Invalid("journal-tamper requires journal_rows".into()))?;

    let expected_run = request
        .payload
        .expected_run_id
        .or(config.run_id)
        .ok_or_else(|| GateError::Invalid("journal-tamper requires expected_run_id".into()))?;

    let evidence = json!({
        "rows": rows,
        "expected_run_id": expected_run,
    });

    if rows.is_empty() {
        return Ok(make_outcome(
            request,
            Verdict::Deny,
            "JOURNAL_TAMPER_DETECTED",
            RiskTier::Security,
            Some("empty journal probe where completeness matters".into()),
            None,
            &evidence,
        ));
    }

    let mut expected_seq = rows[0].seq;
    let mut prev = rows[0].prev_hash.clone();
    for (i, row) in rows.iter().enumerate() {
        if row.run_id != expected_run {
            return Ok(make_outcome(
                request,
                Verdict::Deny,
                "JOURNAL_CROSS_SESSION",
                RiskTier::Security,
                Some(format!(
                    "row seq {} run_id {} != expected {}",
                    row.seq, row.run_id, expected_run
                )),
                Some(row.run_id.to_string()),
                &evidence,
            ));
        }
        if let Some(rr) = row.receipt_run_id {
            if rr != expected_run {
                return Ok(make_outcome(
                    request,
                    Verdict::Deny,
                    "JOURNAL_CROSS_SESSION",
                    RiskTier::Security,
                    Some("receipt run_id disagrees with session".into()),
                    Some(rr.to_string()),
                    &evidence,
                ));
            }
        }
        if i > 0 {
            if row.seq != expected_seq {
                return Ok(make_outcome(
                    request,
                    Verdict::Deny,
                    "JOURNAL_REORDER",
                    RiskTier::Security,
                    Some(format!(
                        "sequence gap/reorder: expected {expected_seq}, got {}",
                        row.seq
                    )),
                    Some(row.seq.to_string()),
                    &evidence,
                ));
            }
            if row.prev_hash != prev {
                return Ok(make_outcome(
                    request,
                    Verdict::Deny,
                    "JOURNAL_TAMPER_DETECTED",
                    RiskTier::Security,
                    Some(format!("prev_hash break at seq {}", row.seq)),
                    Some(row.seq.to_string()),
                    &evidence,
                ));
            }
        }
        prev = row.row_hash.clone();
        expected_seq = row.seq + 1;
    }

    let hashes: Vec<&str> = rows.iter().map(|r| r.row_hash.as_str()).collect();
    let mut sorted = hashes.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != hashes.len() {
        return Ok(make_outcome(
            request,
            Verdict::Deny,
            "JOURNAL_TAMPER_DETECTED",
            RiskTier::Security,
            Some("duplicated/replayed row_hash".into()),
            None,
            &evidence,
        ));
    }

    Ok(make_outcome(
        request,
        Verdict::Allow,
        "GATE_ALLOW",
        RiskTier::Security,
        Some("journal probe chain intact".into()),
        None,
        &evidence,
    ))
}
