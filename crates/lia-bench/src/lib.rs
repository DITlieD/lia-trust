mod claims;
mod corpus;
mod live;
mod metrics;
mod run;

pub use claims::{claims_lint, ClaimsLintFinding};
pub use corpus::{
    assert_corpus_hardened, assert_skill_free, corpus_sha256, load_corpus, make_throwaway_repo,
    ActionSpec, CaseClass, CaseRole, CorpusCase, EntryKind, ValueOrRaw,
};
pub use live::{LiveEndpoint, LiveTrafficProof};
pub use metrics::{
    compute_metrics, metrics_match, paired_bootstrap_ci, recompute_metrics_from_trials,
    render_trust_integrity_table, Arm, Interval, TableRow, TrialRecord, TrustIntegrityMetrics,
    BOOTSTRAP_ITERS, BOOTSTRAP_SEED, FALSE_BLOCK_BOUND,
};
pub use run::{
    probe_bridge, run_arm, verify_bench_bundle, write_signed_bench_bundle, BenchError,
    BenchOptions, BenchResultBundle, Harness, AGENT_MODE_LIVE, AGENT_MODE_RECORDED,
    BENCH_RESULT_VERSION,
};

#[cfg(test)]
mod tests {
    use super::*;
    use lia_protocol::Verdict;
    use std::fs;

    #[test]
    fn bootstrap_deterministic() {
        let trials = vec![
            TrialRecord {
                case_id: "a".into(),
                class: CaseClass::FabricatedPass,
                role: CaseRole::Adversarial,
                arm: Arm::On,
                blocked: true,
                caught: true,
                false_block: false,
                false_open: false,
                verdict: Some(Verdict::Refuted),
                reason_code: Some("TEST_FABRICATED_PASS".into()),
                detail: None,
            },
            TrialRecord {
                case_id: "b".into(),
                class: CaseClass::Benign,
                role: CaseRole::Benign,
                arm: Arm::On,
                blocked: false,
                caught: false,
                false_block: false,
                false_open: false,
                verdict: Some(Verdict::Allow),
                reason_code: Some("GATE_ALLOW".into()),
                detail: None,
            },
        ];
        let m1 = compute_metrics(&trials);
        let m2 = compute_metrics(&trials);
        assert!(metrics_match(&m1, &m2));
        assert!((m1.catch_rate - 1.0).abs() < 1e-12);
        assert!((m1.false_block_rate - 0.0).abs() < 1e-12);
    }

    #[test]
    fn corpus_abort_on_git() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        let err = assert_corpus_hardened(dir.path()).unwrap_err();
        assert!(err.to_string().contains("git"));
    }
}
