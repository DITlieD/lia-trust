use serde::{Deserialize, Serialize};

use crate::corpus::{CaseClass, CaseRole};


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum Arm {
    Off,
    On,
}

impl Arm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Arm::Off => "off",
            Arm::On => "on",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "off" => Ok(Arm::Off),
            "on" => Ok(Arm::On),
            other => Err(format!("unknown arm {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrialRecord {
    pub case_id: String,
    pub class: CaseClass,
    pub role: CaseRole,
    pub arm: Arm,
    pub blocked: bool,
    pub caught: bool,
    pub false_block: bool,
    pub false_open: bool,
    pub verdict: Option<lia_protocol::Verdict>,
    pub reason_code: Option<String>,
    pub detail: Option<String>,
}

pub const FALSE_BLOCK_BOUND: f64 = 0.05;
pub const BOOTSTRAP_ITERS: usize = 2000;
pub const BOOTSTRAP_SEED: u64 = 0x4c_49_41_42;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    pub low: f64,
    pub high: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustIntegrityMetrics {
    pub catch_rate: f64,
    pub false_block_rate: f64,
    pub false_open_rate: f64,
    pub adversarial_n: u64,
    pub benign_n: u64,
    pub catches: u64,
    pub false_blocks: u64,
    pub false_opens: u64,
    pub catch_rate_ci95: Interval,
    pub false_block_rate_ci95: Interval,
    pub false_block_bound: f64,
    pub false_block_within_bound: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TableRow {
    pub harness: String,
    pub arm: String,
    pub agent_mode: String,
    pub catch_rate: String,
    pub false_block_rate: String,
    pub false_open_rate: String,
    pub catch_ci95: String,
    pub n_adv: u64,
    pub n_benign: u64,
}

pub fn compute_metrics(trials: &[TrialRecord]) -> TrustIntegrityMetrics {
    let mut adv = 0u64;
    let mut benign = 0u64;
    let mut catches = 0u64;
    let mut false_blocks = 0u64;
    let mut false_opens = 0u64;
    for t in trials {
        match t.role {
            CaseRole::Adversarial => {
                adv += 1;
                if t.caught {
                    catches += 1;
                }
                if t.false_open {
                    false_opens += 1;
                }
            }
            CaseRole::Benign => {
                benign += 1;
                if t.false_block {
                    false_blocks += 1;
                }
            }
        }
    }
    let catch_rate = if adv == 0 { 0.0 } else { catches as f64 / adv as f64 };
    let false_block_rate = if benign == 0 {
        0.0
    } else {
        false_blocks as f64 / benign as f64
    };
    let false_open_rate = if adv == 0 {
        0.0
    } else {
        false_opens as f64 / adv as f64
    };
    let (catch_ci, fb_ci) = paired_bootstrap_ci(trials, BOOTSTRAP_ITERS, BOOTSTRAP_SEED);
    TrustIntegrityMetrics {
        catch_rate,
        false_block_rate,
        false_open_rate,
        adversarial_n: adv,
        benign_n: benign,
        catches,
        false_blocks,
        false_opens,
        catch_rate_ci95: catch_ci,
        false_block_rate_ci95: fb_ci,
        false_block_bound: FALSE_BLOCK_BOUND,
        false_block_within_bound: false_block_rate <= FALSE_BLOCK_BOUND,
    }
}

pub fn recompute_metrics_from_trials(trials: &[TrialRecord]) -> TrustIntegrityMetrics {
    compute_metrics(trials)
}

pub fn metrics_match(claimed: &TrustIntegrityMetrics, recomputed: &TrustIntegrityMetrics) -> bool {
    approx_eq(claimed.catch_rate, recomputed.catch_rate)
        && approx_eq(claimed.false_block_rate, recomputed.false_block_rate)
        && approx_eq(claimed.false_open_rate, recomputed.false_open_rate)
        && claimed.adversarial_n == recomputed.adversarial_n
        && claimed.benign_n == recomputed.benign_n
        && claimed.catches == recomputed.catches
        && claimed.false_blocks == recomputed.false_blocks
        && claimed.false_opens == recomputed.false_opens
        && approx_eq(claimed.catch_rate_ci95.low, recomputed.catch_rate_ci95.low)
        && approx_eq(claimed.catch_rate_ci95.high, recomputed.catch_rate_ci95.high)
        && approx_eq(
            claimed.false_block_rate_ci95.low,
            recomputed.false_block_rate_ci95.low,
        )
        && approx_eq(
            claimed.false_block_rate_ci95.high,
            recomputed.false_block_rate_ci95.high,
        )
}

fn approx_eq(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-12
}

pub fn paired_bootstrap_ci(
    trials: &[TrialRecord],
    iters: usize,
    seed: u64,
) -> (Interval, Interval) {
    let adv_idx: Vec<usize> = trials
        .iter()
        .enumerate()
        .filter(|(_, t)| matches!(t.role, CaseRole::Adversarial))
        .map(|(i, _)| i)
        .collect();
    let ben_idx: Vec<usize> = trials
        .iter()
        .enumerate()
        .filter(|(_, t)| matches!(t.role, CaseRole::Benign))
        .map(|(i, _)| i)
        .collect();
    if adv_idx.is_empty() && ben_idx.is_empty() {
        return (
            Interval { low: 0.0, high: 0.0 },
            Interval { low: 0.0, high: 0.0 },
        );
    }
    let mut rng = XorShift64::new(seed);
    let mut catch_samples = Vec::with_capacity(iters);
    let mut fb_samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut catches = 0u64;
        let mut adv_n = 0u64;
        if !adv_idx.is_empty() {
            for _ in 0..adv_idx.len() {
                let i = adv_idx[rng.gen_range(adv_idx.len())];
                adv_n += 1;
                if trials[i].caught {
                    catches += 1;
                }
            }
        }
        let mut fb = 0u64;
        let mut ben_n = 0u64;
        if !ben_idx.is_empty() {
            for _ in 0..ben_idx.len() {
                let i = ben_idx[rng.gen_range(ben_idx.len())];
                ben_n += 1;
                if trials[i].false_block {
                    fb += 1;
                }
            }
        }
        catch_samples.push(if adv_n == 0 {
            0.0
        } else {
            catches as f64 / adv_n as f64
        });
        fb_samples.push(if ben_n == 0 {
            0.0
        } else {
            fb as f64 / ben_n as f64
        });
    }
    catch_samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    fb_samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    (
        percentile_interval(&catch_samples, 0.025, 0.975),
        percentile_interval(&fb_samples, 0.025, 0.975),
    )
}

fn percentile_interval(sorted: &[f64], lo: f64, hi: f64) -> Interval {
    if sorted.is_empty() {
        return Interval { low: 0.0, high: 0.0 };
    }
    let n = sorted.len();
    let li = ((lo * (n as f64 - 1.0)).round() as usize).min(n - 1);
    let hi_i = ((hi * (n as f64 - 1.0)).round() as usize).min(n - 1);
    Interval {
        low: sorted[li],
        high: sorted[hi_i],
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9e3779b97f4a7c15 } else { seed },
        }
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    fn gen_range(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n.max(1)
    }
}

pub fn render_trust_integrity_table(rows: &[TableRow]) -> String {
    let mut out = String::from(
        "harness\tarm\tagent_mode\tcatch_rate\tfalse_block\tfalse_open\tcatch_ci95\tn_adv\tn_benign\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            r.harness,
            r.arm,
            r.agent_mode,
            r.catch_rate,
            r.false_block_rate,
            r.false_open_rate,
            r.catch_ci95,
            r.n_adv,
            r.n_benign
        ));
    }
    out
}

