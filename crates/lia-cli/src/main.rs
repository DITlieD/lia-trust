use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use lia_adapters::{
    evaluate_generic_action, evaluate_named_gate, handle_jsonrpc, handle_pre_tool_stdin,
    known_adapters, report_for_adapter, wrap, DenialRecord, GenericAction, InspectionContext,
    RunContext, WrapOptions,
};
use lia_ast::{ast_report_to_outcome, scan_diff, scan_file, Language, ScanOptions, AST_GATE_ID};
use lia_gates::{
    load_core_rules, load_gate_config, load_gate_request, write_core_rules, GateConfig,
    GateOutcome, GateRequest,
};
use lia_ground::{
    ground_result_to_outcome, load_claim, load_context, parse_claim, verify_claim,
    verify_claim_with_id, GroundContext, GROUND_GATE_ID,
};
use lia_journal::{append_signed, verify_chain, Journal, SigningIdentity};
use lia_policy::{
    evaluate_frozen, freeze_policy_from_path, load_evidence_json, EvidenceSet,
};
use lia_protocol::{parse_event, Event, GateVerdictEvent, Verdict};
use lia_syco::{detect, parse_exchange, syco_report_to_outcome, SYCO_GATE_ID};
use lia_taint::{check_flows, parse_graph};
use lia_bench::{
    claims_lint, probe_bridge, run_arm, verify_bench_bundle, Arm, BenchOptions, Harness,
    AGENT_MODE_RECORDED,
};
use lia_verify::{
    build_demo_bundle, build_gate_receipt_bundle, sign_verification_report, verify_bundle,
    verify_report_signature, write_verification_report, VerificationReport,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "lia", about = "LIA Trust Kernel")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(name = "journal-append")]
    JournalAppend {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        event: String,
        #[arg(long)]
        secret_key_hex: String,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
    },
    #[command(name = "journal-verify")]
    JournalVerify {
        db: PathBuf,
    },
    Gate {
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long)]
        evidence: Option<PathBuf>,
        #[arg(long)]
        action: Option<PathBuf>,
        #[arg(long)]
        request: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        journal: Option<PathBuf>,
        #[arg(long)]
        secret_key_hex: Option<String>,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
        #[arg(long)]
        write_rules: Option<PathBuf>,
    },
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        verifier_secret_key_hex: Option<String>,
        #[arg(long, default_value = "verifier")]
        verifier_key_id: String,
        #[arg(long)]
        report_out: Option<PathBuf>,
    },
    #[command(name = "fixture-bundle")]
    FixtureBundle {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        outcome: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        secret_key_hex: String,
        #[arg(long, default_value = "fixture")]
        key_id: String,
        #[arg(long, default_value = "verifier")]
        verifier_key_id: String,
        #[arg(long)]
        verifier_secret_key_hex: Option<String>,
    },
    #[command(name = "demo-bundle")]
    DemoBundle {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        journal_secret_key_hex: String,
        #[arg(long, default_value = "journal")]
        journal_key_id: String,
        #[arg(long)]
        verifier_secret_key_hex: String,
        #[arg(long, default_value = "verifier")]
        verifier_key_id: String,
    },
    Ground {
        #[arg(long)]
        claim: Option<String>,
        #[arg(long)]
        claim_file: Option<PathBuf>,
        #[arg(long)]
        context: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        journal: Option<PathBuf>,
        #[arg(long)]
        secret_key_hex: Option<String>,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
        #[arg(long)]
        action_id: Option<Uuid>,
    },
    Syco {
        #[arg(long)]
        exchange: Option<String>,
        #[arg(long)]
        exchange_file: Option<PathBuf>,
        #[arg(long)]
        journal: Option<PathBuf>,
        #[arg(long)]
        secret_key_hex: Option<String>,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
        #[arg(long)]
        action_id: Option<Uuid>,
    },
    #[command(name = "ast-gate")]
    AstGate {
        path: Option<PathBuf>,
        #[arg(long)]
        diff: Option<PathBuf>,
        #[arg(long)]
        diff_text: Option<String>,
        #[arg(long)]
        language: Option<String>,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        journal: Option<PathBuf>,
        #[arg(long)]
        secret_key_hex: Option<String>,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
        #[arg(long)]
        action_id: Option<Uuid>,
    },
    Taint {
        #[arg(long)]
        graph: Option<String>,
        #[arg(long)]
        graph_file: Option<PathBuf>,
    },
    Wrap {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        evidence_dir: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        secret_key_hex: String,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
        #[arg(long, default_value_t = true)]
        watch: bool,
        #[arg(long)]
        no_watch: bool,
        #[arg(last = true)]
        agent: Vec<String>,
    },
    Report {
        #[arg(long)]
        adapter: String,
        #[arg(long)]
        probe: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Hook {
        #[arg(long, default_value = "claude-code")]
        adapter: String,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        journal: Option<PathBuf>,
        #[arg(long)]
        secret_key_hex: Option<String>,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
    },
    Bench {
        #[arg(long)]
        harness: String,
        #[arg(long)]
        arm: String,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        secret_key_hex: String,
        #[arg(long, default_value = "bench")]
        key_id: String,
        #[arg(long, default_value = "http://127.0.0.1:8810")]
        bridge_url: String,
        #[arg(long, default_value_t = false)]
        force_recorded: bool,
    },
    #[command(name = "claims-lint")]
    ClaimsLint {
        #[arg(long, default_value = "docs")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Mcp {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        journal: Option<PathBuf>,
        #[arg(long)]
        secret_key_hex: Option<String>,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(long)]
        probe: Option<PathBuf>,
        #[arg(long)]
        adapter: Option<String>,
        #[arg(long)]
        request: Option<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::JournalAppend {
            db,
            event,
            secret_key_hex,
            key_id,
            run_id,
        } => {
            let event = parse_event(&event)?;
            let identity = SigningIdentity::from_secret_key_hex(key_id, &secret_key_hex)?;
            let run_id = run_id.unwrap_or_else(Uuid::new_v4);
            let journal = if db.exists() {
                Journal::open(&db)?
            } else {
                Journal::create(&db)?
            };
            let row = append_signed(&journal, run_id, event, &identity)?;
            println!(
                "{}",
                serde_json::json!({
                    "seq": row.seq,
                    "run_id": row.run_id,
                    "row_hash": row.row_hash,
                    "prev_hash": row.prev_hash,
                    "receipt_id": row.receipt.as_ref().map(|r| r.receipt_id),
                    "signature_hex": row.receipt.as_ref().map(|r| &r.signature_hex),
                })
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::JournalVerify { db } => {
            verify_chain(&db)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Gate {
            rules,
            evidence,
            action,
            request,
            config,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            write_rules,
        } => {
            if let Some(path) = write_rules {
                write_core_rules(&path)?;
                let frozen = load_core_rules(&path)?;
                println!(
                    "{}",
                    serde_json::json!({
                        "wrote": path,
                        "policy_id": frozen.policy_id,
                        "policy_hash": frozen.policy_hash,
                    })
                );
                return Ok(ExitCode::SUCCESS);
            }

            if action.is_some() || request.is_some() {
                return run_core_gate(
                    action,
                    request,
                    config,
                    journal,
                    secret_key_hex,
                    key_id,
                    run_id,
                );
            }

            let rules =
                rules.ok_or("gate requires --rules with --evidence, or --action/--request")?;
            let evidence = evidence.ok_or("gate requires --evidence with --rules")?;
            let frozen = freeze_policy_from_path(&rules)?;
            let evidence_set = load_gate_evidence(&evidence)?;
            let report = evaluate_frozen(&frozen, &evidence_set)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if matches!(report.overall, Verdict::Allow | Verdict::Advisory) {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(2))
            }
        }
        Commands::Verify {
            bundle,
            verifier_secret_key_hex,
            verifier_key_id,
            report_out,
        } => {
            let mut report = verify_bundle(&bundle)?;
            if let Some(secret) = verifier_secret_key_hex {
                let identity =
                    SigningIdentity::from_secret_key_hex(verifier_key_id, &secret)?;
                sign_verification_report(&mut report, &identity)?;
                verify_report_signature(&report)?;
            }
            emit_verify_report(&report, report_out.as_ref())?;
            if report.accepted {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
        Commands::FixtureBundle {
            journal,
            outcome,
            bundle,
            secret_key_hex,
            key_id,
            verifier_key_id,
            verifier_secret_key_hex,
        } => {
            let journal_id =
                SigningIdentity::from_secret_key_hex(key_id, &secret_key_hex)?;
            let verifier_secret = match verifier_secret_key_hex {
                Some(s) => s,
                None => {
                    let mut bytes = hex::decode(&secret_key_hex).map_err(|e| {
                        format!("secret_key_hex decode failed: {e}")
                    })?;
                    if bytes.len() != 32 {
                        return Err(format!(
                            "secret_key_hex must be 32 bytes, got {}",
                            bytes.len()
                        )
                        .into());
                    }
                    for b in &mut bytes {
                        *b ^= 0x5a;
                    }
                    hex::encode(bytes)
                }
            };
            let verifier_id =
                SigningIdentity::from_secret_key_hex(verifier_key_id, &verifier_secret)?;
            let outcome_bytes = fs::read(&outcome)?;
            let path = build_gate_receipt_bundle(
                &bundle,
                &journal,
                &journal_id,
                &verifier_id,
                &outcome_bytes,
            )?;
            println!("{}", serde_json::json!({"bundle": path}));
            Ok(ExitCode::SUCCESS)
        }
        Commands::DemoBundle {
            out,
            journal_secret_key_hex,
            journal_key_id,
            verifier_secret_key_hex,
            verifier_key_id,
        } => {
            let journal_id = SigningIdentity::from_secret_key_hex(
                journal_key_id,
                &journal_secret_key_hex,
            )?;
            let verifier_id = SigningIdentity::from_secret_key_hex(
                verifier_key_id,
                &verifier_secret_key_hex,
            )?;
            let (path, run_id) = build_demo_bundle(&out, &journal_id, &verifier_id)?;
            println!("{}", serde_json::json!({"bundle": path, "run_id": run_id}));
            Ok(ExitCode::SUCCESS)
        }
        Commands::Ground {
            claim,
            claim_file,
            context,
            config,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            action_id,
        } => run_ground(
            claim,
            claim_file,
            context,
            config,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            action_id,
        ),
        Commands::Syco {
            exchange,
            exchange_file,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            action_id,
        } => run_syco(
            exchange,
            exchange_file,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            action_id,
        ),
        Commands::AstGate {
            path,
            diff,
            diff_text,
            language,
            manifest,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            action_id,
        } => run_ast_gate(
            path,
            diff,
            diff_text,
            language,
            manifest,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            action_id,
        ),
        Commands::Taint { graph, graph_file } => run_taint(graph, graph_file),
        Commands::Wrap {
            repo,
            evidence_dir,
            config,
            secret_key_hex,
            key_id,
            run_id,
            watch,
            no_watch,
            agent,
        } => run_wrap(
            repo,
            evidence_dir,
            config,
            secret_key_hex,
            key_id,
            run_id,
            watch && !no_watch,
            agent,
        ),
        Commands::Report {
            adapter,
            probe,
            json,
        } => run_report(adapter, probe, json),
        Commands::Hook {
            adapter,
            config,
            journal,
            secret_key_hex,
            key_id,
            run_id,
        } => run_hook(adapter, config, journal, secret_key_hex, key_id, run_id),
        Commands::Bench {
            harness,
            arm,
            corpus,
            out,
            secret_key_hex,
            key_id,
            bridge_url,
            force_recorded,
        } => run_bench(
            harness,
            arm,
            corpus,
            out,
            secret_key_hex,
            key_id,
            bridge_url,
            force_recorded,
        ),
        Commands::ClaimsLint { root, json } => run_claims_lint(root, json),
        Commands::Mcp {
            config,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            policy,
            bundle,
            probe,
            adapter,
            request,
        } => run_mcp(
            config,
            journal,
            secret_key_hex,
            key_id,
            run_id,
            policy,
            bundle,
            probe,
            adapter,
            request,
        ),
    }
}

fn run_core_gate(
    action: Option<PathBuf>,
    request: Option<PathBuf>,
    config: Option<PathBuf>,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let config_path = config.ok_or("core gate requires --config")?;
    let mut cfg = load_gate_config(&config_path)?;
    let run_id = run_id.or(cfg.run_id).unwrap_or_else(Uuid::new_v4);
    cfg.run_id = Some(run_id);

    let outcomes = if let Some(req_path) = request {
        let req = load_gate_request(&req_path)?;
        vec![dispatch_gate_request(&req, &cfg)?]
    } else if let Some(action_path) = action {
        let bytes = fs::read(&action_path)?;
        let action: GenericAction = serde_json::from_slice(&bytes)?;
        evaluate_generic_action(&action, &cfg)?
    } else {
        return Err("core gate requires --action or --request".into());
    };

    let mut journal_rows = Vec::new();
    if let Some(db) = journal {
        let secret = secret_key_hex.ok_or("journaling requires --secret-key-hex")?;
        let identity = SigningIdentity::from_secret_key_hex(key_id, &secret)?;
        let j = if db.exists() {
            Journal::open(&db)?
        } else {
            Journal::create(&db)?
        };
        for outcome in &outcomes {
            let event = outcome_to_event(outcome);
            let row = append_signed(&j, run_id, event, &identity)?;
            journal_rows.push(serde_json::json!({
                "seq": row.seq,
                "row_hash": row.row_hash,
                "prev_hash": row.prev_hash,
                "receipt_id": row.receipt.as_ref().map(|r| r.receipt_id),
                "signature_hex": row.receipt.as_ref().map(|r| &r.signature_hex),
                "gate_id": outcome.gate_id,
                "verdict": outcome.verdict,
                "reason_code": outcome.reason_code,
            }));
        }
    }

    let overall = worst_outcome(&outcomes);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "run_id": run_id,
            "outcomes": outcomes,
            "journal_receipts": journal_rows,
            "overall": overall,
        }))?
    );

    Ok(exit_for_outcomes(&outcomes))
}

fn dispatch_gate_request(
    req: &GateRequest,
    cfg: &GateConfig,
) -> Result<GateOutcome, Box<dyn std::error::Error>> {
    match req.gate_id.as_str() {
        GROUND_GATE_ID => {
            let claim_val = req
                .payload
                .text
                .as_ref()
                .ok_or("ground gate request requires payload.text claim json")?;
            let claim = parse_claim(claim_val)?;
            let ctx = GroundContext::from_gate_config(cfg);
            let result = verify_claim_with_id(&claim, &ctx, req.action_id)?;
            Ok(ground_result_to_outcome(&result))
        }
        SYCO_GATE_ID => {
            let ex_val = req
                .payload
                .text
                .as_ref()
                .ok_or("syco gate request requires payload.text exchange json")?;
            let exchange = parse_exchange(ex_val)?;
            let report = detect(&exchange)?;
            Ok(syco_report_to_outcome(&report, req.action_id))
        }
        AST_GATE_ID => {
            let opts = ScanOptions {
                manifest_packages: req
                    .payload
                    .new_dependencies
                    .clone()
                    .unwrap_or_default(),
                language: None,
            };
            let report = if let Some(diff) = req.payload.text.as_ref() {
                scan_diff(diff, &opts)?
            } else if let Some(path) = req.payload.path.as_ref() {
                scan_file(path, &opts)?
            } else {
                return Err("ast-gate request requires payload.text (diff) or payload.path".into());
            };
            Ok(ast_report_to_outcome(&report, req.action_id))
        }
        _ => Ok(evaluate_named_gate(req, cfg)?),
    }
}

fn run_ground(
    claim: Option<String>,
    claim_file: Option<PathBuf>,
    context: Option<PathBuf>,
    config: Option<PathBuf>,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
    action_id: Option<Uuid>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let claim = match (claim, claim_file) {
        (Some(s), _) => parse_claim(&s)?,
        (None, Some(p)) => load_claim(p)?,
        (None, None) => return Err("ground requires --claim or --claim-file".into()),
    };
    let mut ctx = if let Some(p) = context {
        load_context(p)?
    } else {
        GroundContext {
            root: None,
            registry: Default::default(),
        }
    };
    if let Some(cfg_path) = config {
        let cfg = load_gate_config(cfg_path)?;
        let from_cfg = GroundContext::from_gate_config(&cfg);
        if ctx.root.is_none() {
            ctx.root = from_cfg.root;
        }
        if ctx.registry.is_empty() {
            ctx.registry = from_cfg.registry;
        }
    }
    let result = match action_id {
        Some(id) => verify_claim_with_id(&claim, &ctx, id)?,
        None => verify_claim(&claim, &ctx)?,
    };
    let outcome = ground_result_to_outcome(&result);
    emit_l4_outcome(&outcome, &result, journal, secret_key_hex, key_id, run_id)
}

fn run_syco(
    exchange: Option<String>,
    exchange_file: Option<PathBuf>,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
    action_id: Option<Uuid>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let raw = match (exchange, exchange_file) {
        (Some(s), _) => s,
        (None, Some(p)) => fs::read_to_string(p)?,
        (None, None) => return Err("syco requires --exchange or --exchange-file".into()),
    };
    let ex = parse_exchange(&raw)?;
    let report = detect(&ex)?;
    let action_id = action_id.unwrap_or_else(Uuid::new_v4);
    let outcome = syco_report_to_outcome(&report, action_id);
    emit_l4_outcome(&outcome, &report, journal, secret_key_hex, key_id, run_id)
}

fn run_ast_gate(
    path: Option<PathBuf>,
    diff: Option<PathBuf>,
    diff_text: Option<String>,
    language: Option<String>,
    manifest: Option<PathBuf>,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
    action_id: Option<Uuid>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut opts = ScanOptions::default();
    if let Some(lang) = language {
        opts.language = Some(parse_language(&lang)?);
    }
    if let Some(m) = manifest {
        let text = fs::read_to_string(m)?;
        opts.manifest_packages = text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
    }
    let report = if let Some(t) = diff_text {
        scan_diff(&t, &opts)?
    } else if let Some(p) = diff {
        let t = fs::read_to_string(p)?;
        scan_diff(&t, &opts)?
    } else if let Some(p) = path {
        scan_file(p, &opts)?
    } else {
        return Err("ast-gate requires a path, --diff, or --diff-text".into());
    };
    let action_id = action_id.unwrap_or_else(Uuid::new_v4);
    let outcome = ast_report_to_outcome(&report, action_id);
    emit_l4_outcome(&outcome, &report, journal, secret_key_hex, key_id, run_id)
}

fn run_taint(
    graph: Option<String>,
    graph_file: Option<PathBuf>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let raw = match (graph, graph_file) {
        (Some(s), _) => s,
        (None, Some(p)) => fs::read_to_string(p)?,
        (None, None) => return Err("taint requires --graph or --graph-file".into()),
    };
    let g = parse_graph(&raw)?;
    let report = check_flows(&g)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    match report.verdict {
        lia_taint::TaintVerdict::Allow => Ok(ExitCode::SUCCESS),
        lia_taint::TaintVerdict::Deny => Ok(ExitCode::from(2)),
    }
}

fn run_wrap(
    repo: PathBuf,
    evidence_dir: PathBuf,
    config: PathBuf,
    secret_key_hex: String,
    key_id: String,
    run_id: Option<Uuid>,
    watch: bool,
    agent: Vec<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cfg = load_gate_config(&config)?;
    let run_id = run_id.unwrap_or_else(Uuid::new_v4);
    let report = wrap(WrapOptions {
        repo,
        evidence_dir,
        run_id,
        config: cfg,
        secret_key_hex,
        key_id,
        env_allowlist: None,
        watch,
        agent_argv: agent,
    })?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.agent_exit == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(report.agent_exit as u8))
    }
}

fn run_report(
    adapter: String,
    probe: PathBuf,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !known_adapters().contains(&adapter.as_str()) {
        return Err(format!(
            "unknown adapter {adapter}; expected one of {:?}",
            known_adapters()
        )
        .into());
    }
    let report = report_for_adapter(&adapter, Some(probe.as_path()))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.render_table());
    }
    Ok(ExitCode::SUCCESS)
}

fn run_hook(
    adapter: String,
    config: PathBuf,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if adapter != "claude-code" {
        return Err(format!("hook adapter {adapter} not supported; use claude-code").into());
    }
    let mut cfg = load_gate_config(&config)?;
    let run_id = run_id.or(cfg.run_id).unwrap_or_else(Uuid::new_v4);
    cfg.run_id = Some(run_id);
    let ctx = RunContext {
        run_id,
        config: cfg,
        journal_path: journal,
        secret_key_hex,
        key_id: Some(key_id),
    };
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let out = handle_pre_tool_stdin(&raw, &ctx)?;
    println!("{out}");
    let decision: serde_json::Value = serde_json::from_str(&out)?;
    let perm = decision
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(|v| v.as_str())
        .unwrap_or("deny");
    if perm == "allow" {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}

fn run_mcp(
    config: Option<PathBuf>,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
    policy: Option<PathBuf>,
    bundle: Option<PathBuf>,
    probe: Option<PathBuf>,
    adapter: Option<String>,
    request: Option<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cfg = match config {
        Some(p) => load_gate_config(p)?,
        None => GateConfig {
            allowed_roots: vec![PathBuf::from(".")],
            home_dir: None,
            cwd: PathBuf::from("."),
            protected_paths: vec![],
            registry: Default::default(),
            env: Default::default(),
            run_id: None,
        },
    };
    let run_id = run_id.or(cfg.run_id).unwrap_or_else(Uuid::new_v4);
    let run_ctx = RunContext {
        run_id,
        config: cfg,
        journal_path: journal.clone(),
        secret_key_hex,
        key_id: Some(key_id),
    };
    let inspect_ctx = InspectionContext {
        journal_path: journal,
        policy_path: policy,
        bundle_path: bundle,
        probe_path: probe,
        adapter,
        last_denials: Vec::<DenialRecord>::new(),
    };
    let raw = match request {
        Some(s) => s,
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };
    let response = handle_jsonrpc(&raw, &run_ctx, &inspect_ctx)?;
    println!("{}", serde_json::to_string(&response)?);
    if response.get("error").is_some() {
        Ok(ExitCode::from(1))
    } else if response
        .pointer("/result/isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn parse_language(s: &str) -> Result<Language, Box<dyn std::error::Error>> {
    match s.to_ascii_lowercase().as_str() {
        "python" | "py" => Ok(Language::Python),
        "rust" | "rs" => Ok(Language::Rust),
        "javascript" | "js" => Ok(Language::Javascript),
        other => Err(format!("unknown language: {other}").into()),
    }
}

fn emit_l4_outcome<T: serde::Serialize>(
    outcome: &GateOutcome,
    report: &T,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let run_id = run_id.unwrap_or_else(Uuid::new_v4);
    let mut journal_rows = Vec::new();
    if let Some(db) = journal {
        let secret = secret_key_hex.ok_or("journaling requires --secret-key-hex")?;
        let identity = SigningIdentity::from_secret_key_hex(key_id, &secret)?;
        let j = if db.exists() {
            Journal::open(&db)?
        } else {
            Journal::create(&db)?
        };
        let event = outcome_to_event(outcome);
        let row = append_signed(&j, run_id, event, &identity)?;
        journal_rows.push(serde_json::json!({
            "seq": row.seq,
            "row_hash": row.row_hash,
            "prev_hash": row.prev_hash,
            "receipt_id": row.receipt.as_ref().map(|r| r.receipt_id),
            "signature_hex": row.receipt.as_ref().map(|r| &r.signature_hex),
            "gate_id": outcome.gate_id,
            "verdict": outcome.verdict,
            "reason_code": outcome.reason_code,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "run_id": run_id,
            "report": report,
            "outcomes": [outcome],
            "journal_receipts": journal_rows,
            "overall": outcome.verdict,
        }))?
    );
    Ok(exit_for_outcomes(std::slice::from_ref(outcome)))
}

fn outcome_to_event(outcome: &GateOutcome) -> Event {
    Event::GateVerdict(GateVerdictEvent {
        action_id: outcome.action_id,
        gate_id: outcome.gate_id.clone(),
        verdict: outcome.verdict.clone(),
        reason_code: outcome.reason_code.clone(),
        risk_tier: outcome.risk_tier.clone(),
        detail: outcome.detail.clone(),
        evidence_sha256: Some(outcome.evidence_sha256.clone()),
        timestamp: outcome.timestamp,
    })
}

fn worst_outcome(outcomes: &[GateOutcome]) -> Verdict {
    let mut worst = Verdict::Allow;
    for o in outcomes {
        worst = worse(worst, o.verdict.clone());
    }
    worst
}

fn worse(a: Verdict, b: Verdict) -> Verdict {
    if rank(&a) >= rank(&b) {
        a
    } else {
        b
    }
}

fn rank(v: &Verdict) -> u8 {
    match v {
        Verdict::Allow | Verdict::Verified => 0,
        Verdict::Advisory | Verdict::Unsupported | Verdict::Incomplete => 1,
        Verdict::Quarantine => 2,
        Verdict::Deny | Verdict::Refuted => 3,
    }
}

fn exit_for_outcomes(outcomes: &[GateOutcome]) -> ExitCode {
    if outcomes.is_empty() {
        return ExitCode::from(2);
    }
    let overall = worst_outcome(outcomes);
    match overall {
        Verdict::Allow | Verdict::Advisory | Verdict::Verified => ExitCode::SUCCESS,
        Verdict::Refuted => ExitCode::from(3),
        Verdict::Incomplete => ExitCode::from(4),
        Verdict::Deny | Verdict::Quarantine | Verdict::Unsupported => ExitCode::from(2),
    }
}

fn load_gate_evidence(path: &std::path::Path) -> Result<EvidenceSet, Box<dyn std::error::Error>> {
    if path.is_dir() {
        let candidates = [
            path.join("evidence-set.json"),
            path.join("evidence.json"),
        ];
        for c in &candidates {
            if c.is_file() {
                return Ok(load_evidence_json(c)?);
            }
        }
        return Err(format!(
            "bundle dir {} has no evidence-set.json",
            path.display()
        )
        .into());
    }
    Ok(load_evidence_json(path)?)
}

fn emit_verify_report(
    report: &VerificationReport,
    report_out: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    if let Some(path) = report_out {
        write_verification_report(report, path)?;
    }
    Ok(())
}

fn run_bench(
    harness: String,
    arm: String,
    corpus: PathBuf,
    out: PathBuf,
    secret_key_hex: String,
    key_id: String,
    bridge_url: String,
    force_recorded: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let harness = Harness::parse(&harness)?;
    let arm = Arm::parse(&arm).map_err(|e| e)?;
    let (bridge_ok, model_id) = probe_bridge(&bridge_url);
    if !bridge_ok && !force_recorded {
        eprintln!(
            "bridge unreachable at {bridge_url}; running as {AGENT_MODE_RECORDED}"
        );
    }
    let result = run_arm(&BenchOptions {
        harness,
        arm,
        corpus,
        out_dir: out.clone(),
        secret_key_hex,
        key_id,
        bridge_url,
        force_recorded: force_recorded || !bridge_ok,
    })?;
    let bundle = out.join(format!("bundle-{}-{}", result.harness, result.arm));
    let (ok, metrics) = verify_bench_bundle(&bundle)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "result": result,
            "verify_ok": ok,
            "recomputed_metrics": metrics,
            "bridge_model_id": model_id,
        }))?
    );
    if ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn run_claims_lint(
    root: PathBuf,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let findings = claims_lint(&root)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        for f in &findings {
            println!("{}:{}: {} ({})", f.path, f.line, f.reason, f.excerpt);
        }
        if findings.is_empty() {
            println!("claims-lint clean");
        }
    }
    if findings.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
