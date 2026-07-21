use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use lia_adapters::{
    assert_adapter, collect_registry_evidence, default_claude_home, default_codex_home,
    default_cursor_home, default_gemini_home, default_lia_home, evaluate_generic_action,
    evaluate_named_gate, handle_cursor_mcp_stdin, handle_cursor_shell_stdin,
    handle_gemini_before_tool_stdin, handle_jsonrpc, handle_pre_tool_stdin,
    install as install_kernel, known_adapters, load_and_validate_process_contract,
    looks_like_live_user_home, report_for_adapter, serve_mcp_stdio, status as install_status,
    uninstall as uninstall_kernel, wrap, DenialRecord, GenericAction, InspectionContext,
    InstallRequest, RegistryEcosystem, RegistryEvidenceOptions, RunContext, WrapOptions,
};
use lia_ast::{ast_report_to_outcome, scan_diff, scan_file, Language, ScanOptions, AST_GATE_ID};
use lia_bench::{
    claims_lint, probe_bridge, run_arm, verify_bench_bundle, Arm, BenchOptions, Harness,
};
use lia_gates::{
    load_core_rules, load_gate_config, load_gate_request, write_core_rules, GateConfig,
    GateOutcome, GateRequest,
};
use lia_ground::{
    ground_result_to_outcome, load_claim, load_context, parse_claim, verify_claim,
    verify_claim_with_id, GroundContext, GROUND_GATE_ID,
};
use lia_journal::{
    append_signed, rotate_journal_if_needed, verify_chain, verify_chain_immutable,
    verify_signed_shareable_anchors, Journal, SignedShareableAnchors, SigningIdentity,
};
use lia_policy::{evaluate_frozen, freeze_policy_from_path, load_evidence_json, EvidenceSet};
use lia_protocol::{parse_event, Event, GateVerdictEvent, Verdict};
use lia_syco::{detect, parse_exchange, syco_report_to_outcome, SYCO_GATE_ID};
use lia_taint::{check_flows, parse_graph};
use lia_verify::{
    build_demo_bundle, build_gate_receipt_bundle, sign_verification_report,
    verify_blob_with_cosign, verify_bundle, verify_report_signature, verify_run,
    write_verification_report, PublicVerificationOptions, VerificationReport, VerifyRunOptions,
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
        /// Treat DB as a stable offline archive/copy; refuses WAL/SHM/rollback sidecars.
        #[arg(long)]
        immutable: bool,
    },
    #[command(name = "journal-anchors")]
    JournalAnchors {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value_t = 2)]
        head: usize,
        #[arg(long, default_value_t = 2)]
        tail: usize,
        #[arg(long)]
        secret_key_hex: String,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    #[command(name = "journal-anchors-verify")]
    JournalAnchorsVerify {
        manifest: PathBuf,
        #[arg(long)]
        expected_public_key_hex: String,
    },
    #[command(name = "journal-maintain")]
    JournalMaintain {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        archive_dir: PathBuf,
        #[arg(long, default_value_t = 100_000)]
        max_rows: u64,
        #[arg(long, default_value_t = 268_435_456)]
        max_bytes: u64,
        #[arg(long, default_value_t = 86_400)]
        max_age_seconds: u64,
        #[arg(long)]
        secret_key_hex: String,
        #[arg(long, default_value = "lia-default")]
        key_id: String,
        #[arg(long)]
        run_id: Option<Uuid>,
    },
    #[command(name = "process-contract-validate")]
    ProcessContractValidate {
        #[arg(long)]
        contract: PathBuf,
        #[arg(long)]
        execution: PathBuf,
        #[arg(long)]
        journal: PathBuf,
    },
    #[command(name = "public-verify")]
    PublicVerify {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        certificate_identity: String,
        #[arg(long)]
        certificate_oidc_issuer: String,
        #[arg(long, default_value = "cosign")]
        cosign_bin: PathBuf,
        #[arg(long)]
        expected_cosign_sha256: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },
    #[command(name = "registry-evidence")]
    RegistryEvidence {
        #[arg(long)]
        ecosystem: String,
        #[arg(long)]
        package: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        cache_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        offline: bool,
        #[arg(long, default_value = "curl")]
        http_client: PathBuf,
        #[arg(long)]
        expected_http_client_sha256: Option<String>,
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
        #[arg(long)]
        base_url: Option<String>,
        #[arg(long)]
        expected_response_sha256: Option<String>,
        #[arg(long)]
        expected_cache_manifest_sha256: Option<String>,
        #[arg(long, default_value_t = 86_400)]
        max_cache_age_seconds: u64,
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
        /// External trust-root JSON pinning the signer keys (authenticity). Defaults to
        /// ~/.lia-trust/trust-root.json when present. Without an anchor, verify proves
        /// integrity only, never authenticity.
        #[arg(long)]
        trust_root: Option<PathBuf>,
        /// Fail (nonzero) unless the bundle is authenticated against an external anchor.
        /// Use when verifying a bundle you did not produce.
        #[arg(long, default_value_t = false)]
        require_authenticity: bool,
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
        #[arg(long, default_value_t = 900)]
        timeout_seconds: u64,
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
        #[arg(long, default_value_t = false)]
        require_live: bool,
        #[arg(long)]
        model: Option<String>,
    },
    #[command(name = "claims-lint")]
    ClaimsLint {
        #[arg(long, default_value = "docs")]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    #[command(name = "verify-run")]
    VerifyRun {
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        secret_key_hex: String,
        #[arg(long, default_value = "verify-run")]
        key_id: String,
        #[arg(long)]
        verifier_secret_key_hex: Option<String>,
        #[arg(long, default_value = "verifier")]
        verifier_key_id: String,
    },
    Conform {
        #[arg(long, default_value = "conformance")]
        suite: PathBuf,
        #[arg(long)]
        adapter: Option<String>,
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
    /// Install LIA Trust Kernel into Claude Code, Codex, Gemini CLI, and Cursor configs.
    ///
    /// One-command TCB wiring: PreToolUse hook (Claude Code) + MCP proxy (Codex).
    /// Default is safe for fixtures: refuse writing real ~/.claude / ~/.codex unless
    /// `--apply-live` is set. Use `--dry-run` to print the planned merge.
    Install {
        #[arg(long)]
        lia_home: Option<PathBuf>,
        #[arg(long)]
        lia_bin: Option<PathBuf>,
        #[arg(long)]
        claude_home: Option<PathBuf>,
        #[arg(long)]
        codex_home: Option<PathBuf>,
        #[arg(long)]
        gemini_home: Option<PathBuf>,
        #[arg(long)]
        cursor_home: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Allow writing the real user ~/.claude and ~/.codex (creates backups via merge only).
        #[arg(long, default_value_t = false)]
        apply_live: bool,
        #[arg(long)]
        allowed_root: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Report whether LIA is installed on Claude Code / Codex configs.
    Status {
        #[arg(long)]
        lia_home: Option<PathBuf>,
        #[arg(long)]
        lia_bin: Option<PathBuf>,
        #[arg(long)]
        claude_home: Option<PathBuf>,
        #[arg(long)]
        codex_home: Option<PathBuf>,
        #[arg(long)]
        gemini_home: Option<PathBuf>,
        #[arg(long)]
        cursor_home: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Remove LIA hook/MCP wiring from Claude Code + Codex (state dir retained).
    Uninstall {
        #[arg(long)]
        lia_home: Option<PathBuf>,
        #[arg(long)]
        lia_bin: Option<PathBuf>,
        #[arg(long)]
        claude_home: Option<PathBuf>,
        #[arg(long)]
        codex_home: Option<PathBuf>,
        #[arg(long)]
        gemini_home: Option<PathBuf>,
        #[arg(long)]
        cursor_home: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = false)]
        apply_live: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
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
        Commands::JournalVerify { db, immutable } => {
            if immutable {
                verify_chain_immutable(&db)?;
            } else {
                verify_chain(&db)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::JournalAnchors {
            db,
            head,
            tail,
            secret_key_hex,
            key_id,
            out,
        } => {
            let journal = Journal::open_readonly(&db)?;
            let identity = SigningIdentity::from_secret_key_hex(key_id, &secret_key_hex)?;
            let manifest = journal.signed_shareable_anchors(head, tail, &identity)?;
            let bytes = serde_json::to_vec_pretty(&manifest)?;
            fs::write(out, &bytes)?;
            println!("{}", serde_json::to_string(&manifest)?);
            Ok(ExitCode::SUCCESS)
        }
        Commands::JournalAnchorsVerify {
            manifest,
            expected_public_key_hex,
        } => {
            let parsed: SignedShareableAnchors = serde_json::from_slice(&fs::read(manifest)?)?;
            verify_signed_shareable_anchors(&parsed, Some(&expected_public_key_hex))?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::JournalMaintain {
            db,
            archive_dir,
            max_rows,
            max_bytes,
            max_age_seconds,
            secret_key_hex,
            key_id,
            run_id,
        } => {
            let identity = SigningIdentity::from_secret_key_hex(key_id, &secret_key_hex)?;
            let report = rotate_journal_if_needed(
                db,
                archive_dir,
                max_rows,
                max_bytes,
                max_age_seconds,
                run_id.unwrap_or_else(Uuid::new_v4),
                &identity,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(ExitCode::SUCCESS)
        }
        Commands::ProcessContractValidate {
            contract,
            execution,
            journal,
        } => run_process_contract_validate(contract, execution, journal),
        Commands::PublicVerify {
            artifact,
            bundle,
            certificate_identity,
            certificate_oidc_issuer,
            cosign_bin,
            expected_cosign_sha256,
            timeout_seconds,
        } => run_public_verify(
            artifact,
            bundle,
            certificate_identity,
            certificate_oidc_issuer,
            cosign_bin,
            expected_cosign_sha256,
            timeout_seconds,
        ),
        Commands::RegistryEvidence {
            ecosystem,
            package,
            version,
            cache_dir,
            offline,
            http_client,
            expected_http_client_sha256,
            timeout_seconds,
            base_url,
            expected_response_sha256,
            expected_cache_manifest_sha256,
            max_cache_age_seconds,
        } => run_registry_evidence(
            ecosystem,
            package,
            version,
            cache_dir,
            offline,
            http_client,
            expected_http_client_sha256,
            timeout_seconds,
            base_url,
            expected_response_sha256,
            expected_cache_manifest_sha256,
            max_cache_age_seconds,
        ),
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
            trust_root,
            require_authenticity,
        } => {
            // Resolve an external anchor: explicit --trust-root, else the installed
            // ~/.lia-trust/trust-root.json if present. No anchor => integrity-only.
            let anchor_path = trust_root.or_else(|| {
                let p = default_lia_home().join("trust-root.json");
                p.is_file().then_some(p)
            });
            let anchor = match &anchor_path {
                Some(p) => Some(lia_verify::TrustAnchor::from_trust_root_file(p)?),
                None => None,
            };
            let mut report = lia_verify::verify_bundle_with_anchor(&bundle, anchor.as_ref())?;
            if let Some(secret) = verifier_secret_key_hex {
                let identity = SigningIdentity::from_secret_key_hex(verifier_key_id, &secret)?;
                sign_verification_report(&mut report, &identity)?;
                verify_report_signature(&report)?;
            }
            if anchor.is_none() {
                eprintln!(
                    "[lia] no external trust anchor: integrity verified, authenticity NOT checked \
                     (pass --trust-root to pin the signer, or install ~/.lia-trust)"
                );
            }
            emit_verify_report(&report, report_out.as_ref())?;
            let authenticity_ok = report.authenticated || !require_authenticity;
            if !authenticity_ok {
                eprintln!(
                    "[lia] REJECTED for --require-authenticity: authenticity={}",
                    report.authenticity
                );
            }
            if report.accepted && authenticity_ok {
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
            let journal_id = SigningIdentity::from_secret_key_hex(key_id, &secret_key_hex)?;
            // The verifier key must be INDEPENDENT of the journal key: deriving it (an XOR
            // mask, a KDF, anything) means one leaked journal secret yields both, collapsing
            // the two-party separation. Absent an explicit verifier secret, draw fresh entropy.
            let verifier_secret = match verifier_secret_key_hex {
                Some(s) => s,
                None => lia_journal::random_secret_hex()?,
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
            let journal_id =
                SigningIdentity::from_secret_key_hex(journal_key_id, &journal_secret_key_hex)?;
            let verifier_id =
                SigningIdentity::from_secret_key_hex(verifier_key_id, &verifier_secret_key_hex)?;
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
            timeout_seconds,
            agent,
        } => run_wrap(
            repo,
            evidence_dir,
            config,
            secret_key_hex,
            key_id,
            run_id,
            watch && !no_watch,
            timeout_seconds,
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
            require_live,
            model,
        } => run_bench(
            harness,
            arm,
            corpus,
            out,
            secret_key_hex,
            key_id,
            bridge_url,
            force_recorded,
            require_live,
            model,
        ),
        Commands::ClaimsLint { root, json } => run_claims_lint(root, json),
        Commands::VerifyRun {
            base,
            head,
            evidence,
            repo,
            out,
            secret_key_hex,
            key_id,
            verifier_secret_key_hex,
            verifier_key_id,
        } => run_verify_run(
            base,
            head,
            evidence,
            repo,
            out,
            secret_key_hex,
            key_id,
            verifier_secret_key_hex,
            verifier_key_id,
        ),
        Commands::Conform {
            suite,
            adapter,
            json,
        } => run_conform(suite, adapter, json),
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
        Commands::Install {
            lia_home,
            lia_bin,
            claude_home,
            codex_home,
            gemini_home,
            cursor_home,
            dry_run,
            apply_live,
            allowed_root,
            json,
        } => run_install(
            lia_home,
            lia_bin,
            claude_home,
            codex_home,
            gemini_home,
            cursor_home,
            dry_run,
            apply_live,
            allowed_root,
            json,
        ),
        Commands::Status {
            lia_home,
            lia_bin,
            claude_home,
            codex_home,
            gemini_home,
            cursor_home,
            json,
        } => run_install_status(
            lia_home,
            lia_bin,
            claude_home,
            codex_home,
            gemini_home,
            cursor_home,
            json,
        ),
        Commands::Uninstall {
            lia_home,
            lia_bin,
            claude_home,
            codex_home,
            gemini_home,
            cursor_home,
            dry_run,
            apply_live,
            json,
        } => run_uninstall(
            lia_home,
            lia_bin,
            claude_home,
            codex_home,
            gemini_home,
            cursor_home,
            dry_run,
            apply_live,
            json,
        ),
    }
}

fn resolve_lia_bin(explicit: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(p) = std::env::current_exe() {
        return Ok(p);
    }
    Ok(PathBuf::from("lia"))
}

fn build_install_request(
    lia_home: Option<PathBuf>,
    lia_bin: Option<PathBuf>,
    claude_home: Option<PathBuf>,
    codex_home: Option<PathBuf>,
    gemini_home: Option<PathBuf>,
    cursor_home: Option<PathBuf>,
    dry_run: bool,
    apply_live: bool,
    allowed_root: Vec<PathBuf>,
) -> Result<InstallRequest, Box<dyn std::error::Error>> {
    let claude_home = claude_home.unwrap_or_else(default_claude_home);
    let codex_home = codex_home.unwrap_or_else(default_codex_home);
    let gemini_home = gemini_home.unwrap_or_else(default_gemini_home);
    let cursor_home = cursor_home.unwrap_or_else(default_cursor_home);
    if !dry_run
        && looks_like_live_user_home(&claude_home, &codex_home, &gemini_home, &cursor_home)
        && !apply_live
    {
        return Err(
            "refusing to modify live harness configs without --apply-live \
             (use fixture home flags for tests, or --dry-run)"
                .into(),
        );
    }
    Ok(InstallRequest {
        lia_home: lia_home.unwrap_or_else(default_lia_home),
        lia_bin: resolve_lia_bin(lia_bin)?,
        claude_home,
        codex_home,
        gemini_home,
        cursor_home,
        dry_run,
        apply_live,
        allowed_roots: allowed_root,
    })
}

fn emit_install_report(
    report: &lia_adapters::InstallReport,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("action: {}", report.action);
        println!("dry_run: {}", report.dry_run);
        println!("lia_home: {}", report.lia_home.display());
        println!("claude_settings: {}", report.claude_settings.display());
        println!("codex_config: {}", report.codex_config.display());
        println!("gemini_settings: {}", report.gemini_settings.display());
        println!("cursor_hooks: {}", report.cursor_hooks.display());
        println!("claude_hook_installed: {}", report.claude_hook_installed);
        println!("codex_mcp_installed: {}", report.codex_mcp_installed);
        println!("gemini_hook_installed: {}", report.gemini_hook_installed);
        println!("cursor_hooks_installed: {}", report.cursor_hooks_installed);
        println!("kernel: {}", report.kernel.name);
        println!("assurance: {}", report.kernel.assurance);
        println!("enforced_on:");
        for e in &report.kernel.enforced_on {
            println!("  - {e}");
        }
        println!("cannot_observe:");
        for e in &report.kernel.cannot_observe {
            println!("  - {e}");
        }
        for n in &report.notes {
            println!("note: {n}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_install(
    lia_home: Option<PathBuf>,
    lia_bin: Option<PathBuf>,
    claude_home: Option<PathBuf>,
    codex_home: Option<PathBuf>,
    gemini_home: Option<PathBuf>,
    cursor_home: Option<PathBuf>,
    dry_run: bool,
    apply_live: bool,
    allowed_root: Vec<PathBuf>,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let req = build_install_request(
        lia_home,
        lia_bin,
        claude_home,
        codex_home,
        gemini_home,
        cursor_home,
        dry_run,
        apply_live,
        allowed_root,
    )?;
    let report = install_kernel(&req).map_err(|e| e.to_string())?;
    emit_install_report(&report, json)
}

fn run_install_status(
    lia_home: Option<PathBuf>,
    lia_bin: Option<PathBuf>,
    claude_home: Option<PathBuf>,
    codex_home: Option<PathBuf>,
    gemini_home: Option<PathBuf>,
    cursor_home: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let req = InstallRequest {
        lia_home: lia_home.unwrap_or_else(default_lia_home),
        lia_bin: resolve_lia_bin(lia_bin)?,
        claude_home: claude_home.unwrap_or_else(default_claude_home),
        codex_home: codex_home.unwrap_or_else(default_codex_home),
        gemini_home: gemini_home.unwrap_or_else(default_gemini_home),
        cursor_home: cursor_home.unwrap_or_else(default_cursor_home),
        dry_run: false,
        apply_live: false,
        allowed_roots: vec![],
    };
    let report = install_status(&req).map_err(|e| e.to_string())?;
    emit_install_report(&report, json)
}

fn run_uninstall(
    lia_home: Option<PathBuf>,
    lia_bin: Option<PathBuf>,
    claude_home: Option<PathBuf>,
    codex_home: Option<PathBuf>,
    gemini_home: Option<PathBuf>,
    cursor_home: Option<PathBuf>,
    dry_run: bool,
    apply_live: bool,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let req = build_install_request(
        lia_home,
        lia_bin,
        claude_home,
        codex_home,
        gemini_home,
        cursor_home,
        dry_run,
        apply_live,
        vec![],
    )?;
    let report = uninstall_kernel(&req).map_err(|e| e.to_string())?;
    emit_install_report(&report, json)
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
                manifest_packages: req.payload.new_dependencies.clone().unwrap_or_default(),
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
    timeout_seconds: u64,
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
        timeout_seconds,
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

/// PreToolUse fail-closed: any internal error MUST block the tool, never let it proceed.
/// Claude Code treats exit 2 as a block (its reason is read from stderr; stdout JSON is
/// discarded on exit 2), while exit 1 is a non-blocking error that lets the tool run.
/// A trust kernel that errored has no basis to allow, so it denies.
fn hook_fail_closed(reason: &str) -> ExitCode {
    eprintln!("[lia] blocked (fail-closed): {reason}");
    ExitCode::from(2)
}

fn run_hook(
    adapter: String,
    config: PathBuf,
    journal: Option<PathBuf>,
    secret_key_hex: Option<String>,
    key_id: String,
    run_id: Option<Uuid>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if !matches!(
        adapter.as_str(),
        "claude-code" | "gemini-cli" | "cursor-shell" | "cursor-mcp"
    ) {
        return Ok(hook_fail_closed(&format!(
            "hook adapter {adapter} not supported"
        )));
    }
    // Every fallible step below fails CLOSED: a hook that cannot load its policy, read
    // its input, or evaluate a gate has no basis to allow the tool, so it blocks.
    let mut cfg = match load_gate_config(&config) {
        Ok(c) => c,
        Err(e) => return Ok(hook_fail_closed(&format!("gate config load failed: {e}"))),
    };
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
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        return Ok(hook_fail_closed(&format!("stdin read failed: {e}")));
    }
    let handled = match adapter.as_str() {
        "claude-code" => handle_pre_tool_stdin(&raw, &ctx),
        "gemini-cli" => handle_gemini_before_tool_stdin(&raw, &ctx),
        "cursor-shell" => handle_cursor_shell_stdin(&raw, &ctx),
        "cursor-mcp" => handle_cursor_mcp_stdin(&raw, &ctx),
        _ => unreachable!("adapter checked above"),
    };
    let out = match handled {
        Ok(o) => o,
        Err(e) => return Ok(hook_fail_closed(&format!("gate error: {e}"))),
    };
    println!("{out}");
    let parsed = serde_json::from_str::<serde_json::Value>(&out).ok();
    let perm = parsed
        .as_ref()
        .and_then(|decision| {
            decision
                .pointer("/hookSpecificOutput/permissionDecision")
                .or_else(|| decision.get("decision"))
                .or_else(|| decision.get("permission"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "deny".to_string());
    if perm == "allow" || perm == "ask" {
        Ok(ExitCode::SUCCESS)
    } else {
        // exit 2 blocks but discards stdout JSON; surface the reason on stderr so the
        // model sees why it was denied.
        let reason = parsed
            .as_ref()
            .and_then(|decision| {
                decision
                    .pointer("/hookSpecificOutput/permissionDecisionReason")
                    .or_else(|| decision.get("reason"))
                    .or_else(|| decision.get("agent_message"))
            })
            .and_then(serde_json::Value::as_str)
            .unwrap_or("lia denied")
            .to_string();
        eprintln!("[lia] denied: {reason}");
        Ok(ExitCode::from(2))
    }
}

fn run_process_contract_validate(
    contract: PathBuf,
    execution: PathBuf,
    journal: PathBuf,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let report = load_and_validate_process_contract(contract, execution, journal)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.followed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn run_public_verify(
    artifact: PathBuf,
    bundle: PathBuf,
    certificate_identity: String,
    certificate_oidc_issuer: String,
    cosign_bin: PathBuf,
    expected_cosign_sha256: String,
    timeout_seconds: u64,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let report = verify_blob_with_cosign(&PublicVerificationOptions {
        artifact,
        bundle,
        certificate_identity,
        certificate_oidc_issuer,
        cosign_bin,
        expected_cosign_sha256,
        timeout_seconds,
    })?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[allow(clippy::too_many_arguments)]
fn run_registry_evidence(
    ecosystem: String,
    package: String,
    version: Option<String>,
    cache_dir: PathBuf,
    offline: bool,
    http_client: PathBuf,
    expected_http_client_sha256: Option<String>,
    timeout_seconds: u64,
    base_url: Option<String>,
    expected_response_sha256: Option<String>,
    expected_cache_manifest_sha256: Option<String>,
    max_cache_age_seconds: u64,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let report = collect_registry_evidence(&RegistryEvidenceOptions {
        ecosystem: RegistryEcosystem::parse(&ecosystem)?,
        package,
        version,
        cache_dir,
        offline,
        http_client,
        expected_http_client_sha256,
        timeout_seconds,
        base_url,
        expected_response_sha256,
        expected_cache_manifest_sha256,
        max_cache_age_seconds,
    })?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
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
            cleanup_policy: None,
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
    // Long-lived Content-Length framed MCP session (Codex real client path).
    // One-shot `--request` kept for unit/conformance callers.
    if request.is_none() {
        serve_mcp_stdio(&run_ctx, &inspect_ctx).map_err(|e| e.to_string())?;
        return Ok(ExitCode::SUCCESS);
    }
    let raw = request.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "one-shot MCP mode requires --request",
        )
    })?;
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
        let candidates = [path.join("evidence-set.json"), path.join("evidence.json")];
        for c in &candidates {
            if c.is_file() {
                return Ok(load_evidence_json(c)?);
            }
        }
        return Err(format!("bundle dir {} has no evidence-set.json", path.display()).into());
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
    require_live: bool,
    model: Option<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let harness = Harness::parse(&harness)?;
    let arm = Arm::parse(&arm)?;
    if force_recorded && require_live {
        return Err("cannot combine --force-recorded with --require-live".into());
    }
    if !require_live && !force_recorded {
        let (bridge_ok, _) = probe_bridge(&bridge_url);
        if !bridge_ok {
            eprintln!(
                "bridge unreachable at {bridge_url}; recorded path unless live env arms tool-loop"
            );
        }
    }
    let result = run_arm(&BenchOptions {
        harness,
        arm,
        corpus,
        out_dir: out.clone(),
        secret_key_hex,
        key_id,
        bridge_url,
        force_recorded,
        require_live,
        model,
    })?;
    let bundle = out.join(format!("bundle-{}-{}", result.harness, result.arm));
    let (ok, metrics) = verify_bench_bundle(&bundle)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "result": result,
            "verify_ok": ok,
            "recomputed_metrics": metrics,
            "bridge_model_id": result.bridge_model_id,
            "agent_mode": result.agent_mode,
            "model_lane": result.model_lane,
        }))?
    );
    if ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn run_claims_lint(root: PathBuf, json: bool) -> Result<ExitCode, Box<dyn std::error::Error>> {
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

fn run_verify_run(
    base: String,
    head: String,
    evidence: PathBuf,
    repo: Option<PathBuf>,
    out: PathBuf,
    secret_key_hex: String,
    key_id: String,
    verifier_secret_key_hex: Option<String>,
    verifier_key_id: String,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let repo = repo.unwrap_or_else(|| PathBuf::from("."));
    let journal_id = SigningIdentity::from_secret_key_hex(key_id, &secret_key_hex)?;
    // Independent verifier entropy, never derived from the journal secret (see fixture-bundle).
    let verifier_secret = match verifier_secret_key_hex {
        Some(s) => s,
        None => lia_journal::random_secret_hex()?,
    };
    let verifier_id = SigningIdentity::from_secret_key_hex(verifier_key_id, &verifier_secret)?;
    let (bundle, run_id) = verify_run(&VerifyRunOptions {
        repo: &repo,
        base: &base,
        head: &head,
        evidence_dir: &evidence,
        out_bundle: &out,
        journal_identity: &journal_id,
        verifier_identity: &verifier_id,
    })?;
    let mut report = verify_bundle(&bundle)?;
    sign_verification_report(&mut report, &verifier_id)?;
    verify_report_signature(&report)?;
    write_verification_report(&report, bundle.join("verification-report.json"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "bundle": bundle,
            "run_id": run_id,
            "assurance_level": "AUDIT",
            "mode": "verify-run",
            "prevention": false,
            "accepted": report.accepted,
            "reason_code": report.reason_code,
        }))?
    );
    if report.accepted {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn run_conform(
    suite: PathBuf,
    adapter: Option<String>,
    json: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let report = assert_adapter(&suite, adapter.as_deref())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for r in &report.results {
            println!(
                "{}: {} ({})",
                r.id,
                if r.ok { "PASS" } else { "FAIL" },
                r.detail
            );
        }
        println!(
            "suite={} passed={} failed={}",
            report.suite_id, report.passed, report.failed
        );
    }
    if report.failed == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}
