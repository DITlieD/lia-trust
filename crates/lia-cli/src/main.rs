use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use lia_journal::{append_signed, verify_chain, Journal, SigningIdentity};
use lia_policy::{
    evaluate_frozen, freeze_policy_from_path, load_evidence_json, EvidenceSet,
};
use lia_protocol::parse_event;
use lia_verify::{
    sign_verification_report, verify_bundle, write_verification_report, VerificationReport,
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
        rules: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
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
        Commands::Gate { rules, evidence } => {
            let frozen = freeze_policy_from_path(&rules)?;
            let evidence_set = load_gate_evidence(&evidence)?;
            let report = evaluate_frozen(&frozen, &evidence_set)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if matches!(
                report.overall,
                lia_protocol::Verdict::Allow | lia_protocol::Verdict::Advisory
            ) {
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
            }
            emit_verify_report(&report, report_out.as_ref())?;
            if report.accepted {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
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
