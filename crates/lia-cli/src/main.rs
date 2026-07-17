use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use lia_journal::{append_signed, verify_chain, Journal, SigningIdentity};
use lia_protocol::parse_event;
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
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
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
            Ok(())
        }
        Commands::JournalVerify { db } => {
            verify_chain(&db)?;
            Ok(())
        }
    }
}
