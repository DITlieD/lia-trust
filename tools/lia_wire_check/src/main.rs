use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::Parser;
use lia_wire_check::{check_files, exit_code, files_from_changeset, load_allowlist};

#[derive(Debug, Parser)]
#[command(
    name = "lia_wire_check",
    about = "LIA Layer-2 producer-without-consumer checker (wire-dark)"
)]
struct Args {
    #[arg(long, value_name = "DIFF")]
    changeset: Option<String>,

    #[arg(long, value_delimiter = ',')]
    files: Vec<PathBuf>,

    #[arg(long, default_value = "tools/wire-dark-allowlist.txt")]
    allowlist: PathBuf,

    #[arg(long)]
    root: Option<PathBuf>,

    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("lia_wire_check: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<i32> {
    let args = Args::parse();
    let root = args
        .root
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    let allow = load_allowlist(&root.join(&args.allowlist)).context("load allowlist")?;

    let files = if let Some(cs) = &args.changeset {
        files_from_changeset(&root, cs).context("parse changeset")?
    } else if !args.files.is_empty() {
        args.files
            .iter()
            .map(|f| {
                if f.is_absolute() {
                    f.clone()
                } else {
                    root.join(f)
                }
            })
            .collect()
    } else {
        bail!("provide --changeset <diff|path|git:HEAD> or --files a.rs,b.rs");
    };

    if files.is_empty() {
        bail!("no .rs paths resolved from input (fail-closed)");
    }

    let findings = check_files(&root, &files, &allow).context("check")?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        for f in &findings {
            println!(
                "{:?}\t{}:{}\t{}::{}\t{}",
                f.verdict, f.path, f.line, f.kind, f.symbol, f.detail
            );
        }
        let dark: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == lia_wire_check::Verdict::Dark)
            .collect();
        if !dark.is_empty() {
            eprintln!("DARK symbols:");
            for f in dark {
                eprintln!("  {}::{} ({}:{})", f.kind, f.symbol, f.path, f.line);
            }
        }
    }
    Ok(exit_code(&findings))
}
