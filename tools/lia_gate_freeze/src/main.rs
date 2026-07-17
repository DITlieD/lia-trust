use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use lia_gate_freeze::{check_baseline, default_paths, lock_baseline};

#[derive(Debug, Parser)]
#[command(
    name = "lia_gate_freeze",
    about = "LIA R8 gate-manifest freeze / check (content-hash baseline)"
)]
struct Args {
    #[arg(long)]
    check: bool,

    #[arg(long)]
    lock: bool,

    #[arg(long)]
    manifest: Option<PathBuf>,

    #[arg(long = "lock-file")]
    lock_file: Option<PathBuf>,

    #[arg(long)]
    root: Option<PathBuf>,

    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("lia_gate_freeze: {e:#}");
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
    let (default_manifest, default_lock) = default_paths(&root);
    let manifest = args.manifest.unwrap_or(default_manifest);
    let lock_file = args.lock_file.unwrap_or(default_lock);

    if args.lock {
        let rows = lock_baseline(&root, &manifest, &lock_file).context("lock")?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else {
            println!("locked {} paths → {}", rows.len(), lock_file.display());
            for rel in rows.keys() {
                println!("  {rel}");
            }
        }
        return Ok(0);
    }

    let report = check_baseline(&root, &manifest, &lock_file).context("check")?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.ok {
        println!("gate freeze clean");
    } else {
        eprintln!("gate freeze BLOCK:");
        for c in &report.changes {
            eprintln!("  {:?}\t{}\t{}", c.kind, c.path, c.detail);
        }
    }
    Ok(if report.ok { 0 } else { 3 })
}
