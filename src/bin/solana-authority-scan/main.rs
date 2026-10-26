//! `solana-authority-scan <program-id>...`: who can change each program, and how fast.
//! Read-only. A thin shell over the library: it reads the RPC URL from the
//! environment, connects with the genesis-hash check, loads or builds the Squads v4
//! index, scans each program and writes the report.
//!
//! Exit status: 0 when every scan ran to the end, 2 when one stopped early, 1 on a
//! usage, URL, connection or output-path error.

mod args;
mod cache;
mod out;

use std::process::ExitCode;

use solana_authority_scan::read::{HttpRpc, RpcUrl};
use solana_authority_scan::report::{self, ProgramResult, RunContext};
use solana_authority_scan::scan::{IndexState, Scanner};

use args::{Args, Parsed};

/// The name the binary prints its messages under.
pub const NAME: &str = "solana-authority-scan";
const JSON_FILE: &str = "authority-scan.json";
const MARKDOWN_FILE: &str = "authority-scan.md";
const CANDIDATES_FILE: &str = "candidates.json";

fn main() -> ExitCode {
    match args::parse(std::env::args().skip(1)) {
        Ok(Parsed::Help) => {
            println!("{}", args::USAGE);
            ExitCode::SUCCESS
        }
        Ok(Parsed::Version) => {
            println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Parsed::Run(a)) => match run(&a) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(2),
            Err(e) => {
                eprintln!("{NAME}: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("{NAME}: {e}\n\n{}", args::USAGE);
            ExitCode::FAILURE
        }
    }
}

/// Runs the scan. `Ok(false)` when any program's scan stopped early.
fn run(a: &Args) -> Result<bool, String> {
    // Check the output path before any read, so a refused path costs nothing.
    let out = a.out.as_deref().map(out::open_out).transpose()?;
    let url = RpcUrl::from_env(a.cluster.rpc_url_var()).map_err(|e| e.to_string())?;
    let rpc = HttpRpc::connect(url, a.cluster).map_err(|e| e.to_string())?;

    let built = if a.no_index {
        Err("not built (--no-index)".to_owned())
    } else if !a.multisigs.is_empty() {
        Err("not needed (--multisig given)".to_owned())
    } else {
        out::cache_dir().and_then(|dir| {
            cache::load_or_build(
                &rpc,
                a.cluster,
                &dir,
                a.options.max_vault_index,
                a.refresh_index,
            )
        })
    };
    let index = match &built {
        Ok(index) => IndexState::Ready(index),
        Err(reason) => IndexState::Unavailable(reason.clone()),
    };
    let ctx = RunContext {
        cluster: a.cluster.name(),
        tool_version: env!("CARGO_PKG_VERSION"),
        index: built
            .as_ref()
            .map(|i| (i.slot, i.multisig_count(), i.max_vault_index))
            .map_err(Clone::clone),
    };
    let scanner = Scanner {
        rpc: &rpc,
        index,
        supplied_multisigs: &a.multisigs,
        options: a.options,
    };
    let results: Vec<ProgramResult> = a
        .programs
        .iter()
        .map(|p| ProgramResult::new(scanner.scan(p)))
        .collect();
    let complete = results.iter().all(|r| r.facts.error.is_none());

    let json = report::to_json(&ctx, &results);
    let markdown = report::to_markdown(&ctx, &results);
    let pretty = || {
        serde_json::to_string_pretty(&json).map_err(|e| format!("cannot serialise the report: {e}"))
    };
    match out {
        Some(dir) => {
            for (name, text) in [(JSON_FILE, pretty()?), (MARKDOWN_FILE, markdown)] {
                let path = dir.write(name, &text)?;
                eprintln!("{NAME}: wrote {}", path.display());
            }
            match report::candidates_document(&results)? {
                Some(text) => {
                    let path = dir.write(CANDIDATES_FILE, &text)?;
                    eprintln!(
                        "{NAME}: wrote {} (unreviewed candidate findings)",
                        path.display()
                    );
                }
                None => {
                    dir.remove_old(CANDIDATES_FILE)?;
                    eprintln!("{NAME}: no rule matched, so no {CANDIDATES_FILE}");
                }
            }
        }
        None if a.json => println!("{}", pretty()?),
        None => print!("{markdown}"),
    }
    Ok(complete)
}
