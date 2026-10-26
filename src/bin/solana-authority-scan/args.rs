//! Command-line arguments. Program ids and flags only: the RPC URL never comes from
//! the command line.

use std::path::PathBuf;

use solana_authority_scan::read::{Address, Cluster};
use solana_authority_scan::scan::ScanOptions;

pub const USAGE: &str = "\
usage: solana-authority-scan <program-id>... [options]

Reports who can change each program and how fast, from public chain data. Read-only:
it never signs or sends a transaction and holds no keys. Not an audit.
The RPC URL comes from SOLANA_<CLUSTER>_RPC_URL (https only, never printed),
for example SOLANA_DEVNET_RPC_URL=https://api.devnet.solana.com

options:
  --cluster <mainnet|devnet|testnet>  the cluster (default mainnet)
  --out <dir>             write authority-scan.json, authority-scan.md and, when a
                          rule matched, candidates.json there; refused inside any
                          git work tree. Without it, print the report to stdout
  --json                  print the JSON report instead of Markdown (no --out)
  --multisig <address>    the Squads v4 multisig said to hold the upgrade
                          authority (may repeat). The vault is checked by
                          derivation, and no index or signatures search is made
  --max-vault-index <n>   derive Squads vaults 0 to n (default 3, at most 255)
  --stale-window <n>      read the newest n proposals at or below the stale
                          transaction index for approved ones (default 50)
  --refresh-index         rebuild the Squads v4 index even if the cache is fresh
  --no-index              skip the index; use only the signatures search
  -h, --help              this text
  -V, --version           the version

exit status: 0 every scan ran to the end, 2 a scan stopped early,
             1 a usage, URL, connection or output-path error";

/// The largest `--stale-window`: 100 `getMultipleAccounts` calls per multisig.
pub const MAX_STALE_WINDOW: u64 = 10_000;

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub programs: Vec<Address>,
    pub cluster: Cluster,
    pub out: Option<PathBuf>,
    pub json: bool,
    pub refresh_index: bool,
    pub no_index: bool,
    /// Multisigs named with `--multisig`.
    pub multisigs: Vec<Address>,
    pub options: ScanOptions,
}

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Help,
    Version,
    Run(Args),
}

fn cluster(name: &str) -> Result<Cluster, String> {
    Cluster::ALL
        .into_iter()
        .find(|c| c.name() == name)
        .ok_or_else(|| format!("unknown cluster {name:?}: use mainnet, devnet or testnet"))
}

/// Parses the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Parsed, String> {
    let mut out = Args {
        programs: Vec::new(),
        cluster: Cluster::Mainnet,
        out: None,
        json: false,
        refresh_index: false,
        no_index: false,
        multisigs: Vec::new(),
        options: ScanOptions::default(),
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or_else(|| format!("{flag} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--cluster" => out.cluster = cluster(&value("--cluster")?)?,
            "--out" => out.out = Some(PathBuf::from(value("--out")?)),
            "--json" => out.json = true,
            "--refresh-index" => out.refresh_index = true,
            "--no-index" => out.no_index = true,
            "--max-vault-index" => {
                out.options.max_vault_index = value("--max-vault-index")?
                    .parse()
                    .map_err(|_| "--max-vault-index takes 0 to 255".to_owned())?;
            }
            "--stale-window" => {
                out.options.stale_window = value("--stale-window")?
                    .parse()
                    .ok()
                    .filter(|n| *n <= MAX_STALE_WINDOW)
                    .ok_or_else(|| format!("--stale-window takes 0 to {MAX_STALE_WINDOW}"))?;
            }
            "--multisig" => {
                let text = value("--multisig")?;
                let address: Address = text
                    .parse()
                    .map_err(|e| format!("--multisig {text:?} is not an address: {e}"))?;
                if !out.multisigs.contains(&address) {
                    out.multisigs.push(address);
                }
            }
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            id => out.programs.push(
                id.parse()
                    .map_err(|e| format!("{id:?} is not a program id: {e}"))?,
            ),
        }
    }
    if out.programs.is_empty() {
        return Err("give at least one program id".to_owned());
    }
    if out.json && out.out.is_some() {
        return Err("--json prints to stdout; --out writes both files".to_owned());
    }
    Ok(Parsed::Run(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Parsed, String> {
        parse(args.iter().map(|s| (*s).to_owned()))
    }

    const PROGRAM: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

    #[test]
    fn parses_programs_and_flags() {
        let Ok(Parsed::Run(a)) = run(&[PROGRAM, "--cluster", "devnet", "--max-vault-index", "7"])
        else {
            panic!("did not parse");
        };
        assert_eq!(a.cluster, Cluster::Devnet);
        assert_eq!(a.options.max_vault_index, 7);
        assert_eq!(a.programs.len(), 1);
        assert_eq!(a.options.stale_window, 50);
        assert!(a.multisigs.is_empty());
        assert_eq!(run(&["--help"]), Ok(Parsed::Help));
        assert_eq!(run(&["-V"]), Ok(Parsed::Version));
        let Ok(Parsed::Run(a)) = run(&[
            PROGRAM,
            "--multisig",
            PROGRAM,
            "--multisig",
            PROGRAM,
            "--stale-window",
            "7",
        ]) else {
            panic!("did not parse");
        };
        assert_eq!(a.multisigs, [PROGRAM.parse().unwrap()]);
        assert_eq!(a.options.stale_window, 7);
    }

    #[test]
    fn refuses_bad_arguments() {
        for bad in [
            vec![],
            vec!["not-base58-0OIl"],
            vec![PROGRAM, "--cluster", "localnet"],
            vec![PROGRAM, "--cluster"],
            vec![PROGRAM, "--max-vault-index", "256"],
            vec![PROGRAM, "--rpc-url", "https://example.com"],
            vec![PROGRAM, "--json", "--out", "/tmp/x"],
            vec![PROGRAM, "--multisig", "not-base58-0OIl"],
            vec![PROGRAM, "--multisig"],
            vec![PROGRAM, "--stale-window", "-1"],
            vec![PROGRAM, "--stale-window", "10001"],
        ] {
            assert!(run(&bad).is_err(), "{bad:?}");
        }
    }
}
