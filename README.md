# solana-authority-scan

Who can change a Solana program, and how fast?

`solana-authority-scan` reads public chain data and reports, for each program you name:

- which loader owns it, and whether it can still be upgraded;
- who holds the upgrade authority: nobody (immutable), a single key, a Squads v4
  multisig vault, or a program-derived address it cannot tie to Squads v4;
- for a Squads v4 vault: the multisig's threshold, voting members, time lock, config
  authority, open proposals, and approved proposals that are still executable;
- which of its [rules](#rules) matched, with the chain values behind each match.

It is **read-only**. It never signs or sends a transaction, never asks for a private
key or seed phrase, and holds no keys. Every chain read is one of six typed JSON-RPC
reads (`getGenesisHash`, `getAccountInfo`, `getMultipleAccounts`, `getProgramAccounts`,
`getSignaturesForAddress`, `getTransaction`); a test fails the build if the source gains
any other method name. `cargo-deny` refuses keypair, signer, seed-phrase and
transaction-sending crates in the dependency tree.

**It is not an audit**, and its output is not legal, financial or regulatory advice. A
result of "no rule matched" means none of the rules below matched the on-chain data; it
does not mean the program is safe. The scanner cannot see how keys are stored, who
holds them, or what happens off chain ([what it cannot see](#what-it-cannot-see)).

## Install

Rust 1.98 or later.

```sh
cargo install --locked solana-authority-scan
# or, from a checkout of this repository:
cargo install --locked --path .
```

## Usage

The RPC URL comes only from the environment, `SOLANA_<CLUSTER>_RPC_URL`
(`SOLANA_MAINNET_RPC_URL`, `SOLANA_DEVNET_RPC_URL` or `SOLANA_TESTNET_RPC_URL`). It must be
`https://`, it is never printed, and errors name the endpoint by scheme and host only,
so a provider key in the path or query stays out of logs. Before any other read the
scanner checks the endpoint's genesis hash, so a devnet URL cannot be used for a
mainnet scan by mistake.

A devnet example, on two devnet programs from this crate's test fixtures:

```sh
export SOLANA_DEVNET_RPC_URL=https://api.devnet.solana.com
solana-authority-scan --cluster devnet \
  58L4q3DgvPdvRh7kX4v148EwEwd29WHh4RfaZJR69iYx \
  8hxagcQkw1Km6PWZgpA92qUnqvnFufC7tx2jvxf9Ko8m
```

This prints a Markdown report. An excerpt:

```text
# Solana authority scan

Cluster: devnet. Tool: solana-authority-scan 0.1.1. Schema: solana-authority-scan/report v1.

Squads v4 index: 19313 multisigs at slot 515444879, vaults 0 to 3.

## `58L4q3DgvPdvRh7kX4v148EwEwd29WHh4RfaZJR69iYx`

**Result: no rule matched.**

| Field | Value |
|---|---|
| Loader | bpf-upgradeable |
| Authority | none  |

## `8hxagcQkw1Km6PWZgpA92qUnqvnFufC7tx2jvxf9Ko8m`

**Result: no rule matched.**

| Field | Value |
|---|---|
| Authority | squads-v4-vault `8MpmERed9K14R68F371YJtGVk6mQgNZoQeU3asNPs5mt` |
| Multisig | `9aAiYToZ4ZrHMcyAoNDDnMiswobn3TxtJ1dGXgKkBkU5` (vault 0, found by squads-v4-index) |
| Threshold | 2 of 3 voting members (3 members) |
| Time lock | 86400 seconds |
| Config authority | none |
```

Options:

| Option | Meaning |
|---|---|
| `--cluster <mainnet\|devnet\|testnet>` | The cluster (default `mainnet`) |
| `--out <dir>` | Write `authority-scan.json`, `authority-scan.md` and, when a rule matched, `candidates.json` into `<dir>` instead of printing. Refused inside any git work tree (below) |
| `--json` | Print the JSON report instead of Markdown (not with `--out`) |
| `--multisig <address>` | The Squads v4 multisig said to hold the upgrade authority (may repeat). Its vaults are derived and compared; no index is loaded and no search is made, so a dormant vault is still found |
| `--max-vault-index <n>` | Derive Squads vaults 0 to `n` (default 3, at most 255) |
| `--stale-window <n>` | Read the newest `n` proposals at or below the stale transaction index, for approved ones (default 50, at most 10,000) |
| `--refresh-index` | Rebuild the Squads v4 index even if the cache is fresh |
| `--no-index` | Skip the index; find a vault's multisig from its recent transactions only |
| `-h`, `--help`; `-V`, `--version` | Help; version |

### Exit status

| Code | Meaning |
|---|---|
| 0 | Every program's scan ran to the end (whether or not a rule matched) |
| 2 | At least one program's scan stopped early (for example, the address is not a program); the report says which |
| 1 | A usage error, a missing or refused RPC URL, a connection or cluster-check failure, or a refused output path |

A scan that ran to the end can still say "scan incomplete" when a search was not
possible (a provider refused `getProgramAccounts`, or rate-limited it), a proposal did
not decode, or some proposals were left unread. The report lists each search that was
not possible, and why.

### RPC providers

The Squads v4 index (every Squads v4 multisig, so a vault resolves to its multisig
without a search per program) is built with `getProgramAccounts`. Many free-tier
providers refuse that call; the public devnet endpoint allows it but rate-limits
(HTTP 429). When it is refused, the scanner falls back to the vault's recent
transactions, or use `--multisig` if you know the multisig. The index is cached for 24
hours in `$XDG_CACHE_HOME/solana-authority-scan/` (else `~/.cache/solana-authority-scan/`),
a directory readable by its owner only.

### Where output may go

A report names programs and the rules they matched. So that a result is not committed
and published by accident, `--out` and the cache directory are canonicalised (symlinks
and `..` resolved) and refused inside any git work tree. Files are written atomically
and never through a symlink. (If your cache directory is inside a git work tree, for
example a home directory kept in git, the index is not cached and the scan uses the
fallback search; set `XDG_CACHE_HOME` to a directory outside it.)

## Output formats

- **Markdown** (default, or `authority-scan.md`): a summary per program, the rules that
  matched with their evidence, the searches that were not possible, and what the scan
  cannot see.
- **JSON** (`--json`, or `authority-scan.json`): schema `solana-authority-scan/report`,
  version 1. Every decoded value, the slot each account was read at, and the
  candidates. Fields are listed in [docs/output-formats.md](docs/output-formats.md).
- **Candidates** (`candidates.json`, with `--out`, only when a rule matched): one
  candidate finding per matched rule, in the `dv-candidates` interchange format,
  version 1, so a review tool can import the scanner's output unchanged. The format is
  in [docs/output-formats.md](docs/output-formats.md). Candidates are unreviewed tool
  output for a person to check.

## Rules

| Id | Severity | Matches |
|---|---|---|
| `single-key-upgrade-authority` | high | The upgrade authority is on the ed25519 curve (upgradeable or loader-v4): one key can replace the code |
| `multisig-threshold-below-two` | high | Threshold below 2 |
| `multisig-config-authority-set` | high | A config authority can change members, threshold and time lock without a vote |
| `approved-proposal-still-executable` | high | An approved or executing proposal at or below the stale transaction index whose transaction is a vault transaction or a batch (Squads v4 still executes those after they are marked stale; it refuses a stale config transaction, which does not match). Limits below |
| `multisig-time-lock-zero` | medium | Time lock 0 |
| `multisig-threshold-below-half` | medium | Threshold of at least 2 but less than half of the members with the vote permission (2 of 5 matches, 2 of 4 does not) |
| `multisig-open-proposals` | low | Any draft, active, approved or executing proposal after the stale transaction index |
| `upgrade-authority-unknown-pda` | info | The authority is off the curve but not a Squads v4 vault this scan found: review by hand. Not a weakness on its own |

For `approved-proposal-still-executable`, the scanner reads each stale approved
proposal's transaction account and decodes its type. If that account is missing or
does not decode, the proposal is listed as not read (`stale-transaction-kinds`) and the
scan says "scan incomplete"; it is never a finding and never counted as fine. Known
limits of this rule:

- "Executable" means the Squads v4 program would accept the execute instruction, not
  that the inner instructions would succeed today. For example, a stale approved
  upgrade whose buffer is no longer owned by the vault still matches, though it would
  fail if executed.
- A proposal in the deprecated `executing` status still matches when its transaction
  is a vault transaction or batch, although the current Squads v4 program executes only
  `approved` proposals: a smaller, known false positive.

Loaders decoded: BPF Upgradeable Loader, BPFLoader2 and the older BPFLoader (immutable),
loader v4, and the native loader. Squads v4 accounts follow `@sqds/multisig` 2.1.4.
Details, and how an authority is classified, are in
[docs/how-it-works.md](docs/how-it-works.md).

## What it cannot see

- How and where each signer's key is stored (hardware wallet, hot key, custodian).
- Who holds each key, and whether one person or device holds several.
- Off-chain procedures: how proposals are checked before signing, and incident response.
- Durable nonce accounts that could hold pre-signed transactions. (It counts nonce
  accounts whose authority is a signer when the provider allows it, as information
  only: anyone can create a nonce account with any authority.)
- Authorities of other programs, mints and accounts the program depends on.
- Approved proposals older than the stale window.
- Multisigs other than Squads v4 (Squads v3, Realms and others): reported as a PDA of
  an unknown program.

## If you find a weakness in someone else's program

Tell the program's owner privately, through their published security contact
(`security.txt`, a bug bounty, or the team directly), and give them time to fix it.
Please do not publish scan results that name a program, multisig or team as weak.

## Library

The crate is also a library: `read` (the read-only client: base58 types, PDAs, the `Rpc`
trait and the blocking `HttpRpc`), the pure decoders (`loader`, `squads`, `txn`), the
Squads v4 `index`, `rules`, `report`, `candidate` and `scan`. With
`default-features = false` it has no HTTP or TLS dependency (and no binary); implement
`read::Rpc` over your own transport and pass it to `scan::Scanner`.

## Licence

Apache-2.0. See [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
