# How it works

What the scanner reads, how it decodes and classifies what it reads, and what it
cannot see. For the output files, see [output-formats.md](output-formats.md).

## Shape

- **`read`**: the read-only Solana client. Pure base58 and base64, the `Address`,
  `Hash` and `Signature` types, program derived addresses and the ed25519 on-curve
  check; the `Rpc` trait with six typed reads; `HttpRpc`, the blocking HTTPS transport
  (feature `http`, on by default).
- **Library**, pure over bytes, no I/O of its own:
  - `bytes`: a bounds-checked reader; every decoder returns a `DecodeError` (account,
    field, byte offset, reason) and never panics.
  - `loader`: dispatch on the program account's owner; the ProgramData header.
  - `squads`: Squads v4 Multisig and Proposal decoders; vault and proposal PDAs; the
    open range and the stale window of proposal indexes.
  - `txn`: the accounts of each instruction to one program in a wire transaction
    (legacy and v0).
  - `index`: the Squads v4 vault index (vault PDA to multisig and vault index).
  - `rules`, `facts`, `report`, `candidate`: the rules, what a scan found, and the
    JSON, Markdown and candidate outputs.
  - `scan`: one program's scan over any `Rpc`.
- **Binary** `solana-authority-scan`: reads the RPC URL from the environment, connects
  with the cluster check, loads or builds the index, scans, writes.

## The read-only client

- `Rpc` has six methods: `get_genesis_hash`, `get_account_info`,
  `get_multiple_accounts`, `get_program_accounts` (filters `DataSize` and `Memcmp`,
  optional `DataSlice`), `get_signatures_for_address` (limit, before, until) and
  `get_transaction`. No method takes a method name or raw JSON.
- `tests/no_sending.rs` scans every `.rs` file under `src/`, with comments removed. It
  fails if the trait has another method; if `read::json::method` holds anything but the
  six read names; if any other string literal looks like an RPC method name (`get`,
  `send`, `simulate`, `request` or `sign`, then a capital letter); if a request body's
  method does not come from `read::json::method`; if the source uses `concat!`,
  `stringify!`, `include_str!` or `include_bytes!`; if `ureq` is named outside
  `read/http.rs`; or if `HttpRpc` gains an `impl` or a public method beyond `connect`.
  Its own tests plant each evasion and check it is caught.
- Every read uses `finalized` commitment and `base64` encoding. The three account reads
  return the slot the node read them at. `get_multiple_accounts` takes 1 to 100
  addresses; a signatures limit is 1 to 1000.
- Server text is untrusted: every address, hash and signature in a response must decode
  to its exact length, numbers must fit their type, and a JSON-RPC error message is
  sanitised (control characters escaped, backslashes doubled so a typed `\n` is told
  apart from a real one, at most 200 characters).
- `HttpRpc::connect(url, cluster)` calls `getGenesisHash` first and refuses an endpoint
  on another cluster. There is no other way to make an `HttpRpc`.
- The URL comes only from the environment (`SOLANA_<CLUSTER>_RPC_URL`), must start with
  `https://`, and is never printed: `RpcUrl` and `HttpRpc` have no `Debug` or `Display`,
  errors name the endpoint by scheme, host and port only, and a server message that
  repeats a secret part of the URL (user info, path, query or fragment) is withheld.
  No redirect is followed, no proxy is used, and each request times out after 30
  seconds.

## Layouts decoded

- **BPF Upgradeable Loader** (bincode `UpgradeableLoaderState`, u32 tag): the program
  account is tag 2 and the ProgramData address (36 bytes). ProgramData is tag 3, the
  last deploy slot (u64), and the upgrade authority as `Option<Pubkey>` (one-byte tag):
  a 45-byte header, then the ELF. No authority means immutable.
- **BPFLoader2 and BPFLoader** (`BPFLoader2111…`, `BPFLoader1111…`): no state;
  immutable. The account must be executable.
- **Loader v4** (`LoaderV4State`, 48-byte header): slot (u64), authority or next version
  (32 bytes), status (u64: 0 retracted, 1 deployed, 2 finalized). Finalized means
  immutable, and the address field is the next version, not an authority.
- **Native loader**: a builtin, reported as such.
- **Squads v4** (`SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`), pinned to the account
  types in `@sqds/multisig` 2.1.4, which Squads generates from the program's IDL. An
  Anchor discriminator (sha256 of `account:<Name>`, first 8 bytes), then Borsh:
  - `Multisig`: create key, config authority (all zeros means none), threshold u16,
    time lock u32, transaction index u64, stale transaction index u64, rent collector
    `Option<Pubkey>`, bump u8, members `Vec<{key, permissions u8}>` (1 initiate, 2 vote,
    4 execute). The rent collector is one byte when none, so every later offset varies:
    the decoder reads in order, never at fixed offsets.
  - `Proposal`: multisig, transaction index u64, status (u8 tag: 0 draft, 1 active,
    2 rejected, 3 approved, each with an i64 timestamp; 4 executing, no data;
    5 executed, 6 cancelled, with timestamps), bump, then the approved, rejected and
    cancelled key lists. Open means draft, active, approved or executing. Executable
    means approved or executing.
  - Vault PDA seeds: `"multisig"`, multisig, `"vault"`, index u8. Proposal PDA seeds:
    `"multisig"`, multisig, `"transaction"`, index u64 little-endian, `"proposal"`.
- A `Vec` length is refused if its items cannot fit in the bytes left, so a forged
  length cannot force a large allocation.

## How the authority is classified

- On the ed25519 curve: a single key. Off the curve: a PDA.
- With `--multisig`, a PDA is checked against vaults 0 to `--max-vault-index` of the
  given multisigs only. No index is loaded and no search is made. If no given multisig
  derives the vault, the authority is a PDA of an unknown program, and the report says
  the supplied-multisig search did not match.
- Otherwise a PDA is looked up in the Squads v4 index. If it is not there (or there is
  no index), the vault's recent transactions are read (100 signatures, at most 25
  transactions) and every account of every Squads v4 instruction is tried as the
  multisig.
- Only a derived PDA match counts as proof; the cached index is derived again when it
  is loaded. A PDA nothing ties to Squads v4 is reported as a PDA of an unknown program
  for manual review, never as a single key.

## Proposals

- Open range: `stale_transaction_index + 1` to `transaction_index`, the newest 500.
  Kept: open proposals.
- Stale window: the newest `--stale-window` indexes at or below
  `stale_transaction_index`. Kept: approved and executing proposals, because Squads v4
  can still execute an approved vault transaction after it is marked stale.
- Both are read with `getMultipleAccounts`, at most 100 addresses a call. A missing
  account, an account Squads v4 does not own, and a proposal for another multisig or
  another index are skipped. A proposal that does not decode is listed with its error,
  and the other proposals are still read.

## Nonces

When the provider allows it, the scanner counts System-program nonce accounts whose
authority is a signer key (the single-key authority, or each multisig member and a key
config authority). The count is information only: anyone can create a nonce account
with any authority, and one made by another key is not found, so it proves nothing
either way.

## What it cannot see

- How each signer's key is stored (hardware wallet, hot key, custodian), who holds it,
  and whether one person or device holds several.
- Off-chain procedures: how proposals are checked before signing; incident response.
- Durable nonce accounts holding pre-signed transactions.
- Authorities of other programs, mints and accounts the program depends on.
- Approved proposals older than the stale window.
- Non-Squads multisigs (Squads v3, Realms and others): reported as a PDA of an unknown
  program.
- A vault index above `--max-vault-index`, or, without `--multisig`, a vault that is not
  in the index and whose recent transactions do not call Squads v4.

## Tests and fixtures

- Tests never use the network. Fixtures in `tests/fixtures/` (see its README) are
  devnet scans recorded through a recording `Rpc` and replayed by `tests/common/mod.rs`.
  They are named by the property they show. No fixture comes from mainnet.
- `tests/oracle.rs` checks the Squads v4 decoders and PDAs against values computed with
  `@sqds/multisig` 2.1.4, not with this crate.
- `tests/report.rs` reads every fixture's candidates back with the candidate format's
  checks.
