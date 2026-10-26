# Test fixtures

Every fixture here is derived from **devnet**, never mainnet: captured from devnet,
or (one file, marked) constructed from a devnet capture. Files are named by the
property they show, not by who owns the accounts. They are test data only: a
devnet account with a matched rule says nothing about any mainnet deployment.

## How they were captured

Each JSON file is one scan of one devnet program, recorded by running the scanner
over a recording `Rpc` against the public devnet endpoint. Every answer the scanner
read is saved, so the tests replay the same scan with no network:

- `accounts`: address → `{ slot, account }`. `account` is `null` when there was none.
  `data_saved` is `full` (the whole account), `header` (only the bytes the
  decoders read: 45 bytes of a ProgramData account, 48 of a loader-v4 program, none
  of a BPFLoader2 program; `data_len` is the full length), or `constructed`. For
  `full` and `constructed` data, trailing zero bytes are left out of `data_base64`
  and the replay restores them up to `data_len`, so the bytes are exactly the
  account's.
- `signatures`, `transactions`: what `getSignaturesForAddress` and `getTransaction`
  returned for the fallback search. Transactions are the wire bytes in base64.
- `program_accounts`: `getProgramAccounts` answers, keyed
  `<program>:<memcmp bytes as an address>` (the durable-nonce searches). A missing
  key means the provider refused or rate-limited the query during capture (the
  description says so); the replay refuses it the same way.
- `captured_at_slot`: the newest slot of any read in the file. Captured on devnet
  between slots 514964483 and 514964619 (25 Oct 2026).

The scanner now also reads proposals at or below each multisig's stale transaction
index (the stale window). The fixtures were captured before it did, so they hold no
such reads; the replay answers those proposal addresses as "no account".
`tests/proposals.rs` adds constructed proposals where a test needs them.

## Files

| File | Shows |
|---|---|
| `upgradeable-squads-vault-time-lock-set.json` | Squads v4 vault authority, 2 of 3, time lock 86400 s, no config authority, no open proposals: no rule matches. Also holds the transaction the fallback search uses |
| `upgradeable-squads-vault-time-lock-zero.json` | Vault authority; time lock 0; one active proposal |
| `upgradeable-squads-vault-config-authority.json` | Vault authority; config authority set; time lock 0 |
| `upgradeable-squads-vault-threshold-below-half.json` | Vault authority; 2 of 5 voters; two approved proposals |
| `upgradeable-squads-vault-threshold-one.json` | Vault authority; threshold 1 |
| `upgradeable-squads-vault-rent-collector.json` | Vault authority; `rent_collector` set, so later offsets shift; approved and cancelled proposals |
| `upgradeable-unknown-pda-authority.json` | Authority off the curve, not a Squads v4 vault. The second fallback fixture: it holds the authority's recent signatures and the 5 transactions the fallback search reads and rejects (none calls Squads v4) |
| `upgradeable-single-key-authority.json` | Authority on the curve |
| `upgradeable-immutable.json` | No upgrade authority |
| `bpf-loader-2-program.json` | Owned by BPFLoader2 |
| `loader-v4-single-key-authority.json` | Loader-v4, deployed, key authority |
| `rpc/devnet-usdc-mint.json` | A saved `getAccountInfo` response for the devnet USDC mint (`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`), for the RPC parser test in `src/read/json_tests.rs`. Not a scan |
| `malformed-multisig.json` | **Constructed**: the threshold-one fixture with its Multisig bytes corrupted, plus three corruptions with the error each must give |

Devnet had no finalized loader-v4 program to capture; that case is tested with
constructed bytes in `src/loader.rs`.

The expected Squads values in `tests/oracle.rs` come from `@sqds/multisig` 2.1.4
(`accounts.Multisig.fromAccountInfo`, `accounts.Proposal.fromAccountInfo`,
`getVaultPda`, `getProposalPda`), run over these same bytes, not from this crate.
