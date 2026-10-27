# Changelog

All notable changes are listed here. Versions follow [semantic versioning](https://semver.org/).

## 0.1.1 (2026-10-27)

Fixed:

- `approved-proposal-still-executable` no longer matches a stale approved **config
  transaction**. Squads v4 refuses to execute a config transaction at or below the
  stale transaction index; only vault transactions and batches stay executable. For
  each approved proposal at or below the stale index, the scanner now reads the
  transaction account at the PDA (`multisig`, multisig, `transaction`, index) and
  decodes its Anchor discriminator. A config transaction matches nothing; a vault
  transaction or batch matches as before. A transaction account that is missing, not
  owned by Squads v4, undecodable, or for another multisig or index is listed under
  `searches_not_possible` as `stale-transaction-kinds`, and the scan says "scan
  incomplete": never a finding, never fine.

Added:

- `transaction_kind` on each entry of `stale_approved_proposals` in the JSON report
  (`vault-transaction`, `config-transaction`, `batch`, or null when not read). An added
  field, so the report stays schema version 1.
- `squads::TransactionKind`, `squads::decode_transaction_header`,
  `squads::transaction_address` and the three transaction discriminators.
- `solana_authority_scan::VERSION`, the crate version.
- The published package includes `tests/no_sending.rs`, so the no-sending check runs
  from the packaged crate.

Known limits (documented in the README and the rule's text):

- "Executable" means the Squads program would accept the execute instruction, not that
  the inner instructions would succeed today (for example, an upgrade whose buffer has
  since changed authority).
- A stale proposal in the deprecated `executing` status still matches when its
  transaction is a vault transaction or batch, although the current Squads v4 program
  executes only `approved` proposals: a smaller, known false positive.

## 0.1.0

First release.

- `solana-authority-scan <program-id>...`: upgrade authority (BPF Upgradeable Loader,
  BPFLoader2 and older, loader v4, native), Squads v4 multisig settings, open proposals
  and approved proposals still executable below the stale transaction index, from
  public chain data. Read-only.
- Eight rules with severities; Markdown and JSON reports (schema
  `solana-authority-scan/report` version 1); `candidates.json` in the `dv-candidates`
  interchange format, version 1.
- The Squads v4 vault index, cached for 24 hours; a fallback search of the vault's
  recent transactions; `--multisig` to check a named multisig by derivation.
- The RPC URL only from `SOLANA_<CLUSTER>_RPC_URL`, HTTPS only, never printed; the
  endpoint's genesis hash is checked before any other read.
- Output refused inside any git work tree.
- The `read` module: a read-only Solana client (six typed JSON-RPC reads), usable
  without its HTTPS transport (`default-features = false`).
