# Changelog

All notable changes are listed here. Versions follow [semantic versioning](https://semver.org/).

## 0.1.0 (unreleased)

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
