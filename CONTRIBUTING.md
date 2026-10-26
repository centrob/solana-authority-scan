# Contributing

Issues and pull requests are welcome. For a security problem, see
[SECURITY.md](SECURITY.md) instead.

Before opening a pull request, run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo clippy --all-targets --no-default-features --locked -- -D warnings
cargo test --locked
cargo test --no-default-features --locked
scripts/cargo-deny.sh        # Linux x86_64; downloads a pinned, checksummed cargo-deny
scripts/test-deny-bans.sh
scripts/leak-check.sh
scripts/test-leak-check.sh
```

Ground rules:

- **Read-only, no keys.** No change may add a way to sign, send or simulate a
  transaction, or to read, ask for or store a private key or seed phrase. New chain
  reads go through a typed method on `read::Rpc`; `tests/no_sending.rs` and `deny.toml`
  enforce this.
- **No network in tests.** Tests replay saved responses from `tests/fixtures/`.
- **Devnet fixtures only.** A fixture comes from a program and multisig on devnet,
  named by the property it shows, never by who owns it. No test, doc or example names
  a mainnet program, multisig or team as having a weakness.
- **No panics on chain data.** No `unwrap`, `expect` or unchecked indexing or
  arithmetic outside tests (the lints deny them). A decoder returns an error.
- **Dependencies are pinned exactly** (`=x.y.z`) with default features off unless one
  is needed. Explain any new dependency in the pull request.
- **Files stay at or below 1,000 lines.**
- Output text never calls a program "safe": a clean result is "no rule matched".

By contributing, you agree that your contribution is licensed under Apache-2.0.
