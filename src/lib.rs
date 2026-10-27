//! Who can change a Solana program, and how fast, from public chain data.
//!
//! - [`read`]: a read-only Solana client. It reads accounts and transactions and
//!   derives addresses; it cannot sign, send, simulate or airdrop, and holds no keys.
//! - Pure decoders over account bytes: [`loader`] (upgradeable, BPFLoader2 and older,
//!   loader v4), [`squads`] (Squads v4 Multisig and Proposal, vault and proposal
//!   PDAs), [`txn`] (instruction accounts from a wire transaction).
//! - [`index`]: the Squads v4 vault index, vault PDA to multisig.
//! - [`rules`]: named rules with a severity; [`report`]: the JSON report, the
//!   Markdown summary and the candidate findings ([`candidate`]).
//! - [`scan`]: one program's scan over any [`read::Rpc`]. It does no I/O of its own;
//!   the caller passes the transport.
//!
//! Read-only: every chain read goes through [`read::Rpc`], which has no method that
//! signs or sends. Layouts and limits: `docs/how-it-works.md`.

/// This crate's version, as published (the `version` in `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod bytes;
pub mod candidate;
pub mod facts;
pub mod index;
pub mod loader;
pub mod read;
pub mod report;
pub mod rules;
pub mod scan;
pub mod squads;
pub mod txn;
