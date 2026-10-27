//! What one scan of a program found: the values the rules read and the report
//! prints. Plain data; no I/O.

use crate::read::Address;

use crate::execution::Check;
use crate::loader::V4Status;
use crate::squads::{Multisig, ProposalStatus, TransactionKind};

/// How a vault PDA was tied to its multisig.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundBy {
    /// The vault index built from every Squads v4 multisig.
    Index,
    /// An instruction to Squads v4 in the vault's recent transactions.
    Signatures,
    /// A multisig given with `--multisig`, checked by deriving its vaults.
    Supplied,
}

impl FoundBy {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Index => "squads-v4-index",
            Self::Signatures => "recent-signatures",
            Self::Supplied => "supplied-multisig",
        }
    }
}

/// Who can change the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// No one: the program is immutable.
    None,
    /// A builtin: only a validator release changes it.
    Builtin,
    /// An address on the ed25519 curve: one private key.
    SingleKey(Address),
    /// A Squads v4 vault PDA.
    SquadsVault {
        vault: Address,
        multisig: Address,
        index: u8,
        found_by: FoundBy,
    },
    /// Off the curve, so a PDA, but not a Squads v4 vault this scan could tie to a
    /// multisig: Squads v3, Realms, another program, or a vault the search missed.
    UnknownPda(Address),
}

/// Names used in the report. Matched by readers of the JSON.
pub mod authority_kind {
    pub const NONE: &str = "none";
    pub const BUILTIN: &str = "builtin";
    pub const SINGLE_KEY: &str = "single-key";
    pub const SQUADS_V4_VAULT: &str = "squads-v4-vault";
    pub const UNKNOWN_PDA: &str = "unknown-pda";
}

impl Authority {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::None => authority_kind::NONE,
            Self::Builtin => authority_kind::BUILTIN,
            Self::SingleKey(_) => authority_kind::SINGLE_KEY,
            Self::SquadsVault { .. } => authority_kind::SQUADS_V4_VAULT,
            Self::UnknownPda(_) => authority_kind::UNKNOWN_PDA,
        }
    }

    pub fn address(&self) -> Option<Address> {
        match self {
            Self::None | Self::Builtin => None,
            Self::SingleKey(a) | Self::UnknownPda(a) => Some(*a),
            Self::SquadsVault { vault, .. } => Some(*vault),
        }
    }
}

/// The on-curve test: a key (on the curve) or a PDA (off it).
pub fn key_kind(address: &Address) -> &'static str {
    if crate::read::is_on_curve(address.as_bytes()) {
        authority_kind::SINGLE_KEY
    } else {
        "pda"
    }
}

/// An open proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenProposal {
    pub transaction_index: u64,
    pub address: Address,
    pub status: ProposalStatus,
    pub approvals: usize,
    /// The kind of the proposal's transaction account. Read only for approved
    /// proposals at or below the stale index; `None` when it was not read (always for
    /// open proposals, and for a stale one whose account was missing or undecodable).
    pub transaction_kind: Option<TransactionKind>,
    /// For a stale approved vault transaction or batch: whether executing it now
    /// would certainly fail, or why it was kept (`execution`). `None` when not
    /// checked (open proposals, config transactions, transactions not read).
    pub check: Option<Check>,
}

impl OpenProposal {
    /// Whether Squads v4 would accept execution of this stale approved proposal:
    /// only when its transaction account was read and is a vault transaction or a
    /// batch. A transaction not read is not counted here; the scan lists it under
    /// `search::STALE_TRANSACTIONS` instead.
    pub fn executable_when_stale(&self) -> bool {
        self.status.is_executable()
            && self
                .transaction_kind
                .is_some_and(TransactionKind::executable_when_stale)
    }

    /// Executable when stale, and not shown to fail if executed now: the proposals
    /// `approved-proposal-still-executable` matches.
    pub fn still_executable(&self) -> bool {
        self.executable_when_stale() && !self.check.is_some_and(Check::would_fail)
    }
}

/// A proposal account the decoder could not read. It is listed, and the other
/// proposals are still read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndecodableProposal {
    pub transaction_index: u64,
    pub address: Address,
    pub error: String,
}

/// The decoded multisig behind a vault, and its open proposals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigFacts {
    pub address: Address,
    /// The slot this multisig account was read at (each program's accounts carry
    /// their own slot too).
    pub read_at_slot: u64,
    pub multisig: Multisig,
    pub open_proposals: Vec<OpenProposal>,
    /// Proposal indexes in the open range that were not read (the newest are read).
    pub proposals_not_read: u64,
    /// Approved or executing proposals at or below the stale transaction index, in
    /// the window read, each with the kind of its transaction account when read.
    /// Squads can still execute an approved vault transaction or batch there, never
    /// a config transaction.
    pub stale_approved: Vec<OpenProposal>,
    /// Indexes at or below the stale index older than the window: not read.
    pub stale_not_read: u64,
    pub undecodable_proposals: Vec<UndecodableProposal>,
}

/// A search the scan could not make, and why. The report lists each one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotPossible {
    pub search: &'static str,
    pub reason: String,
}

/// Names of the searches, as the report prints them.
pub mod search {
    pub const SQUADS_INDEX: &str = "squads-v4-index";
    pub const SIGNATURES: &str = "recent-signatures";
    pub const PROPOSALS: &str = "open-proposals";
    pub const STALE_PROPOSALS: &str = "stale-approved-proposals";
    /// The transaction account of a stale approved proposal could not be read or
    /// decoded, so whether Squads would still execute it is unknown.
    pub const STALE_TRANSACTIONS: &str = "stale-transaction-kinds";
    pub const SUPPLIED_MULTISIG: &str = "supplied-multisig";
    pub const NONCES: &str = "durable-nonces";
}

/// Everything one scan found about one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFacts {
    pub program: Address,
    pub read_at_slot: u64,
    /// `None` if the program account could not be read or is not a program.
    pub loader: Option<&'static str>,
    pub programdata: Option<Address>,
    pub last_deploy_slot: Option<u64>,
    pub v4_status: Option<V4Status>,
    pub authority: Option<Authority>,
    pub multisig: Option<MultisigFacts>,
    /// Durable nonce accounts whose authority is each signer key (the single-key
    /// authority, or each multisig member and config authority), when the search ran.
    /// Information only: anyone can make a nonce account with any authority, and a
    /// nonce made by someone else's key would not be found, so a count proves nothing.
    pub nonce_accounts: Option<Vec<(Address, usize)>>,
    pub not_possible: Vec<NotPossible>,
    /// Why the scan stopped early, if it did.
    pub error: Option<String>,
}

impl ProgramFacts {
    pub fn new(program: Address) -> Self {
        Self {
            program,
            read_at_slot: 0,
            loader: None,
            programdata: None,
            last_deploy_slot: None,
            v4_status: None,
            authority: None,
            multisig: None,
            nonce_accounts: None,
            not_possible: Vec::new(),
            error: None,
        }
    }

    /// True when the scan stopped, a search was not possible, a proposal could not
    /// be decoded, or open-range proposals were left unread.
    pub fn incomplete(&self) -> bool {
        self.error.is_some()
            || !self.not_possible.is_empty()
            || self
                .multisig
                .as_ref()
                .is_some_and(|m| m.proposals_not_read > 0 || !m.undecodable_proposals.is_empty())
    }
}
