//! Squads v4 (`SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`): the Multisig and
//! Proposal account layouts and the PDAs this scanner derives. Pure; no I/O.
//!
//! Layouts are pinned to the account types in `@sqds/multisig` 2.1.4, which Squads
//! generates from the program's IDL (`docs/how-it-works.md`). Anchor accounts start
//! with an 8-byte discriminator, sha256("account:<Name>")[..8]; the fields follow in
//! Borsh. `rent_collector` is an `Option<Pubkey>`, one byte when none, so every
//! offset after it varies: fields are read in order, never at fixed offsets.

use crate::read::{Address, PdaError, find_program_address};

use crate::bytes::{DecodeError, Reader, Reason};

/// The Squads v4 program.
pub const PROGRAM_ID: Address = Address::new([
    6, 129, 196, 206, 71, 226, 35, 104, 184, 177, 85, 94, 200, 135, 175, 9, 46, 252, 126, 251, 182,
    108, 163, 245, 47, 191, 104, 212, 172, 156, 183, 168,
]);

/// sha256("account:Multisig")[..8].
pub const MULTISIG_DISCRIMINATOR: [u8; 8] = [0xe0, 0x74, 0x79, 0xba, 0x44, 0xa1, 0x4f, 0xec];
/// sha256("account:Proposal")[..8].
pub const PROPOSAL_DISCRIMINATOR: [u8; 8] = [0x1a, 0x5e, 0xbd, 0xbb, 0x74, 0x88, 0x35, 0x21];
/// sha256("account:VaultTransaction")[..8].
pub const VAULT_TRANSACTION_DISCRIMINATOR: [u8; 8] =
    [0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf];
/// sha256("account:ConfigTransaction")[..8].
pub const CONFIG_TRANSACTION_DISCRIMINATOR: [u8; 8] =
    [0x5e, 0x08, 0x04, 0x23, 0x71, 0x8b, 0x8b, 0x70];
/// sha256("account:Batch")[..8].
pub const BATCH_DISCRIMINATOR: [u8; 8] = [0x9c, 0xc2, 0x46, 0x2c, 0x16, 0x58, 0x89, 0x2c];

pub(crate) const SEED_PREFIX: &[u8] = b"multisig";
const SEED_VAULT: &[u8] = b"vault";
pub(crate) const SEED_TRANSACTION: &[u8] = b"transaction";
const SEED_PROPOSAL: &[u8] = b"proposal";

/// A member's permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions(pub u8);

impl Permissions {
    pub const INITIATE: u8 = 1;
    pub const VOTE: u8 = 2;
    pub const EXECUTE: u8 = 4;

    pub const fn can_vote(self) -> bool {
        self.0 & Self::VOTE != 0
    }

    /// The names of the bits that are set, in bit order. Unknown bits are left out;
    /// the raw mask is reported beside them.
    pub fn names(self) -> Vec<&'static str> {
        [
            (Self::INITIATE, "initiate"),
            (Self::VOTE, "vote"),
            (Self::EXECUTE, "execute"),
        ]
        .into_iter()
        .filter(|(bit, _)| self.0 & bit != 0)
        .map(|(_, name)| name)
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    pub key: Address,
    pub permissions: Permissions,
}

/// A Squads v4 Multisig account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multisig {
    pub create_key: Address,
    /// `None` when the field is the default (all-zero) key: the multisig is
    /// autonomous and changes its own settings only through proposals.
    pub config_authority: Option<Address>,
    pub threshold: u16,
    /// Seconds between a proposal's approval and its execution.
    pub time_lock: u32,
    pub transaction_index: u64,
    pub stale_transaction_index: u64,
    pub rent_collector: Option<Address>,
    pub bump: u8,
    pub members: Vec<Member>,
}

impl Multisig {
    /// Members holding the vote permission.
    pub fn voters(&self) -> usize {
        self.members
            .iter()
            .filter(|m| m.permissions.can_vote())
            .count()
    }
}

/// Bytes per member: key and permission mask.
const MEMBER_LEN: usize = 33;

pub(crate) fn check_discriminator(
    r: &mut Reader<'_>,
    expected: &[u8; 8],
    account: &'static str,
) -> Result<(), DecodeError> {
    let found = r.take(8, "discriminator")?;
    if found != expected {
        return Err(DecodeError {
            account,
            field: "discriminator",
            offset: 0,
            reason: Reason::WrongType,
        });
    }
    Ok(())
}

/// Decodes a Multisig account's data. Bytes after the members are ignored (the
/// account may be allocated larger than it needs).
pub fn decode_multisig(data: &[u8]) -> Result<Multisig, DecodeError> {
    let mut r = Reader::new(data, "Multisig");
    check_discriminator(&mut r, &MULTISIG_DISCRIMINATOR, "Multisig")?;
    let create_key = r.address("create_key")?;
    let config_authority = r.address("config_authority")?;
    let threshold = r.u16("threshold")?;
    let time_lock = r.u32("time_lock")?;
    let transaction_index = r.u64("transaction_index")?;
    let stale_transaction_index = r.u64("stale_transaction_index")?;
    let rent_collector = r.option_address("rent_collector")?;
    let bump = r.u8("bump")?;
    let count = r.vec_len(MEMBER_LEN, "members")?;
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let key = r.address("members.key")?;
        let permissions = Permissions(r.u8("members.permissions")?);
        members.push(Member { key, permissions });
    }
    Ok(Multisig {
        create_key,
        config_authority: (config_authority != Address::new([0; 32])).then_some(config_authority),
        threshold,
        time_lock,
        transaction_index,
        stale_transaction_index,
        rent_collector,
        bump,
        members,
    })
}

/// A proposal's status. The timestamp is unix seconds of the last change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    Draft(i64),
    Active(i64),
    Rejected(i64),
    Approved(i64),
    /// Deprecated in the program; kept so old accounts decode.
    Executing,
    Executed(i64),
    Cancelled(i64),
}

impl ProposalStatus {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Draft(_) => "draft",
            Self::Active(_) => "active",
            Self::Rejected(_) => "rejected",
            Self::Approved(_) => "approved",
            Self::Executing => "executing",
            Self::Executed(_) => "executed",
            Self::Cancelled(_) => "cancelled",
        }
    }

    /// Still open: it could yet be approved or executed.
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Draft(_) | Self::Active(_) | Self::Approved(_) | Self::Executing
        )
    }

    /// Approved (or executing): a member with the execute permission may run it.
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Approved(_) | Self::Executing)
    }
}

/// A Squads v4 Proposal account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub multisig: Address,
    pub transaction_index: u64,
    pub status: ProposalStatus,
    pub bump: u8,
    pub approved: Vec<Address>,
    pub rejected: Vec<Address>,
    pub cancelled: Vec<Address>,
}

/// Decodes a Proposal account's data.
pub fn decode_proposal(data: &[u8]) -> Result<Proposal, DecodeError> {
    let mut r = Reader::new(data, "Proposal");
    check_discriminator(&mut r, &PROPOSAL_DISCRIMINATOR, "Proposal")?;
    let multisig = r.address("multisig")?;
    let transaction_index = r.u64("transaction_index")?;
    let at = r.pos();
    let status = match r.u8("status")? {
        0 => ProposalStatus::Draft(r.i64("status.timestamp")?),
        1 => ProposalStatus::Active(r.i64("status.timestamp")?),
        2 => ProposalStatus::Rejected(r.i64("status.timestamp")?),
        3 => ProposalStatus::Approved(r.i64("status.timestamp")?),
        4 => ProposalStatus::Executing,
        5 => ProposalStatus::Executed(r.i64("status.timestamp")?),
        6 => ProposalStatus::Cancelled(r.i64("status.timestamp")?),
        tag => {
            return Err(DecodeError {
                account: "Proposal",
                field: "status",
                offset: at,
                reason: Reason::BadTag(u64::from(tag)),
            });
        }
    };
    let bump = r.u8("bump")?;
    let approved = r.addresses("approved")?;
    let rejected = r.addresses("rejected")?;
    let cancelled = r.addresses("cancelled")?;
    Ok(Proposal {
        multisig,
        transaction_index,
        status,
        bump,
        approved,
        rejected,
        cancelled,
    })
}

/// The kind of transaction account a proposal belongs to, from its discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionKind {
    Vault,
    Config,
    Batch,
}

/// Names used in the report. Matched by readers of the JSON.
pub mod transaction_kind {
    pub const VAULT: &str = "vault-transaction";
    pub const CONFIG: &str = "config-transaction";
    pub const BATCH: &str = "batch";
}

impl TransactionKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vault => transaction_kind::VAULT,
            Self::Config => transaction_kind::CONFIG,
            Self::Batch => transaction_kind::BATCH,
        }
    }

    /// Whether Squads v4 still accepts execution of an approved transaction of this
    /// kind once it is at or below the stale transaction index. In the Squads v4
    /// program source, `config_transaction_execute` refuses a stale proposal
    /// (`StaleProposal`); `vault_transaction_execute` and `batch_execute_transaction`
    /// have no staleness check. File and line references: `docs/how-it-works.md`,
    /// "Proposals".
    ///
    /// "Executable" means the Squads program would accept the execute instruction,
    /// not that the inner instructions would succeed.
    pub const fn executable_when_stale(self) -> bool {
        matches!(self, Self::Vault | Self::Batch)
    }
}

/// The header every Squads v4 transaction account starts with: the discriminator,
/// then `multisig`, `creator`, `index` (VaultTransaction, ConfigTransaction and
/// Batch all share it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionHeader {
    pub kind: TransactionKind,
    pub multisig: Address,
    pub index: u64,
}

/// Decodes the kind, multisig and index of a transaction account. Any discriminator
/// but the three transaction kinds is refused.
pub fn decode_transaction_header(data: &[u8]) -> Result<TransactionHeader, DecodeError> {
    let mut r = Reader::new(data, "Transaction");
    let found = r.take(8, "discriminator")?;
    let kind = if found == VAULT_TRANSACTION_DISCRIMINATOR {
        TransactionKind::Vault
    } else if found == CONFIG_TRANSACTION_DISCRIMINATOR {
        TransactionKind::Config
    } else if found == BATCH_DISCRIMINATOR {
        TransactionKind::Batch
    } else {
        return Err(DecodeError {
            account: "Transaction",
            field: "discriminator",
            offset: 0,
            reason: Reason::WrongType,
        });
    };
    let multisig = r.address("multisig")?;
    r.address("creator")?;
    let index = r.u64("index")?;
    Ok(TransactionHeader {
        kind,
        multisig,
        index,
    })
}

/// The transaction PDA for `index` (a vault transaction, config transaction or batch):
/// seeds `multisig`, the multisig address, `transaction`, the index as u64
/// little-endian.
pub fn transaction_address(multisig: &Address, index: u64) -> Result<Address, PdaError> {
    find_program_address(
        &[
            SEED_PREFIX,
            multisig.as_bytes(),
            SEED_TRANSACTION,
            &index.to_le_bytes(),
        ],
        &PROGRAM_ID,
    )
    .map(|(address, _)| address)
}

/// The vault PDA at `index`: seeds `multisig`, the multisig address, `vault`, index.
pub fn vault_address(multisig: &Address, index: u8) -> Result<Address, PdaError> {
    find_program_address(
        &[SEED_PREFIX, multisig.as_bytes(), SEED_VAULT, &[index]],
        &PROGRAM_ID,
    )
    .map(|(address, _)| address)
}

/// The proposal PDA for transaction `index`: seeds `multisig`, the multisig address,
/// `transaction`, the index as u64 little-endian, `proposal`.
pub fn proposal_address(multisig: &Address, index: u64) -> Result<Address, PdaError> {
    find_program_address(
        &[
            SEED_PREFIX,
            multisig.as_bytes(),
            SEED_TRANSACTION,
            &index.to_le_bytes(),
            SEED_PROPOSAL,
        ],
        &PROGRAM_ID,
    )
    .map(|(address, _)| address)
}

/// Transaction indexes whose proposals may still be open: from
/// `stale_transaction_index + 1` to `transaction_index`, the newest `cap` of them.
/// The second value is how many older indexes were left out.
pub fn open_proposal_indexes(multisig: &Multisig, cap: u64) -> (Vec<u64>, u64) {
    let first = multisig.stale_transaction_index.saturating_add(1);
    let last = multisig.transaction_index;
    if last < first {
        return (Vec::new(), 0);
    }
    let span = last.saturating_sub(first).saturating_add(1);
    let skipped = span.saturating_sub(cap);
    let start = first.saturating_add(skipped);
    ((start..=last).collect(), skipped)
}

/// Transaction indexes at or below `stale_transaction_index`, the newest `window` of
/// them (index 0 is never a transaction). Squads marks these stale, but an approved
/// vault transaction among them can still be executed. The second value is how many
/// older indexes were left out.
pub fn stale_proposal_indexes(multisig: &Multisig, window: u64) -> (Vec<u64>, u64) {
    let last = multisig.stale_transaction_index;
    if last == 0 {
        return (Vec::new(), 0);
    }
    let skipped = last.saturating_sub(window);
    let start = skipped.saturating_add(1);
    ((start..=last).collect(), skipped)
}

/// The first vault index from 0 to `max_index` whose PDA under any of `candidates`
/// is `authority`: the multisig and the index.
pub fn find_vault_owner(
    candidates: &[Address],
    authority: &Address,
    max_index: u8,
) -> Option<(Address, u8)> {
    candidates.iter().find_map(|multisig| {
        (0..=max_index).find_map(|index| {
            (vault_address(multisig, index).ok().as_ref() == Some(authority))
                .then_some((*multisig, index))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds Multisig data from the documented layout.
    pub(crate) fn multisig_bytes(m: &Multisig) -> Vec<u8> {
        let mut d = MULTISIG_DISCRIMINATOR.to_vec();
        d.extend(m.create_key.as_bytes());
        d.extend(
            m.config_authority
                .unwrap_or(Address::new([0; 32]))
                .as_bytes(),
        );
        d.extend(m.threshold.to_le_bytes());
        d.extend(m.time_lock.to_le_bytes());
        d.extend(m.transaction_index.to_le_bytes());
        d.extend(m.stale_transaction_index.to_le_bytes());
        match m.rent_collector {
            None => d.push(0),
            Some(a) => {
                d.push(1);
                d.extend(a.as_bytes());
            }
        }
        d.push(m.bump);
        d.extend(u32::try_from(m.members.len()).unwrap().to_le_bytes());
        for member in &m.members {
            d.extend(member.key.as_bytes());
            d.push(member.permissions.0);
        }
        d
    }

    fn sample(rent_collector: Option<Address>) -> Multisig {
        Multisig {
            create_key: Address::new([1; 32]),
            config_authority: None,
            threshold: 2,
            time_lock: 3600,
            transaction_index: 5,
            stale_transaction_index: 2,
            rent_collector,
            bump: 254,
            members: vec![
                Member {
                    key: Address::new([3; 32]),
                    permissions: Permissions(7),
                },
                Member {
                    key: Address::new([4; 32]),
                    permissions: Permissions(2),
                },
            ],
        }
    }

    #[test]
    fn discriminators_are_sha256_of_the_anchor_account_names() {
        use sha2::{Digest, Sha256};
        for (name, constant) in [
            ("Multisig", MULTISIG_DISCRIMINATOR),
            ("Proposal", PROPOSAL_DISCRIMINATOR),
            ("VaultTransaction", VAULT_TRANSACTION_DISCRIMINATOR),
            ("ConfigTransaction", CONFIG_TRANSACTION_DISCRIMINATOR),
            ("Batch", BATCH_DISCRIMINATOR),
        ] {
            let digest = Sha256::digest(format!("account:{name}").as_bytes());
            assert_eq!(digest.get(..8), Some(constant.as_slice()), "{name}");
        }
    }

    #[test]
    fn transaction_headers_decode_by_discriminator_and_others_are_refused() {
        let multisig = Address::new([9; 32]);
        for (disc, kind) in [
            (VAULT_TRANSACTION_DISCRIMINATOR, TransactionKind::Vault),
            (CONFIG_TRANSACTION_DISCRIMINATOR, TransactionKind::Config),
            (BATCH_DISCRIMINATOR, TransactionKind::Batch),
        ] {
            let mut d = disc.to_vec();
            d.extend(multisig.as_bytes());
            d.extend([5; 32]);
            d.extend(7u64.to_le_bytes());
            assert_eq!(
                decode_transaction_header(&d),
                Ok(TransactionHeader {
                    kind,
                    multisig,
                    index: 7
                })
            );
            let (_, short) = d.split_last().unwrap();
            assert!(decode_transaction_header(short).is_err(), "short");
        }
        let mut proposal = PROPOSAL_DISCRIMINATOR.to_vec();
        proposal.extend([0; 72]);
        assert_eq!(
            decode_transaction_header(&proposal).map_err(|e| e.reason),
            Err(Reason::WrongType)
        );
        assert!(!TransactionKind::Config.executable_when_stale());
        assert!(TransactionKind::Vault.executable_when_stale());
        assert!(TransactionKind::Batch.executable_when_stale());
    }

    #[test]
    fn transaction_pda_is_the_proposal_seeds_without_the_suffix() {
        let multisig = Address::new([9; 32]);
        let (expected, _) = find_program_address(
            &[
                b"multisig",
                multisig.as_bytes(),
                b"transaction",
                &5u64.to_le_bytes(),
            ],
            &PROGRAM_ID,
        )
        .unwrap();
        assert_eq!(transaction_address(&multisig, 5), Ok(expected));
        assert_ne!(
            transaction_address(&multisig, 5).ok(),
            proposal_address(&multisig, 5).ok()
        );
    }

    #[test]
    fn program_id_prints_as_squads_v4() {
        assert_eq!(
            PROGRAM_ID.to_string(),
            "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
        );
    }

    /// Constructed bytes, both shapes of the `rent_collector` option.
    #[test]
    fn decodes_both_rent_collector_shapes_sequentially() {
        for rc in [None, Some(Address::new([8; 32]))] {
            let m = sample(rc);
            let mut data = multisig_bytes(&m);
            assert_eq!(decode_multisig(&data), Ok(m.clone()));
            data.extend([0; 40]);
            assert_eq!(decode_multisig(&data), Ok(m.clone()), "trailing bytes");
        }
    }

    #[test]
    fn open_proposal_range_runs_from_stale_plus_one() {
        let mut m = sample(None);
        assert_eq!(open_proposal_indexes(&m, 100), (vec![3, 4, 5], 0));
        assert_eq!(open_proposal_indexes(&m, 2), (vec![4, 5], 1));
        m.stale_transaction_index = 5;
        assert_eq!(open_proposal_indexes(&m, 100), (vec![], 0));
        m.transaction_index = 0;
        m.stale_transaction_index = 0;
        assert_eq!(open_proposal_indexes(&m, 100), (vec![], 0));
    }

    #[test]
    fn stale_window_runs_down_from_the_stale_index() {
        let mut m = sample(None);
        assert_eq!(stale_proposal_indexes(&m, 50), (vec![1, 2], 0));
        assert_eq!(stale_proposal_indexes(&m, 1), (vec![2], 1));
        assert_eq!(stale_proposal_indexes(&m, 0), (vec![], 2));
        m.stale_transaction_index = 0;
        assert_eq!(stale_proposal_indexes(&m, 50), (vec![], 0));
        m.stale_transaction_index = 120;
        let (indexes, skipped) = stale_proposal_indexes(&m, 50);
        assert_eq!(
            (indexes.first(), indexes.last(), skipped),
            (Some(&71), Some(&120), 70)
        );
    }

    #[test]
    fn draft_and_executing_are_pending_and_only_approved_is_executable() {
        use ProposalStatus as S;
        let pending: Vec<bool> = [
            S::Draft(0),
            S::Active(0),
            S::Rejected(0),
            S::Approved(0),
            S::Executing,
            S::Executed(0),
            S::Cancelled(0),
        ]
        .map(|s| s.is_pending())
        .to_vec();
        assert_eq!(pending, [true, true, false, true, true, false, false]);
        assert!(S::Approved(0).is_executable() && S::Executing.is_executable());
        assert!(!S::Draft(0).is_executable() && !S::Active(0).is_executable());
    }

    #[test]
    fn a_vault_at_exactly_the_max_index_is_found_and_one_above_is_not() {
        let multisig = Address::new([9; 32]);
        let other = Address::new([10; 32]);
        let vault3 = vault_address(&multisig, 3).unwrap();
        assert_eq!(
            find_vault_owner(&[other, multisig], &vault3, 3),
            Some((multisig, 3))
        );
        assert_eq!(find_vault_owner(&[other, multisig], &vault3, 2), None);
        let vault255 = vault_address(&multisig, 255).unwrap();
        assert_eq!(
            find_vault_owner(&[multisig], &vault255, 255),
            Some((multisig, 255))
        );
    }

    #[test]
    fn permission_names() {
        assert_eq!(
            Permissions(7).names(),
            ["initiate", "vote", "execute"].to_vec()
        );
        assert_eq!(Permissions(0x0a).names(), ["vote"].to_vec());
        assert!(!Permissions(5).can_vote());
    }
}
