//! Whether a stale approved vault transaction or batch would fail if executed now,
//! from the accounts its loader instructions name. Read-only: accounts are read
//! through [`Rpc`], never simulated. `docs/how-it-works.md`, "Would it still
//! execute?", gives the reasoning and the sources.
//!
//! "Would fail" is claimed only when it is certain from the accounts read: an
//! upgradeable loader instruction whose account is missing, owned by another program,
//! in the wrong state, or under another authority, and that no earlier instruction in
//! the same message names (an earlier instruction could create or change it). A
//! message with address lookup tables, an instruction to another program, or a read
//! that fails keeps the finding.

use std::collections::HashMap;

use crate::facts::OpenProposal;
use crate::loader::{self, LoaderState, UPGRADEABLE_LOADER, instruction};
use crate::read::{Account, Address, Rpc};
use crate::squads::{self, TransactionKind};
use crate::squads_tx::{self, VaultMessage};

/// Accounts read per `getMultipleAccounts` call for the instructions' accounts. A
/// buffer holds a whole program, so the batch is kept small enough that the answer
/// stays under the transport's response limit.
pub const ACCOUNT_CHUNK: usize = 4;

/// The outcome of the check, per stale approved vault transaction or batch. The
/// report prints [`Check::name`] as `check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    // Would fail: no finding.
    /// `Upgrade` whose buffer account does not exist.
    BufferMissing,
    /// `Upgrade` whose buffer account another program owns.
    BufferNotLoaderOwned,
    /// `Upgrade` whose buffer account is not in the Buffer state.
    BufferNotBufferState,
    /// `Upgrade` whose buffer has no authority, or not the instruction's authority.
    BufferWrongAuthority,
    /// `SetAuthority`, `SetAuthorityChecked` or `Close` whose account does not exist.
    AccountMissing,
    /// The same, owned by another program.
    AccountNotLoaderOwned,
    /// `SetAuthority`, `SetAuthorityChecked` (or `Close` of a buffer) where the account
    /// has no authority, or not the instruction's.
    AccountWrongAuthority,
    // Finding kept.
    /// No instruction to the upgradeable loader: the inner instructions are not
    /// checked.
    NoLoaderInstruction,
    /// Every loader instruction that could be checked looked executable, or none
    /// could be checked. Not a claim that it would succeed.
    NotShownToFail,
    /// The message loads keys from address lookup tables: not fully checked.
    NotCheckedAlt,
    /// The transaction, batch or batch transaction did not decode.
    NotCheckedUndecodable,
    /// A batch with no transaction left to execute, or whose next transaction account
    /// is missing or not Squads v4's.
    NotCheckedBatch,
    /// A read the check needed failed.
    NotCheckedReadFailed,
}

/// Names used in the report. Matched by readers of the JSON.
pub mod check_name {
    pub const BUFFER_MISSING: &str = "buffer-missing";
    pub const BUFFER_NOT_LOADER_OWNED: &str = "buffer-not-loader-owned";
    pub const BUFFER_NOT_BUFFER_STATE: &str = "buffer-not-buffer-state";
    pub const BUFFER_WRONG_AUTHORITY: &str = "buffer-wrong-authority";
    pub const ACCOUNT_MISSING: &str = "account-missing";
    pub const ACCOUNT_NOT_LOADER_OWNED: &str = "account-not-loader-owned";
    pub const ACCOUNT_WRONG_AUTHORITY: &str = "account-wrong-authority";
    pub const NO_LOADER_INSTRUCTION: &str = "no-loader-instruction";
    pub const NOT_SHOWN_TO_FAIL: &str = "not-shown-to-fail";
    pub const NOT_CHECKED_ALT: &str = "not-checked-alt";
    pub const NOT_CHECKED_UNDECODABLE: &str = "not-checked-undecodable";
    pub const NOT_CHECKED_BATCH: &str = "not-checked-batch";
    pub const NOT_CHECKED_READ_FAILED: &str = "not-checked-read-failed";
}

impl Check {
    pub const fn name(self) -> &'static str {
        use check_name as n;
        match self {
            Self::BufferMissing => n::BUFFER_MISSING,
            Self::BufferNotLoaderOwned => n::BUFFER_NOT_LOADER_OWNED,
            Self::BufferNotBufferState => n::BUFFER_NOT_BUFFER_STATE,
            Self::BufferWrongAuthority => n::BUFFER_WRONG_AUTHORITY,
            Self::AccountMissing => n::ACCOUNT_MISSING,
            Self::AccountNotLoaderOwned => n::ACCOUNT_NOT_LOADER_OWNED,
            Self::AccountWrongAuthority => n::ACCOUNT_WRONG_AUTHORITY,
            Self::NoLoaderInstruction => n::NO_LOADER_INSTRUCTION,
            Self::NotShownToFail => n::NOT_SHOWN_TO_FAIL,
            Self::NotCheckedAlt => n::NOT_CHECKED_ALT,
            Self::NotCheckedUndecodable => n::NOT_CHECKED_UNDECODABLE,
            Self::NotCheckedBatch => n::NOT_CHECKED_BATCH,
            Self::NotCheckedReadFailed => n::NOT_CHECKED_READ_FAILED,
        }
    }

    /// Executing it now would certainly fail, so it is not a finding.
    pub const fn would_fail(self) -> bool {
        matches!(
            self,
            Self::BufferMissing
                | Self::BufferNotLoaderOwned
                | Self::BufferNotBufferState
                | Self::BufferWrongAuthority
                | Self::AccountMissing
                | Self::AccountNotLoaderOwned
                | Self::AccountWrongAuthority
        )
    }

    /// Said in the finding's evidence beside the name, when there is more to say.
    pub const fn note(self) -> Option<&'static str> {
        match self {
            Self::NotCheckedAlt => {
                Some("not fully checked: the message uses address lookup tables")
            }
            Self::NotCheckedUndecodable => Some("not checked: the message did not decode"),
            Self::NotCheckedBatch => Some("not checked: the batch's next transaction"),
            Self::NotCheckedReadFailed => Some("not checked: an account read failed"),
            _ => None,
        }
    }
}

/// One loader instruction to check, and the account whose state decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// `Upgrade`: the buffer and the authority account (index 6).
    Upgrade { buffer: Address, authority: Address },
    /// `SetAuthority` or `SetAuthorityChecked`: the account and the current
    /// authority (index 1).
    SetAuthority {
        account: Address,
        authority: Address,
    },
    /// `Close`: the account, and the authority (index 2) if given.
    Close {
        account: Address,
        authority: Option<Address>,
    },
}

impl Probe {
    /// The account to read.
    pub const fn account(&self) -> Address {
        match self {
            Self::Upgrade { buffer, .. } => *buffer,
            Self::SetAuthority { account, .. } | Self::Close { account, .. } => *account,
        }
    }

    /// `Some` when the account read proves the instruction fails. `None` keeps it.
    pub fn fails(&self, account: Option<&Account>) -> Option<Check> {
        let upgrade = matches!(self, Self::Upgrade { .. });
        let Some(account) = account else {
            return Some(if upgrade {
                Check::BufferMissing
            } else {
                Check::AccountMissing
            });
        };
        if account.owner != UPGRADEABLE_LOADER {
            return Some(if upgrade {
                Check::BufferNotLoaderOwned
            } else {
                Check::AccountNotLoaderOwned
            });
        }
        // A state this decoder cannot read is not proof of anything.
        let state = loader::decode_state(&account.data).ok()?;
        match (self, state) {
            (Self::Upgrade { authority, .. }, LoaderState::Buffer { authority: held }) => {
                (held != Some(*authority)).then_some(Check::BufferWrongAuthority)
            }
            (Self::Upgrade { .. }, _) => Some(Check::BufferNotBufferState),
            (
                Self::SetAuthority { authority, .. },
                LoaderState::Buffer { authority: held }
                | LoaderState::ProgramData {
                    upgrade_authority: held,
                },
            ) => (held != Some(*authority)).then_some(Check::AccountWrongAuthority),
            (Self::SetAuthority { .. }, _) => Some(Check::AccountWrongAuthority),
            (
                Self::Close {
                    authority: Some(authority),
                    ..
                },
                LoaderState::Buffer { authority: held },
            ) => (held != Some(*authority)).then_some(Check::AccountWrongAuthority),
            // Closing an uninitialized account needs no authority; closing a program's
            // data depends on accounts not read here.
            (Self::Close { .. }, _) => None,
        }
    }
}

/// What a message needs: a decision now, or accounts to read first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Decided(Check),
    /// Loader instructions to check, in order. Empty: none could be checked.
    Read(Vec<Probe>),
}

/// The loader instructions of `message` that can be checked from one account each.
pub fn plan(message: &VaultMessage) -> Plan {
    if !message.address_table_lookups.is_empty() {
        return Plan::Decided(Check::NotCheckedAlt);
    }
    let keys = &message.account_keys;
    let key = |i: u8| keys.get(usize::from(i)).copied();
    let mut named: Vec<Address> = Vec::new();
    let mut probes = Vec::new();
    let mut any_loader = false;
    for ix in &message.instructions {
        let Some(program) = key(ix.program_id_index) else {
            return Plan::Decided(Check::NotCheckedUndecodable);
        };
        let Some(accounts) = ix
            .account_indexes
            .iter()
            .map(|&i| key(i))
            .collect::<Option<Vec<_>>>()
        else {
            return Plan::Decided(Check::NotCheckedUndecodable);
        };
        if program == UPGRADEABLE_LOADER {
            any_loader = true;
            let at = |i: usize| accounts.get(i).copied();
            let probe = match loader::instruction_tag(&ix.data) {
                Some(instruction::UPGRADE) => at(2)
                    .zip(at(6))
                    .map(|(buffer, authority)| Probe::Upgrade { buffer, authority }),
                Some(instruction::SET_AUTHORITY | instruction::SET_AUTHORITY_CHECKED) => at(0)
                    .zip(at(1))
                    .map(|(account, authority)| Probe::SetAuthority { account, authority }),
                Some(instruction::CLOSE) => at(0).map(|account| Probe::Close {
                    account,
                    authority: at(2),
                }),
                _ => None,
            };
            // An account an earlier instruction names may be created or changed
            // before this one runs.
            if let Some(probe) = probe.filter(|p| !named.contains(&p.account())) {
                probes.push(probe);
            }
        }
        named.push(program);
        named.extend(accounts);
    }
    if any_loader {
        Plan::Read(probes)
    } else {
        Plan::Decided(Check::NoLoaderInstruction)
    }
}

/// The outcome of `probes` over the accounts read (`None` for an address whose read
/// failed): the first certain failure, else kept.
pub fn decide(probes: &[Probe], read: &HashMap<Address, Option<Account>>) -> Check {
    let mut unread = false;
    for probe in probes {
        match read.get(&probe.account()) {
            Some(account) => {
                if let Some(check) = probe.fails(account.as_ref()) {
                    return check;
                }
            }
            None => unread = true,
        }
    }
    if unread {
        Check::NotCheckedReadFailed
    } else {
        Check::NotShownToFail
    }
}

/// Reads `keys` in chunks of `chunk`. A chunk whose read fails is left out, so its
/// addresses are absent from the map.
fn read_accounts<R: Rpc + ?Sized>(
    rpc: &R,
    keys: &[Address],
    chunk: usize,
) -> HashMap<Address, Option<Account>> {
    let mut out = HashMap::new();
    for part in keys.chunks(chunk.max(1)) {
        if let Ok(read) = rpc.get_multiple_accounts(part)
            && read.value.len() == part.len()
        {
            out.extend(part.iter().copied().zip(read.value));
        }
    }
    out
}

/// Where each proposal stands while it is checked.
enum Pending {
    Done(Check),
    Message(VaultMessage),
    BatchNext(Address),
}

/// Sets `check` on each stale approved vault transaction or batch in `stale`, from
/// its transaction account's data (`data`, by position in `stale`). Reads the next
/// transaction of each batch, then every account the loader instructions name.
pub fn check_stale<R: Rpc + ?Sized>(
    rpc: &R,
    multisig: &Address,
    stale: &mut [OpenProposal],
    data: &HashMap<usize, Vec<u8>>,
) {
    let mut pending: Vec<(usize, Pending)> = Vec::new();
    for (i, proposal) in stale.iter().enumerate() {
        let Some(bytes) = data.get(&i) else { continue };
        let state = match proposal.transaction_kind {
            Some(TransactionKind::Vault) => match squads_tx::decode_vault_transaction(bytes) {
                Ok(t) => Pending::Message(t.message),
                Err(_) => Pending::Done(Check::NotCheckedUndecodable),
            },
            Some(TransactionKind::Batch) => match squads_tx::decode_batch(bytes) {
                Ok(batch) => match batch
                    .next_transaction()
                    .map(|next| squads_tx::batch_transaction_address(multisig, batch.index, next))
                {
                    Some(Ok(at)) => Pending::BatchNext(at),
                    Some(Err(_)) | None => Pending::Done(Check::NotCheckedBatch),
                },
                Err(_) => Pending::Done(Check::NotCheckedUndecodable),
            },
            _ => continue,
        };
        pending.push((i, state));
    }

    let batch_keys: Vec<Address> = pending
        .iter()
        .filter_map(|(_, p)| match p {
            Pending::BatchNext(at) => Some(*at),
            _ => None,
        })
        .collect();
    if !batch_keys.is_empty() {
        let read = read_accounts(rpc, &batch_keys, crate::scan::MULTIPLE_ACCOUNTS_CHUNK);
        for (_, p) in &mut pending {
            if let Pending::BatchNext(at) = p {
                *p = match read.get(at) {
                    None => Pending::Done(Check::NotCheckedReadFailed),
                    Some(Some(a)) if a.owner == squads::PROGRAM_ID => {
                        match squads_tx::decode_batch_transaction(&a.data) {
                            Ok(message) => Pending::Message(message),
                            Err(_) => Pending::Done(Check::NotCheckedUndecodable),
                        }
                    }
                    Some(_) => Pending::Done(Check::NotCheckedBatch),
                };
            }
        }
    }

    let mut plans: Vec<(usize, Plan)> = Vec::new();
    for (i, p) in pending {
        plans.push((
            i,
            match p {
                Pending::Done(check) => Plan::Decided(check),
                Pending::Message(message) => plan(&message),
                Pending::BatchNext(_) => Plan::Decided(Check::NotCheckedReadFailed),
            },
        ));
    }
    let mut keys: Vec<Address> = Vec::new();
    for (_, p) in &plans {
        if let Plan::Read(probes) = p {
            for probe in probes {
                if !keys.contains(&probe.account()) {
                    keys.push(probe.account());
                }
            }
        }
    }
    let read = if keys.is_empty() {
        HashMap::new()
    } else {
        read_accounts(rpc, &keys, ACCOUNT_CHUNK)
    };
    for (i, p) in plans {
        let check = match p {
            Plan::Decided(check) => check,
            Plan::Read(probes) => decide(&probes, &read),
        };
        if let Some(proposal) = stale.get_mut(i) {
            proposal.check = Some(check);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::squads_tx::{AddressTableLookup, CompiledInstruction};

    fn key(b: u8) -> Address {
        Address::new([b; 32])
    }

    fn ix(program: u8, accounts: &[u8], tag: u32) -> CompiledInstruction {
        CompiledInstruction {
            program_id_index: program,
            account_indexes: accounts.to_vec(),
            data: tag.to_le_bytes().to_vec(),
        }
    }

    /// Keys: vault, ProgramData, program, buffer, rent, clock, loader, other.
    fn message(instructions: Vec<CompiledInstruction>) -> VaultMessage {
        VaultMessage {
            num_signers: 1,
            num_writable_signers: 1,
            num_writable_non_signers: 3,
            account_keys: vec![
                key(1),
                key(2),
                key(3),
                key(4),
                key(5),
                key(6),
                UPGRADEABLE_LOADER,
                key(8),
            ],
            instructions,
            address_table_lookups: vec![],
        }
    }

    fn upgrade() -> CompiledInstruction {
        ix(6, &[1, 2, 3, 0, 4, 5, 0], instruction::UPGRADE)
    }

    fn state(owner: Address, data: Vec<u8>) -> Option<Account> {
        Some(Account {
            lamports: 1,
            owner,
            data,
            executable: false,
        })
    }

    fn buffer(authority: Option<Address>) -> Vec<u8> {
        let mut d = 1u32.to_le_bytes().to_vec();
        match authority {
            None => d.push(0),
            Some(a) => {
                d.push(1);
                d.extend(a.as_bytes());
            }
        }
        d
    }

    #[test]
    fn an_upgrade_probes_its_buffer_against_its_authority() {
        let probe = Probe::Upgrade {
            buffer: key(4),
            authority: key(1),
        };
        assert_eq!(plan(&message(vec![upgrade()])), Plan::Read(vec![probe]));
        let check = |account: Option<Account>| probe.fails(account.as_ref());
        assert_eq!(check(None), Some(Check::BufferMissing));
        assert_eq!(
            check(state(key(9), buffer(Some(key(1))))),
            Some(Check::BufferNotLoaderOwned)
        );
        assert_eq!(
            check(state(UPGRADEABLE_LOADER, vec![0; 4])),
            Some(Check::BufferNotBufferState)
        );
        assert_eq!(
            check(state(UPGRADEABLE_LOADER, buffer(Some(key(9))))),
            Some(Check::BufferWrongAuthority)
        );
        assert_eq!(
            check(state(UPGRADEABLE_LOADER, buffer(None))),
            Some(Check::BufferWrongAuthority)
        );
        assert_eq!(check(state(UPGRADEABLE_LOADER, buffer(Some(key(1))))), None);
        assert_eq!(
            check(state(UPGRADEABLE_LOADER, vec![9; 4])),
            None,
            "undecodable"
        );
    }

    #[test]
    fn plans_that_decide_without_reading() {
        let mut m = message(vec![upgrade()]);
        m.address_table_lookups.push(AddressTableLookup {
            account_key: key(9),
            writable_indexes: vec![0],
            readonly_indexes: vec![],
        });
        assert_eq!(plan(&m), Plan::Decided(Check::NotCheckedAlt));
        assert_eq!(
            plan(&message(vec![ix(7, &[0], 2)])),
            Plan::Decided(Check::NoLoaderInstruction)
        );
        assert_eq!(
            plan(&message(vec![ix(6, &[1, 2, 30], instruction::UPGRADE)])),
            Plan::Decided(Check::NotCheckedUndecodable)
        );
        // A loader instruction this check does not read, or too few accounts.
        assert_eq!(plan(&message(vec![ix(6, &[1], 6)])), Plan::Read(vec![]));
        assert_eq!(
            plan(&message(vec![ix(6, &[1, 2, 3], instruction::UPGRADE)])),
            Plan::Read(vec![])
        );
        assert_eq!(decide(&[], &HashMap::new()), Check::NotShownToFail);
    }

    #[test]
    fn an_account_an_earlier_instruction_names_is_not_probed() {
        let m = message(vec![ix(7, &[3], 0), upgrade()]);
        assert_eq!(plan(&m), Plan::Read(vec![]));
        let m = message(vec![upgrade(), ix(7, &[3], 0)]);
        assert_eq!(plan(&m).clone(), plan(&message(vec![upgrade()])));
    }

    #[test]
    fn set_authority_and_close() {
        let set = Probe::SetAuthority {
            account: key(4),
            authority: key(1),
        };
        assert_eq!(
            plan(&message(vec![ix(
                6,
                &[3, 0, 7],
                instruction::SET_AUTHORITY_CHECKED
            )])),
            Plan::Read(vec![set])
        );
        assert_eq!(set.fails(None), Some(Check::AccountMissing));
        let mut programdata = 3u32.to_le_bytes().to_vec();
        programdata.extend([0; 8]);
        programdata.push(1);
        programdata.extend(key(1).as_bytes());
        let pd = state(UPGRADEABLE_LOADER, programdata);
        assert_eq!(set.fails(pd.as_ref()), None);
        let other = state(UPGRADEABLE_LOADER, buffer(Some(key(9))));
        assert_eq!(
            set.fails(other.as_ref()),
            Some(Check::AccountWrongAuthority)
        );
        let mut program_state = 2u32.to_le_bytes().to_vec();
        program_state.extend([0; 32]);
        let program = state(UPGRADEABLE_LOADER, program_state);
        assert_eq!(
            set.fails(program.as_ref()),
            Some(Check::AccountWrongAuthority)
        );

        let close = Probe::Close {
            account: key(4),
            authority: Some(key(1)),
        };
        assert_eq!(
            plan(&message(vec![ix(6, &[3, 0, 0], instruction::CLOSE)])),
            Plan::Read(vec![close])
        );
        assert_eq!(close.fails(None), Some(Check::AccountMissing));
        let foreign = state(key(9), buffer(Some(key(1))));
        assert_eq!(
            close.fails(foreign.as_ref()),
            Some(Check::AccountNotLoaderOwned)
        );
        assert_eq!(
            close.fails(other.as_ref()),
            Some(Check::AccountWrongAuthority)
        );
        let uninitialized = state(UPGRADEABLE_LOADER, vec![0; 4]);
        assert_eq!(close.fails(uninitialized.as_ref()), None);
        assert_eq!(close.fails(pd.as_ref()), None);
    }

    #[test]
    fn decide_takes_the_first_failure_and_names_a_failed_read() {
        let a = Probe::Upgrade {
            buffer: key(4),
            authority: key(1),
        };
        let b = Probe::Close {
            account: key(5),
            authority: None,
        };
        let mut read = HashMap::new();
        read.insert(key(5), None);
        assert_eq!(decide(&[a, b], &read), Check::AccountMissing);
        assert_eq!(decide(&[a], &read), Check::NotCheckedReadFailed);
        read.insert(key(4), state(UPGRADEABLE_LOADER, buffer(Some(key(1)))));
        assert_eq!(decide(&[a], &read), Check::NotShownToFail);
    }

    #[test]
    fn names_are_distinct_and_only_failures_drop_the_finding() {
        use Check as C;
        let all = [
            C::BufferMissing,
            C::BufferNotLoaderOwned,
            C::BufferNotBufferState,
            C::BufferWrongAuthority,
            C::AccountMissing,
            C::AccountNotLoaderOwned,
            C::AccountWrongAuthority,
            C::NoLoaderInstruction,
            C::NotShownToFail,
            C::NotCheckedAlt,
            C::NotCheckedUndecodable,
            C::NotCheckedBatch,
            C::NotCheckedReadFailed,
        ];
        for a in all {
            for b in all {
                assert_eq!(a.name() == b.name(), a == b);
            }
            assert_eq!(
                a.would_fail(),
                !a.name().starts_with("not-") && a != C::NoLoaderInstruction
            );
        }
    }
}
