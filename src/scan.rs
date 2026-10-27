//! One program's scan, over any [`Rpc`]. This module does no I/O of its own: every
//! read goes through the `Rpc` the caller passes (`HttpRpc` in the binary, a fake of
//! saved accounts in tests), and every read is a typed, read-only call.
//!
//! Order: the program account; by its loader, the ProgramData account; the authority
//! classified on or off the curve; a PDA checked against the multisigs the caller
//! supplied, or else looked up in the Squads v4 vault index, then searched for in its
//! own recent transactions; the multisig decoded; its open proposals, and a window of
//! proposals at or below the stale index, read with `getMultipleAccounts` in chunks
//! of at most 100; for each stale approved vault transaction or batch, whether
//! executing it now would fail (`execution`), from one more read of the accounts its
//! loader instructions name (and, for a batch, its next transaction).

use std::collections::HashMap;

use crate::read::{Address, DataSlice, Filter, ProgramAccountsQuery, Rpc, SignaturesQuery};

use crate::facts::{
    Authority, FoundBy, MultisigFacts, NotPossible, OpenProposal, ProgramFacts,
    UndecodableProposal, search,
};
use crate::index::VaultIndex;
use crate::loader::{self, ProgramKind};
use crate::squads::{self, ProposalStatus};
use crate::txn;

/// The most addresses one `getMultipleAccounts` call takes.
pub const MULTIPLE_ACCOUNTS_CHUNK: usize = crate::read::rpc::MAX_MULTIPLE_ACCOUNTS;

/// The System program, which owns durable nonce accounts.
pub const SYSTEM_PROGRAM: Address = Address::new([0; 32]);
/// A nonce account's size, and the offset of its authority (after the version and
/// state tags, u32 each).
pub const NONCE_ACCOUNT_LEN: u64 = 80;
pub const NONCE_AUTHORITY_OFFSET: u64 = 8;

/// The query for nonce accounts whose authority is `key`. No data back.
pub fn nonce_query(key: &Address) -> ProgramAccountsQuery {
    ProgramAccountsQuery {
        filters: vec![
            Filter::DataSize(NONCE_ACCOUNT_LEN),
            Filter::Memcmp {
                offset: NONCE_AUTHORITY_OFFSET,
                bytes: key.as_bytes().to_vec(),
            },
        ],
        data_slice: Some(DataSlice {
            offset: 0,
            length: 0,
        }),
    }
}

/// The keys that sign for the program: a single-key authority, or the multisig's
/// members and its config authority if it is a key.
fn signer_keys(facts: &ProgramFacts) -> Vec<Address> {
    let mut keys = Vec::new();
    if let Some(Authority::SingleKey(key)) = &facts.authority {
        keys.push(*key);
    }
    if let Some(m) = &facts.multisig {
        keys.extend(m.multisig.members.iter().map(|member| member.key));
        if let Some(c) = m.multisig.config_authority
            && crate::read::is_on_curve(c.as_bytes())
            && !keys.contains(&c)
        {
            keys.push(c);
        }
    }
    keys
}

/// Limits on how far a scan reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    /// Vault indexes 0 to this are derived for each multisig.
    pub max_vault_index: u8,
    /// Signatures read for the fallback search (1 to 1000).
    pub signature_limit: u16,
    /// Transactions fetched for the fallback search, newest first.
    pub max_transactions: usize,
    /// Open-range proposals read, newest first.
    pub max_proposals: u64,
    /// Proposals at or below the stale transaction index read, newest first.
    pub stale_window: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_vault_index: 3,
            signature_limit: 100,
            max_transactions: 25,
            max_proposals: 500,
            stale_window: 50,
        }
    }
}

/// The index, or why there is none.
pub enum IndexState<'a> {
    Ready(&'a VaultIndex),
    Unavailable(String),
}

/// Scans programs on one cluster.
pub struct Scanner<'a, R: Rpc + ?Sized> {
    pub rpc: &'a R,
    pub index: IndexState<'a>,
    /// Multisigs the caller named (`--multisig`). When any is given, a PDA authority
    /// is checked against their vaults only, and no search is made.
    pub supplied_multisigs: &'a [Address],
    pub options: ScanOptions,
}

impl<R: Rpc + ?Sized> Scanner<'_, R> {
    /// Everything this scan can find about `program`. A failed read stops the scan
    /// and is recorded in `error`; it never panics.
    pub fn scan(&self, program: &Address) -> ProgramFacts {
        let mut facts = ProgramFacts::new(*program);
        if let Err(e) = self.scan_into(&mut facts) {
            facts.error = Some(e);
        }
        let keys = signer_keys(&facts);
        if !keys.is_empty() {
            match self.search_nonces(&keys) {
                Ok(counts) => facts.nonce_accounts = Some(counts),
                Err(reason) => facts.not_possible.push(NotPossible {
                    search: search::NONCES,
                    reason,
                }),
            }
        }
        facts
    }

    /// Counts System-program nonce accounts (80 bytes) whose authority, at offset 8,
    /// is each key.
    fn search_nonces(&self, keys: &[Address]) -> Result<Vec<(Address, usize)>, String> {
        keys.iter()
            .map(|key| {
                self.rpc
                    .get_program_accounts(&SYSTEM_PROGRAM, &nonce_query(key))
                    .map(|read| (*key, read.value.len()))
                    .map_err(|e| format!("the nonce search was refused or failed: {e}"))
            })
            .collect()
    }

    fn scan_into(&self, facts: &mut ProgramFacts) -> Result<(), String> {
        let read = self
            .rpc
            .get_account_info(&facts.program)
            .map_err(|e| format!("reading the program account: {e}"))?;
        facts.read_at_slot = read.slot;
        let account = read
            .value
            .ok_or_else(|| format!("no account at {}", facts.program))?;
        let kind = loader::classify_program(&account).map_err(|e| e.to_string())?;
        facts.loader = Some(kind.loader_name());
        let authority = match kind {
            ProgramKind::Builtin => {
                facts.authority = Some(Authority::Builtin);
                return Ok(());
            }
            ProgramKind::Legacy { .. } => {
                facts.authority = Some(Authority::None);
                return Ok(());
            }
            ProgramKind::LoaderV4 {
                last_deploy_slot,
                authority,
                status,
            } => {
                facts.last_deploy_slot = Some(last_deploy_slot);
                facts.v4_status = Some(status);
                authority
            }
            ProgramKind::Upgradeable { programdata } => {
                facts.programdata = Some(programdata);
                let read = self
                    .rpc
                    .get_account_info(&programdata)
                    .map_err(|e| format!("reading the ProgramData account: {e}"))?;
                let account = read
                    .value
                    .ok_or_else(|| format!("no ProgramData account at {programdata}"))?;
                if account.owner != loader::UPGRADEABLE_LOADER {
                    return Err(format!(
                        "ProgramData account {programdata} is not owned by the upgradeable loader"
                    ));
                }
                let header =
                    loader::decode_program_data(&account.data).map_err(|e| e.to_string())?;
                facts.last_deploy_slot = Some(header.last_deploy_slot);
                header.upgrade_authority
            }
        };
        let Some(authority) = authority else {
            facts.authority = Some(Authority::None);
            return Ok(());
        };
        if crate::read::is_on_curve(authority.as_bytes()) {
            facts.authority = Some(Authority::SingleKey(authority));
            return Ok(());
        }
        let Some((multisig, index, found_by)) = self.resolve_vault(&authority, facts) else {
            facts.authority = Some(Authority::UnknownPda(authority));
            return Ok(());
        };
        facts.authority = Some(Authority::SquadsVault {
            vault: authority,
            multisig,
            index,
            found_by,
        });
        facts.multisig = Some(self.read_multisig(&multisig, facts)?);
        Ok(())
    }

    /// Ties a PDA to a Squads v4 multisig: the index first, then the vault's own
    /// recent transactions. Each search that cannot run is recorded.
    fn resolve_vault(
        &self,
        authority: &Address,
        facts: &mut ProgramFacts,
    ) -> Option<(Address, u8, FoundBy)> {
        if !self.supplied_multisigs.is_empty() {
            let max = self.options.max_vault_index;
            if let Some((multisig, i)) =
                squads::find_vault_owner(self.supplied_multisigs, authority, max)
            {
                return Some((multisig, i, FoundBy::Supplied));
            }
            let named: Vec<String> = self
                .supplied_multisigs
                .iter()
                .map(ToString::to_string)
                .collect();
            facts.not_possible.push(NotPossible {
                search: search::SUPPLIED_MULTISIG,
                reason: format!(
                    "upgrade authority {authority} is not vault 0 to {max} of the supplied \
                     multisig {}; no other search was made (a higher vault index needs \
                     --max-vault-index)",
                    named.join(", ")
                ),
            });
            return None;
        }
        match &self.index {
            IndexState::Ready(index) => {
                if let Some((multisig, i)) = index.lookup(authority) {
                    return Some((multisig, i, FoundBy::Index));
                }
            }
            IndexState::Unavailable(reason) => facts.not_possible.push(NotPossible {
                search: search::SQUADS_INDEX,
                reason: reason.clone(),
            }),
        }
        match self.search_signatures(authority) {
            Ok(Some((multisig, i))) => Some((multisig, i, FoundBy::Signatures)),
            Ok(None) => None,
            Err(reason) => {
                facts.not_possible.push(NotPossible {
                    search: search::SIGNATURES,
                    reason,
                });
                None
            }
        }
    }

    /// Looks for an instruction to Squads v4 in `authority`'s recent transactions
    /// with an account whose vault (index 0 to the maximum) is `authority`.
    fn search_signatures(&self, authority: &Address) -> Result<Option<(Address, u8)>, String> {
        let query = SignaturesQuery {
            limit: Some(self.options.signature_limit),
            before: None,
            until: None,
        };
        let signatures = self
            .rpc
            .get_signatures_for_address(authority, &query)
            .map_err(|e| format!("reading the authority's signatures: {e}"))?;
        let mut tried: Vec<Address> = Vec::new();
        for info in signatures
            .iter()
            .filter(|s| !s.failed)
            .take(self.options.max_transactions)
        {
            let Some(record) = self
                .rpc
                .get_transaction(&info.signature)
                .map_err(|e| format!("reading transaction {}: {e}", info.signature))?
            else {
                continue;
            };
            let loaded = record
                .meta
                .as_ref()
                .map(|m| m.loaded_addresses.clone())
                .unwrap_or_default();
            // A transaction this decoder cannot read is skipped, not fatal.
            let Ok(instructions) =
                txn::instruction_accounts(&record.transaction, &loaded, &squads::PROGRAM_ID)
            else {
                continue;
            };
            let candidates: Vec<Address> = instructions
                .into_iter()
                .flatten()
                .filter(|a| !tried.contains(a))
                .collect();
            if let Some(found) =
                squads::find_vault_owner(&candidates, authority, self.options.max_vault_index)
            {
                return Ok(Some(found));
            }
            tried.extend(candidates);
        }
        Ok(None)
    }

    fn read_multisig(
        &self,
        address: &Address,
        facts: &mut ProgramFacts,
    ) -> Result<MultisigFacts, String> {
        let read = self
            .rpc
            .get_account_info(address)
            .map_err(|e| format!("reading multisig {address}: {e}"))?;
        let account = read
            .value
            .ok_or_else(|| format!("no multisig account at {address}"))?;
        if account.owner != squads::PROGRAM_ID {
            return Err(format!("{address} is not owned by Squads v4"));
        }
        let multisig = squads::decode_multisig(&account.data).map_err(|e| e.to_string())?;
        let mut undecodable = Vec::new();
        let (indexes, proposals_not_read) =
            squads::open_proposal_indexes(&multisig, self.options.max_proposals);
        let open_proposals = self
            .read_proposals(
                address,
                &indexes,
                ProposalStatus::is_pending,
                &mut undecodable,
            )
            .unwrap_or_else(|reason| {
                facts.not_possible.push(NotPossible {
                    search: search::PROPOSALS,
                    reason,
                });
                Vec::new()
            });
        let (indexes, stale_not_read) =
            squads::stale_proposal_indexes(&multisig, self.options.stale_window);
        let mut stale_approved = self
            .read_proposals(
                address,
                &indexes,
                ProposalStatus::is_executable,
                &mut undecodable,
            )
            .unwrap_or_else(|reason| {
                facts.not_possible.push(NotPossible {
                    search: search::STALE_PROPOSALS,
                    reason,
                });
                Vec::new()
            });
        let (not_read, data) = self.read_transaction_kinds(address, &mut stale_approved);
        crate::execution::check_stale(self.rpc, address, &mut stale_approved, &data);
        if !not_read.is_empty() {
            facts.not_possible.push(NotPossible {
                search: search::STALE_TRANSACTIONS,
                reason: format!(
                    "the transaction account of each stale approved proposal must be read \
                     to tell a vault transaction or batch (still executable) from a config \
                     transaction (not executable); not read: {}",
                    not_read.join("; ")
                ),
            });
        }
        Ok(MultisigFacts {
            address: *address,
            read_at_slot: read.slot,
            multisig,
            open_proposals,
            proposals_not_read,
            stale_approved,
            stale_not_read,
            undecodable_proposals: undecodable,
        })
    }

    /// Reads the transaction account of each stale approved proposal and records its
    /// kind (`docs/how-it-works.md`, "Proposals": Squads v4 executes a stale approved
    /// vault transaction or batch, never a stale config transaction). An account that
    /// is missing, not owned by Squads v4, undecodable, or for another multisig or
    /// index keeps `None`, and is returned as `#<index>: <why>`: the caller reports
    /// it as not read, never as a finding and never as fine. The data of each vault
    /// transaction and batch read is returned by its position in `stale`, for
    /// `execution::check_stale`.
    fn read_transaction_kinds(
        &self,
        multisig: &Address,
        stale: &mut [OpenProposal],
    ) -> (Vec<String>, HashMap<usize, Vec<u8>>) {
        let mut not_read = Vec::new();
        let mut data = HashMap::new();
        for (n, chunk) in stale.chunks_mut(MULTIPLE_ACCOUNTS_CHUNK).enumerate() {
            let first = n.saturating_mul(MULTIPLE_ACCOUNTS_CHUNK);
            let keys =
                match chunk
                    .iter()
                    .map(|p| squads::transaction_address(multisig, p.transaction_index))
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(keys) => keys,
                    Err(e) => {
                        not_read.extend(chunk.iter().map(|p| {
                            format!("#{}: deriving its address: {e}", p.transaction_index)
                        }));
                        continue;
                    }
                };
            let accounts = match self.rpc.get_multiple_accounts(&keys) {
                Ok(read) if read.value.len() == chunk.len() => read.value,
                Ok(_) => {
                    not_read.extend(chunk.iter().map(|p| {
                        format!(
                            "#{}: the RPC answered a different number of accounts",
                            p.transaction_index
                        )
                    }));
                    continue;
                }
                Err(e) => {
                    not_read.extend(
                        chunk
                            .iter()
                            .map(|p| format!("#{}: reading it: {e}", p.transaction_index)),
                    );
                    continue;
                }
            };
            for (i, ((proposal, key), account)) in
                chunk.iter_mut().zip(&keys).zip(accounts).enumerate()
            {
                let index = proposal.transaction_index;
                let kind = match account {
                    None => Err(format!("no account at {key}")),
                    Some(a) if a.owner != squads::PROGRAM_ID => {
                        Err(format!("{key} is not owned by Squads v4"))
                    }
                    Some(a) => match squads::decode_transaction_header(&a.data) {
                        Err(e) => Err(e.to_string()),
                        Ok(h) if h.multisig != *multisig || h.index != index => Err(format!(
                            "{key} is for another multisig or transaction index"
                        )),
                        Ok(h) => Ok((h.kind, a.data)),
                    },
                };
                match kind {
                    Ok((kind, bytes)) => {
                        proposal.transaction_kind = Some(kind);
                        if kind.executable_when_stale() {
                            data.insert(first.saturating_add(i), bytes);
                        }
                    }
                    Err(why) => not_read.push(format!("#{index}: {why}")),
                }
            }
        }
        (not_read, data)
    }

    /// Reads the proposals at `indexes` and keeps those of `multisig` whose status
    /// passes `keep`. A missing account, one Squads v4 does not own, or one for
    /// another multisig or index is skipped. One that does not decode is added to
    /// `undecodable` and the rest are still read.
    fn read_proposals(
        &self,
        multisig: &Address,
        indexes: &[u64],
        keep: fn(ProposalStatus) -> bool,
        undecodable: &mut Vec<UndecodableProposal>,
    ) -> Result<Vec<OpenProposal>, String> {
        let addresses = indexes
            .iter()
            .map(|&i| squads::proposal_address(multisig, i).map(|a| (i, a)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("deriving a proposal address: {e}"))?;
        let mut open = Vec::new();
        for chunk in addresses.chunks(MULTIPLE_ACCOUNTS_CHUNK) {
            let keys: Vec<Address> = chunk.iter().map(|(_, a)| *a).collect();
            let read = self
                .rpc
                .get_multiple_accounts(&keys)
                .map_err(|e| format!("reading proposals: {e}"))?;
            for ((index, address), account) in chunk.iter().zip(read.value) {
                // No account: the proposal was never made, or was closed.
                let Some(account) = account else { continue };
                if account.owner != squads::PROGRAM_ID {
                    continue;
                }
                let proposal = match squads::decode_proposal(&account.data) {
                    Ok(p) => p,
                    Err(e) => {
                        undecodable.push(UndecodableProposal {
                            transaction_index: *index,
                            address: *address,
                            error: e.to_string(),
                        });
                        continue;
                    }
                };
                if proposal.multisig == *multisig
                    && proposal.transaction_index == *index
                    && keep(proposal.status)
                {
                    open.push(OpenProposal {
                        transaction_index: *index,
                        address: *address,
                        status: proposal.status,
                        approvals: proposal.approved.len(),
                        transaction_kind: None,
                        check: None,
                    });
                }
            }
        }
        Ok(open)
    }
}
