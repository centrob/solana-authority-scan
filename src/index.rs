//! The Squads v4 vault index: every Multisig account's vault PDAs, so an upgrade
//! authority that is a vault resolves to its multisig without a search per program.
//! Pure; no I/O. The binary reads the multisig list with `getProgramAccounts`
//! ([`multisig_list_query`]) and keeps the index in a local cache file, outside any
//! git work tree, with the slot it was read at.

use std::collections::HashMap;

use crate::read::{Address, DataSlice, Filter, KeyedAccount, ProgramAccountsQuery};
use serde_json::{Value, json};

use crate::squads::{self, MULTISIG_DISCRIMINATOR};

/// The cache file's schema name and version. A file with another is rebuilt.
pub const CACHE_SCHEMA: &str = "solana-authority-scan/squads-v4-index";
pub const CACHE_VERSION: u64 = 1;

/// The `getProgramAccounts` query that lists every Multisig account: the
/// discriminator at offset 0, and no data back (`dataSlice` length 0).
pub fn multisig_list_query() -> ProgramAccountsQuery {
    ProgramAccountsQuery {
        filters: vec![Filter::Memcmp {
            offset: 0,
            bytes: MULTISIG_DISCRIMINATOR.to_vec(),
        }],
        data_slice: Some(DataSlice {
            offset: 0,
            length: 0,
        }),
    }
}

/// Vault address to (multisig, vault index), for vault indexes 0 to `max_vault_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultIndex {
    /// The slot the multisig list was read at. A multisig made later is not in it.
    pub slot: u64,
    pub max_vault_index: u8,
    multisigs: Vec<Address>,
    vaults: HashMap<Address, (Address, u8)>,
}

impl VaultIndex {
    /// Derives the vaults of every multisig. Accounts not owned by Squads v4 are
    /// skipped (the query asks only for those).
    pub fn build(slot: u64, multisigs: &[Address], max_vault_index: u8) -> Self {
        let mut vaults = HashMap::with_capacity(
            multisigs
                .len()
                .saturating_mul(usize::from(max_vault_index).saturating_add(1)),
        );
        for multisig in multisigs {
            for index in 0..=max_vault_index {
                if let Ok(vault) = squads::vault_address(multisig, index) {
                    vaults.insert(vault, (*multisig, index));
                }
            }
        }
        Self {
            slot,
            max_vault_index,
            multisigs: multisigs.to_vec(),
            vaults,
        }
    }

    /// The addresses `getProgramAccounts` returned that Squads v4 owns.
    pub fn multisigs_from(accounts: &[KeyedAccount]) -> Vec<Address> {
        accounts
            .iter()
            .filter(|a| a.account.owner == squads::PROGRAM_ID)
            .map(|a| a.address)
            .collect()
    }

    /// How many multisigs the index holds.
    pub fn multisig_count(&self) -> usize {
        self.multisigs.len()
    }

    /// The multisig and vault index whose vault is `address`.
    pub fn lookup(&self, address: &Address) -> Option<(Address, u8)> {
        self.vaults.get(address).copied()
    }

    /// The cache file's JSON: the multisig list and its slot. Vaults are derived
    /// again on load, so a cache file cannot assert a vault-to-multisig link.
    pub fn to_cache_json(&self, cluster: &str) -> Value {
        let multisigs: Vec<String> = self.multisigs.iter().map(|m| m.to_string()).collect();
        json!({
            "schema": CACHE_SCHEMA,
            "schema_version": CACHE_VERSION,
            "cluster": cluster,
            "slot": self.slot,
            "multisigs": multisigs,
        })
    }

    /// Reads a cache file written by [`Self::to_cache_json`] for `cluster`. `None`
    /// if it is for another schema or cluster, or any entry does not parse.
    pub fn from_cache_json(text: &str, cluster: &str, max_vault_index: u8) -> Option<Self> {
        let value: Value = serde_json::from_str(text).ok()?;
        if value.get("schema")?.as_str()? != CACHE_SCHEMA
            || value.get("schema_version")?.as_u64()? != CACHE_VERSION
            || value.get("cluster")?.as_str()? != cluster
        {
            return None;
        }
        let slot = value.get("slot")?.as_u64()?;
        let multisigs = value
            .get("multisigs")?
            .as_array()?
            .iter()
            .map(|m| m.as_str()?.parse::<Address>().ok())
            .collect::<Option<Vec<_>>>()?;
        Some(Self::build(slot, &multisigs, max_vault_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Squads-published multisig and its vault 0, from `@sqds/multisig` 2.1.4
    /// `getVaultPda` (the same pair the `read::pda` test uses).
    const MULTISIG: &str = "MjJVd8YZSUjtGB6EJbYBnSxhA1JiKAHnTUfsWVQwQem";

    #[test]
    fn the_list_query_matches_the_multisig_discriminator_and_returns_no_data() {
        let q = multisig_list_query();
        assert_eq!(
            q.filters,
            vec![Filter::Memcmp {
                offset: 0,
                bytes: MULTISIG_DISCRIMINATOR.to_vec()
            }]
        );
        assert_eq!(q.data_slice.map(|s| s.length), Some(0));
    }

    #[test]
    fn looks_up_a_vault_and_round_trips_the_cache() {
        let multisig: Address = MULTISIG.parse().unwrap();
        let index = VaultIndex::build(42, &[multisig], 2);
        let vault1 = squads::vault_address(&multisig, 1).unwrap();
        assert_eq!(index.lookup(&vault1), Some((multisig, 1)));
        assert_eq!(index.lookup(&multisig), None);

        let text = index.to_cache_json("devnet").to_string();
        assert_eq!(VaultIndex::from_cache_json(&text, "devnet", 2), Some(index));
        assert_eq!(VaultIndex::from_cache_json(&text, "mainnet", 2), None);
        assert_eq!(
            VaultIndex::from_cache_json(&text.replace(MULTISIG, "not-an-address"), "devnet", 2),
            None
        );
    }
}
