//! A replaying `Rpc` over a saved fixture (see `tests/fixtures/README.md`). A read the
//! fixture does not hold is refused, so a scan that reads something new fails loudly.

#![allow(
    dead_code,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test helpers shared by several test files: they index fixture JSON and \
              fail the test on a bad fixture"
)]

use std::cell::RefCell;
use std::collections::HashMap;

use serde_json::Value;
use solana_authority_scan::index::VaultIndex;
use solana_authority_scan::read::{
    Account, Address, Filter, Hash, KeyedAccount, LoadedAddresses, ProgramAccountsQuery, Rpc,
    RpcError, Signature, SignatureInfo, SignaturesQuery, Slotted, TransactionMeta,
    TransactionRecord, decode_base64,
};
use solana_authority_scan::scan::ScanOptions;
use solana_authority_scan::squads::{self, MULTISIG_DISCRIMINATOR, PROPOSAL_DISCRIMINATOR};

/// The text of fixture `name` in `tests/fixtures/`. `name` is a plain file name: a
/// path separator or `..` is refused, so a fixture cannot be read from elsewhere.
pub fn fixture(name: &str) -> Result<String, String> {
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(format!("fixture name {name:?} is not a plain file name"));
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read fixture {name}: {e}"))
}

pub fn load(name: &str) -> Value {
    serde_json::from_str(&fixture(name).unwrap()).unwrap()
}

pub fn address(v: &Value) -> Address {
    v.as_str().unwrap().parse().unwrap()
}

/// The account in a fixture entry. `full` data has its trailing zero bytes left out
/// of `data_base64`; they are restored up to `data_len`. `header` data is the prefix
/// the decoders read and is not padded.
pub fn account_of(v: &Value) -> Account {
    let mut data = decode_base64(v["data_base64"].as_str().unwrap()).unwrap();
    if v["data_saved"] != "header" {
        let len = usize::try_from(v["data_len"].as_u64().unwrap()).unwrap();
        assert!(data.len() <= len, "data longer than data_len");
        data.resize(len, 0);
    }
    Account {
        lamports: v["lamports"].as_u64().unwrap(),
        owner: address(&v["owner"]),
        data,
        executable: v["executable"].as_bool().unwrap(),
    }
}

/// Replays one fixture. `calls` records each method called, with the batch size for
/// `get_multiple_accounts`.
pub struct Replay {
    pub fixture: Value,
    accounts: HashMap<Address, (u64, Option<Account>)>,
    /// Addresses not in the fixture read as "no account" instead of an error.
    pub missing_is_none: bool,
    pub calls: RefCell<Vec<(&'static str, usize)>>,
}

impl Replay {
    pub fn new(name: &str) -> Self {
        let fixture = load(name);
        let accounts = fixture["accounts"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                let account = (!v["account"].is_null()).then(|| account_of(&v["account"]));
                (k.parse().unwrap(), (v["slot"].as_u64().unwrap(), account))
            })
            .collect();
        let mut replay = Self {
            fixture,
            accounts,
            missing_is_none: false,
            calls: RefCell::new(Vec::new()),
        };
        replay.stale_window_absent();
        replay
    }

    /// The fixtures were captured before the scanner read proposals at or below the
    /// stale transaction index, so those reads were not recorded. The replay answers
    /// them as "no account" (stated in `tests/fixtures/README.md`). Tests of the
    /// stale window insert their own constructed proposals.
    fn stale_window_absent(&mut self) {
        let window = ScanOptions::default().stale_window;
        for multisig in self.multisigs() {
            let Some((_, Some(account))) = self.accounts.get(&multisig) else {
                continue;
            };
            let Ok(ms) = squads::decode_multisig(&account.data) else {
                continue;
            };
            for i in squads::stale_proposal_indexes(&ms, window).0 {
                let address = squads::proposal_address(&multisig, i).unwrap();
                self.accounts.entry(address).or_insert((0, None));
            }
        }
    }

    /// Adds or replaces the account at `at`.
    pub fn insert(&mut self, at: Address, slot: u64, account: Option<Account>) {
        self.accounts.insert(at, (slot, account));
    }

    /// The account at `at`, if the fixture holds one.
    pub fn get(&self, at: &Address) -> Option<Account> {
        self.accounts.get(at).and_then(|(_, a)| a.clone())
    }

    pub fn program(&self) -> Address {
        address(&self.fixture["program"])
    }

    /// Replaces the data of the account at `at`.
    pub fn set_data(&mut self, at: &Address, data: Vec<u8>) {
        if let Some((_, Some(account))) = self.accounts.get_mut(at) {
            account.data = data;
        }
    }

    /// The Squads v4 Multisig accounts in the fixture.
    pub fn multisigs(&self) -> Vec<Address> {
        self.accounts
            .iter()
            .filter(|(_, (_, a))| {
                a.as_ref().is_some_and(|a| {
                    a.owner == squads::PROGRAM_ID && a.data.starts_with(&MULTISIG_DISCRIMINATOR)
                })
            })
            .map(|(k, _)| *k)
            .collect()
    }

    /// A vault index holding only this fixture's multisigs, as the full index would.
    pub fn index(&self) -> VaultIndex {
        VaultIndex::build(1, &self.multisigs(), 3)
    }

    fn account(&self, a: &Address) -> Result<(u64, Option<Account>), RpcError> {
        match self.accounts.get(a) {
            Some(found) => Ok(found.clone()),
            None if self.missing_is_none => Ok((0, None)),
            None => Err(RpcError::BadRequest("the fixture has no such account")),
        }
    }

    fn call(&self, name: &'static str, n: usize) {
        self.calls.borrow_mut().push((name, n));
    }
}

/// Constructed Proposal data, from the documented layout: `multisig`, `index`, a
/// status tag (with a zero timestamp unless it is executing, tag 4) and no votes.
pub fn proposal_bytes(multisig: &Address, index: u64, status: u8) -> Vec<u8> {
    let mut d = PROPOSAL_DISCRIMINATOR.to_vec();
    d.extend(multisig.as_bytes());
    d.extend(index.to_le_bytes());
    d.push(status);
    if status != 4 {
        d.extend(0i64.to_le_bytes());
    }
    d.push(255);
    for _ in 0..3 {
        d.extend(0u32.to_le_bytes());
    }
    d
}

/// A constructed Squads v4 account holding `data`.
pub fn squads_account(data: Vec<u8>) -> Account {
    Account {
        lamports: 1,
        owner: squads::PROGRAM_ID,
        data,
        executable: false,
    }
}

fn refused() -> RpcError {
    RpcError::Server {
        code: -32600,
        message: "refused during capture".to_owned(),
    }
}

impl Rpc for Replay {
    fn get_genesis_hash(&self) -> Result<Hash, RpcError> {
        self.call("get_genesis_hash", 0);
        Err(RpcError::BadRequest("not replayed"))
    }

    fn get_account_info(&self, a: &Address) -> Result<Slotted<Option<Account>>, RpcError> {
        self.call("get_account_info", 1);
        let (slot, value) = self.account(a)?;
        Ok(Slotted { slot, value })
    }

    fn get_multiple_accounts(
        &self,
        addresses: &[Address],
    ) -> Result<Slotted<Vec<Option<Account>>>, RpcError> {
        self.call("get_multiple_accounts", addresses.len());
        assert!(
            addresses.len() <= 100,
            "a getMultipleAccounts batch over 100"
        );
        let mut slot = 0;
        let mut value = Vec::new();
        for a in addresses {
            let (s, account) = self.account(a)?;
            slot = slot.max(s);
            value.push(account);
        }
        Ok(Slotted { slot, value })
    }

    fn get_program_accounts(
        &self,
        program: &Address,
        query: &ProgramAccountsQuery,
    ) -> Result<Slotted<Vec<KeyedAccount>>, RpcError> {
        self.call("get_program_accounts", 0);
        let Some(Filter::Memcmp { bytes, .. }) = query.filters.last() else {
            return Err(refused());
        };
        let key = Address::new(bytes.clone().try_into().map_err(|_| refused())?);
        let saved = &self.fixture["program_accounts"][format!("{program}:{key}")];
        if saved.is_null() {
            return Err(refused());
        }
        let value = saved["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| KeyedAccount {
                address: address(a),
                account: Account {
                    lamports: 0,
                    owner: *program,
                    data: Vec::new(),
                    executable: false,
                },
            })
            .collect();
        Ok(Slotted {
            slot: saved["slot"].as_u64().unwrap(),
            value,
        })
    }

    fn get_signatures_for_address(
        &self,
        a: &Address,
        _: &SignaturesQuery,
    ) -> Result<Vec<SignatureInfo>, RpcError> {
        self.call("get_signatures_for_address", 0);
        let saved = &self.fixture["signatures"][a.to_string()];
        let Some(list) = saved.as_array() else {
            return Err(refused());
        };
        Ok(list
            .iter()
            .map(|s| SignatureInfo {
                signature: s["signature"].as_str().unwrap().parse().unwrap(),
                slot: s["slot"].as_u64().unwrap(),
                failed: s["failed"].as_bool().unwrap(),
                block_time: s["block_time"].as_i64(),
            })
            .collect())
    }

    fn get_transaction(&self, s: &Signature) -> Result<Option<TransactionRecord>, RpcError> {
        self.call("get_transaction", 0);
        let t = &self.fixture["transactions"][s.to_string()];
        if t.is_null() {
            return Err(refused());
        }
        let list = |key: &str| t[key].as_array().unwrap().iter().map(address).collect();
        Ok(Some(TransactionRecord {
            slot: t["slot"].as_u64().unwrap(),
            block_time: t["block_time"].as_i64(),
            transaction: decode_base64(t["transaction_base64"].as_str().unwrap()).unwrap(),
            meta: Some(TransactionMeta {
                failed: t["failed"].as_bool().unwrap(),
                fee: 0,
                pre_balances: Vec::new(),
                post_balances: Vec::new(),
                log_messages: Vec::new(),
                loaded_addresses: LoadedAddresses {
                    writable: list("loaded_writable"),
                    readonly: list("loaded_readonly"),
                },
            }),
        }))
    }
}
