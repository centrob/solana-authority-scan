//! Whether a stale approved vault transaction or batch would fail if executed today.
//! Replayed devnet scans with constructed Squads v4 transaction accounts and loader
//! buffers, built here from the public layouts (Squads v4 `state/vault_transaction.rs`
//! and `state/batch.rs`; the upgradeable loader's `UpgradeableLoaderState` and
//! `UpgradeableLoaderInstruction`), not from this crate's decoders. Synthetic keys
//! only.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests index known-length results and fail on a bad fixture"
)]

mod common;

use common::{Replay, proposal_bytes, squads_account, transaction_pda};
use serde_json::Value;
use solana_authority_scan::read::{Account, Address, find_program_address};
use solana_authority_scan::report::{self, ProgramResult, RunContext, SCAN_INCOMPLETE};
use solana_authority_scan::rules;
use solana_authority_scan::scan::{IndexState, ScanOptions, Scanner};
use solana_authority_scan::squads::{self, proposal_address, vault_address};

/// Time lock 0; transaction index 9, stale index 6; proposal 7 active.
const TIME_LOCK_ZERO: &str = "upgradeable-squads-vault-time-lock-zero.json";
/// Proposal status tag: approved.
const APPROVED: u8 = 3;
/// The proposal and transaction index used throughout, at or below the stale index.
const INDEX: u64 = 5;
const STILL_EXECUTABLE: &str = rules::APPROVED_PROPOSAL_STILL_EXECUTABLE.id;
/// The fixture's own matches, without the stale-proposal rule.
const FIXTURE_RULES: [&str; 2] = [
    rules::MULTISIG_NO_TIME_LOCK.id,
    rules::MULTISIG_OPEN_PROPOSALS.id,
];

/// Upgradeable loader instruction tags (bincode u32).
const UPGRADE: u32 = 3;
const SET_AUTHORITY: u32 = 4;
/// Upgradeable loader state tags (bincode u32).
const BUFFER: u32 = 1;
const PROGRAM_DATA: u32 = 3;

fn loader() -> Address {
    "BPFLoaderUpgradeab1e11111111111111111111111"
        .parse()
        .unwrap()
}

fn key(byte: u8) -> Address {
    Address::new([byte; 32])
}

fn discriminator(name: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("account:{name}").as_bytes())[..8].to_vec()
}

fn borsh_bytes(d: &mut Vec<u8>, bytes: &[u8]) {
    d.extend(u32::try_from(bytes.len()).unwrap().to_le_bytes());
    d.extend(bytes);
}

/// One compiled instruction: program key index, account key indexes, data.
struct Ix {
    program: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

/// A `VaultTransactionMessage`: three u8 counts, then Borsh `Vec`s (u32 lengths) of
/// account keys, instructions (`program_id_index` u8, `account_indexes` Vec<u8>,
/// `data` Vec<u8>) and address table lookups (`account_key`, `writable_indexes`,
/// `readonly_indexes`).
fn message(keys: &[Address], ixs: &[Ix], lookups: &[Address]) -> Vec<u8> {
    let mut d = vec![1, 1, 1];
    d.extend(u32::try_from(keys.len()).unwrap().to_le_bytes());
    for k in keys {
        d.extend(k.as_bytes());
    }
    d.extend(u32::try_from(ixs.len()).unwrap().to_le_bytes());
    for ix in ixs {
        d.push(ix.program);
        borsh_bytes(&mut d, &ix.accounts);
        borsh_bytes(&mut d, &ix.data);
    }
    d.extend(u32::try_from(lookups.len()).unwrap().to_le_bytes());
    for table in lookups {
        d.extend(table.as_bytes());
        borsh_bytes(&mut d, &[0]);
        borsh_bytes(&mut d, &[]);
    }
    d
}

/// A `VaultTransaction` account: multisig, creator, index, bump, vault index, vault
/// bump, ephemeral signer bumps (empty), then the message.
fn vault_transaction(multisig: &Address, index: u64, message: &[u8]) -> Vec<u8> {
    let mut d = discriminator("VaultTransaction");
    d.extend(multisig.as_bytes());
    d.extend([5; 32]);
    d.extend(index.to_le_bytes());
    d.extend([254, 0, 255]);
    d.extend(0u32.to_le_bytes());
    d.extend(message);
    d
}

/// A `Batch` account: multisig, creator, index, bump, vault index, vault bump, size,
/// executed transaction index.
fn batch(multisig: &Address, index: u64, size: u32, executed: u32) -> Vec<u8> {
    let mut d = discriminator("Batch");
    d.extend(multisig.as_bytes());
    d.extend([5; 32]);
    d.extend(index.to_le_bytes());
    d.extend([254, 0, 255]);
    d.extend(size.to_le_bytes());
    d.extend(executed.to_le_bytes());
    d
}

/// A `VaultBatchTransaction` account: bump, ephemeral signer bumps (empty), message.
fn batch_transaction(message: &[u8]) -> Vec<u8> {
    let mut d = discriminator("VaultBatchTransaction");
    d.push(253);
    d.extend(0u32.to_le_bytes());
    d.extend(message);
    d
}

/// Seeds `multisig`, multisig, `transaction`, batch index u64, `batch_transaction`,
/// transaction index u32 (both little-endian).
fn batch_transaction_pda(multisig: &Address, index: u64, i: u32) -> Address {
    find_program_address(
        &[
            b"multisig",
            multisig.as_bytes(),
            b"transaction",
            &index.to_le_bytes(),
            b"batch_transaction",
            &i.to_le_bytes(),
        ],
        &squads::PROGRAM_ID,
    )
    .unwrap()
    .0
}

/// A loader account with state `tag` and an `Option<Pubkey>` authority after it
/// (Buffer: straight after the tag; ProgramData: after the slot), then code bytes.
fn loader_state(owner: Address, tag: u32, authority: Option<Address>) -> Account {
    let mut data = tag.to_le_bytes().to_vec();
    if tag == PROGRAM_DATA {
        data.extend(7u64.to_le_bytes());
    }
    match authority {
        None => data.push(0),
        Some(a) => {
            data.push(1);
            data.extend(a.as_bytes());
        }
    }
    data.extend([0x7f, b'E', b'L', b'F', 2, 1, 1]);
    Account {
        lamports: 1,
        owner,
        data,
        executable: false,
    }
}

const BUFFER_KEY: u8 = 0xb0;
const PROGRAM_KEY: u8 = 0xc0;
const PROGRAMDATA_KEY: u8 = 0xc1;
const MEMO_PROGRAM: u8 = 0xd0;

/// Keys of an upgrade message signed by `vault`: the vault (signer), ProgramData,
/// program, buffer, rent and clock sysvars (stand-ins), the loader, and a second
/// program for other instructions.
fn upgrade_keys(vault: Address) -> Vec<Address> {
    vec![
        vault,
        key(PROGRAMDATA_KEY),
        key(PROGRAM_KEY),
        key(BUFFER_KEY),
        key(0xe0),
        key(0xe1),
        loader(),
        key(MEMO_PROGRAM),
    ]
}

/// `Upgrade`: ProgramData, program, buffer, spill, rent, clock, authority.
fn upgrade_ix() -> Ix {
    Ix {
        program: 6,
        accounts: vec![1, 2, 3, 0, 4, 5, 0],
        data: UPGRADE.to_le_bytes().to_vec(),
    }
}

/// An instruction to another program that names the buffer.
fn memo_ix(accounts: Vec<u8>) -> Ix {
    Ix {
        program: 7,
        accounts,
        data: b"hello".to_vec(),
    }
}

/// The fixture with an approved proposal at `INDEX`, its transaction account holding
/// `transaction`, and the buffer account (`None`: no account).
fn setup(
    transaction: impl FnOnce(&Address, &Address) -> Vec<u8>,
    buffer: Option<Account>,
) -> Replay {
    let mut rpc = Replay::new(TIME_LOCK_ZERO);
    let multisig = rpc.multisigs()[0];
    let vault = vault_address(&multisig, 0).unwrap();
    rpc.insert(
        proposal_address(&multisig, INDEX).unwrap(),
        1,
        Some(squads_account(proposal_bytes(&multisig, INDEX, APPROVED))),
    );
    let data = transaction(&multisig, &vault);
    rpc.insert(
        transaction_pda(&multisig, INDEX),
        1,
        Some(squads_account(data)),
    );
    rpc.insert(key(BUFFER_KEY), 1, buffer);
    rpc
}

fn upgrade_tx(ixs: Vec<Ix>) -> impl FnOnce(&Address, &Address) -> Vec<u8> {
    move |multisig, vault| {
        vault_transaction(multisig, INDEX, &message(&upgrade_keys(*vault), &ixs, &[]))
    }
}

fn scan(rpc: &Replay) -> ProgramResult {
    let index = rpc.index();
    let scanner = Scanner {
        rpc,
        index: IndexState::Ready(&index),
        supplied_multisigs: &[],
        options: ScanOptions::default(),
    };
    ProgramResult::new(scanner.scan(&rpc.program()))
}

fn ids(r: &ProgramResult) -> Vec<&'static str> {
    r.matches.iter().map(|m| m.rule.id).collect()
}

/// The `check` field of the one stale approved proposal in the JSON report.
fn check(r: ProgramResult) -> Value {
    let ctx = RunContext {
        cluster: "devnet",
        tool_version: "test",
        index: Err("not used".to_owned()),
    };
    let json = report::to_json(&ctx, &[r]);
    let stale = &json["programs"][0]["multisig"]["stale_approved_proposals"];
    assert_eq!(stale.as_array().map(Vec::len), Some(1), "{stale}");
    stale[0]["check"].clone()
}

/// No finding, and the reason recorded; the scan is complete.
fn assert_would_fail(rpc: &Replay, reason: &str) {
    let r = scan(rpc);
    assert_eq!(ids(&r), FIXTURE_RULES, "no finding when it would fail");
    assert!(
        !r.result_text().starts_with(SCAN_INCOMPLETE),
        "{}",
        r.result_text()
    );
    assert_eq!(check(r), reason);
}

/// The finding is kept, with the check named in its evidence.
fn assert_kept(rpc: &Replay, reason: &str) -> String {
    let r = scan(rpc);
    assert_eq!(
        ids(&r),
        [STILL_EXECUTABLE, FIXTURE_RULES[0], FIXTURE_RULES[1]]
    );
    let evidence = r.matches[0].evidence.clone();
    assert!(evidence.contains(&format!("check: {reason}")), "{evidence}");
    assert_eq!(check(r), reason);
    evidence
}

fn buffer(owner: Address, authority: Option<Address>) -> Option<Account> {
    Some(loader_state(owner, BUFFER, authority))
}

fn vault_of(rpc: &Replay) -> Address {
    vault_address(&rpc.multisigs()[0], 0).unwrap()
}

#[test]
fn an_upgrade_whose_buffer_is_missing_would_fail() {
    let rpc = setup(upgrade_tx(vec![upgrade_ix()]), None);
    assert_would_fail(&rpc, "buffer-missing");
}

#[test]
fn an_upgrade_whose_buffer_has_another_authority_would_fail() {
    let rpc = setup(
        upgrade_tx(vec![upgrade_ix()]),
        buffer(loader(), Some(key(0x66))),
    );
    assert_would_fail(&rpc, "buffer-wrong-authority");
    let rpc = setup(upgrade_tx(vec![upgrade_ix()]), buffer(loader(), None));
    assert_would_fail(&rpc, "buffer-wrong-authority");
}

#[test]
fn an_upgrade_whose_buffer_another_program_owns_would_fail() {
    let mut rpc = setup(upgrade_tx(vec![upgrade_ix()]), None);
    let vault = vault_of(&rpc);
    rpc.insert(key(BUFFER_KEY), 1, buffer(key(0x77), Some(vault)));
    assert_would_fail(&rpc, "buffer-not-loader-owned");
}

#[test]
fn an_upgrade_whose_buffer_account_is_not_a_buffer_would_fail() {
    let mut rpc = setup(upgrade_tx(vec![upgrade_ix()]), None);
    let vault = vault_of(&rpc);
    let programdata = loader_state(loader(), PROGRAM_DATA, Some(vault));
    rpc.insert(key(BUFFER_KEY), 1, Some(programdata));
    assert_would_fail(&rpc, "buffer-not-buffer-state");
}

#[test]
fn an_upgrade_with_a_valid_buffer_keeps_the_finding() {
    let mut rpc = setup(upgrade_tx(vec![upgrade_ix()]), None);
    let vault = vault_of(&rpc);
    rpc.insert(key(BUFFER_KEY), 1, buffer(loader(), Some(vault)));
    assert_kept(&rpc, "not-shown-to-fail");
}

/// An earlier instruction could create or change the buffer, so a missing buffer
/// proves nothing.
#[test]
fn a_buffer_an_earlier_instruction_names_keeps_the_finding() {
    let rpc = setup(upgrade_tx(vec![memo_ix(vec![3]), upgrade_ix()]), None);
    assert_kept(&rpc, "not-shown-to-fail");
}

#[test]
fn a_message_with_address_lookup_tables_keeps_the_finding_not_fully_checked() {
    let rpc = setup(
        |multisig, vault| {
            let m = message(&upgrade_keys(*vault), &[upgrade_ix()], &[key(0xaa)]);
            vault_transaction(multisig, INDEX, &m)
        },
        None,
    );
    let evidence = assert_kept(&rpc, "not-checked-alt");
    assert!(evidence.contains("not fully checked"), "{evidence}");
}

#[test]
fn a_message_without_a_loader_instruction_keeps_the_finding() {
    let rpc = setup(upgrade_tx(vec![memo_ix(vec![0])]), None);
    assert_kept(&rpc, "no-loader-instruction");
}

#[test]
fn a_set_authority_on_an_account_with_another_authority_would_fail() {
    let ix = Ix {
        program: 6,
        accounts: vec![3, 0, 4],
        data: SET_AUTHORITY.to_le_bytes().to_vec(),
    };
    let rpc = setup(upgrade_tx(vec![ix]), buffer(loader(), Some(key(0x66))));
    assert_would_fail(&rpc, "account-wrong-authority");
    let ix = Ix {
        program: 6,
        accounts: vec![3, 0, 4],
        data: SET_AUTHORITY.to_le_bytes().to_vec(),
    };
    let rpc = setup(upgrade_tx(vec![ix]), None);
    assert_would_fail(&rpc, "account-missing");
}

/// A batch executes its transactions in order from `executed_transaction_index + 1`;
/// that next transaction is the one checked.
fn batch_setup(executed: u32, next: &[u8], buffer: Option<Account>) -> Replay {
    let mut rpc = setup(|multisig, _| batch(multisig, INDEX, 3, executed), buffer);
    let multisig = rpc.multisigs()[0];
    let at = batch_transaction_pda(&multisig, INDEX, executed.checked_add(1).unwrap());
    rpc.insert(at, 1, Some(squads_account(batch_transaction(next))));
    rpc
}

#[test]
fn a_batch_whose_next_transaction_would_fail_is_not_flagged() {
    let probe = Replay::new(TIME_LOCK_ZERO);
    let vault = vault_of(&probe);
    let upgrade = message(&upgrade_keys(vault), &[upgrade_ix()], &[]);
    assert_would_fail(&batch_setup(0, &upgrade, None), "buffer-missing");
    assert_would_fail(&batch_setup(1, &upgrade, None), "buffer-missing");
    let valid = buffer(loader(), Some(vault));
    assert_kept(&batch_setup(1, &upgrade, valid), "not-shown-to-fail");
    let alt = message(&upgrade_keys(vault), &[upgrade_ix()], &[key(0xaa)]);
    assert_kept(&batch_setup(0, &alt, None), "not-checked-alt");
}
