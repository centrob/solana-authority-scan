//! Approved proposals at or below the stale transaction index, by the kind of
//! transaction they belong to. Squads v4 refuses to execute a stale config
//! transaction but still executes a stale approved vault transaction or batch
//! (`docs/how-it-works.md`, "Proposals"). Replayed devnet scans with constructed
//! proposal and transaction accounts, built from the public Squads v4 layouts in
//! `tests/common/mod.rs`, not from this crate's decoder.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests index known-length results and fail on a bad fixture"
)]

mod common;

use common::{Replay, TxKind, proposal_bytes, squads_account, transaction_bytes, transaction_pda};
use solana_authority_scan::facts::search;
use solana_authority_scan::read::{Account, Address};
use solana_authority_scan::report::{ProgramResult, SCAN_INCOMPLETE};
use solana_authority_scan::rules;
use solana_authority_scan::scan::{IndexState, ScanOptions, Scanner};
use solana_authority_scan::squads::proposal_address;

/// Time lock 0; transaction index 9, stale index 6; proposal 7 active.
const TIME_LOCK_ZERO: &str = "upgradeable-squads-vault-time-lock-zero.json";
/// The search name a stale transaction account that could not be read is listed under.
const NOT_READ: &str = search::STALE_TRANSACTIONS;
/// Proposal status tag: approved.
const APPROVED: u8 = 3;

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

/// The time-lock-zero fixture with an approved proposal at stale index 5.
fn with_stale_approved() -> (Replay, Address) {
    let mut rpc = Replay::new(TIME_LOCK_ZERO);
    let multisig = rpc.multisigs()[0];
    let at = proposal_address(&multisig, 5).unwrap();
    rpc.insert(
        at,
        1,
        Some(squads_account(proposal_bytes(&multisig, 5, APPROVED))),
    );
    (rpc, multisig)
}

fn put_transaction(rpc: &mut Replay, multisig: &Address, index: u64, account: Option<Account>) {
    rpc.insert(transaction_pda(multisig, index), 1, account);
}

/// The fixture's own matches, without the stale-proposal rule.
const FIXTURE_RULES: [&str; 2] = [
    rules::MULTISIG_NO_TIME_LOCK.id,
    rules::MULTISIG_OPEN_PROPOSALS.id,
];

#[test]
fn a_stale_approved_config_transaction_is_not_executable() {
    let (mut rpc, multisig) = with_stale_approved();
    let data = transaction_bytes(TxKind::Config, &multisig, 5);
    put_transaction(&mut rpc, &multisig, 5, Some(squads_account(data)));
    let r = scan(&rpc);
    assert_eq!(ids(&r), FIXTURE_RULES);
    assert!(
        r.facts.not_possible.iter().all(|n| n.search != NOT_READ),
        "{:?}",
        r.facts.not_possible
    );
    assert!(
        !r.result_text().starts_with(SCAN_INCOMPLETE),
        "{}",
        r.result_text()
    );
}

#[test]
fn a_stale_approved_vault_transaction_is_still_executable() {
    let (mut rpc, multisig) = with_stale_approved();
    let data = transaction_bytes(TxKind::Vault, &multisig, 5);
    put_transaction(&mut rpc, &multisig, 5, Some(squads_account(data)));
    let r = scan(&rpc);
    assert_eq!(
        ids(&r),
        [
            rules::APPROVED_PROPOSAL_STILL_EXECUTABLE.id,
            FIXTURE_RULES[0],
            FIXTURE_RULES[1]
        ]
    );
    assert!(
        r.matches[0]
            .evidence
            .ends_with("#5 approved vault-transaction"),
        "{}",
        r.matches[0].evidence
    );
    assert!(
        !r.result_text().starts_with(SCAN_INCOMPLETE),
        "{}",
        r.result_text()
    );
}

#[test]
fn a_stale_approved_batch_is_still_executable() {
    let (mut rpc, multisig) = with_stale_approved();
    let data = transaction_bytes(TxKind::Batch, &multisig, 5);
    put_transaction(&mut rpc, &multisig, 5, Some(squads_account(data)));
    let r = scan(&rpc);
    assert_eq!(ids(&r)[0], rules::APPROVED_PROPOSAL_STILL_EXECUTABLE.id);
    assert!(
        r.matches[0].evidence.ends_with("#5 approved batch"),
        "{}",
        r.matches[0].evidence
    );
}

/// No finding, never "fine": the scan says it is incomplete and names the index.
fn assert_not_read(r: &ProgramResult) {
    assert_eq!(
        ids(r),
        FIXTURE_RULES,
        "no finding from a transaction not read"
    );
    let listed: Vec<&str> = r
        .facts
        .not_possible
        .iter()
        .filter(|n| n.search == NOT_READ)
        .map(|n| n.reason.as_str())
        .collect();
    assert_eq!(listed.len(), 1, "{:?}", r.facts.not_possible);
    assert!(listed[0].contains("#5"), "{}", listed[0]);
    assert!(
        r.result_text().starts_with(SCAN_INCOMPLETE),
        "{}",
        r.result_text()
    );
}

#[test]
fn a_missing_transaction_account_is_not_read() {
    let (mut rpc, multisig) = with_stale_approved();
    put_transaction(&mut rpc, &multisig, 5, None);
    assert_not_read(&scan(&rpc));
}

#[test]
fn an_unknown_transaction_discriminator_is_not_read() {
    let (mut rpc, multisig) = with_stale_approved();
    let mut data = transaction_bytes(TxKind::Vault, &multisig, 5);
    data[0] ^= 0xff;
    put_transaction(&mut rpc, &multisig, 5, Some(squads_account(data)));
    assert_not_read(&scan(&rpc));
}

#[test]
fn a_transaction_squads_does_not_own_is_not_read() {
    let (mut rpc, multisig) = with_stale_approved();
    let mut account = squads_account(transaction_bytes(TxKind::Config, &multisig, 5));
    account.owner = Address::new([0; 32]);
    put_transaction(&mut rpc, &multisig, 5, Some(account));
    assert_not_read(&scan(&rpc));
}

#[test]
fn a_transaction_for_another_index_is_not_read() {
    let (mut rpc, multisig) = with_stale_approved();
    let data = transaction_bytes(TxKind::Config, &multisig, 4);
    put_transaction(&mut rpc, &multisig, 5, Some(squads_account(data)));
    assert_not_read(&scan(&rpc));
}

#[test]
fn a_failed_transaction_read_is_not_read() {
    // The replay refuses an address it does not hold, as a provider error would.
    let (rpc, _) = with_stale_approved();
    assert_not_read(&scan(&rpc));
}
