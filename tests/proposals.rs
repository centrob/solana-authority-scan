//! Proposals (open, stale and approved, undecodable, foreign), a supplied
//! multisig, and the oldest loader, through replayed devnet scans with constructed
//! changes. Each change is built from the documented layout
//! (`docs/how-it-works.md`), not from this crate's decoder.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests index known-length results and fail on a bad fixture"
)]

mod common;

use common::{Replay, TxKind, proposal_bytes, squads_account, transaction_bytes, transaction_pda};
use solana_authority_scan::facts::{Authority, FoundBy, ProgramFacts, search};
use solana_authority_scan::loader::{self, loader_name};
use solana_authority_scan::read::Address;
use solana_authority_scan::report::{ProgramResult, SCAN_INCOMPLETE};
use solana_authority_scan::rules;
use solana_authority_scan::scan::{IndexState, ScanOptions, Scanner};
use solana_authority_scan::squads::proposal_address;

/// Time lock 0; transaction index 9, stale index 6; proposal 7 active, 8 and 9
/// executed.
const TIME_LOCK_ZERO: &str = "upgradeable-squads-vault-time-lock-zero.json";
/// Vault 0 of multisig `9aAi...`; found by the index or by its own transactions.
const TIME_LOCK_SET: &str = "upgradeable-squads-vault-time-lock-set.json";

fn scan_full(
    rpc: &Replay,
    use_index: bool,
    supplied: &[Address],
    options: ScanOptions,
) -> ProgramFacts {
    let index = rpc.index();
    let scanner = Scanner {
        rpc,
        index: if use_index {
            IndexState::Ready(&index)
        } else {
            IndexState::Unavailable("not built in this test".to_owned())
        },
        supplied_multisigs: supplied,
        options,
    };
    scanner.scan(&rpc.program())
}

fn scan(rpc: &Replay) -> ProgramResult {
    ProgramResult::new(scan_full(rpc, true, &[], ScanOptions::default()))
}

fn open(r: &ProgramResult) -> Vec<(u64, &'static str)> {
    r.facts
        .multisig
        .as_ref()
        .unwrap()
        .open_proposals
        .iter()
        .map(|p| (p.transaction_index, p.status.name()))
        .collect()
}

fn ids(r: &ProgramResult) -> Vec<&'static str> {
    r.matches.iter().map(|m| m.rule.id).collect()
}

/// The replay and its one multisig.
fn time_lock_zero() -> (Replay, Address) {
    let rpc = Replay::new(TIME_LOCK_ZERO);
    let multisig = rpc.multisigs()[0];
    (rpc, multisig)
}

fn put_proposal(rpc: &mut Replay, multisig: &Address, index: u64, data: Vec<u8>) {
    let at = proposal_address(multisig, index).unwrap();
    rpc.insert(at, 1, Some(squads_account(data)));
}

#[test]
fn the_unchanged_fixture_has_one_active_proposal() {
    let (rpc, _) = time_lock_zero();
    let r = scan(&rpc);
    assert_eq!(open(&r), [(7, "active")]);
    assert_eq!(r.result_text(), "2 rules matched");
}

#[test]
fn a_draft_proposal_counts_as_open() {
    let (mut rpc, multisig) = time_lock_zero();
    put_proposal(&mut rpc, &multisig, 8, proposal_bytes(&multisig, 8, 0));
    assert_eq!(open(&scan(&rpc)), [(7, "active"), (8, "draft")]);
}

#[test]
fn a_proposal_account_squads_does_not_own_is_skipped() {
    let (mut rpc, multisig) = time_lock_zero();
    let at = proposal_address(&multisig, 7).unwrap();
    let mut account = rpc.get(&at).unwrap();
    account.owner = Address::new([0; 32]);
    rpc.insert(at, 1, Some(account));
    let r = scan(&rpc);
    assert!(open(&r).is_empty());
    assert!(!ids(&r).contains(&rules::MULTISIG_OPEN_PROPOSALS.id));
}

#[test]
fn a_proposal_for_another_multisig_is_skipped() {
    let (mut rpc, multisig) = time_lock_zero();
    let other = Address::new([7; 32]);
    put_proposal(&mut rpc, &multisig, 7, proposal_bytes(&other, 7, 1));
    assert!(open(&scan(&rpc)).is_empty());
}

#[test]
fn an_undecodable_proposal_is_listed_and_the_rest_are_still_read() {
    let (mut rpc, multisig) = time_lock_zero();
    // Status tag 9 does not exist.
    put_proposal(&mut rpc, &multisig, 8, proposal_bytes(&multisig, 8, 9));
    let r = scan(&rpc);
    assert_eq!(r.facts.error, None);
    assert_eq!(open(&r), [(7, "active")]);
    let bad = &r.facts.multisig.as_ref().unwrap().undecodable_proposals;
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].transaction_index, 8);
    assert!(bad[0].error.contains("status"), "{}", bad[0].error);
    assert!(
        r.result_text().starts_with(SCAN_INCOMPLETE),
        "{}",
        r.result_text()
    );
}

#[test]
fn capped_open_proposals_make_the_scan_incomplete() {
    let (rpc, _) = time_lock_zero();
    let options = ScanOptions {
        max_proposals: 1,
        ..ScanOptions::default()
    };
    let r = ProgramResult::new(scan_full(&rpc, true, &[], options));
    assert_eq!(r.facts.multisig.as_ref().unwrap().proposals_not_read, 2);
    assert_eq!(
        r.result_text(),
        "scan incomplete: 1 rule matched in what was read"
    );
}

#[test]
fn an_approved_proposal_at_or_below_the_stale_index_is_still_executable() {
    let (mut rpc, multisig) = time_lock_zero();
    put_proposal(&mut rpc, &multisig, 5, proposal_bytes(&multisig, 5, 3));
    put_proposal(&mut rpc, &multisig, 4, proposal_bytes(&multisig, 4, 5));
    put_proposal(&mut rpc, &multisig, 3, proposal_bytes(&multisig, 3, 4));
    put_proposal(&mut rpc, &multisig, 2, proposal_bytes(&multisig, 2, 1));
    for i in [3, 5] {
        let data = transaction_bytes(TxKind::Vault, &multisig, i);
        rpc.insert(transaction_pda(&multisig, i), 1, Some(squads_account(data)));
    }
    let r = scan(&rpc);
    let m = r.facts.multisig.as_ref().unwrap();
    let stale: Vec<(u64, &str)> = m
        .stale_approved
        .iter()
        .map(|p| (p.transaction_index, p.status.name()))
        .collect();
    // Executed and active proposals there cannot run; approved and executing can.
    assert_eq!(stale, [(3, "executing"), (5, "approved")]);
    assert_eq!(m.stale_not_read, 0);
    assert_eq!(
        ids(&r),
        [
            rules::APPROVED_PROPOSAL_STILL_EXECUTABLE.id,
            rules::MULTISIG_NO_TIME_LOCK.id,
            rules::MULTISIG_OPEN_PROPOSALS.id
        ]
    );
    assert!(
        r.matches[0]
            .evidence
            .ends_with("#3 executing vault-transaction, #5 approved vault-transaction"),
        "{}",
        r.matches[0].evidence
    );
}

#[test]
fn the_stale_window_reads_only_the_newest_indexes() {
    let (mut rpc, multisig) = time_lock_zero();
    put_proposal(&mut rpc, &multisig, 3, proposal_bytes(&multisig, 3, 3));
    let options = ScanOptions {
        stale_window: 2,
        ..ScanOptions::default()
    };
    let r = ProgramResult::new(scan_full(&rpc, true, &[], options));
    let m = r.facts.multisig.as_ref().unwrap();
    assert!(m.stale_approved.is_empty(), "index 3 is outside 5 to 6");
    assert_eq!(m.stale_not_read, 4);
}

#[test]
fn a_supplied_multisig_is_checked_by_derivation_and_nothing_is_searched() {
    let rpc = Replay::new(TIME_LOCK_SET);
    let multisig = rpc.multisigs()[0];
    let facts = scan_full(&rpc, false, &[multisig], ScanOptions::default());
    let Some(Authority::SquadsVault {
        multisig: found,
        index,
        found_by,
        ..
    }) = facts.authority
    else {
        panic!("not a vault: {:?}", facts.authority);
    };
    assert_eq!((found, index, found_by), (multisig, 0, FoundBy::Supplied));
    assert!(facts.not_possible.is_empty(), "{:?}", facts.not_possible);
    assert!(
        !rpc.calls
            .borrow()
            .iter()
            .any(|(name, _)| *name == "get_signatures_for_address")
    );
}

#[test]
fn a_supplied_multisig_that_does_not_own_the_vault_is_reported() {
    let rpc = Replay::new(TIME_LOCK_SET);
    let wrong = Address::new([7; 32]);
    let r = ProgramResult::new(scan_full(&rpc, true, &[wrong], ScanOptions::default()));
    assert!(matches!(r.facts.authority, Some(Authority::UnknownPda(_))));
    assert_eq!(r.facts.not_possible.len(), 1);
    assert_eq!(r.facts.not_possible[0].search, search::SUPPLIED_MULTISIG);
    assert!(
        r.facts.not_possible[0].reason.contains(&wrong.to_string()),
        "{}",
        r.facts.not_possible[0].reason
    );
    assert!(r.result_text().starts_with(SCAN_INCOMPLETE));
    // The supplied multisig replaces the searches: neither ran.
    assert!(
        !rpc.calls
            .borrow()
            .iter()
            .any(|(name, _)| *name == "get_signatures_for_address")
    );
}

#[test]
fn a_bpf_loader_1_program_is_immutable() {
    // Constructed: the BPFLoader2 fixture's program account, owned by BPFLoader1.
    let mut rpc = Replay::new("bpf-loader-2-program.json");
    let program = rpc.program();
    let mut account = rpc.get(&program).unwrap();
    account.owner = loader::BPF_LOADER_1;
    rpc.insert(program, 1, Some(account));
    let r = scan(&rpc);
    assert_eq!(r.facts.loader, Some(loader_name::BPF_LOADER_1));
    assert_eq!(r.facts.authority, Some(Authority::None));
    assert!(r.matches.is_empty());
}
