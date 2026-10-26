//! Each rule, and each loader, through a replayed devnet scan (see
//! `tests/fixtures/README.md`). Expected multisig properties come from the
//! `@sqds/multisig` decode in `tests/oracle.rs`, not from this crate's decoder.

#![allow(clippy::indexing_slicing, reason = "tests index known-length results")]

mod common;

use common::Replay;
use solana_authority_scan::facts::{Authority, FoundBy, ProgramFacts, search};
use solana_authority_scan::loader::{V4Status, loader_name};
use solana_authority_scan::read::Address;
use solana_authority_scan::report::ProgramResult;
use solana_authority_scan::rules::{self, NO_RULE_MATCHED};
use solana_authority_scan::scan::{IndexState, ScanOptions, Scanner};

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

fn scan_with(rpc: &Replay, use_index: bool) -> ProgramFacts {
    scan_full(rpc, use_index, &[], ScanOptions::default())
}

fn scan(name: &str) -> ProgramResult {
    ProgramResult::new(scan_with(&Replay::new(name), true))
}

fn ids(r: &ProgramResult) -> Vec<&'static str> {
    r.matches.iter().map(|m| m.rule.id).collect()
}

fn not_possible(r: &ProgramResult) -> Vec<&'static str> {
    r.facts.not_possible.iter().map(|n| n.search).collect()
}

#[test]
fn a_vault_with_a_time_lock_matches_no_rule() {
    let r = scan("upgradeable-squads-vault-time-lock-set.json");
    assert_eq!(r.facts.error, None);
    assert_eq!(ids(&r), Vec::<&str>::new());
    assert_eq!(r.result_text(), NO_RULE_MATCHED);
    let Some(Authority::SquadsVault {
        multisig,
        index,
        found_by,
        ..
    }) = r.facts.authority
    else {
        panic!("not a vault: {:?}", r.facts.authority);
    };
    assert_eq!(
        multisig.to_string(),
        "9aAiYToZ4ZrHMcyAoNDDnMiswobn3TxtJ1dGXgKkBkU5"
    );
    assert_eq!((index, found_by), (0, FoundBy::Index));
    let m = r.facts.multisig.as_ref().unwrap();
    assert_eq!((m.multisig.threshold, m.multisig.time_lock), (2, 86_400));
    // Every nonce search ran, and found none.
    let nonces = r.facts.nonce_accounts.as_ref().unwrap();
    assert_eq!(nonces.len(), 3);
    assert!(nonces.iter().all(|(_, n)| *n == 0));
    assert!(r.facts.not_possible.is_empty());
}

#[test]
fn without_the_index_the_vault_is_found_in_its_own_transactions() {
    let rpc = Replay::new("upgradeable-squads-vault-time-lock-set.json");
    let r = ProgramResult::new(scan_with(&rpc, false));
    let Some(Authority::SquadsVault {
        multisig, found_by, ..
    }) = r.facts.authority
    else {
        panic!("not a vault: {:?}", r.facts.authority);
    };
    assert_eq!(found_by, FoundBy::Signatures);
    assert_eq!(
        multisig.to_string(),
        "9aAiYToZ4ZrHMcyAoNDDnMiswobn3TxtJ1dGXgKkBkU5"
    );
    assert_eq!(not_possible(&r), [search::SQUADS_INDEX]);
    assert_eq!(ids(&r), Vec::<&str>::new());
    assert_eq!(
        r.result_text(),
        "scan incomplete: no rule matched in what was read"
    );
    let calls = rpc.calls.borrow();
    assert!(calls.contains(&("get_signatures_for_address", 0)));
}

#[test]
fn time_lock_zero() {
    let r = scan("upgradeable-squads-vault-time-lock-zero.json");
    assert_eq!(
        ids(&r),
        [
            rules::MULTISIG_NO_TIME_LOCK.id,
            rules::MULTISIG_OPEN_PROPOSALS.id
        ]
    );
    // Proposals 7 to 9 are in range; the SDK reads 7 active, 8 and 9 executed.
    let open = &r.facts.multisig.as_ref().unwrap().open_proposals;
    assert_eq!(open.len(), 1);
    assert_eq!(
        (open[0].transaction_index, open[0].status.name()),
        (7, "active")
    );
}

#[test]
fn config_authority_set() {
    let r = scan("upgradeable-squads-vault-config-authority.json");
    assert_eq!(
        ids(&r),
        [
            rules::MULTISIG_CONFIG_AUTHORITY_SET.id,
            rules::MULTISIG_NO_TIME_LOCK.id
        ]
    );
    assert!(
        r.matches[0]
            .evidence
            .contains("3XPn1NpR9H4byZQUpDTf6c4eq55aXNiU6Ax3gC3ACN2v"),
        "{}",
        r.matches[0].evidence
    );
}

#[test]
fn threshold_below_half() {
    let r = scan("upgradeable-squads-vault-threshold-below-half.json");
    assert_eq!(
        ids(&r),
        [
            rules::MULTISIG_NO_TIME_LOCK.id,
            rules::MULTISIG_THRESHOLD_BELOW_HALF.id,
            rules::MULTISIG_OPEN_PROPOSALS.id
        ]
    );
    // The nonce search was rate-limited during capture: reported, not hidden.
    assert_eq!(not_possible(&r), [search::NONCES]);
    assert_eq!(r.facts.nonce_accounts, None);
    assert_eq!(
        r.result_text(),
        "scan incomplete: 3 rules matched in what was read"
    );
}

#[test]
fn threshold_below_two() {
    let r = scan("upgradeable-squads-vault-threshold-one.json");
    assert_eq!(
        ids(&r),
        [
            rules::MULTISIG_THRESHOLD_BELOW_TWO.id,
            rules::MULTISIG_NO_TIME_LOCK.id
        ]
    );
}

#[test]
fn a_rent_collector_shifts_offsets_and_cancelled_proposals_are_not_open() {
    let r = scan("upgradeable-squads-vault-rent-collector.json");
    assert_eq!(ids(&r), [rules::MULTISIG_OPEN_PROPOSALS.id]);
    let m = r.facts.multisig.as_ref().unwrap();
    assert_eq!((m.multisig.threshold, m.multisig.voters()), (3, 5));
    let open: Vec<u64> = m
        .open_proposals
        .iter()
        .map(|p| p.transaction_index)
        .collect();
    assert_eq!(open, [1, 3]);
}

#[test]
fn an_unknown_pda_is_flagged_for_review_not_as_a_key() {
    let r = scan("upgradeable-unknown-pda-authority.json");
    assert_eq!(ids(&r), [rules::UNKNOWN_PDA_AUTHORITY.id]);
    assert!(matches!(r.facts.authority, Some(Authority::UnknownPda(_))));
    assert!(!r.matches[0].rule.weakness);
    assert!(r.facts.multisig.is_none());
}

#[test]
fn single_key_authority() {
    let r = scan("upgradeable-single-key-authority.json");
    assert_eq!(ids(&r), [rules::SINGLE_KEY_UPGRADE_AUTHORITY.id]);
    assert_eq!(r.facts.loader, Some(loader_name::UPGRADEABLE));
    assert_eq!(r.facts.last_deploy_slot, Some(342_736_608));
}

#[test]
fn immutable_programs_match_no_rule() {
    for (name, loader) in [
        ("upgradeable-immutable.json", loader_name::UPGRADEABLE),
        ("bpf-loader-2-program.json", loader_name::BPF_LOADER_2),
    ] {
        let r = scan(name);
        assert_eq!(r.facts.authority, Some(Authority::None), "{name}");
        assert_eq!(r.facts.loader, Some(loader), "{name}");
        assert_eq!(r.result_text(), NO_RULE_MATCHED, "{name}");
        assert_eq!(r.facts.nonce_accounts, None, "{name}: no signer to search");
    }
}

#[test]
fn loader_v4_authority_is_read_from_the_program_account() {
    let r = scan("loader-v4-single-key-authority.json");
    assert_eq!(r.facts.loader, Some(loader_name::LOADER_V4));
    assert_eq!(r.facts.v4_status, Some(V4Status::Deployed));
    assert_eq!(
        r.facts.authority,
        Some(Authority::SingleKey(
            "8aLFsNZZReyFqvfEotJxFtRc1CZ4LzpedRLEuGrwmmg8"
                .parse()
                .unwrap()
        ))
    );
    assert_eq!(ids(&r), [rules::SINGLE_KEY_UPGRADE_AUTHORITY.id]);
}

#[test]
fn a_malformed_multisig_stops_the_scan_with_a_named_field() {
    let r = scan("malformed-multisig.json");
    let error = r.facts.error.as_deref().unwrap();
    assert!(error.contains("`rent_collector` at byte 94"), "{error}");
    assert_eq!(r.result_text(), "scan incomplete");
    assert!(r.facts.multisig.is_none());
}

#[test]
fn open_proposals_are_read_in_batches_of_at_most_100() {
    let mut rpc = Replay::new("upgradeable-squads-vault-time-lock-set.json");
    rpc.missing_is_none = true;
    let multisig = rpc.multisigs()[0];
    // Constructed: transaction_index 250, stale 0, so 250 proposals are in range.
    let account = common::account_of(&rpc.fixture["accounts"][multisig.to_string()]["account"]);
    let mut data = account.data;
    data[78..86].copy_from_slice(&250u64.to_le_bytes());
    data[86..94].copy_from_slice(&0u64.to_le_bytes());
    rpc.set_data(&multisig, data);
    let facts = scan_with(&rpc, true);
    assert_eq!(facts.error, None);
    let batches: Vec<usize> = rpc
        .calls
        .borrow()
        .iter()
        .filter(|(name, _)| *name == "get_multiple_accounts")
        .map(|(_, n)| *n)
        .collect();
    assert_eq!(batches, [100, 100, 50]);
}
