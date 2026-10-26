//! This crate's Squads v4 decoders and PDAs against an independent decoder.
//!
//! Every expected value below is the output of the official TypeScript SDK,
//! `@sqds/multisig` 2.1.4 (installed from npm with scripts disabled), run over the
//! same fixture bytes: `accounts.Multisig.fromAccountInfo`,
//! `accounts.Proposal.fromAccountInfo`, `getVaultPda({ multisigPda, index })` and
//! `getProposalPda({ multisigPda, transactionIndex })`. None of it comes from this
//! crate. The SDK prints the default config authority as the all-zero key
//! (`11111111111111111111111111111111`); this crate reads that as "none".

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests and their helpers index known-length results and fail on a bad fixture"
)]

mod common;

use solana_authority_scan::read::Address;
use solana_authority_scan::squads::{
    Multisig, ProposalStatus, decode_multisig, decode_proposal, proposal_address, vault_address,
};

fn a(text: &str) -> Address {
    text.parse().unwrap()
}

fn data(fixture: &str, address: &str) -> Vec<u8> {
    let f = common::load(fixture);
    common::account_of(&f["accounts"][address]["account"]).data
}

struct Expected {
    fixture: &'static str,
    address: &'static str,
    create_key: &'static str,
    threshold: u16,
    time_lock: u32,
    transaction_index: u64,
    stale_transaction_index: u64,
    rent_collector: Option<&'static str>,
    bump: u8,
    members: &'static [(&'static str, u8)],
    vault0: &'static str,
    vault1: &'static str,
    proposal1: &'static str,
    proposal3: &'static str,
}

const MULTISIGS: [Expected; 2] = [
    Expected {
        fixture: "upgradeable-squads-vault-time-lock-set.json",
        address: "9aAiYToZ4ZrHMcyAoNDDnMiswobn3TxtJ1dGXgKkBkU5",
        create_key: "C6FGaXKC6zgjYPuN85hZR3soHjXS9EXPV83rZGXf7JL4",
        threshold: 2,
        time_lock: 86400,
        transaction_index: 2,
        stale_transaction_index: 2,
        rent_collector: None,
        bump: 255,
        members: &[
            ("2BsUD47dif7i6swE3VcbSdKB6u4E35RzPYzu2JAn8gbr", 7),
            ("3dh3Bxu1hJzH3aHfwNAibRqTxyrPsUFyteiuGxycoohh", 7),
            ("HAd3rsh7wXUJ4effxXTmHPRzHVpKnY3W5qLvgo2LpFJC", 7),
        ],
        vault0: "8MpmERed9K14R68F371YJtGVk6mQgNZoQeU3asNPs5mt",
        vault1: "2JGhkaK9EY8N56GZFNWp9TqPcMrp9yUNZbN6MYD3NT7z",
        proposal1: "HtXVLhXR8LD4R42kRJ5KfoqMft53f62CrzEDjaovBjRf",
        proposal3: "2xoYqJGXJzMFqR4g14oGpt44Lhs5gdJYc68hcd358tKQ",
    },
    Expected {
        fixture: "upgradeable-squads-vault-rent-collector.json",
        address: "AB6CTdbwLckrXKXjXPauWAdRfoHLExebuMZyWEocfoEw",
        create_key: "C92MewP98Z76YqfvFQLzFsgPU33KhCn3PjzWJuWtbah9",
        threshold: 3,
        time_lock: 259200,
        transaction_index: 3,
        stale_transaction_index: 0,
        rent_collector: Some("BUJX2DxXjQJEZPhnpw4WsVxD5SZYaQJDUCpTfL88taXo"),
        bump: 255,
        members: &[
            ("2o225PhyGec6vjE7ipKv4LyzyHwcJDXKgemijoRHegSd", 3),
            ("3LkvVKCNj25e4WaoaPYDUv7SESNozoHmWumUHwWMvgQu", 3),
            ("5pU4fcr2cNfMwgjCcrUC3jzBWaiZax1523t24BFP9eJN", 3),
            ("BJmUvyyjnXLgcTH225rSyiSF5ktMLXdgD39vJPk51Ep7", 4),
            ("FD5XZAxT7N4vmMaaXoti8YUPSwagdH3UMWhrmZ1NnekQ", 3),
            ("HEcWaU9tjMgmeDonkrYvHro5QiuWESQ7t3LL4X87Ya29", 3),
        ],
        vault0: "6BxtMaaxNxUwsN86ad1hvK56LsnZVskJH73UeLj7uFpT",
        vault1: "2rimd8HqX6G57R8pvirKDFdhFwSc1qHfgCBPyftJaNBP",
        proposal1: "H6fqwrhJZP2c8YYEHbgYG7gqsC55AaCZB7XPzueZ8A7J",
        proposal3: "GP2BywViKYkaoMvQtKaXw6aFW1kzDozdKEmKBKGtcnCu",
    },
];

#[test]
fn multisigs_decode_as_the_sdk_decodes_them() {
    for e in &MULTISIGS {
        let m: Multisig = decode_multisig(&data(e.fixture, e.address)).unwrap();
        assert_eq!(m.create_key, a(e.create_key), "{}", e.address);
        assert_eq!(m.config_authority, None, "{}", e.address);
        assert_eq!(m.threshold, e.threshold, "{}", e.address);
        assert_eq!(m.time_lock, e.time_lock, "{}", e.address);
        assert_eq!(m.transaction_index, e.transaction_index, "{}", e.address);
        assert_eq!(
            m.stale_transaction_index, e.stale_transaction_index,
            "{}",
            e.address
        );
        assert_eq!(m.rent_collector, e.rent_collector.map(a), "{}", e.address);
        assert_eq!(m.bump, e.bump, "{}", e.address);
        let members: Vec<(Address, u8)> =
            m.members.iter().map(|x| (x.key, x.permissions.0)).collect();
        let expected: Vec<(Address, u8)> = e.members.iter().map(|(k, p)| (a(k), *p)).collect();
        assert_eq!(members, expected, "{}", e.address);
    }
}

#[test]
fn vault_and_proposal_pdas_match_the_sdk() {
    for e in &MULTISIGS {
        let ms = a(e.address);
        assert_eq!(vault_address(&ms, 0), Ok(a(e.vault0)), "{}", e.address);
        assert_eq!(vault_address(&ms, 1), Ok(a(e.vault1)), "{}", e.address);
        assert_eq!(
            proposal_address(&ms, 1),
            Ok(a(e.proposal1)),
            "{}",
            e.address
        );
        assert_eq!(
            proposal_address(&ms, 3),
            Ok(a(e.proposal3)),
            "{}",
            e.address
        );
    }
}

#[test]
fn proposals_decode_as_the_sdk_decodes_them() {
    let fixture = "upgradeable-squads-vault-rent-collector.json";
    let multisig = a("AB6CTdbwLckrXKXjXPauWAdRfoHLExebuMZyWEocfoEw");
    let voters = [
        a("5pU4fcr2cNfMwgjCcrUC3jzBWaiZax1523t24BFP9eJN"),
        a("FD5XZAxT7N4vmMaaXoti8YUPSwagdH3UMWhrmZ1NnekQ"),
        a("HEcWaU9tjMgmeDonkrYvHro5QiuWESQ7t3LL4X87Ya29"),
    ];
    for (address, index, status, bump, cancelled) in [
        (
            "H6fqwrhJZP2c8YYEHbgYG7gqsC55AaCZB7XPzueZ8A7J",
            1,
            ProposalStatus::Approved(1_791_890_955),
            248,
            false,
        ),
        (
            "9EBpFZ8EzuK2cCiqcg6YMUBtvF7z3FmrbTJehCc1SmD7",
            2,
            ProposalStatus::Cancelled(1_792_765_282),
            255,
            true,
        ),
        (
            "GP2BywViKYkaoMvQtKaXw6aFW1kzDozdKEmKBKGtcnCu",
            3,
            ProposalStatus::Approved(1_792_766_083),
            255,
            false,
        ),
    ] {
        let p = decode_proposal(&data(fixture, address)).unwrap();
        assert_eq!(p.multisig, multisig, "{address}");
        assert_eq!(p.transaction_index, index, "{address}");
        assert_eq!(p.status, status, "{address}");
        assert_eq!(p.bump, bump, "{address}");
        assert_eq!(p.approved, voters, "{address}");
        assert!(p.rejected.is_empty(), "{address}");
        assert_eq!(
            p.cancelled,
            if cancelled { voters.to_vec() } else { vec![] }
        );
    }
}

#[test]
fn the_discriminators_are_the_anchor_account_hashes() {
    use sha2::{Digest, Sha256};
    for (name, expected) in [
        (
            "account:Multisig",
            solana_authority_scan::squads::MULTISIG_DISCRIMINATOR,
        ),
        (
            "account:Proposal",
            solana_authority_scan::squads::PROPOSAL_DISCRIMINATOR,
        ),
    ] {
        let hash = Sha256::digest(name.as_bytes());
        assert_eq!(&hash[..8], &expected, "{name}");
    }
}

#[test]
fn malformed_multisigs_are_refused_with_the_field_and_offset() {
    use solana_authority_scan::bytes::Reason;
    let f = common::load("malformed-multisig.json");
    let cases = f["decoder_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let bytes =
            solana_authority_scan::read::decode_base64(case["data_base64"].as_str().unwrap())
                .unwrap();
        let error = decode_multisig(&bytes).unwrap_err();
        let name = case["name"].as_str().unwrap();
        assert_eq!(error.field, case["field"].as_str().unwrap(), "{name}");
        assert_eq!(
            u64::try_from(error.offset).unwrap(),
            case["offset"].as_u64().unwrap(),
            "{name}"
        );
        let reason = match error.reason {
            Reason::TooShort => "too-short",
            Reason::BadTag(_) => "bad-tag",
            Reason::WrongType => "wrong-type",
        };
        assert_eq!(reason, case["reason"].as_str().unwrap(), "{name}");
    }
}
