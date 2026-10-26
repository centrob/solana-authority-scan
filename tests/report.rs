//! The JSON report and the Markdown summary, from replayed devnet scans.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests index known JSON; the fixture-listing helper fails the test on a bad directory"
)]

mod common;

use common::Replay;
use solana_authority_scan::candidate;
use solana_authority_scan::report::{self, ProgramResult, RunContext};
use solana_authority_scan::rules::NO_RULE_MATCHED;
use solana_authority_scan::scan::{IndexState, ScanOptions, Scanner};

fn results(names: &[&str]) -> Vec<ProgramResult> {
    names
        .iter()
        .map(|name| {
            let rpc = Replay::new(name);
            let index = rpc.index();
            let scanner = Scanner {
                rpc: &rpc,
                index: IndexState::Ready(&index),
                supplied_multisigs: &[],
                options: ScanOptions::default(),
            };
            ProgramResult::new(scanner.scan(&rpc.program()))
        })
        .collect()
}

fn ctx() -> RunContext {
    RunContext {
        cluster: "devnet",
        tool_version: "0.1.0",
        index: Err("getProgramAccounts over Squads v4 was refused".to_owned()),
    }
}

#[test]
fn the_json_report_is_versioned_and_carries_slots_and_candidates() {
    let r = results(&[
        "upgradeable-squads-vault-time-lock-set.json",
        "upgradeable-single-key-authority.json",
    ]);
    let json = report::to_json(&ctx(), &r);
    assert_eq!(json["schema"], report::SCHEMA);
    assert_eq!(json["schema_version"], report::SCHEMA_VERSION);
    assert_eq!(json["cluster"], "devnet");
    assert_eq!(json["squads_v4_index"]["available"], false);
    let programs = json["programs"].as_array().unwrap();
    assert_eq!(programs.len(), 2);
    assert_eq!(programs[0]["read_at_slot"], 514_964_483);
    assert_eq!(programs[0]["result"], NO_RULE_MATCHED);
    assert_eq!(programs[0]["authority"]["kind"], "squads-v4-vault");
    assert_eq!(programs[0]["multisig"]["time_lock_seconds"], 86_400);
    assert_eq!(programs[0]["multisig"]["read_at_slot"], 514_964_488);
    assert_eq!(
        programs[1]["matched_rules"][0],
        "single-key-upgrade-authority"
    );

    let candidates = json["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    for field in [
        "title",
        "severity",
        "category",
        "location",
        "description",
        "evidence",
        "recommendation",
        "source",
    ] {
        assert!(c[field].as_str().is_some_and(|s| !s.is_empty()), "{field}");
    }
    assert_eq!(c["source"], report::SOURCE);
    assert_eq!(c["severity"], "high");
    assert!(
        c["evidence"]
            .as_str()
            .unwrap()
            .contains("read at slot 514964596")
    );
    assert_eq!(json["cannot_see"].as_array().unwrap().len(), 6);
}

#[test]
fn a_clean_result_says_no_rule_matched_and_never_safe() {
    let r = results(&[
        "upgradeable-squads-vault-time-lock-set.json",
        "upgradeable-immutable.json",
    ]);
    let md = report::to_markdown(&ctx(), &r);
    assert_eq!(
        md.matches("**Result: no rule matched.**").count(),
        2,
        "{md}"
    );
    // "safe" appears only in the sentence that says the result does not mean it.
    for line in md.lines().filter(|l| l.contains("safe")) {
        assert!(line.contains("does not mean the program is safe"), "{line}");
    }
    assert!(md.contains("Squads v4 index: not available"));
    assert!(md.contains("## What this scan cannot see"));
}

#[test]
fn searches_that_were_not_possible_are_listed() {
    let r = results(&["upgradeable-squads-vault-threshold-below-half.json"]);
    let md = report::to_markdown(&ctx(), &r);
    assert!(md.contains("Searches not possible:"), "{md}");
    assert!(
        md.contains("- durable-nonces: the nonce search was refused"),
        "{md}"
    );
    let json = report::to_json(&ctx(), &r);
    assert_eq!(
        json["programs"][0]["searches_not_possible"][0]["search"],
        "durable-nonces"
    );
}

/// Every fixture under `tests/fixtures/`.
fn every_fixture() -> Vec<String> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
}

#[test]
fn every_fixtures_candidates_read_back_as_a_candidate_document() {
    let mut imported = 0;
    for name in every_fixture() {
        let r = results(&[name.as_str()]);
        let expected = report::candidates(&r);
        assert_eq!(expected.len(), r[0].matches.len(), "{name}");
        let Some(text) = report::candidates_document(&r).unwrap() else {
            assert!(expected.is_empty(), "{name}");
            continue;
        };
        // Read back with the format's checks (`docs/output-formats.md`).
        let parsed = candidate::parse_document(&text).unwrap();
        assert_eq!(parsed, expected, "{name}");
        for ((source, f), m) in parsed.iter().zip(&r[0].matches) {
            assert_eq!(source, report::SOURCE, "{name}");
            assert_eq!(f.severity, m.rule.severity, "{name}");
            assert_eq!(f.title, m.rule.title, "{name}");
        }
        // The report JSON holds the same candidates, with the rule id beside them.
        let json = report::to_json(&ctx(), &r);
        let in_report = json["candidates"].as_array().unwrap();
        assert_eq!(in_report.len(), parsed.len(), "{name}");
        for (c, (_, f)) in in_report.iter().zip(&parsed) {
            assert_eq!(c["evidence"], f.evidence.as_str(), "{name}");
            assert_eq!(c["severity"], f.severity.as_str(), "{name}");
        }
        imported += parsed.len();
    }
    assert!(
        imported >= 10,
        "only {imported} candidates across the fixtures"
    );
}
