//! The JSON report (versioned) and its Markdown summary. Pure; no I/O.
//!
//! Each matched rule is also written as a candidate finding with the fields every
//! tool emits: title, severity, category, location, description, evidence,
//! recommendation and `source`. [`candidates_document`] writes the same candidates
//! as a `dv-candidates` document ([`crate::candidate`]) for a review tool to import;
//! the report JSON keeps them too, with the rule id, as evidence. Candidates are
//! unreviewed tool output; nothing here marks one as reviewed or confirmed.
//!
//! All text in the report is built from decoded values (addresses, numbers, fixed
//! strings) or from errors that already redact the RPC URL and sanitise server text.

use serde_json::{Value, json};

use crate::candidate::Finding;
use crate::facts::{Authority, MultisigFacts, OpenProposal, ProgramFacts};
use crate::rules::{self, Match, NO_RULE_MATCHED};

pub const SCHEMA: &str = "solana-authority-scan/report";
pub const SCHEMA_VERSION: u64 = 1;
pub const TOOL: &str = "solana-authority-scan";
/// The `source` every candidate carries, in the report and in `candidates.json`.
pub const SOURCE: &str = "tool:solana-authority-scan";
pub const CATEGORY: &str = "admin-plane";
/// What a report says when the scan stopped, a search was not possible, or some
/// proposals were not read or not decoded.
pub const SCAN_INCOMPLETE: &str = "scan incomplete";

/// What no scan can see. Printed in every report.
pub const CANNOT_SEE: [&str; 6] = [
    "how and where each signer's key is stored (hardware wallet, hot key, custodian)",
    "who holds each key, and whether one person or device holds several",
    "off-chain procedures: how proposals are checked before signing, and incident response",
    "durable nonce accounts that could hold pre-signed transactions",
    "authorities of other programs, mints and accounts this program depends on",
    "old approved proposals: only the newest proposals at or below the stale transaction \
     index are read (50 unless set with --stale-window), so an approved proposal older \
     than that is not seen, and it may still be executable",
];

/// Why a nonce count is information only.
pub const NONCE_CAVEAT: &str = "information only: anyone can make a nonce account with \
    any authority, and the count proves nothing either way";

/// The scan's context, the same for every program in one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunContext {
    pub cluster: &'static str,
    pub tool_version: &'static str,
    /// The Squads v4 index's slot and size, or why there is none.
    pub index: Result<(u64, usize, u8), String>,
}

/// One program's facts and matches, as the report holds them.
pub struct ProgramResult {
    pub facts: ProgramFacts,
    pub matches: Vec<Match>,
}

impl ProgramResult {
    pub fn new(facts: ProgramFacts) -> Self {
        let matches = rules::evaluate(&facts);
        Self { facts, matches }
    }

    /// "no rule matched" or "N rules matched". Never "safe". A scan that stopped
    /// early says "scan incomplete" alone; a scan that finished without every search
    /// or every proposal says "scan incomplete" first, then what matched in what was
    /// read.
    pub fn result_text(&self) -> String {
        if self.facts.error.is_some() {
            return SCAN_INCOMPLETE.to_owned();
        }
        let matched = match self.matches.len() {
            0 => NO_RULE_MATCHED.to_owned(),
            1 => "1 rule matched".to_owned(),
            n => format!("{n} rules matched"),
        };
        if self.facts.incomplete() {
            format!("{SCAN_INCOMPLETE}: {matched} in what was read")
        } else {
            matched
        }
    }

    /// One candidate finding per matched rule, in the shared candidate format.
    pub fn candidates(&self) -> Vec<(String, Finding)> {
        self.matches
            .iter()
            .map(|m| (SOURCE.to_owned(), self.finding(m)))
            .collect()
    }

    fn finding(&self, m: &Match) -> Finding {
        Finding {
            title: m.rule.title.to_owned(),
            severity: m.rule.severity,
            category: CATEGORY.to_owned(),
            location: format!("program {}", self.facts.program),
            description: m.rule.explanation.to_owned(),
            evidence: format!("{} (read at slot {})", m.evidence, self.facts.read_at_slot),
            recommendation: m.rule.recommendation.to_owned(),
        }
    }
}

/// Every program's candidates.
pub fn candidates(results: &[ProgramResult]) -> Vec<(String, Finding)> {
    results.iter().flat_map(ProgramResult::candidates).collect()
}

/// The `dv-candidates` document, or `None` when no rule matched (a reader refuses an
/// empty document).
pub fn candidates_document(results: &[ProgramResult]) -> Result<Option<String>, String> {
    let list = candidates(results);
    if list.is_empty() {
        return Ok(None);
    }
    crate::candidate::document(&list).map(Some)
}

fn proposals_json(list: &[OpenProposal]) -> Vec<Value> {
    list.iter()
        .map(|p| {
            json!({
                "transaction_index": p.transaction_index,
                "address": p.address.to_string(),
                "status": p.status.name(),
                "approvals": p.approvals,
            })
        })
        .collect()
}

fn authority_json(authority: Option<&Authority>) -> Value {
    let Some(authority) = authority else {
        return Value::Null;
    };
    let (multisig, vault_index, found_by) = match authority {
        Authority::SquadsVault {
            multisig,
            index,
            found_by,
            ..
        } => (
            Some(multisig.to_string()),
            Some(*index),
            Some(found_by.name()),
        ),
        _ => (None, None, None),
    };
    json!({
        "kind": authority.kind(),
        "address": authority.address().map(|a| a.to_string()),
        "multisig": multisig,
        "vault_index": vault_index,
        "found_by": found_by,
    })
}

fn multisig_json(m: &MultisigFacts) -> Value {
    let ms = &m.multisig;
    json!({
        "address": m.address.to_string(),
        "read_at_slot": m.read_at_slot,
        "threshold": ms.threshold,
        "voting_members": ms.voters(),
        "time_lock_seconds": ms.time_lock,
        "config_authority": ms.config_authority.map(|a| a.to_string()),
        "rent_collector": ms.rent_collector.map(|a| a.to_string()),
        "transaction_index": ms.transaction_index,
        "stale_transaction_index": ms.stale_transaction_index,
        "members": ms.members.iter().map(|member| json!({
            "key": member.key.to_string(),
            "permissions": member.permissions.names(),
            "mask": member.permissions.0,
        })).collect::<Vec<_>>(),
        "open_proposals": proposals_json(&m.open_proposals),
        "proposals_not_read": m.proposals_not_read,
        "stale_approved_proposals": proposals_json(&m.stale_approved),
        "stale_proposals_not_read": m.stale_not_read,
        "undecodable_proposals": m.undecodable_proposals.iter().map(|u| json!({
            "transaction_index": u.transaction_index,
            "address": u.address.to_string(),
            "error": u.error,
        })).collect::<Vec<_>>(),
    })
}

fn program_json(r: &ProgramResult) -> Value {
    let f = &r.facts;
    json!({
        "program": f.program.to_string(),
        "read_at_slot": f.read_at_slot,
        "loader": f.loader,
        "programdata": f.programdata.map(|a| a.to_string()),
        "last_deploy_slot": f.last_deploy_slot,
        "loader_v4_status": f.v4_status.map(|s| s.name()),
        "authority": authority_json(f.authority.as_ref()),
        "multisig": f.multisig.as_ref().map(multisig_json),
        "nonce_accounts_by_signer": f.nonce_accounts.as_ref().map(|counts| counts
            .iter()
            .map(|(key, count)| json!({ "key": key.to_string(), "count": count }))
            .collect::<Vec<_>>()),
        "matched_rules": r.matches.iter().map(|m| m.rule.id).collect::<Vec<_>>(),
        "result": r.result_text(),
        "searches_not_possible": f.not_possible.iter().map(|n| json!({
            "search": n.search,
            "reason": n.reason,
        })).collect::<Vec<_>>(),
        "error": f.error,
    })
}

/// The candidate as the report holds it: the same fields as `candidates.json`, plus
/// the rule id, as evidence of what the scanner matched.
fn candidate_json(r: &ProgramResult, m: &Match) -> Value {
    let f = r.finding(m);
    json!({
        "title": f.title,
        "severity": f.severity.as_str(),
        "category": f.category,
        "rule": m.rule.id,
        "location": f.location,
        "description": f.description,
        "evidence": f.evidence,
        "recommendation": f.recommendation,
        "source": SOURCE,
    })
}

/// The JSON report.
pub fn to_json(ctx: &RunContext, results: &[ProgramResult]) -> Value {
    let index = match &ctx.index {
        Ok((slot, count, max)) => json!({
            "available": true, "slot": slot, "multisigs": count, "max_vault_index": max,
        }),
        Err(reason) => json!({ "available": false, "reason": reason }),
    };
    json!({
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "tool_version": ctx.tool_version,
        "cluster": ctx.cluster,
        "squads_v4_index": index,
        "programs": results.iter().map(program_json).collect::<Vec<_>>(),
        "candidates": results
            .iter()
            .flat_map(|r| r.matches.iter().map(move |m| candidate_json(r, m)))
            .collect::<Vec<_>>(),
        "cannot_see": CANNOT_SEE,
        "nonce_note": NONCE_CAVEAT,
        "note": "Candidates are unverified tool output. A result of \"no rule matched\" \
                 means none of this scanner's rules matched the on-chain data; it does not \
                 mean the program is safe.",
    })
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "-".to_owned(), |v| v.to_string())
}

/// The Markdown summary.
pub fn to_markdown(ctx: &RunContext, results: &[ProgramResult]) -> String {
    let mut s = String::new();
    s.push_str("# Solana authority scan\n\n");
    s.push_str(&format!(
        "Cluster: {}. Tool: {TOOL} {}. Schema: {SCHEMA} v{SCHEMA_VERSION}.\n\n",
        ctx.cluster, ctx.tool_version
    ));
    match &ctx.index {
        Ok((slot, count, max)) => s.push_str(&format!(
            "Squads v4 index: {count} multisigs at slot {slot}, vaults 0 to {max}.\n\n"
        )),
        Err(reason) => s.push_str(&format!("Squads v4 index: not available ({reason}).\n\n")),
    }
    s.push_str(
        "This is unverified tool output, not an audit. \"No rule matched\" means none of \
         the rules below matched the on-chain data; it does not mean the program is safe.\n",
    );
    for r in results {
        let f = &r.facts;
        s.push_str(&format!("\n## `{}`\n\n", f.program));
        s.push_str(&format!("**Result: {}.**\n\n", r.result_text()));
        s.push_str("| Field | Value |\n|---|---|\n");
        s.push_str(&format!("| Read at slot | {} |\n", f.read_at_slot));
        s.push_str(&format!("| Loader | {} |\n", opt(f.loader)));
        if let Some(pd) = f.programdata {
            s.push_str(&format!("| ProgramData | `{pd}` |\n"));
        }
        s.push_str(&format!(
            "| Last deploy slot | {} |\n",
            opt(f.last_deploy_slot)
        ));
        if let Some(status) = f.v4_status {
            s.push_str(&format!("| Loader-v4 status | {} |\n", status.name()));
        }
        if let Some(a) = &f.authority {
            s.push_str(&format!(
                "| Authority | {} {} |\n",
                a.kind(),
                a.address().map_or_else(String::new, |a| format!("`{a}`"))
            ));
            if let Authority::SquadsVault {
                multisig,
                index,
                found_by,
                ..
            } = a
            {
                s.push_str(&format!(
                    "| Multisig | `{multisig}` (vault {index}, found by {}) |\n",
                    found_by.name()
                ));
            }
        }
        if let Some(m) = &f.multisig {
            let ms = &m.multisig;
            s.push_str(&format!("| Multisig read at slot | {} |\n", m.read_at_slot));
            s.push_str(&format!(
                "| Threshold | {} of {} voting members ({} members) |\n",
                ms.threshold,
                ms.voters(),
                ms.members.len()
            ));
            s.push_str(&format!("| Time lock | {} seconds |\n", ms.time_lock));
            s.push_str(&format!(
                "| Config authority | {} |\n",
                ms.config_authority
                    .map_or_else(|| "none".to_owned(), |a| format!("`{a}`"))
            ));
            let first = ms.stale_transaction_index.saturating_add(1);
            let range = if first > ms.transaction_index {
                "no transaction after the stale index".to_owned()
            } else if m.proposals_not_read > 0 {
                format!(
                    "read the newest of #{first} to #{}; {} older not read",
                    ms.transaction_index, m.proposals_not_read
                )
            } else {
                format!("read #{first} to #{}", ms.transaction_index)
            };
            s.push_str(&format!(
                "| Open proposals | {} ({range}) |\n",
                m.open_proposals.len()
            ));
            let stale = ms.stale_transaction_index;
            if stale > 0 {
                let first = m.stale_not_read.saturating_add(1);
                let older = if m.stale_not_read > 0 {
                    format!("; {} older not read", m.stale_not_read)
                } else {
                    String::new()
                };
                s.push_str(&format!(
                    "| Approved at or below the stale index | {} (read #{first} to #{stale}{older}) |\n",
                    m.stale_approved.len()
                ));
            }
            for u in &m.undecodable_proposals {
                s.push_str(&format!(
                    "| Proposal not decoded | #{} `{}`: {} |\n",
                    u.transaction_index, u.address, u.error
                ));
            }
            for member in &ms.members {
                s.push_str(&format!(
                    "| Member | `{}` {} |\n",
                    member.key,
                    member.permissions.names().join(", ")
                ));
            }
        }
        if let Some(counts) = &f.nonce_accounts {
            let total: usize = counts
                .iter()
                .map(|(_, n)| n)
                .fold(0, |a, n| a.saturating_add(*n));
            s.push_str(&format!(
                "| Nonce accounts with a signer as authority | {total} ({NONCE_CAVEAT}) |\n"
            ));
        }
        if let Some(e) = &f.error {
            s.push_str(&format!("\nThe scan stopped: {e}\n"));
        }
        if !r.matches.is_empty() {
            s.push_str("\n| Rule | Severity | Evidence |\n|---|---|---|\n");
            for m in &r.matches {
                s.push_str(&format!(
                    "| {} | {} | {} |\n",
                    m.rule.title, m.rule.severity, m.evidence
                ));
            }
        }
        if f.not_possible.is_empty() {
            s.push_str("\nEvery search this scan makes was possible.\n");
        } else {
            s.push_str("\nSearches not possible:\n\n");
            for n in &f.not_possible {
                s.push_str(&format!("- {}: {}\n", n.search, n.reason));
            }
        }
    }
    s.push_str("\n## What this scan cannot see\n\n");
    for item in CANNOT_SEE {
        s.push_str(&format!("- {item}\n"));
    }
    s
}
