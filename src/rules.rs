//! The rules: each a named constant with an id, a severity, an explanation and a
//! recommendation. [`evaluate`] returns the rules a scan matches. Pure; no I/O.
//!
//! A clean result is "no rule matched", never "safe": the rules see only what is on
//! chain (see "What it cannot see" in `docs/how-it-works.md`).

use crate::candidate::Severity;

use crate::facts::{Authority, ProgramFacts, key_kind};

/// The text a report gives when no rule matched.
pub const NO_RULE_MATCHED: &str = "no rule matched";

#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: &'static str,
    /// The shared severity scale of every candidate finding.
    pub severity: Severity,
    pub title: &'static str,
    pub explanation: &'static str,
    pub recommendation: &'static str,
    /// False for a rule that asks for a manual review rather than naming a weakness.
    pub weakness: bool,
}

pub const SINGLE_KEY_UPGRADE_AUTHORITY: Rule = Rule {
    id: "single-key-upgrade-authority",
    severity: Severity::High,
    title: "One key can upgrade the program",
    explanation: "The upgrade authority is an address on the ed25519 curve, so one private \
        key can replace the program's code at once, with no second signer and no delay.",
    recommendation: "Move the upgrade authority to a multisig vault with a threshold of at \
        least two and a time lock, or make the program immutable.",
    weakness: true,
};

pub const MULTISIG_NO_TIME_LOCK: Rule = Rule {
    id: "multisig-time-lock-zero",
    severity: Severity::Medium,
    title: "The multisig has no time lock",
    explanation: "The multisig's time lock is 0, so an approved proposal (an upgrade, or a \
        change of members or threshold) can execute in the same moment it is approved. \
        Users and monitors get no time to react.",
    recommendation: "Set a time lock long enough for monitoring to see and answer a \
        proposal, for example 24 hours.",
    weakness: true,
};

pub const MULTISIG_THRESHOLD_BELOW_TWO: Rule = Rule {
    id: "multisig-threshold-below-two",
    severity: Severity::High,
    title: "One member can approve alone",
    explanation: "The multisig's threshold is below 2, so a single member's key approves \
        a proposal on its own: in effect a single key.",
    recommendation: "Raise the threshold to at least 2, and to more than half of the \
        voting members.",
    weakness: true,
};

pub const MULTISIG_THRESHOLD_BELOW_HALF: Rule = Rule {
    id: "multisig-threshold-below-half",
    severity: Severity::Medium,
    title: "The threshold is less than half of the voting members",
    explanation: "The threshold is less than half of the members who hold the vote \
        permission (2 of 5, for example), so a minority of keys can approve a proposal. \
        A threshold of exactly half (2 of 4) does not match this rule.",
    recommendation: "Raise the threshold to at least half of the voting members, and \
        preferably to more than half.",
    weakness: true,
};

pub const MULTISIG_CONFIG_AUTHORITY_SET: Rule = Rule {
    id: "multisig-config-authority-set",
    severity: Severity::High,
    title: "A config authority can change the multisig alone",
    explanation: "The multisig has a config authority. That address can add and remove \
        members, change the threshold and the time lock without any proposal or vote, so \
        the multisig is only as strong as that one authority.",
    recommendation: "Remove the config authority so that changes need a proposal and the \
        threshold, unless the authority is itself a stronger multisig.",
    weakness: true,
};

pub const MULTISIG_OPEN_PROPOSALS: Rule = Rule {
    id: "multisig-open-proposals",
    severity: Severity::Low,
    title: "The multisig has open proposals",
    explanation: "Proposals in draft, active or approved state exist. An approved one can \
        be executed by any member with the execute permission once its time lock passes.",
    recommendation: "Review each open proposal; execute or cancel it so none waits to be \
        used later.",
    weakness: true,
};

pub const APPROVED_PROPOSAL_STILL_EXECUTABLE: Rule = Rule {
    id: "approved-proposal-still-executable",
    severity: Severity::High,
    title: "An approved proposal is still executable",
    explanation: "A proposal at or below the multisig's stale transaction index is still \
        approved, and its transaction is a vault transaction or a batch. Squads v4 marks \
        such transactions stale but still executes an approved vault transaction or batch \
        (it refuses a stale config transaction, which this rule does not match), so any \
        member with the execute permission can run it long after the members who \
        approved it expected it to be used or forgotten. The scanner decodes the stored \
        message and leaves out a proposal that would certainly fail if executed now: an \
        upgradeable-loader upgrade whose buffer is missing, owned by another program, not \
        a buffer, or under another authority, or a set-authority or close whose account \
        is missing or under another authority. Any other proposal is kept, including one \
        whose message uses address lookup tables (not fully checked) or calls other \
        programs, whose inner instructions are not checked; each entry names its check. \
        A proposal in the deprecated executing status also matches, although the current \
        Squads v4 program executes only approved proposals.",
    recommendation: "Review each approved proposal listed. Execute it if it is still \
        wanted; otherwise cancel it so it cannot be executed later.",
    weakness: true,
};

pub const UNKNOWN_PDA_AUTHORITY: Rule = Rule {
    id: "upgrade-authority-unknown-pda",
    severity: Severity::Info,
    title: "The upgrade authority is a PDA of an unknown program: review by hand",
    explanation: "The upgrade authority is off the ed25519 curve, so no single private key \
        exists for it; it is controlled by a program. The scanner could not tie it to a \
        Squads v4 multisig (it may be Squads v3, Realms governance, another program, or a \
        vault the search missed). This is not a weakness on its own.",
    recommendation: "Find the controlling program and review its signers, threshold and \
        delay by hand.",
    weakness: false,
};

/// Every rule, in the order the report lists matches.
pub const ALL: [&Rule; 8] = [
    &SINGLE_KEY_UPGRADE_AUTHORITY,
    &MULTISIG_THRESHOLD_BELOW_TWO,
    &MULTISIG_CONFIG_AUTHORITY_SET,
    &APPROVED_PROPOSAL_STILL_EXECUTABLE,
    &MULTISIG_NO_TIME_LOCK,
    &MULTISIG_THRESHOLD_BELOW_HALF,
    &MULTISIG_OPEN_PROPOSALS,
    &UNKNOWN_PDA_AUTHORITY,
];

/// A matched rule and the chain values behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub rule: &'static Rule,
    pub evidence: String,
}

/// The rules `facts` matches, in [`ALL`] order.
pub fn evaluate(facts: &ProgramFacts) -> Vec<Match> {
    let mut out = Vec::new();
    match &facts.authority {
        Some(Authority::SingleKey(key)) => out.push(Match {
            rule: &SINGLE_KEY_UPGRADE_AUTHORITY,
            evidence: format!("upgrade authority {key} is on the ed25519 curve"),
        }),
        Some(Authority::UnknownPda(pda)) => out.push(Match {
            rule: &UNKNOWN_PDA_AUTHORITY,
            evidence: format!(
                "upgrade authority {pda} is off the curve and is not a Squads v4 vault this \
                 scan found"
            ),
        }),
        _ => {}
    }
    if let Some(m) = &facts.multisig {
        let ms = &m.multisig;
        let voters = ms.voters();
        if ms.threshold < 2 {
            out.push(Match {
                rule: &MULTISIG_THRESHOLD_BELOW_TWO,
                evidence: format!(
                    "multisig {} threshold {} of {} voting members",
                    m.address, ms.threshold, voters
                ),
            });
        }
        if let Some(authority) = ms.config_authority {
            out.push(Match {
                rule: &MULTISIG_CONFIG_AUTHORITY_SET,
                evidence: format!(
                    "multisig {} config authority {authority} ({})",
                    m.address,
                    key_kind(&authority)
                ),
            });
        }
        if ms.time_lock == 0 {
            out.push(Match {
                rule: &MULTISIG_NO_TIME_LOCK,
                evidence: format!("multisig {} time lock 0 seconds", m.address),
            });
        }
        // Only vault transactions and batches: Squads v4 refuses a stale config
        // transaction (`docs/how-it-works.md`, "Proposals"). One whose transaction was
        // not read is listed as not read by the scan, not matched here. One that would
        // certainly fail if executed now is not matched either (`execution`).
        let list: Vec<String> = m
            .stale_approved
            .iter()
            .filter(|p| p.still_executable())
            .filter_map(|p| {
                p.transaction_kind.map(|kind| {
                    let check = p.check.map_or_else(String::new, |c| match c.note() {
                        Some(note) => format!(" (check: {}; {note})", c.name()),
                        None => format!(" (check: {})", c.name()),
                    });
                    format!(
                        "#{} {} {}{check}",
                        p.transaction_index,
                        p.status.name(),
                        kind.name()
                    )
                })
            })
            .collect();
        if !list.is_empty() {
            out.push(Match {
                rule: &APPROVED_PROPOSAL_STILL_EXECUTABLE,
                evidence: format!(
                    "multisig {} stale transaction index {}; still approved at or below it: {}",
                    m.address,
                    ms.stale_transaction_index,
                    list.join(", ")
                ),
            });
        }
        // Less than half: threshold < voters / 2, that is 2 * threshold < voters.
        // A threshold below 2 already matched.
        let doubled = usize::from(ms.threshold).saturating_mul(2);
        if ms.threshold >= 2 && doubled < voters {
            out.push(Match {
                rule: &MULTISIG_THRESHOLD_BELOW_HALF,
                evidence: format!(
                    "multisig {} threshold {} of {} voting members",
                    m.address, ms.threshold, voters
                ),
            });
        }
        if !m.open_proposals.is_empty() {
            let list: Vec<String> = m
                .open_proposals
                .iter()
                .map(|p| format!("#{} {}", p.transaction_index, p.status.name()))
                .collect();
            out.push(Match {
                rule: &MULTISIG_OPEN_PROPOSALS,
                evidence: format!("multisig {} open proposals: {}", m.address, list.join(", ")),
            });
        }
    }
    // By id: two uses of a `const` need not share an address.
    out.sort_by_key(|m| ALL.iter().position(|r| r.id == m.rule.id));
    out
}

#[cfg(test)]
mod tests {
    //! Constructed facts, built from the documented layout's fields. The devnet
    //! fixtures in `tests/` exercise the same rules through real account bytes.
    #![allow(clippy::indexing_slicing, reason = "tests index known-length results")]

    use crate::read::Address;

    use super::*;
    use crate::facts::{FoundBy, MultisigFacts, OpenProposal};
    use crate::squads::{Member, Multisig, Permissions, ProposalStatus, TransactionKind};

    fn multisig(threshold: u16, voters: u8, time_lock: u32) -> Multisig {
        Multisig {
            create_key: Address::new([1; 32]),
            config_authority: None,
            threshold,
            time_lock,
            transaction_index: 0,
            stale_transaction_index: 0,
            rent_collector: None,
            bump: 255,
            members: (0..voters)
                .map(|i| Member {
                    key: Address::new([i.saturating_add(10); 32]),
                    permissions: Permissions(7),
                })
                .collect(),
        }
    }

    fn facts_with(ms: Multisig) -> ProgramFacts {
        let mut f = ProgramFacts::new(Address::new([2; 32]));
        f.authority = Some(Authority::SquadsVault {
            vault: Address::new([3; 32]),
            multisig: Address::new([4; 32]),
            index: 0,
            found_by: FoundBy::Index,
        });
        f.multisig = Some(MultisigFacts {
            address: Address::new([4; 32]),
            read_at_slot: 1,
            multisig: ms,
            open_proposals: vec![],
            proposals_not_read: 0,
            stale_approved: vec![],
            stale_not_read: 0,
            undecodable_proposals: vec![],
        });
        f
    }

    fn ids(facts: &ProgramFacts) -> Vec<&'static str> {
        evaluate(facts).iter().map(|m| m.rule.id).collect()
    }

    #[test]
    fn a_strong_multisig_matches_no_rule() {
        assert!(ids(&facts_with(multisig(3, 5, 86_400))).is_empty());
        assert!(ids(&facts_with(multisig(2, 3, 1))).is_empty());
        assert!(
            ids(&facts_with(multisig(2, 4, 1))).is_empty(),
            "exactly half"
        );
    }

    #[test]
    fn time_lock_zero() {
        assert_eq!(
            ids(&facts_with(multisig(2, 3, 0))),
            [MULTISIG_NO_TIME_LOCK.id]
        );
    }

    #[test]
    fn threshold_below_two_and_below_half() {
        assert_eq!(
            ids(&facts_with(multisig(1, 3, 60))),
            [MULTISIG_THRESHOLD_BELOW_TWO.id]
        );
        assert_eq!(
            ids(&facts_with(multisig(0, 0, 60))),
            [MULTISIG_THRESHOLD_BELOW_TWO.id]
        );
        assert_eq!(
            ids(&facts_with(multisig(2, 5, 60))),
            [MULTISIG_THRESHOLD_BELOW_HALF.id]
        );
        // A member without the vote permission does not count.
        let mut ms = multisig(2, 5, 60);
        for m in ms.members.iter_mut().take(2) {
            m.permissions = Permissions(Permissions::INITIATE | Permissions::EXECUTE);
        }
        assert!(ids(&facts_with(ms)).is_empty());
    }

    #[test]
    fn below_half_means_less_than_half_of_the_voters() {
        // 2 of 4 is exactly half: no match. 2 of 5 is less than half: a match.
        assert!(ids(&facts_with(multisig(2, 4, 60))).is_empty());
        assert_eq!(
            ids(&facts_with(multisig(2, 5, 60))),
            [MULTISIG_THRESHOLD_BELOW_HALF.id]
        );
        assert!(ids(&facts_with(multisig(3, 6, 60))).is_empty());
        assert_eq!(
            ids(&facts_with(multisig(3, 7, 60))),
            [MULTISIG_THRESHOLD_BELOW_HALF.id]
        );
        assert!(
            MULTISIG_THRESHOLD_BELOW_HALF
                .title
                .contains("less than half")
        );
        assert!(
            MULTISIG_THRESHOLD_BELOW_HALF
                .explanation
                .contains("less than half")
        );
    }

    fn with_stale(kind: Option<TransactionKind>) -> ProgramFacts {
        let mut f = facts_with(multisig(2, 3, 60));
        if let Some(m) = f.multisig.as_mut() {
            m.multisig.stale_transaction_index = 6;
            m.stale_approved.push(OpenProposal {
                transaction_index: 5,
                address: Address::new([6; 32]),
                status: ProposalStatus::Approved(0),
                approvals: 2,
                transaction_kind: kind,
                check: None,
            });
        }
        f
    }

    #[test]
    fn an_approved_stale_vault_transaction_or_batch_is_still_executable() {
        for (kind, name) in [
            (TransactionKind::Vault, "vault-transaction"),
            (TransactionKind::Batch, "batch"),
        ] {
            let matched = evaluate(&with_stale(Some(kind)));
            assert_eq!(matched.len(), 1);
            assert_eq!(matched[0].rule, &APPROVED_PROPOSAL_STILL_EXECUTABLE);
            assert_eq!(matched[0].rule.severity, Severity::High);
            let end = format!("#5 approved {name}");
            assert!(
                matched[0].evidence.ends_with(&end),
                "{}",
                matched[0].evidence
            );
        }
    }

    #[test]
    fn a_stale_config_transaction_or_one_not_read_matches_nothing() {
        assert!(ids(&with_stale(Some(TransactionKind::Config))).is_empty());
        assert!(ids(&with_stale(None)).is_empty());
    }

    #[test]
    fn a_stale_proposal_that_would_fail_matches_nothing_and_a_kept_one_names_its_check() {
        use crate::execution::Check;
        let mut f = with_stale(Some(TransactionKind::Vault));
        if let Some(m) = f.multisig.as_mut() {
            m.stale_approved[0].check = Some(Check::BufferMissing);
        }
        assert!(ids(&f).is_empty());
        if let Some(m) = f.multisig.as_mut() {
            m.stale_approved[0].check = Some(Check::NotCheckedAlt);
        }
        let matched = evaluate(&f);
        assert_eq!(matched.len(), 1);
        assert!(
            matched[0].evidence.ends_with(
                "#5 approved vault-transaction (check: not-checked-alt; not fully checked: \
                 the message uses address lookup tables)"
            ),
            "{}",
            matched[0].evidence
        );
    }

    #[test]
    fn config_authority_set() {
        let mut ms = multisig(2, 3, 60);
        ms.config_authority = Some(Address::new([5; 32]));
        assert_eq!(ids(&facts_with(ms)), [MULTISIG_CONFIG_AUTHORITY_SET.id]);
    }

    #[test]
    fn open_proposals() {
        let mut f = facts_with(multisig(2, 3, 60));
        if let Some(m) = f.multisig.as_mut() {
            m.open_proposals.push(OpenProposal {
                transaction_index: 4,
                address: Address::new([6; 32]),
                status: ProposalStatus::Approved(0),
                approvals: 2,
                transaction_kind: None,
                check: None,
            });
        }
        let matched = evaluate(&f);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].rule, &MULTISIG_OPEN_PROPOSALS);
        assert!(
            matched[0].evidence.ends_with("#4 approved"),
            "{}",
            matched[0].evidence
        );
    }

    #[test]
    fn single_key_and_unknown_pda_authorities() {
        let mut f = ProgramFacts::new(Address::new([2; 32]));
        f.authority = Some(Authority::SingleKey(Address::new([7; 32])));
        assert_eq!(ids(&f), [SINGLE_KEY_UPGRADE_AUTHORITY.id]);
        f.authority = Some(Authority::UnknownPda(Address::new([8; 32])));
        assert_eq!(ids(&f), [UNKNOWN_PDA_AUTHORITY.id]);
        f.authority = Some(Authority::None);
        assert!(ids(&f).is_empty());
        let weakness: Vec<bool> = ALL.iter().map(|r| r.weakness).collect();
        assert_eq!(weakness, [true, true, true, true, true, true, true, false]);
    }

    #[test]
    fn several_matches_come_in_rule_order() {
        let mut ms = multisig(1, 1, 0);
        ms.config_authority = Some(Address::new([5; 32]));
        assert_eq!(
            ids(&facts_with(ms)),
            [
                MULTISIG_THRESHOLD_BELOW_TWO.id,
                MULTISIG_CONFIG_AUTHORITY_SET.id,
                MULTISIG_NO_TIME_LOCK.id
            ]
        );
    }

    #[test]
    fn rule_ids_are_distinct() {
        for a in ALL {
            for b in ALL {
                assert_eq!(a.id == b.id, std::ptr::eq(a, b));
            }
        }
    }
}
