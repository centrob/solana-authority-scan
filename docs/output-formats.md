# Output formats

The scanner writes three things: a Markdown summary, a JSON report, and, when a rule
matched, a candidate document. Without `--out`, it prints the Markdown (or the JSON with
`--json`) to stdout and writes no candidate document.

| File (with `--out`) | Written | Holds |
|---|---|---|
| `authority-scan.md` | always | The Markdown summary |
| `authority-scan.json` | always | The JSON report |
| `candidates.json` | when at least one rule matched | One candidate finding per matched rule. When no rule matched, none is written, and one left by an earlier run in the same directory is removed |

Everything in the outputs is built from decoded chain values (addresses, numbers),
fixed text, or error messages that already redact the RPC URL and sanitise server
text. No output ever says "safe": a clean result is "no rule matched".

## Result text

Each program's `result` is one of:

- `no rule matched` or `N rules matched`;
- `scan incomplete`: the scan stopped early (the report's `error` says why; exit 2);
- `scan incomplete: … in what was read`: the scan ran to the end, but a search was not
  possible, a proposal did not decode, or some open proposals were not read.

## JSON report

Schema `solana-authority-scan/report`, `schema_version` 1. A field may be added in a
later version 1 report; a change to an existing field's meaning or shape bumps the
version.

Top level:

| Field | Meaning |
|---|---|
| `schema`, `schema_version` | `"solana-authority-scan/report"`, `1` |
| `tool`, `tool_version` | `"solana-authority-scan"` and the crate version |
| `cluster` | `mainnet`, `devnet` or `testnet` |
| `squads_v4_index` | `{available: true, slot, multisigs, max_vault_index}` or `{available: false, reason}` |
| `programs` | One object per program, in the order given |
| `candidates` | Every matched rule as a candidate, with its rule id (below) |
| `cannot_see` | What no scan can see, as text |
| `nonce_note` | Why a nonce count is information only |
| `note` | What "no rule matched" does and does not mean |

Each program:

| Field | Meaning |
|---|---|
| `program` | The program id |
| `read_at_slot` | The slot the program's accounts were read at |
| `loader` | `bpf-upgradeable`, `bpf-loader-2`, `bpf-loader-1`, `loader-v4`, `builtin`, or null when the scan stopped first |
| `programdata` | The ProgramData address (upgradeable loader), else null |
| `last_deploy_slot` | From ProgramData or the loader-v4 header, else null |
| `loader_v4_status` | `retracted`, `deployed` or `finalized` for a loader-v4 program, else null |
| `authority` | `{kind, address, multisig, vault_index, found_by}`; `kind` is `none`, `builtin`, `single-key`, `squads-v4-vault` or `unknown-pda`, and `found_by` (vaults only) is `squads-v4-index`, `recent-signatures` or `supplied-multisig` |
| `multisig` | For a Squads v4 vault: the decoded multisig (below), else null |
| `nonce_accounts_by_signer` | `[{key, count}]` when the nonce search ran, else null |
| `matched_rules` | Rule ids, in report order |
| `result` | The result text above |
| `searches_not_possible` | `[{search, reason}]`: each search that could not be made, and why. `search` is `squads-v4-index`, `recent-signatures`, `open-proposals`, `stale-approved-proposals`, `stale-transaction-kinds` (a stale approved proposal's transaction account was not read; added in 0.1.1), `supplied-multisig` or `durable-nonces` |
| `error` | Why the scan stopped early, else null |

The multisig:

| Field | Meaning |
|---|---|
| `address`, `read_at_slot` | The multisig account and the slot it was read at |
| `threshold`, `voting_members`, `time_lock_seconds` | As decoded; `voting_members` counts members with the vote permission |
| `config_authority`, `rent_collector` | Addresses, or null when none |
| `transaction_index`, `stale_transaction_index` | As decoded |
| `members` | `[{key, permissions, mask}]`; `permissions` names the bits (`initiate`, `vote`, `execute`) |
| `open_proposals` | `[{transaction_index, address, status, approvals}]` in the open range |
| `proposals_not_read` | Open-range indexes older than the newest 500, not read |
| `stale_approved_proposals` | Approved or executing proposals in the stale window, same shape plus `transaction_kind`: `vault-transaction`, `config-transaction` or `batch`, or null when the transaction account was not read (then `searches_not_possible` has a `stale-transaction-kinds` entry). Added in 0.1.1, within version 1. Only vault transactions and batches match `approved-proposal-still-executable`. Also `check` (added in 0.1.2, within version 1): for a vault transaction or batch, the outcome of the would-it-fail check below; null for a config transaction or a transaction not read |
| `stale_proposals_not_read` | Indexes at or below the stale index older than the window |
| `undecodable_proposals` | `[{transaction_index, address, error}]` |

`check` values. The first seven mean executing the proposal now would certainly fail,
so it does not match `approved-proposal-still-executable`; the rest keep the match, and
the rule's evidence names them (`#5 approved vault-transaction (check: not-checked-alt;
not fully checked: …)`). How each is decided: [how-it-works.md](how-it-works.md),
"Would it still execute?".

| `check` | Flagged | Meaning |
|---|---|---|
| `buffer-missing` | no | An `Upgrade` whose buffer account does not exist |
| `buffer-not-loader-owned` | no | An `Upgrade` whose buffer is owned by another program |
| `buffer-not-buffer-state` | no | An `Upgrade` whose buffer account is not in the Buffer state |
| `buffer-wrong-authority` | no | An `Upgrade` whose buffer has no authority, or not the instruction's authority |
| `account-missing` | no | A `SetAuthority`, `SetAuthorityChecked` or `Close` whose account does not exist |
| `account-not-loader-owned` | no | The same, with the account owned by another program |
| `account-wrong-authority` | no | A `SetAuthority` or `SetAuthorityChecked` whose account has no authority or another one, or a `Close` of a buffer with another authority |
| `no-loader-instruction` | yes | No upgradeable-loader instruction; nothing in the message is checked |
| `not-shown-to-fail` | yes | Every loader instruction that could be checked looked executable, or none could be checked. Not a claim that it would succeed |
| `not-checked-alt` | yes | The message uses address lookup tables: not fully checked |
| `not-checked-undecodable` | yes | The transaction, batch or batch transaction did not decode, or names a key outside the message |
| `not-checked-batch` | yes | A batch with no transaction left, or whose next transaction account is not Squads v4's |
| `not-checked-read-failed` | yes | A read the check needed failed |

Each entry of `candidates` has the candidate fields below plus `rule` (the rule id) and
`source`.

## Candidate document (`candidates.json`)

The `dv-candidates` interchange format, version 1: the format review tools use to take
in candidate findings from scanners and other tools. A reader can import the scanner's
`candidates.json` unchanged.

```json
{
  "format": "dv-candidates",
  "version": 1,
  "candidates": [
    {
      "source": "tool:solana-authority-scan",
      "finding": {
        "title": "One key can upgrade the program",
        "severity": "high",
        "category": "admin-plane",
        "location": "program 8eYh1HSHzX2aqqbQU1thPGu1ZwCYMv2Uf2r45oy5K3m3",
        "description": "The upgrade authority is an address on the ed25519 curve, ...",
        "evidence": "upgrade authority 18W1HSbXvKGny4oRBjZPdkCKVQsPyhjrZeNeDPqUvh2 is on the ed25519 curve (read at slot 515444744)",
        "recommendation": "Move the upgrade authority to a multisig vault ..."
      }
    }
  ]
}
```

(The example is from a devnet test program.)

Rules for the document, which the scanner checks before it writes one
(`candidate::document`) and `candidate::parse_document` checks on reading:

- `format` is `"dv-candidates"` and `version` is `1`. Any change to the shape bumps the
  version.
- `candidates` has at least one entry. Unknown fields are refused, at every level.
- `source` is `tool:<name>`, where a name is 1 to 64 lowercase letters, digits, `-` and
  `_`. This scanner always writes `tool:solana-authority-scan`.
- Each entry the scanner writes has a `finding`. (The format also allows other tools to
  write `section` entries, report prose for one named slot, instead of a finding; this
  crate never writes them and its parser does not read them.) An entry never carries an
  `id`: a reader assigns ids when it imports.
- `severity` is one of `critical`, `high`, `medium`, `low`, `info`.
- Every text field is non-empty, at most 20,000 characters, with no control character
  except newline and tab, no bidirectional or zero-width mark, and none of U+2028,
  U+2029, U+FEFF and U+061C. `title`, `category` and `location` are one line.
- `category` is `admin-plane` for every rule of this scanner, and `location` is
  `program <id>`. `evidence` ends with the slot it was read at.

A candidate is unreviewed tool output: something for a person to check against the
chain and the context, not a conclusion.
