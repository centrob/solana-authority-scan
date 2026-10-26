//! The read-only RPC interface: the `Rpc` trait, the values it returns, and its error.
//!
//! `Rpc` has typed methods only, one per JSON-RPC read this workspace uses. There is
//! no method that takes a method name or raw JSON, and none that sends, simulates or
//! airdrops; `tests/no_sending.rs` fails if one is added. A transport (`HttpRpc`, or a
//! fake in tests) implements it; request bodies and response parsing are pure, in
//! `json`.

use std::fmt;

use crate::read::cluster::Cluster;
use crate::read::codec::{Address, Hash, Signature};

/// The commitment every read uses.
pub const COMMITMENT: &str = "finalized";
/// The account data encoding every read asks for.
pub const ENCODING: &str = "base64";
/// The most addresses one `get_multiple_accounts` call takes (the RPC's own limit).
pub const MAX_MULTIPLE_ACCOUNTS: usize = 100;
/// The most signatures one `get_signatures_for_address` call returns (the RPC's limit).
pub const MAX_SIGNATURES: u16 = 1000;
/// The most characters of server text that reach an error message.
pub const MAX_SERVER_TEXT: usize = 200;

/// A value and the slot the node read it at (the RPC's `context.slot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slotted<T> {
    pub slot: u64,
    pub value: T,
}

/// An account as the chain returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub lamports: u64,
    /// The owning program.
    pub owner: Address,
    /// The account data, or the requested slice of it.
    pub data: Vec<u8>,
    pub executable: bool,
}

/// An account with its address, as `get_program_accounts` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyedAccount {
    pub address: Address,
    pub account: Account,
}

/// A server-side filter for `get_program_accounts`. All filters must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// The account data is exactly this many bytes.
    DataSize(u64),
    /// The account data holds `bytes` at `offset`.
    Memcmp { offset: u64, bytes: Vec<u8> },
}

/// The part of each account's data to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSlice {
    pub offset: u64,
    pub length: u64,
}

/// What `get_program_accounts` asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramAccountsQuery {
    pub filters: Vec<Filter>,
    pub data_slice: Option<DataSlice>,
}

/// Paging for `get_signatures_for_address`. Signatures come newest first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignaturesQuery {
    /// 1 to `MAX_SIGNATURES`; the RPC's default (1000) when `None`.
    pub limit: Option<u16>,
    /// Start after this signature.
    pub before: Option<Signature>,
    /// Stop at this signature.
    pub until: Option<Signature>,
}

/// One entry of `get_signatures_for_address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    pub signature: Signature,
    pub slot: u64,
    /// The transaction failed (its `err` is set).
    pub failed: bool,
    /// Unix seconds, when the node knows it.
    pub block_time: Option<i64>,
}

/// The accounts a v0 transaction loaded from address lookup tables, in the order the
/// node lists them. They follow the transaction's static account keys. Empty for a
/// legacy transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadedAddresses {
    pub writable: Vec<Address>,
    pub readonly: Vec<Address>,
}

/// The status part of a transaction, when the node returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionMeta {
    pub failed: bool,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    /// Program log lines exactly as the node sent them. Untrusted text: sanitise
    /// before printing.
    pub log_messages: Vec<String>,
    /// `meta.loadedAddresses`.
    pub loaded_addresses: LoadedAddresses,
}

/// A confirmed transaction as `get_transaction` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRecord {
    pub slot: u64,
    pub block_time: Option<i64>,
    /// The signed transaction in wire format, to be decoded by the caller.
    pub transaction: Vec<u8>,
    pub meta: Option<TransactionMeta>,
}

/// Why a read failed. No variant can hold the RPC URL's path, query or credentials:
/// `endpoint` is the redacted form from `RpcUrl::redacted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// The request did not complete. `reason` never holds the URL.
    Transport { endpoint: String, reason: String },
    /// The server answered with an HTTP error status.
    Status { endpoint: String, code: u16 },
    /// The server returned a JSON-RPC error object. `message` is sanitised.
    Server { code: i64, message: String },
    /// The response is not what the method returns.
    BadResponse(&'static str),
    /// The request was refused before it was sent.
    BadRequest(&'static str),
    /// The endpoint's genesis hash is not the expected cluster's.
    WrongCluster { expected: Cluster, found: Hash },
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { endpoint, reason } => {
                write!(f, "RPC request to {endpoint} failed: {reason}")
            }
            Self::Status { endpoint, code } => write!(f, "RPC {endpoint} answered HTTP {code}"),
            Self::Server { code, message } => write!(f, "RPC error {code}: {message}"),
            Self::BadResponse(reason) => write!(f, "unexpected RPC response: {reason}"),
            Self::BadRequest(reason) => write!(f, "request refused: {reason}"),
            Self::WrongCluster { expected, found } => write!(
                f,
                "the RPC endpoint is not on {} (its genesis hash is {found})",
                expected.name()
            ),
        }
    }
}

impl std::error::Error for RpcError {}

/// Reads from one cluster. Typed methods only; nothing here can change chain state.
pub trait Rpc {
    /// The cluster's genesis hash.
    fn get_genesis_hash(&self) -> Result<Hash, RpcError>;

    /// The account at `address`, or `None` if there is none, and the slot it was read at.
    fn get_account_info(&self, address: &Address) -> Result<Slotted<Option<Account>>, RpcError>;

    /// The accounts at `addresses` (at most `MAX_MULTIPLE_ACCOUNTS`), in the same order;
    /// `None` where there is none. One slot for all of them.
    fn get_multiple_accounts(
        &self,
        addresses: &[Address],
    ) -> Result<Slotted<Vec<Option<Account>>>, RpcError>;

    /// The accounts owned by `program` that match every filter in `query`, and the slot
    /// they were read at.
    fn get_program_accounts(
        &self,
        program: &Address,
        query: &ProgramAccountsQuery,
    ) -> Result<Slotted<Vec<KeyedAccount>>, RpcError>;

    /// Signatures of transactions that touched `address`, newest first.
    fn get_signatures_for_address(
        &self,
        address: &Address,
        query: &SignaturesQuery,
    ) -> Result<Vec<SignatureInfo>, RpcError>;

    /// The transaction with `signature`, or `None` if the node has none.
    fn get_transaction(&self, signature: &Signature)
    -> Result<Option<TransactionRecord>, RpcError>;
}

/// Server text made safe to print: at most `MAX_SERVER_TEXT` characters, each control
/// or non-printable character escaped (`\n`, `\u{1b}`), and `...` when cut short. A
/// backslash is doubled, so text that spells out an escape (a typed `\n`) never looks
/// like an escaped control character.
pub fn sanitise(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_SERVER_TEXT));
    let mut chars = text.chars();
    for c in chars.by_ref().take(MAX_SERVER_TEXT) {
        match c {
            '"' | '\'' => out.push(c),
            _ => out.extend(c.escape_debug()),
        }
    }
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_escapes_control_text_and_caps_length() {
        assert_eq!(sanitise("plain \"text\" ok"), "plain \"text\" ok");
        // A typed escape and the control character it names come out different.
        assert_eq!(sanitise("a\\nb"), "a\\\\nb");
        assert_eq!(sanitise("a\nb"), "a\\nb");
        assert_eq!(sanitise("\\u{202e}"), "\\\\u{202e}");
        assert_eq!(sanitise("a\r\n\tb\u{7}"), "a\\r\\n\\tb\\u{7}");
        assert_eq!(sanitise("x\u{202e}y"), "x\\u{202e}y");
        let long = "a".repeat(MAX_SERVER_TEXT + 1);
        assert_eq!(
            sanitise(&long),
            format!("{}...", "a".repeat(MAX_SERVER_TEXT))
        );
        let exact = "a".repeat(MAX_SERVER_TEXT);
        assert_eq!(sanitise(&exact), exact);
    }
}
