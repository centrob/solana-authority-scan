//! A read-only Solana client. It reads accounts and transactions and derives
//! addresses; it cannot sign, send, simulate or airdrop, and holds no keys.
//!
//! - Pure layer, no I/O: base58 and base64 ([`codec`]), the [`Address`], [`Hash`] and
//!   [`Signature`] types, program derived addresses and the ed25519 on-curve check
//!   ([`pda`]).
//! - [`Rpc`]: typed JSON-RPC reads. [`HttpRpc`] (feature `http`, on by default) is the
//!   blocking HTTPS transport; it checks the cluster's genesis hash before any other
//!   call. The RPC URL comes only from the environment ([`RpcUrl::from_env`]) and is
//!   never printed. Request bodies and response parsing are pure, in [`json`], so
//!   another transport reuses them.

mod base58;
pub mod cluster;
pub mod codec;
#[cfg(feature = "http")]
mod http;
pub mod json;
pub mod pda;
pub mod rpc;
pub mod url;

pub use cluster::{Cluster, check_cluster, checked};
pub use codec::{Address, Hash, ParseError, Signature, decode_base64, encode_base64};
#[cfg(feature = "http")]
pub use http::HttpRpc;
pub use pda::{PdaError, create_program_address, find_program_address, is_on_curve};
pub use rpc::{
    Account, DataSlice, Filter, KeyedAccount, LoadedAddresses, ProgramAccountsQuery, Rpc, RpcError,
    SignatureInfo, SignaturesQuery, Slotted, TransactionMeta, TransactionRecord, sanitise,
};
pub use url::{RpcUrl, UrlError};
