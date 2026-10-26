//! JSON-RPC request bodies and response parsing for the `Rpc` methods. Pure; no I/O.
//! Text the server controls is untrusted: every address, hash and signature must decode
//! to its exact length, every number must fit its type, and a server error message is
//! sanitised before it reaches an error.

use serde_json::{Map, Value, json};

use crate::read::codec::{Address, Hash, Signature, decode_base64, encode_base64};
use crate::read::rpc::{
    Account, COMMITMENT, ENCODING, Filter, KeyedAccount, LoadedAddresses, MAX_MULTIPLE_ACCOUNTS,
    MAX_SIGNATURES, ProgramAccountsQuery, RpcError, SignatureInfo, SignaturesQuery, Slotted,
    TransactionMeta, TransactionRecord, sanitise,
};

/// The method names this crate sends. Constants, so the list is in one place.
pub mod method {
    pub const GET_GENESIS_HASH: &str = "getGenesisHash";
    pub const GET_ACCOUNT_INFO: &str = "getAccountInfo";
    pub const GET_MULTIPLE_ACCOUNTS: &str = "getMultipleAccounts";
    pub const GET_PROGRAM_ACCOUNTS: &str = "getProgramAccounts";
    pub const GET_SIGNATURES_FOR_ADDRESS: &str = "getSignaturesForAddress";
    pub const GET_TRANSACTION: &str = "getTransaction";
}

fn request(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

fn account_config() -> Value {
    json!({"encoding": ENCODING, "commitment": COMMITMENT})
}

pub fn genesis_hash_request() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method::GET_GENESIS_HASH})
}

pub fn account_info_request(address: &Address) -> Value {
    request(
        method::GET_ACCOUNT_INFO,
        json!([address.to_string(), account_config()]),
    )
}

pub fn multiple_accounts_request(addresses: &[Address]) -> Result<Value, RpcError> {
    if addresses.is_empty() || addresses.len() > MAX_MULTIPLE_ACCOUNTS {
        return Err(RpcError::BadRequest("between 1 and 100 addresses per call"));
    }
    let keys: Vec<String> = addresses.iter().map(Address::to_string).collect();
    Ok(request(
        method::GET_MULTIPLE_ACCOUNTS,
        json!([keys, account_config()]),
    ))
}

pub fn program_accounts_request(program: &Address, query: &ProgramAccountsQuery) -> Value {
    let filters: Vec<Value> = query
        .filters
        .iter()
        .map(|filter| match filter {
            Filter::DataSize(size) => json!({"dataSize": size}),
            Filter::Memcmp { offset, bytes } => json!({"memcmp": {
                "offset": offset,
                "bytes": encode_base64(bytes),
                "encoding": "base64",
            }}),
        })
        .collect();
    let mut config = Map::new();
    config.insert("encoding".to_owned(), json!(ENCODING));
    config.insert("commitment".to_owned(), json!(COMMITMENT));
    // The result then carries the slot it was read at, like the other account reads.
    config.insert("withContext".to_owned(), json!(true));
    if !filters.is_empty() {
        config.insert("filters".to_owned(), Value::Array(filters));
    }
    if let Some(slice) = query.data_slice {
        config.insert(
            "dataSlice".to_owned(),
            json!({"offset": slice.offset, "length": slice.length}),
        );
    }
    request(
        method::GET_PROGRAM_ACCOUNTS,
        json!([program.to_string(), Value::Object(config)]),
    )
}

pub fn signatures_request(address: &Address, query: &SignaturesQuery) -> Result<Value, RpcError> {
    let mut config = Map::new();
    config.insert("commitment".to_owned(), json!(COMMITMENT));
    if let Some(limit) = query.limit {
        if limit == 0 || limit > MAX_SIGNATURES {
            return Err(RpcError::BadRequest("limit is between 1 and 1000"));
        }
        config.insert("limit".to_owned(), json!(limit));
    }
    if let Some(before) = query.before {
        config.insert("before".to_owned(), json!(before.to_string()));
    }
    if let Some(until) = query.until {
        config.insert("until".to_owned(), json!(until.to_string()));
    }
    Ok(request(
        method::GET_SIGNATURES_FOR_ADDRESS,
        json!([address.to_string(), Value::Object(config)]),
    ))
}

pub fn transaction_request(signature: &Signature) -> Value {
    request(
        method::GET_TRANSACTION,
        json!([signature.to_string(), {
            "encoding": ENCODING,
            "commitment": COMMITMENT,
            "maxSupportedTransactionVersion": 0,
        }]),
    )
}

/// The `result` of a JSON-RPC response, or its error.
fn result_of(body: &str) -> Result<Value, RpcError> {
    let mut value: Value =
        serde_json::from_str(body).map_err(|_| RpcError::BadResponse("not JSON"))?;
    // `"error": null` is no error.
    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = sanitise(error.get("message").and_then(Value::as_str).unwrap_or(""));
        return Err(RpcError::Server { code, message });
    }
    value
        .get_mut("result")
        .map(Value::take)
        .ok_or(RpcError::BadResponse("no result"))
}

/// The slot and `value` of a `{context: {slot}, value}` result.
fn context_value(body: &str) -> Result<Slotted<Value>, RpcError> {
    let mut result = result_of(body)?;
    let slot = result
        .get("context")
        .and_then(|context| context.get("slot"))
        .and_then(Value::as_u64)
        .ok_or(RpcError::BadResponse("no context slot"))?;
    let value = result
        .get_mut("value")
        .map(Value::take)
        .ok_or(RpcError::BadResponse("no value"))?;
    Ok(Slotted { slot, value })
}

fn address_list(value: &Value, key: &'static str) -> Result<Vec<Address>, RpcError> {
    let Some(items) = value.get(key).and_then(Value::as_array) else {
        return Err(RpcError::BadResponse(key));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(|text| text.parse().ok())
                .ok_or(RpcError::BadResponse(key))
        })
        .collect()
}

/// `meta.loadedAddresses`: the accounts a v0 transaction loaded from lookup tables.
/// Absent or null (a legacy transaction, or an older node) is none.
fn loaded_addresses(meta: &Value) -> Result<LoadedAddresses, RpcError> {
    match meta.get("loadedAddresses") {
        None | Some(Value::Null) => Ok(LoadedAddresses::default()),
        Some(loaded) => Ok(LoadedAddresses {
            writable: address_list(loaded, "writable")?,
            readonly: address_list(loaded, "readonly")?,
        }),
    }
}

fn u64_field(value: &Value, key: &'static str) -> Result<u64, RpcError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(RpcError::BadResponse(key))
}

fn optional_i64(value: &Value, key: &'static str) -> Result<Option<i64>, RpcError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_i64().map(Some).ok_or(RpcError::BadResponse(key)),
    }
}

fn u64_list(value: &Value, key: &'static str) -> Result<Vec<u64>, RpcError> {
    let Some(items) = value.get(key).and_then(Value::as_array) else {
        return Err(RpcError::BadResponse(key));
    };
    items
        .iter()
        .map(|item| item.as_u64().ok_or(RpcError::BadResponse(key)))
        .collect()
}

/// Bytes sent as `[text, "base64"]`.
fn base64_data(value: Option<&Value>) -> Result<Vec<u8>, RpcError> {
    let Some([Value::String(encoded), Value::String(encoding)]) =
        value.and_then(Value::as_array).map(Vec::as_slice)
    else {
        return Err(RpcError::BadResponse("data is not [text, encoding]"));
    };
    if encoding != ENCODING {
        return Err(RpcError::BadResponse("data is not base64"));
    }
    decode_base64(encoded).map_err(|_| RpcError::BadResponse("data is not valid base64"))
}

fn parse_account(value: &Value) -> Result<Account, RpcError> {
    let owner = value
        .get("owner")
        .and_then(Value::as_str)
        .ok_or(RpcError::BadResponse("no owner"))?
        .parse::<Address>()
        .map_err(|_| RpcError::BadResponse("owner is not a 32-byte base58 key"))?;
    let executable = value
        .get("executable")
        .and_then(Value::as_bool)
        .ok_or(RpcError::BadResponse("executable"))?;
    Ok(Account {
        lamports: u64_field(value, "lamports")?,
        owner,
        data: base64_data(value.get("data"))?,
        executable,
    })
}

fn parse_optional_account(value: &Value) -> Result<Option<Account>, RpcError> {
    if value.is_null() {
        return Ok(None);
    }
    parse_account(value).map(Some)
}

pub fn parse_genesis_hash(body: &str) -> Result<Hash, RpcError> {
    match result_of(body)? {
        Value::String(text) => text
            .parse()
            .map_err(|_| RpcError::BadResponse("genesis hash is not 32-byte base58")),
        _ => Err(RpcError::BadResponse("genesis hash is not a string")),
    }
}

pub fn parse_account_info(body: &str) -> Result<Slotted<Option<Account>>, RpcError> {
    let Slotted { slot, value } = context_value(body)?;
    Ok(Slotted {
        slot,
        value: parse_optional_account(&value)?,
    })
}

/// `expected` is how many addresses were asked for; any other count is refused.
pub fn parse_multiple_accounts(
    body: &str,
    expected: usize,
) -> Result<Slotted<Vec<Option<Account>>>, RpcError> {
    let Slotted { slot, value } = context_value(body)?;
    let items = value
        .as_array()
        .ok_or(RpcError::BadResponse("value is not a list"))?;
    if items.len() != expected {
        return Err(RpcError::BadResponse("wrong number of accounts"));
    }
    Ok(Slotted {
        slot,
        value: items
            .iter()
            .map(parse_optional_account)
            .collect::<Result<_, _>>()?,
    })
}

/// The request asks for `withContext`, so the result is `{context, value}`.
pub fn parse_program_accounts(body: &str) -> Result<Slotted<Vec<KeyedAccount>>, RpcError> {
    let Slotted { slot, value } = context_value(body)?;
    let items = value
        .as_array()
        .ok_or(RpcError::BadResponse("value is not a list"))?;
    let accounts = items
        .iter()
        .map(|item| {
            let address = item
                .get("pubkey")
                .and_then(Value::as_str)
                .ok_or(RpcError::BadResponse("no pubkey"))?
                .parse::<Address>()
                .map_err(|_| RpcError::BadResponse("pubkey is not a 32-byte base58 key"))?;
            let account = parse_account(
                item.get("account")
                    .ok_or(RpcError::BadResponse("no account"))?,
            )?;
            Ok(KeyedAccount { address, account })
        })
        .collect::<Result<_, _>>()?;
    Ok(Slotted {
        slot,
        value: accounts,
    })
}

pub fn parse_signatures(body: &str) -> Result<Vec<SignatureInfo>, RpcError> {
    let result = result_of(body)?;
    let items = result
        .as_array()
        .ok_or(RpcError::BadResponse("result is not a list"))?;
    items
        .iter()
        .map(|item| {
            let signature = item
                .get("signature")
                .and_then(Value::as_str)
                .ok_or(RpcError::BadResponse("no signature"))?
                .parse::<Signature>()
                .map_err(|_| RpcError::BadResponse("signature is not 64-byte base58"))?;
            Ok(SignatureInfo {
                signature,
                slot: u64_field(item, "slot")?,
                failed: !item.get("err").is_none_or(Value::is_null),
                block_time: optional_i64(item, "blockTime")?,
            })
        })
        .collect()
}

pub fn parse_transaction(body: &str) -> Result<Option<TransactionRecord>, RpcError> {
    let result = result_of(body)?;
    if result.is_null() {
        return Ok(None);
    }
    let meta = match result.get("meta") {
        None | Some(Value::Null) => None,
        Some(meta) => {
            let log_messages = match meta.get("logMessages") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(lines)) => lines
                    .iter()
                    .map(|line| {
                        line.as_str()
                            .map(str::to_owned)
                            .ok_or(RpcError::BadResponse("logMessages"))
                    })
                    .collect::<Result<_, _>>()?,
                Some(_) => return Err(RpcError::BadResponse("logMessages")),
            };
            Some(TransactionMeta {
                failed: !meta.get("err").is_none_or(Value::is_null),
                fee: u64_field(meta, "fee")?,
                pre_balances: u64_list(meta, "preBalances")?,
                post_balances: u64_list(meta, "postBalances")?,
                log_messages,
                loaded_addresses: loaded_addresses(meta)?,
            })
        }
    };
    Ok(Some(TransactionRecord {
        slot: u64_field(&result, "slot")?,
        block_time: optional_i64(&result, "blockTime")?,
        transaction: base64_data(result.get("transaction"))?,
        meta,
    }))
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
