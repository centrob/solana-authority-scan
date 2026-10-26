//! Tests for the request bodies and response parsers, on saved and hand-built responses.
//! Method names come from `method`: `tests/no_sending.rs` refuses method-name literals
//! anywhere else, and checks the constants' values.

#![allow(clippy::indexing_slicing, reason = "tests index known-length results")]

use super::*;
use crate::read::rpc::DataSlice;

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

fn token_program() -> Address {
    TOKEN_PROGRAM.parse().unwrap()
}

fn signature(byte: u8) -> Signature {
    Signature::new([byte; 64])
}

fn account_json(owner: &str, data: &str) -> String {
    format!(r#"{{"lamports":5,"owner":"{owner}","data":{data},"executable":false}}"#)
}

fn context_body(value: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","result":{{"context":{{"slot":1}},"value":{value}}},"id":1}}"#)
}

#[test]
fn parses_a_saved_mint_account() {
    // A saved devnet `getAccountInfo` response for the devnet USDC mint
    // (`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, 82 bytes of SPL Token mint data).
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rpc/devnet-usdc-mint.json");
    let body = std::fs::read_to_string(path).unwrap();
    let read = parse_account_info(&body).unwrap();
    assert_eq!(read.slot, 514_919_960);
    let account = read.value.unwrap();
    assert_eq!(account.owner, token_program());
    assert_eq!(account.data.len(), 82);
    assert_eq!(account.lamports, 454_525_905_289);
    assert!(!account.executable);
}

#[test]
fn builds_finalized_base64_requests() {
    assert_eq!(
        genesis_hash_request(),
        json!({"jsonrpc": "2.0", "id": 1, "method": method::GET_GENESIS_HASH})
    );
    assert_eq!(
        account_info_request(&token_program()),
        json!({
            "jsonrpc": "2.0", "id": 1, "method": method::GET_ACCOUNT_INFO,
            "params": [TOKEN_PROGRAM, {"encoding": "base64", "commitment": "finalized"}],
        })
    );
    assert_eq!(
        transaction_request(&signature(1)),
        json!({
            "jsonrpc": "2.0", "id": 1, "method": method::GET_TRANSACTION,
            "params": [signature(1).to_string(), {
                "encoding": "base64", "commitment": "finalized",
                "maxSupportedTransactionVersion": 0,
            }],
        })
    );
}

#[test]
fn builds_a_program_accounts_request_with_filters_and_a_slice() {
    let query = ProgramAccountsQuery {
        filters: vec![
            Filter::DataSize(165),
            Filter::Memcmp {
                offset: 32,
                bytes: b"solana".to_vec(),
            },
        ],
        data_slice: Some(DataSlice {
            offset: 0,
            length: 64,
        }),
    };
    assert_eq!(
        program_accounts_request(&token_program(), &query),
        json!({
            "jsonrpc": "2.0", "id": 1, "method": method::GET_PROGRAM_ACCOUNTS,
            "params": [TOKEN_PROGRAM, {
                "encoding": "base64", "commitment": "finalized", "withContext": true,
                "filters": [
                    {"dataSize": 165},
                    {"memcmp": {"offset": 32, "bytes": "c29sYW5h", "encoding": "base64"}},
                ],
                "dataSlice": {"offset": 0, "length": 64},
            }],
        })
    );
    let bare = program_accounts_request(&token_program(), &ProgramAccountsQuery::default());
    assert_eq!(
        bare["params"][1],
        json!({"encoding": "base64", "commitment": "finalized", "withContext": true})
    );
}

#[test]
fn bounds_multiple_accounts_and_signature_limits() {
    let one = [token_program()];
    assert!(multiple_accounts_request(&one).is_ok());
    assert!(multiple_accounts_request(&[]).is_err());
    let too_many = vec![token_program(); MAX_MULTIPLE_ACCOUNTS + 1];
    assert!(multiple_accounts_request(&too_many).is_err());

    let address = token_program();
    for bad in [0, MAX_SIGNATURES + 1] {
        let query = SignaturesQuery {
            limit: Some(bad),
            ..SignaturesQuery::default()
        };
        assert!(signatures_request(&address, &query).is_err(), "{bad}");
    }
    let query = SignaturesQuery {
        limit: Some(10),
        before: Some(signature(2)),
        until: None,
    };
    assert_eq!(
        signatures_request(&address, &query).unwrap()["params"][1],
        json!({"commitment": "finalized", "limit": 10, "before": signature(2).to_string()})
    );
}

#[test]
fn reads_missing_accounts_as_none() {
    assert_eq!(
        parse_account_info(&context_body("null")),
        Ok(Slotted {
            slot: 1,
            value: None
        })
    );
    let both = format!(
        "[null,{}]",
        account_json(SYSTEM_PROGRAM, r#"["AAE=","base64"]"#)
    );
    let read = parse_multiple_accounts(&context_body(&both), 2).unwrap();
    assert_eq!(read.slot, 1);
    let accounts = read.value;
    assert_eq!(accounts[0], None);
    assert_eq!(accounts[1].as_ref().unwrap().data, vec![0, 1]);
    assert_eq!(
        parse_multiple_accounts(&context_body(&both), 3),
        Err(RpcError::BadResponse("wrong number of accounts"))
    );
}

#[test]
fn refuses_a_context_read_without_a_slot() {
    let no_slot = r#"{"jsonrpc":"2.0","result":{"context":{},"value":null},"id":1}"#;
    let negative = r#"{"jsonrpc":"2.0","result":{"context":{"slot":-1},"value":null},"id":1}"#;
    let no_context = r#"{"jsonrpc":"2.0","result":{"value":null},"id":1}"#;
    let bare_list = r#"{"jsonrpc":"2.0","result":[],"id":1}"#;
    for body in [no_slot, negative, no_context, bare_list] {
        let missing = RpcError::BadResponse("no context slot");
        assert_eq!(parse_account_info(body), Err(missing.clone()), "{body}");
        assert_eq!(
            parse_multiple_accounts(body, 0),
            Err(missing.clone()),
            "{body}"
        );
        assert_eq!(parse_program_accounts(body), Err(missing), "{body}");
    }
}

#[test]
fn refuses_an_owner_that_is_not_a_key() {
    for bad in ["x", "", "0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl", "a\\nb"] {
        assert_eq!(
            parse_account_info(&context_body(&account_json(bad, r#"["AA==","base64"]"#))),
            Err(RpcError::BadResponse("owner is not a 32-byte base58 key")),
            "{bad}"
        );
    }
}

#[test]
fn refuses_data_that_is_not_base64() {
    let cases = [
        (r#"["AA==","base58"]"#, "data is not base64"),
        (r#"["!!","base64"]"#, "data is not valid base64"),
        (r#""AA==""#, "data is not [text, encoding]"),
    ];
    for (data, reason) in cases {
        assert_eq!(
            parse_account_info(&context_body(&account_json(TOKEN_PROGRAM, data))),
            Err(RpcError::BadResponse(reason)),
            "{data}"
        );
    }
}

#[test]
fn parses_program_accounts() {
    let body = context_body(&format!(
        r#"[{{"pubkey":"{TOKEN_PROGRAM}","account":{}}}]"#,
        account_json(SYSTEM_PROGRAM, r#"["","base64"]"#)
    ));
    let read = parse_program_accounts(&body).unwrap();
    assert_eq!(read.slot, 1);
    let accounts = read.value;
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].address, token_program());
    assert!(accounts[0].account.data.is_empty());
    let bad = body.replace(TOKEN_PROGRAM, "short");
    assert_eq!(
        parse_program_accounts(&bad),
        Err(RpcError::BadResponse("pubkey is not a 32-byte base58 key"))
    );
}

#[test]
fn parses_signatures() {
    let body = format!(
        r#"{{"jsonrpc":"2.0","result":[
            {{"signature":"{}","slot":7,"err":null,"memo":null,"blockTime":1700000000}},
            {{"signature":"{}","slot":6,"err":{{"InstructionError":[0,"Custom"]}},"blockTime":null}}
        ],"id":1}}"#,
        signature(3),
        signature(4)
    );
    let entries = parse_signatures(&body).unwrap();
    assert_eq!(
        entries,
        vec![
            SignatureInfo {
                signature: signature(3),
                slot: 7,
                failed: false,
                block_time: Some(1_700_000_000),
            },
            SignatureInfo {
                signature: signature(4),
                slot: 6,
                failed: true,
                block_time: None,
            },
        ]
    );
    let short = body.replace(&signature(3).to_string(), TOKEN_PROGRAM);
    assert_eq!(
        parse_signatures(&short),
        Err(RpcError::BadResponse("signature is not 64-byte base58"))
    );
}

#[test]
fn parses_a_transaction() {
    let body = r#"{"jsonrpc":"2.0","result":{"slot":9,"blockTime":null,
        "meta":{"err":null,"fee":5000,"preBalances":[10,0],"postBalances":[5,0],
                "logMessages":["Program log: hi\u001b[2K"]},
        "transaction":["AQID","base64"],"version":0},"id":1}"#;
    let record = parse_transaction(body).unwrap().unwrap();
    assert_eq!(record.slot, 9);
    assert_eq!(record.transaction, vec![1, 2, 3]);
    let meta = record.meta.unwrap();
    assert_eq!(meta.fee, 5000);
    assert_eq!(meta.pre_balances, vec![10, 0]);
    assert!(!meta.failed);
    // No `loadedAddresses`: none loaded.
    assert_eq!(meta.loaded_addresses, LoadedAddresses::default());
    // Kept as sent; a caller sanitises before printing.
    assert_eq!(
        meta.log_messages,
        vec!["Program log: hi\u{1b}[2K".to_owned()]
    );

    let null = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
    assert_eq!(parse_transaction(null), Ok(None));
    let negative = body.replace("\"fee\":5000", "\"fee\":-1");
    assert_eq!(
        parse_transaction(&negative),
        Err(RpcError::BadResponse("fee"))
    );
}

/// A hand-built v0 `getTransaction` result in the documented shape: `meta.loadedAddresses`
/// lists the lookup-table accounts as base58 `writable` and `readonly` lists.
#[test]
fn parses_the_addresses_a_v0_transaction_loaded() {
    let body = format!(
        r#"{{"jsonrpc":"2.0","result":{{"slot":9,"blockTime":1700000000,"version":0,
        "meta":{{"err":null,"fee":5000,"preBalances":[1],"postBalances":[1],
                "logMessages":[],
                "loadedAddresses":{{"writable":["{TOKEN_PROGRAM}"],
                                    "readonly":["{SYSTEM_PROGRAM}","{TOKEN_PROGRAM}"]}}}},
        "transaction":["AQID","base64"]}},"id":1}}"#
    );
    let meta = parse_transaction(&body).unwrap().unwrap().meta.unwrap();
    let system: Address = SYSTEM_PROGRAM.parse().unwrap();
    assert_eq!(
        meta.loaded_addresses,
        LoadedAddresses {
            writable: vec![token_program()],
            readonly: vec![system, token_program()],
        }
    );
    let null = body.replace(
        &body[body.find("{\"writable\"").unwrap()..body.find("}},").unwrap() + 1],
        "null",
    );
    assert_eq!(
        parse_transaction(&null)
            .unwrap()
            .unwrap()
            .meta
            .unwrap()
            .loaded_addresses,
        LoadedAddresses::default()
    );
    for (from, to) in [
        (format!("[\"{TOKEN_PROGRAM}\"]"), "[\"short\"]".to_owned()),
        (format!("[\"{TOKEN_PROGRAM}\"]"), "[7]".to_owned()),
        (format!("[\"{TOKEN_PROGRAM}\"]"), "null".to_owned()),
    ] {
        let bad = body.replacen(&from, &to, 1);
        assert_eq!(
            parse_transaction(&bad),
            Err(RpcError::BadResponse("writable")),
            "{to}"
        );
    }
}

#[test]
fn parses_a_genesis_hash_of_32_bytes_only() {
    let body = format!(r#"{{"jsonrpc":"2.0","result":"{TOKEN_PROGRAM}","id":1}}"#);
    assert_eq!(
        parse_genesis_hash(&body).unwrap().to_string(),
        TOKEN_PROGRAM
    );
    for bad in [r#""abc""#, "5"] {
        let body = format!(r#"{{"jsonrpc":"2.0","result":{bad},"id":1}}"#);
        assert!(parse_genesis_hash(&body).is_err(), "{bad}");
    }
}

#[test]
fn reads_a_null_error_as_no_error() {
    let body = format!(r#"{{"jsonrpc":"2.0","result":"{TOKEN_PROGRAM}","error":null,"id":1}}"#);
    assert_eq!(
        parse_genesis_hash(&body).map(|hash| hash.to_string()),
        Ok(TOKEN_PROGRAM.to_owned())
    );
    // An error object still wins over a result.
    let both = r#"{"jsonrpc":"2.0","result":"x","error":{"code":-32600,"message":"m"},"id":1}"#;
    assert_eq!(
        parse_genesis_hash(both),
        Err(RpcError::Server {
            code: -32600,
            message: "m".to_owned()
        })
    );
}

#[test]
fn sanitises_a_server_error_message() {
    let body = r#"{"jsonrpc":"2.0","error":{"code":1,"message":"bad\nok: yes\u001b[2K"},"id":1}"#;
    let error = parse_account_info(body).unwrap_err();
    assert_eq!(
        error,
        RpcError::Server {
            code: 1,
            message: "bad\\nok: yes\\u{1b}[2K".to_owned()
        }
    );
    assert!(!error.to_string().contains('\n'));
    assert_eq!(
        parse_genesis_hash("<html>"),
        Err(RpcError::BadResponse("not JSON"))
    );
}
