//! The crate can only read. These tests scan every `.rs` file under `src/` (the client,
//! the scanner and the binary), at any depth, with comments removed, and fail if:
//!
//! - the `Rpc` trait has any method beyond the six reads;
//! - `json::method` holds anything but the six read method names;
//! - any other string literal looks like an RPC method name (`get…`, `send…`,
//!   `simulate…`, `request…` or `sign…` followed by a capital letter);
//! - a request body takes its method from anywhere but `json::method`, or `HttpRpc`
//!   sends a body that `json` did not build;
//! - the source uses `concat!`, `stringify!`, `include_str!` or `include_bytes!`, which
//!   could build a method name the literal check cannot see;
//! - `ureq` is named outside `read/http.rs`;
//! - `HttpRpc` has any `impl` beyond its own and `Rpc`, or a public inherent method
//!   other than `connect`.
//!
//! Each rule is an allowlist: the crate passes only if what it sends is one of the six
//! reads. The scanner's own tests below plant each evasion and check it is caught.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers outside #[test] functions"
)]

use std::path::{Path, PathBuf};

/// The trait's methods, exactly.
const READS: [&str; 6] = [
    "get_account_info",
    "get_genesis_hash",
    "get_multiple_accounts",
    "get_program_accounts",
    "get_signatures_for_address",
    "get_transaction",
];

/// The JSON-RPC method names the crate may send, exactly.
const METHODS: [&str; 6] = [
    "getAccountInfo",
    "getGenesisHash",
    "getMultipleAccounts",
    "getProgramAccounts",
    "getSignaturesForAddress",
    "getTransaction",
];

/// Prefixes of JSON-RPC method names. A literal that starts with one of these and then
/// a capital letter is treated as a method name.
const METHOD_PREFIXES: [&str; 5] = ["get", "send", "simulate", "request", "sign"];

/// Macros that can build a string the literal check cannot see.
const REFUSED_MACROS: [&str; 4] = ["concat", "stringify", "include_str", "include_bytes"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// An identifier, keyword or number.
    Word(String),
    /// A string or byte-string literal, escapes resolved.
    Str(String),
    /// Any other single character, except whitespace. Char literals are dropped.
    Punct(char),
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Rust source as tokens, with comments removed.
fn tokens(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = at(i) {
        let next = at(i + 1);
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && next == Some('/') {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while let Some(c) = at(i) {
                if c == '/' && at(i + 1) == Some('*') {
                    depth += 1;
                    i += 2;
                } else if c == '*' && at(i + 1) == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == '"' {
            let (value, end) = string(&chars, i + 1);
            out.push(Token::Str(value));
            i = end;
        } else if c == '\'' {
            if next == Some('\\') {
                // An escaped char literal: skip to its closing quote.
                i += 3;
                while at(i).is_some_and(|c| c != '\'') {
                    i += 1;
                }
                i += 1;
            } else if at(i + 2) == Some('\'') {
                i += 3;
            } else {
                // A lifetime or a label.
                out.push(Token::Punct('\''));
                i += 1;
            }
        } else if is_ident(c) {
            if let Some((value, end)) = prefixed_string(&chars, i) {
                out.push(Token::Str(value));
                i = end;
                continue;
            }
            let start = i;
            while at(i).is_some_and(is_ident) {
                i += 1;
            }
            out.push(Token::Word(chars[start..i].iter().collect()));
        } else {
            out.push(Token::Punct(c));
            i += 1;
        }
    }
    out
}

/// A `b"…"`, `r"…"`, `r#"…"#` or `br#"…"#` literal starting at `i`, if there is one.
fn prefixed_string(chars: &[char], i: usize) -> Option<(String, usize)> {
    let at = |i: usize| chars.get(i).copied();
    let mut j = i;
    if at(j) == Some('b') {
        j += 1;
    }
    let raw = at(j) == Some('r');
    if raw {
        j += 1;
    }
    if !raw {
        // Only `b"…"` is left: an escaped string.
        return (j > i && at(j) == Some('"')).then(|| string(chars, j + 1));
    }
    let hashes = chars[j..].iter().take_while(|c| **c == '#').count();
    j += hashes;
    if at(j) != Some('"') {
        return None;
    }
    let start = j + 1;
    let mut k = start;
    while k < chars.len() {
        if chars[k] == '"'
            && chars[k + 1..]
                .iter()
                .take(hashes)
                .filter(|c| **c == '#')
                .count()
                == hashes
        {
            return Some((chars[start..k].iter().collect(), k + 1 + hashes));
        }
        k += 1;
    }
    Some((chars[start..].iter().collect(), chars.len()))
}

/// An escaped string whose body starts at `i`: its value and the index after it.
fn string(chars: &[char], mut i: usize) -> (String, usize) {
    let mut value = String::new();
    while let Some(&c) = chars.get(i) {
        i += 1;
        match c {
            '"' => return (value, i),
            '\\' => {
                let Some(&e) = chars.get(i) else { break };
                i += 1;
                match e {
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    '0' => value.push('\0'),
                    'x' => {
                        let hex: String = chars[i..(i + 2).min(chars.len())].iter().collect();
                        i += 2;
                        value.extend(u8::from_str_radix(&hex, 16).ok().map(char::from));
                    }
                    'u' => {
                        let close = chars[i..].iter().position(|c| *c == '}').unwrap_or(0);
                        let hex: String =
                            chars.get(i + 1..i + close).unwrap_or(&[]).iter().collect();
                        i += close + 1;
                        value.extend(u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32));
                    }
                    '\n' => {
                        while chars.get(i).is_some_and(|c| c.is_whitespace()) {
                            i += 1;
                        }
                    }
                    other => value.push(other),
                }
            }
            other => value.push(other),
        }
    }
    (value, i)
}

/// The index of the `}` that closes the `{` at `open`.
fn closing_brace(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate().skip(open) {
        match token {
            Token::Punct('{') => depth += 1,
            Token::Punct('}') => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    tokens.len()
}

fn word(token: Option<&Token>, expected: &str) -> bool {
    matches!(token, Some(Token::Word(w)) if w == expected)
}

/// The index of the first `{` after `start`.
fn next_open(tokens: &[Token], start: usize) -> Option<usize> {
    (start..tokens.len()).find(|i| tokens[*i] == Token::Punct('{'))
}

/// The body of the item that `words` (consecutive words) introduce, without its braces.
fn item_body<'a>(tokens: &'a [Token], words: &[&str]) -> Option<(usize, &'a [Token])> {
    let start = (0..tokens.len()).find(|i| {
        words
            .iter()
            .enumerate()
            .all(|(k, w)| word(tokens.get(i + k), w))
    })?;
    let open = next_open(tokens, start)?;
    let close = closing_brace(tokens, open);
    Some((open, &tokens[open + 1..close.min(tokens.len())]))
}

/// Names declared with `fn` in `body`; with `public`, only those after `pub fn`.
fn fn_names(body: &[Token], public: bool) -> Vec<String> {
    let mut names: Vec<String> = body
        .windows(2)
        .enumerate()
        .filter(|(i, pair)| {
            word(pair.first(), "fn") && (!public || (*i > 0 && word(body.get(i - 1), "pub")))
        })
        .filter_map(|(_, pair)| match pair.get(1) {
            Some(Token::Word(name)) => Some(name.clone()),
            _ => None,
        })
        .collect();
    names.sort();
    names
}

fn looks_like_a_method(text: &str) -> bool {
    METHOD_PREFIXES.iter().any(|prefix| {
        text.strip_prefix(prefix)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_ascii_uppercase())
    })
}

/// Every rule broken by `files`, given as (path under `src/`, text).
fn violations(files: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    let mut http_impls = Vec::new();
    for (name, text) in files {
        let toks = tokens(text);

        for (i, token) in toks.iter().enumerate() {
            let Token::Word(w) = token else { continue };
            if REFUSED_MACROS.contains(&w.as_str()) {
                found.push(format!("{name} uses `{w}`"));
            }
            if w == "ureq" && name != "read/http.rs" {
                found.push(format!("{name} names ureq; only read/http.rs may"));
            }
            // A request body's method must come from `json::method`.
            if w == "request"
                && toks.get(i + 1) == Some(&Token::Punct('('))
                && !(i > 0 && word(toks.get(i - 1), "fn"))
                && !word(toks.get(i + 2), "method")
            {
                found.push(format!(
                    "{name} calls request() without a json::method name"
                ));
            }
            if w == "call"
                && name == "read/http.rs"
                && i > 0
                && toks.get(i - 1) == Some(&Token::Punct('.'))
                && !(toks.get(i + 2) == Some(&Token::Punct('&')) && word(toks.get(i + 3), "json"))
            {
                found.push(format!("{name} sends a body that json did not build"));
            }
            if w == "impl" {
                let end = next_open(&toks, i).unwrap_or(toks.len());
                let header = &toks[i..end];
                if header.iter().any(|t| word(Some(t), "HttpRpc")) {
                    let words: Vec<String> = header
                        .iter()
                        .map(|t| match t {
                            Token::Word(w) => w.clone(),
                            Token::Punct(c) => c.to_string(),
                            Token::Str(s) => format!("{s:?}"),
                        })
                        .collect();
                    http_impls.push(words.join(" "));
                    if words == ["impl", "HttpRpc"] {
                        let close = closing_brace(&toks, end);
                        let public = fn_names(&toks[end..close.min(toks.len())], true);
                        if public != ["connect"] {
                            found.push(format!("HttpRpc's public methods are {public:?}"));
                        }
                    }
                }
            }
        }

        // The literals in `json::method`, which are checked against the allowlist.
        let module = (name == "read/json.rs")
            .then(|| item_body(&toks, &["pub", "mod", "method"]))
            .flatten();
        let module_range = module.map(|(open, body)| open..open + body.len() + 2);
        if name == "read/json.rs" {
            match module {
                None => found.push("json.rs has no `pub mod method`".to_owned()),
                Some((_, body)) => {
                    let mut names: Vec<&str> = body
                        .iter()
                        .filter_map(|t| match t {
                            Token::Str(s) => Some(s.as_str()),
                            _ => None,
                        })
                        .collect();
                    names.sort_unstable();
                    let consts = body.iter().filter(|t| word(Some(t), "const")).count();
                    if names != METHODS || consts != METHODS.len() {
                        found.push(format!("json::method holds {names:?}"));
                    }
                }
            }
        }
        for (i, token) in toks.iter().enumerate() {
            let Token::Str(literal) = token else { continue };
            let in_module = module_range.as_ref().is_some_and(|r| r.contains(&i));
            if !in_module && looks_like_a_method(literal) {
                found.push(format!("{name} has the literal {literal:?}"));
            }
            // A `"method"` key is followed by `: method` (the parameter or the module).
            if literal == "method"
                && !(toks.get(i + 1) == Some(&Token::Punct(':')) && word(toks.get(i + 2), "method"))
            {
                found.push(format!("{name} sets \"method\" from outside json::method"));
            }
        }

        if name == "read/rpc.rs" {
            match item_body(&toks, &["pub", "trait", "Rpc"]) {
                None => found.push("rpc.rs has no `pub trait Rpc`".to_owned()),
                Some((_, body)) => {
                    let methods = fn_names(body, false);
                    if methods != READS {
                        found.push(format!("the Rpc trait has {methods:?}"));
                    }
                }
            }
        }
    }
    http_impls.sort();
    if !http_impls.is_empty() && http_impls != ["impl HttpRpc", "impl Rpc for HttpRpc"] {
        found.push(format!("HttpRpc has the impls {http_impls:?}"));
    }
    found
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `.rs` file under `src/`, as (path under `src/`, text).
fn sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    rs_files(&src, &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            (name, std::fs::read_to_string(&path).unwrap())
        })
        .collect()
}

#[test]
fn the_crate_sends_only_the_six_reads() {
    let files = sources();
    assert!(files.len() >= 10, "only {} source files found", files.len());
    for required in ["read/json.rs", "read/rpc.rs", "read/http.rs"] {
        assert!(files.iter().any(|(n, _)| n == required), "no {required}");
    }
    let found = violations(&files);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn the_json_method_names_are_the_six_reads() {
    use solana_authority_scan::read::json::method;
    let mut sent = [
        method::GET_ACCOUNT_INFO,
        method::GET_GENESIS_HASH,
        method::GET_MULTIPLE_ACCOUNTS,
        method::GET_PROGRAM_ACCOUNTS,
        method::GET_SIGNATURES_FOR_ADDRESS,
        method::GET_TRANSACTION,
    ];
    sent.sort_unstable();
    assert_eq!(sent, METHODS);
}

// The scanner's own tests: each plants one evasion into the real sources.

fn planted(file: &str, text: &str) -> Vec<String> {
    let mut files = sources();
    files.push((file.to_owned(), text.to_owned()));
    violations(&files)
}

fn edited(file: &str, from: &str, to: &str) -> Vec<String> {
    let mut files = sources();
    let entry = files.iter_mut().find(|(n, _)| n == file).unwrap();
    assert!(entry.1.contains(from), "{from:?} is not in {file}");
    entry.1 = entry.1.replace(from, to);
    violations(&files)
}

#[test]
fn the_scanner_sees_a_method_built_in_a_submodule_macro() {
    let found = planted(
        "sub/mod.rs",
        "macro_rules! m { () => { concat!(\"send\", \"Transaction\") } }",
    );
    assert_eq!(found, ["sub/mod.rs uses `concat`"]);
    let renamed = planted("sub/mod.rs", "use std::stringify as s;");
    assert_eq!(renamed, ["sub/mod.rs uses `stringify`"]);
}

#[test]
fn the_scanner_sees_method_literals_however_written() {
    for literal in [
        "\"sendTransaction\"",
        "\"send\\x54ransaction\"",
        "\"send\\u{54}ransaction\"",
        "r#\"simulateTransaction\"#",
        "b\"requestAirdrop\"",
        "\"signMessage\"",
        "\"getFeeForMessage\"",
    ] {
        let found = planted("deep/x.rs", &format!("const M: &str = {literal};"));
        assert_eq!(found.len(), 1, "{literal}: {found:?}");
    }
    // Comments may say what the crate does not do.
    let prose = planted(
        "deep/x.rs",
        "// sendTransaction\n/* \"sendTransaction\" /* */ */",
    );
    assert!(prose.is_empty(), "{prose:?}");
    // A char literal holding a quote does not hide the literal after it.
    let quoted = planted(
        "deep/x.rs",
        "const Q: char = '\"'; const M: &str = \"sendTransaction\";",
    );
    assert_eq!(quoted.len(), 1, "{quoted:?}");
}

#[test]
fn the_scanner_sees_an_added_trait_method_or_method_name() {
    let trait_method = edited(
        "read/rpc.rs",
        "pub trait Rpc {",
        "pub trait Rpc {\n    fn send_transaction(&self);",
    );
    assert_eq!(trait_method.len(), 1, "{trait_method:?}");
    let method = edited(
        "read/json.rs",
        "pub mod method {",
        "pub mod method {\n    pub const SEND: &str = \"sendTransaction\";",
    );
    assert_eq!(method.len(), 1, "{method:?}");
    let other = edited("read/json.rs", "\"getTransaction\"", "\"getBlock\"");
    assert_eq!(other.len(), 1, "{other:?}");
}

#[test]
fn the_scanner_sees_a_method_from_outside_the_allowlist() {
    let key = planted(
        "x.rs",
        "fn f(m: &mut Map) { m.insert(\"method\".to_owned(), name()); }",
    );
    assert_eq!(key.len(), 1, "{key:?}");
    let request = planted("x.rs", "fn f() { request(name(), Value::Null); }");
    assert_eq!(request.len(), 1, "{request:?}");
    let body = edited(
        "read/http.rs",
        "self.call(&json::genesis_hash_request(),",
        "self.call(&raw(),",
    );
    assert_eq!(body.len(), 1, "{body:?}");
}

#[test]
fn the_scanner_sees_new_network_code_or_http_methods() {
    let ureq = planted("x.rs", "fn f() { let _ = ureq::get(\"https://x\"); }");
    assert_eq!(ureq, ["x.rs names ureq; only read/http.rs may"]);
    let method = edited(
        "read/http.rs",
        "    fn unchecked(url: RpcUrl)",
        "    pub fn post(&self) {}\n\n    fn unchecked(url: RpcUrl)",
    );
    assert_eq!(method.len(), 1, "{method:?}");
    let extra = planted("x.rs", "impl Send for crate::HttpRpc { fn s(&self) {} }");
    assert_eq!(extra.len(), 1, "{extra:?}");
}
