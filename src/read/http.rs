//! JSON-RPC over HTTPS with blocking `ureq`: the only code in the crate that touches
//! the network. Built only with the `http` feature.
//!
//! The URL may carry credentials, so it is never printed: `HttpRpc` has no `Debug`, it
//! takes only a checked `RpcUrl`, transport errors are reduced to messages that cannot
//! contain the URL, naming the endpoint by its redacted form only, and a server error
//! message that repeats a secret part of the URL is withheld.

use std::time::Duration;

use serde_json::Value;

use crate::read::cluster::{Cluster, checked};
use crate::read::codec::{Address, Hash, Signature};
use crate::read::json;
use crate::read::rpc::{
    Account, KeyedAccount, ProgramAccountsQuery, Rpc, RpcError, SignatureInfo, SignaturesQuery,
    Slotted, TransactionRecord,
};
use crate::read::url::RpcUrl;

const TIMEOUT: Duration = Duration::from_secs(30);
/// The largest response read, in bytes. `getProgramAccounts` can be large.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
/// Replaces a server error message that repeats part of the URL's secrets.
const WITHHELD: &str = "(message withheld: it repeats part of the RPC URL)";

/// JSON-RPC over HTTPS to one cluster. Deliberately not `Debug`: it holds the URL.
pub struct HttpRpc {
    agent: ureq::Agent,
    url: RpcUrl,
}

impl HttpRpc {
    /// A client for `url` that has checked the endpoint is on `cluster`. The genesis
    /// hash is the first call made; no other read is possible until it matches.
    pub fn connect(url: RpcUrl, cluster: Cluster) -> Result<Self, RpcError> {
        checked(Self::unchecked(url), cluster)
    }

    fn unchecked(url: RpcUrl) -> Self {
        Self {
            agent: ureq::Agent::new_with_config(agent_config()),
            url,
        }
    }

    /// Posts `body` and parses the answer with `parse`. Any status but 2xx is refused
    /// before the body is read.
    fn call<T>(
        &self,
        body: &Value,
        parse: impl FnOnce(&str) -> Result<T, RpcError>,
    ) -> Result<T, RpcError> {
        let endpoint = self.url.redacted();
        let mut response = self
            .agent
            .post(self.url.expose())
            .send_json(body)
            .map_err(|e| transport_error(e, endpoint))?;
        check_status(response.status().as_u16(), endpoint)?;
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|e| transport_error(e, endpoint))?;
        parse(&text).map_err(|e| withhold_url(e, &self.url))
    }
}

impl Rpc for HttpRpc {
    fn get_genesis_hash(&self) -> Result<Hash, RpcError> {
        self.call(&json::genesis_hash_request(), json::parse_genesis_hash)
    }

    fn get_account_info(&self, address: &Address) -> Result<Slotted<Option<Account>>, RpcError> {
        self.call(
            &json::account_info_request(address),
            json::parse_account_info,
        )
    }

    fn get_multiple_accounts(
        &self,
        addresses: &[Address],
    ) -> Result<Slotted<Vec<Option<Account>>>, RpcError> {
        self.call(&json::multiple_accounts_request(addresses)?, |text| {
            json::parse_multiple_accounts(text, addresses.len())
        })
    }

    fn get_program_accounts(
        &self,
        program: &Address,
        query: &ProgramAccountsQuery,
    ) -> Result<Slotted<Vec<KeyedAccount>>, RpcError> {
        self.call(
            &json::program_accounts_request(program, query),
            json::parse_program_accounts,
        )
    }

    fn get_signatures_for_address(
        &self,
        address: &Address,
        query: &SignaturesQuery,
    ) -> Result<Vec<SignatureInfo>, RpcError> {
        self.call(
            &json::signatures_request(address, query)?,
            json::parse_signatures,
        )
    }

    fn get_transaction(
        &self,
        signature: &Signature,
    ) -> Result<Option<TransactionRecord>, RpcError> {
        self.call(
            &json::transaction_request(signature),
            json::parse_transaction,
        )
    }
}

/// The agent's settings. A function of its own so the tests can read them back.
fn agent_config() -> ureq::config::Config {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .https_only(true)
        // A redirect could send the request, and its credentials, elsewhere. With 0, ureq
        // returns a 3xx response as it is; `check_status` refuses it.
        .max_redirects(0)
        // A proxy named in the environment would see the URL, and its credentials.
        .proxy(None)
        // Every status is checked in one place, `check_status`.
        .http_status_as_error(false)
        .build()
}

/// Refuses any HTTP status outside 200 to 299: errors, and redirects too, which are
/// never followed.
fn check_status(code: u16, endpoint: &str) -> Result<(), RpcError> {
    if (200..=299).contains(&code) {
        Ok(())
    } else {
        Err(RpcError::Status {
            endpoint: endpoint.to_owned(),
            code,
        })
    }
}

/// A server error whose message repeats a secret part of `url` keeps its code only.
fn withhold_url(error: RpcError, url: &RpcUrl) -> RpcError {
    match error {
        RpcError::Server { code, message } if url.appears_in(&message) => RpcError::Server {
            code,
            message: WITHHELD.to_owned(),
        },
        other => other,
    }
}

/// Maps a ureq error to one that cannot contain the URL. Only variants whose content is
/// known to be URL-free keep any detail; `endpoint` is the redacted URL.
fn transport_error(error: ureq::Error, endpoint: &str) -> RpcError {
    let endpoint = endpoint.to_owned();
    let reason = match error {
        ureq::Error::StatusCode(code) => return RpcError::Status { endpoint, code },
        ureq::Error::Timeout(_) => "timed out".to_owned(),
        ureq::Error::HostNotFound => "host not found".to_owned(),
        ureq::Error::ConnectionFailed => "connection failed".to_owned(),
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => {
            "the server redirected; redirects are refused".to_owned()
        }
        ureq::Error::RequireHttpsOnly(_) => "the URL is not HTTPS".to_owned(),
        ureq::Error::Io(e) => format!("I/O error ({:?})", e.kind()),
        ureq::Error::BodyExceedsLimit(limit) => format!("response larger than {limit} bytes"),
        _ => "details withheld; they may contain the RPC URL".to_owned(),
    };
    RpcError::Transport { endpoint, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_URL_PARTS: [&str; 5] = [
        "secret-pass",
        "/v2/secret-path-token",
        "secret-path-token",
        "api-key=secret-query-token",
        "secret-query-token",
    ];

    fn secret_url(port: u16) -> String {
        format!(
            "https://user:secret-pass@127.0.0.1:{port}/v2/secret-path-token?api-key=secret-query-token"
        )
    }

    fn checked_url(url: &str) -> RpcUrl {
        RpcUrl::from_value("SAS_TEST_RPC_URL", Some(url))
            .ok()
            .unwrap()
    }

    fn assert_no_secret(error: &RpcError, url: &str) {
        for text in [error.to_string(), format!("{error:?}")] {
            for secret in std::iter::once(url).chain(SECRET_URL_PARTS) {
                assert!(!text.contains(secret), "{secret:?} in {text:?}");
            }
        }
    }

    /// A local port with nothing listening: bound, then released.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn a_failed_request_never_shows_the_url() {
        let port = closed_port();
        let url = secret_url(port);
        let Err(error) = HttpRpc::connect(checked_url(&url), Cluster::Devnet) else {
            panic!("a request to a closed port succeeded");
        };
        assert!(
            matches!(error, RpcError::Transport { .. }),
            "not a transport error: {error}"
        );
        assert_no_secret(&error, &url);
        assert!(
            error
                .to_string()
                .contains(&format!("https://127.0.0.1:{port}")),
            "{error}"
        );
    }

    #[test]
    fn refuses_every_status_but_2xx() {
        for code in [200, 201, 204, 299] {
            assert_eq!(check_status(code, "https://h"), Ok(()), "{code}");
        }
        for code in [
            100, 101, 199, 300, 301, 302, 303, 307, 308, 400, 404, 429, 500, 503,
        ] {
            assert_eq!(
                check_status(code, "https://h"),
                Err(RpcError::Status {
                    endpoint: "https://h".to_owned(),
                    code
                }),
                "{code}"
            );
        }
    }

    #[test]
    fn a_status_error_never_shows_the_url() {
        let url = secret_url(8899);
        let checked = checked_url(&url);
        let error = check_status(307, checked.redacted()).unwrap_err();
        assert_no_secret(&error, &url);
        assert!(
            error.to_string().contains("https://127.0.0.1:8899"),
            "{error}"
        );
        let from_ureq = transport_error(ureq::Error::StatusCode(502), checked.redacted());
        assert_no_secret(&from_ureq, &url);
    }

    #[test]
    fn a_server_message_that_repeats_the_url_is_withheld() {
        let url = secret_url(8899);
        let checked = checked_url(&url);
        for echoed in [
            "invalid api key secret-query-token",
            "no route /v2/secret-path-token",
            "bad credentials user:secret-pass",
        ] {
            let body = format!(
                r#"{{"jsonrpc":"2.0","error":{{"code":-32001,"message":"{echoed}"}},"id":1}}"#
            );
            let error = withhold_url(json::parse_genesis_hash(&body).unwrap_err(), &checked);
            assert_eq!(
                error,
                RpcError::Server {
                    code: -32001,
                    message: WITHHELD.to_owned()
                }
            );
            assert_no_secret(&error, &url);
        }
        let plain = RpcError::Server {
            code: -32601,
            message: "Method not found".to_owned(),
        };
        assert_eq!(withhold_url(plain.clone(), &checked), plain);
    }

    #[test]
    fn the_agent_is_https_only_with_no_redirects_and_no_proxy() {
        let config = agent_config();
        assert!(config.https_only());
        assert_eq!(config.max_redirects(), 0);
        assert!(config.proxy().is_none());
        assert!(!config.http_status_as_error());
        assert_eq!(config.timeouts().global, Some(TIMEOUT));
    }
}
