//! The RPC URL: read from the environment only, HTTPS only, and never printed.
//!
//! An RPC URL often carries credentials in its path, query or user info. `RpcUrl` has no
//! `Debug` or `Display`, and the only text of it that may reach an error or a log line
//! is [`RpcUrl::redacted`]: the scheme and host, with user info, path, query and
//! fragment removed. Credentials must therefore never be put in the host name.
//!
//! The authority must be `[user info@]host[:port]`, where the host is a name or a
//! bracketed IPv6 address and the port is numeric. Anything else is refused rather
//! than guessed at, so no part of the user info can end up in the redacted form.

use std::fmt;

/// The only scheme accepted. Compared case-sensitively.
pub const HTTPS_PREFIX: &str = "https://";

/// The shortest piece of a URL's secret parts that [`RpcUrl::appears_in`] looks for.
pub const MIN_SECRET_PIECE: usize = 4;

/// Why no RPC URL could be used. It names the variable, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// The variable is unset, empty, or not valid Unicode.
    Missing(String),
    /// The value does not start with `https://`.
    NotHttps(String),
    /// After `https://`, the authority is not `[user info@]host[:port]`: an empty or
    /// badly formed host, a bad port, or an `@` after the authority ends.
    Malformed(String),
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(var) => write!(f, "{var} is not set"),
            Self::NotHttps(var) => {
                write!(f, "{var} must be an {HTTPS_PREFIX} URL (value not shown)")
            }
            Self::Malformed(var) => write!(
                f,
                "{var} is not a well-formed {HTTPS_PREFIX} URL: it needs a host name or \
                 [IPv6] address and at most a numeric port (value not shown)"
            ),
        }
    }
}

impl std::error::Error for UrlError {}

/// A checked HTTPS RPC URL. Deliberately neither `Debug` nor `Display`.
pub struct RpcUrl {
    url: String,
    redacted: String,
}

impl RpcUrl {
    /// Reads the URL from environment variable `var`. There is no other public
    /// constructor: a URL never comes from the command line or a file in the repo.
    pub fn from_env(var: &str) -> Result<Self, UrlError> {
        Self::from_value(var, std::env::var(var).ok().as_deref())
    }

    /// Checks `value`, the content of variable `var`.
    pub(crate) fn from_value(var: &str, value: Option<&str>) -> Result<Self, UrlError> {
        let url = value
            .filter(|v| !v.is_empty())
            .ok_or_else(|| UrlError::Missing(var.to_owned()))?;
        let rest = url
            .strip_prefix(HTTPS_PREFIX)
            .ok_or_else(|| UrlError::NotHttps(var.to_owned()))?;
        let host = host_and_port(rest).ok_or_else(|| UrlError::Malformed(var.to_owned()))?;
        Ok(Self {
            url: url.to_owned(),
            redacted: format!("{HTTPS_PREFIX}{host}"),
        })
    }

    /// The scheme and host only: safe to print.
    pub fn redacted(&self) -> &str {
        &self.redacted
    }

    /// True if `text` holds a part of the URL that [`RpcUrl::redacted`] removes: the user
    /// info, the path, query or fragment, or any piece of them (split at `:`, `/`, `?`,
    /// `&`, `=`, `#` and `;`) of at least `MIN_SECRET_PIECE` characters. Shorter pieces
    /// are too common to tell apart from ordinary text, and too short to be a credential.
    #[cfg_attr(not(feature = "http"), allow(dead_code, reason = "used by HttpRpc"))]
    pub(crate) fn appears_in(&self, text: &str) -> bool {
        let rest = self.url.get(HTTPS_PREFIX.len()..).unwrap_or_default();
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at_checked(end).unwrap_or_default();
        let user_info = authority.rsplit_once('@').map_or("", |(user, _)| user);
        [user_info, tail]
            .into_iter()
            .chain(user_info.split(':'))
            .chain(tail.split(['/', '?', '&', '=', '#', ';']))
            .filter(|piece| piece.chars().count() >= MIN_SECRET_PIECE)
            .any(|piece| text.contains(piece))
    }

    /// The full URL, for the transport alone.
    #[cfg_attr(not(feature = "http"), allow(dead_code, reason = "used by HttpRpc"))]
    pub(crate) fn expose(&self) -> &str {
        &self.url
    }
}

/// The `host[:port]` of `rest`, the URL after `https://`, or `None` if it is not
/// well formed.
///
/// The authority ends at the first `/`, `?` or `#`. An `@` after that point is refused,
/// so user info can never be cut in two. User info is everything in the authority up
/// to its last `@`. The host is a name (ASCII letters, digits, `-` and `.`) or an IPv6
/// address in brackets, optionally followed by `:` and a port of 1 to 5 digits, at most
/// 65535.
fn host_and_port(rest: &str) -> Option<&str> {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(end)?;
    if tail.contains('@') {
        return None;
    }
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = if let Some(inner) = host_port.strip_prefix('[') {
        let (address, after) = inner.split_once(']')?;
        let ipv6 = !address.is_empty()
            && address
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        if !ipv6 {
            return None;
        }
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (address, port)
    } else {
        let (host, port) = match host_port.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        };
        let name = host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
        if !name {
            return None;
        }
        (host, port)
    };
    if host.is_empty() {
        return None;
    }
    if let Some(port) = port {
        let digits = (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit());
        if !digits || port.parse::<u16>().is_err() {
            return None;
        }
    }
    Some(host_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAR: &str = "SAS_TEST_RPC_URL";

    #[test]
    fn refuses_a_url_that_is_not_https() {
        for bad in [
            "http://api.example.com/key",
            "http://127.0.0.1:8899",
            "HTTPS://api.example.com",
            "ws://api.example.com",
            "api.example.com",
            " https://api.example.com",
        ] {
            let error = RpcUrl::from_value(VAR, Some(bad)).err();
            assert_eq!(error, Some(UrlError::NotHttps(VAR.to_owned())), "{bad}");
        }
    }

    #[test]
    fn refuses_an_authority_that_is_not_a_host_and_port() {
        let mut accepted = Vec::new();
        for bad in [
            // An '@' after the first '/', '?' or '#': user info that a naive cut would
            // leave partly in the host.
            "https://user:pa/ss@rpc.example.com",
            "https://user:p?ss@rpc.example.com",
            "https://key#x@rpc.example.com",
            // What looks like a port is user info without its '@'.
            "https://apikey:SECRETKEY",
            "https://host:99999",
            "https://host:",
            "https://host:123456",
            "https://host:-1",
            "https://ho_st.example.com",
            "https://[::1",
            "https://[]:8899",
            "https://[::1]x",
            "https://[::1]:",
            "https://user@:8899",
            // No host.
            "https://",
            "https:///path",
            "https://user:secret@/path",
            "https://bad host/",
        ] {
            match RpcUrl::from_value(VAR, Some(bad)) {
                Err(UrlError::Malformed(v)) if v == VAR => {}
                Err(other) => accepted.push(format!("{bad} -> {other:?}")),
                Ok(url) => accepted.push(format!("{bad} -> redacted {}", url.redacted())),
            }
        }
        assert!(
            accepted.is_empty(),
            "not refused as Malformed: {accepted:#?}"
        );
    }

    #[test]
    fn refuses_a_missing_url() {
        for missing in [None, Some("")] {
            let error = RpcUrl::from_value(VAR, missing).err();
            assert_eq!(error, Some(UrlError::Missing(VAR.to_owned())));
        }
        assert!(RpcUrl::from_env("SAS_TEST_RPC_URL_THAT_IS_NEVER_SET").is_err());
    }

    #[test]
    fn redacts_user_info_path_query_and_fragment() {
        let cases = [
            ("https://rpc.example.com", "https://rpc.example.com"),
            (
                "https://rpc.example.com/v2/secret-path?api-key=secret-query#frag",
                "https://rpc.example.com",
            ),
            (
                "https://user:secret-pass@rpc.example.com:8443/x",
                "https://rpc.example.com:8443",
            ),
            ("https://[::1]:8899?k=v", "https://[::1]:8899"),
            ("https://[::1]:8899", "https://[::1]:8899"),
            (
                "https://user:pw@host.example.com:8443/path?api-key=x",
                "https://host.example.com:8443",
            ),
            ("https://a@b:c@rpc.example.com/p", "https://rpc.example.com"),
        ];
        for (url, redacted) in cases {
            let checked = RpcUrl::from_value(VAR, Some(url)).ok().unwrap();
            assert_eq!(checked.redacted(), redacted);
            assert_eq!(checked.expose(), url);
        }
    }

    #[test]
    fn redacted_never_holds_user_info_path_query_or_fragment() {
        let url =
            "https://user-part:pass-part@rpc.example.com:8443/path-part?query-part=v#frag-part";
        let checked = RpcUrl::from_value(VAR, Some(url)).ok().unwrap();
        for secret in [
            "user-part",
            "pass-part",
            "@",
            "path-part",
            "query-part",
            "frag-part",
            "/",
            "?",
            "#",
        ] {
            let redacted = checked.redacted().trim_start_matches(HTTPS_PREFIX);
            assert!(!redacted.contains(secret), "{secret:?} in {redacted:?}");
        }
    }

    #[test]
    fn finds_any_secret_part_in_text() {
        let url =
            "https://user-part:pass-part@rpc.example.com/v2/path-part?api-key=query-part#frag-part";
        let checked = RpcUrl::from_value(VAR, Some(url)).ok().unwrap();
        for leaked in [
            "user-part",
            "invalid key pass-part",
            "user-part:pass-part",
            "no such path /v2/path-part",
            "unknown key query-part",
            "api-key=query-part",
            "frag-part",
        ] {
            assert!(checked.appears_in(leaked), "{leaked}");
        }
        for clean in [
            "Method not found",
            "rpc.example.com",
            "v2",
            "Invalid params",
        ] {
            assert!(!checked.appears_in(clean), "{clean}");
        }
        let bare = RpcUrl::from_value(VAR, Some("https://rpc.example.com"))
            .ok()
            .unwrap();
        assert!(!bare.appears_in("anything at rpc.example.com"));
    }

    #[test]
    fn errors_never_hold_the_value() {
        for bad in [
            "http://h/secret-path?k=secret-query",
            "https://user:secret-pass/x@h/secret-path",
        ] {
            let error = RpcUrl::from_value(VAR, Some(bad)).err().unwrap();
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("secret"), "{text}");
                assert!(text.contains(VAR), "{text}");
            }
        }
    }
}
