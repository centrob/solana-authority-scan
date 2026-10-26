//! Typed byte values and their text forms: 32-byte addresses and hashes and 64-byte
//! signatures in base58, account data in base64. Pure; no I/O.

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::read::base58;

/// Why text is not a value of the expected type. It never holds the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Empty, or holds a character outside the base58 (or base64) alphabet.
    Malformed,
    /// Valid base58, but not the expected number of bytes.
    WrongLength,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("not valid base58 or base64 text"),
            Self::WrongLength => f.write_str("does not decode to the expected number of bytes"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Decodes base58 text of exactly `N` bytes.
fn decode_exact<const N: usize>(text: &str, max_len: usize) -> Result<[u8; N], ParseError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(ParseError::Malformed);
    }
    if text.len() > max_len {
        return Err(ParseError::WrongLength);
    }
    let bytes = base58::decode(text, max_len).ok_or(ParseError::Malformed)?;
    bytes.try_into().map_err(|_| ParseError::WrongLength)
}

macro_rules! byte_value {
    // `$label` is the type name as Debug prints it. It is passed as a literal because
    // `tests/no_sending.rs` refuses `concat!` and `stringify!` in this crate.
    ($(#[$doc:meta])* $name:ident, $label:literal, $len:literal, $max:path) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub const fn to_bytes(self) -> [u8; $len] {
                self.0
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(text: &str) -> Result<Self, ParseError> {
                decode_exact::<$len>(text, $max).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&base58::encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", $label, self)
            }
        }
    };
}

byte_value!(
    /// A 32-byte account or program address, shown as base58.
    Address,
    "Address",
    32,
    base58::MAX_LEN_32
);

byte_value!(
    /// A 32-byte hash (a genesis hash or a blockhash), shown as base58.
    Hash,
    "Hash",
    32,
    base58::MAX_LEN_32
);

byte_value!(
    /// A 64-byte transaction signature, shown as base58. Used only to look a
    /// transaction up; this crate never makes one.
    Signature,
    "Signature",
    64,
    base58::MAX_LEN_64
);

/// Standard base64 (with padding), as the RPC uses for account data.
pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes standard base64 (with padding).
pub fn decode_base64(text: &str) -> Result<Vec<u8>, ParseError> {
    STANDARD.decode(text).map_err(|_| ParseError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    #[test]
    fn parses_and_prints_an_address() {
        let address: Address = TOKEN_PROGRAM.parse().unwrap();
        assert_eq!(address.to_string(), TOKEN_PROGRAM);
        assert_eq!(format!("{address:?}"), format!("Address({TOKEN_PROGRAM})"));
        assert_eq!(Address::new(*address.as_bytes()), address);
        assert_eq!("1".repeat(32).parse::<Address>(), Ok(Address::new([0; 32])));
    }

    #[test]
    fn refuses_malformed_base58() {
        // 0, O, I and l are outside the alphabet; so are spaces, punctuation and
        // non-ASCII letters.
        for bad in [
            "",
            "0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5D0",
            " TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5D+",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5Dé",
        ] {
            assert_eq!(bad.parse::<Address>(), Err(ParseError::Malformed), "{bad}");
        }
    }

    #[test]
    fn refuses_a_wrong_length_address() {
        // 31 and 33 bytes, a short value, and text too long for any 32-byte value.
        let short = base58::encode(&[7; 31]);
        let long = base58::encode(&[7; 33]);
        for bad in [short.as_str(), long.as_str(), "2g", &"z".repeat(45)] {
            assert_eq!(
                bad.parse::<Address>(),
                Err(ParseError::WrongLength),
                "{bad}"
            );
        }
        // The largest 44-character text is more than 32 bytes.
        assert_eq!(
            "z".repeat(44).parse::<Address>(),
            Err(ParseError::WrongLength)
        );
    }

    #[test]
    fn parses_a_signature_of_64_bytes_only() {
        let bytes = [0xab; 64];
        let text = base58::encode(&bytes);
        assert_eq!(text.parse::<Signature>(), Ok(Signature::new(bytes)));
        assert_eq!(
            format!("{:?}", Signature::new(bytes)),
            format!("Signature({text})")
        );
        let hash = Hash::new([1; 32]);
        assert_eq!(format!("{hash:?}"), format!("Hash({hash})"));
        assert_eq!(
            TOKEN_PROGRAM.parse::<Signature>(),
            Err(ParseError::WrongLength)
        );
    }

    #[test]
    fn round_trips_base64() {
        assert_eq!(encode_base64(b"solana"), "c29sYW5h");
        assert_eq!(decode_base64("c29sYW5h"), Ok(b"solana".to_vec()));
        assert_eq!(decode_base64("!!"), Err(ParseError::Malformed));
    }
}
