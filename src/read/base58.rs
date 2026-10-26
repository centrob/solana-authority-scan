//! Base58 (Bitcoin alphabet) for Solana addresses, hashes and signatures.
//!
//! Works on values of any length, so it also reads 64-byte signatures. Callers check
//! the decoded length.

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The longest base58 text of a 32-byte value.
pub(crate) const MAX_LEN_32: usize = 44;
/// The longest base58 text of a 64-byte value.
pub(crate) const MAX_LEN_64: usize = 88;

/// Encodes bytes as base58 text, the inverse of [`decode`].
pub(crate) fn encode(bytes: &[u8]) -> String {
    // Big-endian bytes are folded into little-endian base58 digits.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            // Both terms are below 58 * 256 + 256, far inside u32.
            let value = u32::from(*digit).saturating_mul(256).saturating_add(carry);
            *digit = u8::try_from(value % 58).unwrap_or(0);
            carry = value / 58;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 58).unwrap_or(0));
            carry /= 58;
        }
    }
    // Each leading zero byte is one leading '1'.
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut text = String::with_capacity(zeros.saturating_add(digits.len()));
    text.extend(std::iter::repeat_n('1', zeros));
    for &digit in digits.iter().rev() {
        let c = BASE58_ALPHABET
            .get(usize::from(digit))
            .copied()
            .unwrap_or(b'1');
        text.push(char::from(c));
    }
    text
}

/// Decodes Bitcoin-alphabet base58. `None` if the text is empty, longer than
/// `max_len` characters, or holds a character outside the alphabet.
pub(crate) fn decode(text: &str, max_len: usize) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() > max_len {
        return None;
    }
    // Big-endian digits are folded into a little-endian byte vector.
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.bytes() {
        let digit = BASE58_ALPHABET.iter().position(|&a| a == c)?;
        let mut carry = u32::try_from(digit).ok()?;
        for byte in &mut bytes {
            carry = u32::from(*byte).checked_mul(58)?.checked_add(carry)?;
            *byte = u8::try_from(carry & 0xff).ok()?;
            carry = carry.checked_shr(8)?;
        }
        while carry > 0 {
            bytes.push(u8::try_from(carry & 0xff).ok()?);
            carry = carry.checked_shr(8)?;
        }
    }
    // Each leading '1' is one leading zero byte.
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    bytes.extend(std::iter::repeat_n(0, zeros));
    bytes.reverse();
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base58_like_the_reference() {
        // Values from the base58 reference vectors.
        assert_eq!(decode("2g", MAX_LEN_32), Some(b"a".to_vec()));
        assert_eq!(decode("a3gV", MAX_LEN_32), Some(b"bbb".to_vec()));
        assert_eq!(decode("1112", MAX_LEN_32), Some(vec![0, 0, 0, 1]));
        assert_eq!(decode("", MAX_LEN_32), None);
        assert_eq!(decode("0", MAX_LEN_32), None);
        assert_eq!(decode(&"2".repeat(MAX_LEN_32 + 1), MAX_LEN_32), None);
    }

    #[test]
    fn encodes_the_inverse_of_decode() {
        // The SPL Token program id, a well-known 32-byte address.
        let text = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        let bytes = decode(text, MAX_LEN_32).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(encode(&bytes), text);
        assert_eq!(encode(&[0; 32]), "1".repeat(32));
        let mut leading_zero = [0xff; 32];
        leading_zero[0] = 0;
        assert_eq!(
            decode(&encode(&leading_zero), MAX_LEN_32),
            Some(leading_zero.to_vec())
        );
        assert_eq!(encode(&[0xff; 32]).len(), MAX_LEN_32);
        assert_eq!(encode(&[0xff; 64]).len(), MAX_LEN_64);
        assert_eq!(encode(&[]), "");
    }
}
