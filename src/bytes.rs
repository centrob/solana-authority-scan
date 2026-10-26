//! A bounds-checked reader over account bytes, and the error every decoder returns.
//! Pure; no I/O. Every read checks its length first, so a short or malformed account
//! is an error, never a panic.

use std::fmt;

use crate::read::Address;

/// Why account bytes could not be decoded. Names the account type, the field and the
/// byte offset; never holds the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub account: &'static str,
    pub field: &'static str,
    pub offset: usize,
    pub reason: Reason,
}

/// What was wrong at that offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The data ends before the field does.
    TooShort,
    /// The first bytes are not this account type's discriminator or tag.
    WrongType,
    /// An enum or `Option` tag outside the known values.
    BadTag(u64),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.reason {
            Reason::TooShort => "the data ends too soon".to_owned(),
            Reason::WrongType => "the data is not this account type".to_owned(),
            Reason::BadTag(tag) => format!("unknown tag {tag}"),
        };
        write!(
            f,
            "cannot decode {} field `{}` at byte {}: {what}",
            self.account, self.field, self.offset
        )
    }
}

impl std::error::Error for DecodeError {}

/// Reads fields in order from account data, little-endian, as Borsh and bincode lay
/// them out.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    account: &'static str,
}

impl<'a> Reader<'a> {
    /// A reader over `data`, which is an account of type `account` (used in errors).
    pub fn new(data: &'a [u8], account: &'static str) -> Self {
        Self {
            data,
            pos: 0,
            account,
        }
    }

    /// The offset of the next byte to read.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// An error at the current offset.
    pub fn error(&self, field: &'static str, reason: Reason) -> DecodeError {
        DecodeError {
            account: self.account,
            field,
            offset: self.pos,
            reason,
        }
    }

    /// The next `len` bytes.
    pub fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| self.error(field, Reason::TooShort))?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| self.error(field, Reason::TooShort))?;
        self.pos = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], DecodeError> {
        let start = self.pos;
        let bytes = self.take(N, field)?;
        bytes.try_into().map_err(|_| DecodeError {
            account: self.account,
            field,
            offset: start,
            reason: Reason::TooShort,
        })
    }

    pub fn u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        Ok(u8::from_le_bytes(self.array(field)?))
    }

    pub fn u16(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array(field)?))
    }

    pub fn u32(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array(field)?))
    }

    pub fn u64(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array(field)?))
    }

    pub fn i64(&mut self, field: &'static str) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.array(field)?))
    }

    pub fn address(&mut self, field: &'static str) -> Result<Address, DecodeError> {
        Ok(Address::new(self.array(field)?))
    }

    /// A Borsh or bincode `Option<Pubkey>`: a one-byte tag (0 none, 1 some), then the
    /// key if some. Any other tag is an error.
    pub fn option_address(&mut self, field: &'static str) -> Result<Option<Address>, DecodeError> {
        let at = self.pos;
        match self.u8(field)? {
            0 => Ok(None),
            1 => self.address(field).map(Some),
            tag => Err(DecodeError {
                account: self.account,
                field,
                offset: at,
                reason: Reason::BadTag(u64::from(tag)),
            }),
        }
    }

    /// A Borsh `Vec<T>` length (u32), refused if `len * item_size` bytes do not
    /// remain, so a forged length cannot make the caller allocate.
    pub fn vec_len(&mut self, item_size: usize, field: &'static str) -> Result<usize, DecodeError> {
        let len =
            usize::try_from(self.u32(field)?).map_err(|_| self.error(field, Reason::TooShort))?;
        let need = len
            .checked_mul(item_size)
            .ok_or_else(|| self.error(field, Reason::TooShort))?;
        let left = self.data.len().saturating_sub(self.pos);
        if need > left {
            return Err(self.error(field, Reason::TooShort));
        }
        Ok(len)
    }

    /// A Borsh `Vec<Pubkey>`.
    pub fn addresses(&mut self, field: &'static str) -> Result<Vec<Address>, DecodeError> {
        let len = self.vec_len(32, field)?;
        (0..len).map(|_| self.address(field)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_in_order_and_refuses_short_data() {
        let data = [1, 0, 2, 0, 0, 0, 9];
        let mut r = Reader::new(&data, "Test");
        assert_eq!(r.u16("a"), Ok(1));
        assert_eq!(r.u32("b"), Ok(2));
        assert_eq!(r.pos(), 6);
        let error = r.u16("c").unwrap_err();
        assert_eq!(error.offset, 6);
        assert_eq!(error.reason, Reason::TooShort);
        assert_eq!(
            error.to_string(),
            "cannot decode Test field `c` at byte 6: the data ends too soon"
        );
    }

    #[test]
    fn refuses_a_bad_option_tag_and_a_forged_vec_length() {
        let mut r = Reader::new(&[2], "Test");
        assert_eq!(r.option_address("o").unwrap_err().reason, Reason::BadTag(2));
        // A length of u32::MAX with no items after it.
        let mut r = Reader::new(&[255, 255, 255, 255], "Test");
        assert_eq!(r.addresses("v").unwrap_err().reason, Reason::TooShort);
        let mut r = Reader::new(&[0], "Test");
        assert_eq!(r.option_address("o"), Ok(None));
    }
}
