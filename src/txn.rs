//! Just enough of the Solana wire transaction format to list the accounts each
//! instruction to one program uses. Pure; no I/O. Used by the fallback that finds a
//! vault's multisig in the vault's own recent transactions.
//!
//! Format: a compact-u16 count of 64-byte signatures, then the message. A message
//! whose first byte has the top bit set is versioned (only v0 is read); otherwise it
//! is legacy and that byte is the header's first. Header (3 bytes), compact-u16 count
//! of 32-byte keys, recent blockhash (32), compact-u16 count of instructions (program
//! index u8, compact-u16 count of account indexes u8, compact-u16 data length, data),
//! then for v0 the address table lookups, which the RPC has already resolved into
//! `loadedAddresses`. Account indexes count the static keys, then the loaded
//! writable, then the loaded read-only addresses.

use crate::read::{Address, LoadedAddresses};

use crate::bytes::{DecodeError, Reader, Reason};

const ACCOUNT: &str = "Transaction";

/// A compact-u16 ("shortvec"): 7 bits per byte, low first, at most 3 bytes.
fn compact_u16(r: &mut Reader<'_>, field: &'static str) -> Result<usize, DecodeError> {
    let mut value: usize = 0;
    for i in 0..3u32 {
        let byte = r.u8(field)?;
        let bits = usize::from(byte & 0x7f)
            .checked_shl(i.saturating_mul(7))
            .ok_or_else(|| r.error(field, Reason::TooShort))?;
        value |= bits;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(r.error(field, Reason::BadTag(u64::from(u16::MAX))))
}

/// The accounts of every instruction in `transaction` whose program is `program`,
/// one list per instruction, in order.
pub fn instruction_accounts(
    transaction: &[u8],
    loaded: &LoadedAddresses,
    program: &Address,
) -> Result<Vec<Vec<Address>>, DecodeError> {
    let mut r = Reader::new(transaction, ACCOUNT);
    let signatures = compact_u16(&mut r, "signatures")?;
    let signature_bytes = signatures
        .checked_mul(64)
        .ok_or_else(|| r.error("signatures", Reason::TooShort))?;
    r.take(signature_bytes, "signatures")?;

    let first = r.u8("message")?;
    if first & 0x80 != 0 {
        let version = first & 0x7f;
        if version != 0 {
            return Err(r.error("version", Reason::BadTag(u64::from(version))));
        }
        r.take(3, "header")?;
    } else {
        r.take(2, "header")?;
    }

    let key_count = compact_u16(&mut r, "account_keys")?;
    let mut keys = Vec::with_capacity(key_count.min(256));
    for _ in 0..key_count {
        keys.push(r.address("account_keys")?);
    }
    keys.extend(loaded.writable.iter().copied());
    keys.extend(loaded.readonly.iter().copied());
    r.take(32, "recent_blockhash")?;

    let mut found = Vec::new();
    let instructions = compact_u16(&mut r, "instructions")?;
    for _ in 0..instructions {
        let program_index = r.u8("program_id_index")?;
        let account_count = compact_u16(&mut r, "accounts")?;
        let indexes = r.take(account_count, "accounts")?;
        let data_len = compact_u16(&mut r, "data")?;
        r.take(data_len, "data")?;
        let lookup = |index: u8| {
            keys.get(usize::from(index))
                .copied()
                .ok_or_else(|| r.error("account index", Reason::TooShort))
        };
        if lookup(program_index)? == *program {
            found.push(
                indexes
                    .iter()
                    .map(|&i| lookup(i))
                    .collect::<Result<_, _>>()?,
            );
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "tests index known-length data and step a test-only generator"
    )]

    use super::*;

    fn legacy_transaction(keys: &[Address], instructions: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut t = vec![1];
        t.extend([0xaa; 64]);
        t.extend([1, 0, 1]);
        t.push(u8::try_from(keys.len()).unwrap());
        for k in keys {
            t.extend(k.as_bytes());
        }
        t.extend([0x11; 32]);
        t.push(u8::try_from(instructions.len()).unwrap());
        for (program, accounts) in instructions {
            t.push(*program);
            t.push(u8::try_from(accounts.len()).unwrap());
            t.extend(accounts);
            t.extend([2, 0xde, 0xad]);
        }
        t
    }

    #[test]
    fn lists_the_accounts_of_one_programs_instructions() {
        let keys: Vec<Address> = (0..4).map(|i| Address::new([i; 32])).collect();
        let program = Address::new([3; 32]);
        let tx = legacy_transaction(&keys, &[(2, vec![0]), (3, vec![1, 0, 4])]);
        let loaded = LoadedAddresses {
            writable: vec![Address::new([9; 32])],
            readonly: vec![],
        };
        let found = instruction_accounts(&tx, &loaded, &program).unwrap();
        assert_eq!(found, vec![vec![keys[1], keys[0], Address::new([9; 32])]]);
        // Without the loaded address, index 4 does not resolve.
        assert!(instruction_accounts(&tx, &LoadedAddresses::default(), &program).is_err());
    }

    #[test]
    fn reads_a_v0_message_and_refuses_other_versions() {
        let keys = [Address::new([5; 32])];
        let legacy = legacy_transaction(&keys, &[(0, vec![0])]);
        let mut v0 = legacy[..65].to_vec();
        v0.push(0x80);
        v0.extend(&legacy[65..]);
        v0.push(0); // no lookups
        let found = instruction_accounts(&v0, &LoadedAddresses::default(), &keys[0]).unwrap();
        assert_eq!(found, vec![vec![keys[0]]]);
        if let Some(b) = v0.get_mut(65) {
            *b = 0x81;
        }
        assert!(instruction_accounts(&v0, &LoadedAddresses::default(), &keys[0]).is_err());
    }

    #[test]
    fn compact_u16_reads_up_to_three_bytes() {
        let mut r = Reader::new(&[0x80, 0x01], "T");
        assert_eq!(compact_u16(&mut r, "n"), Ok(128));
        let mut r = Reader::new(&[0xff, 0xff, 0x03], "T");
        assert_eq!(compact_u16(&mut r, "n"), Ok(0xffff));
        let mut r = Reader::new(&[0x80, 0x80, 0x80, 0x01], "T");
        assert!(compact_u16(&mut r, "n").is_err());
    }

    /// Every prefix of a valid transaction is refused, never a panic.
    #[test]
    fn refuses_every_truncation() {
        let keys: Vec<Address> = (0..3).map(|i| Address::new([i; 32])).collect();
        let tx = legacy_transaction(&keys, &[(2, vec![0, 1]), (1, vec![2])]);
        let none = LoadedAddresses::default();
        assert!(instruction_accounts(&tx, &none, &keys[2]).is_ok());
        for end in 0..tx.len() {
            let error = instruction_accounts(&tx[..end], &none, &keys[2]).unwrap_err();
            assert_eq!(error.reason, Reason::TooShort, "at {end}: {error}");
            assert_eq!(error.account, ACCOUNT);
        }
    }

    /// Property: random bytes never panic, and whatever is found fits in the input.
    #[test]
    fn random_bytes_never_panic() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let len = usize::try_from(next() % 300).unwrap();
            let bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
            let program = Address::new([0; 32]);
            if let Ok(found) = instruction_accounts(&bytes, &LoadedAddresses::default(), &program) {
                let accounts: usize = found.iter().map(Vec::len).sum();
                assert!(accounts <= bytes.len());
            }
        }
    }
}
