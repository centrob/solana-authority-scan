//! Squads v4 transaction accounts in full: `VaultTransaction` with its stored message,
//! `Batch`, and `VaultBatchTransaction`. Pure; no I/O.
//!
//! Layouts from the Squads v4 program source (github.com/Squads-Protocol/v4, commit
//! `af94153ff77a28b6effe46b9c94baaa93742b48c`, `programs/squads_multisig_program/src/`):
//! `state/vault_transaction.rs` (`VaultTransaction`, `VaultTransactionMessage`,
//! `MultisigCompiledInstruction`, `MultisigMessageAddressTableLookup`) and
//! `state/batch.rs` (`Batch`, `VaultBatchTransaction`); the batch transaction seeds
//! from `instructions/batch_execute_transaction.rs` and `state/seeds.rs`. Every `Vec`
//! is Borsh (u32 length): the stored message is the program's own type, not the
//! compact `TransactionMessage` the create instruction takes. `docs/how-it-works.md`,
//! "Layouts decoded", lists the fields.

use crate::bytes::{DecodeError, Reader};
use crate::read::{Address, PdaError, find_program_address};
use crate::squads::{
    BATCH_DISCRIMINATOR, PROGRAM_ID, SEED_PREFIX, SEED_TRANSACTION,
    VAULT_TRANSACTION_DISCRIMINATOR, check_discriminator,
};

/// sha256("account:VaultBatchTransaction")[..8].
pub const VAULT_BATCH_TRANSACTION_DISCRIMINATOR: [u8; 8] =
    [0xc4, 0x79, 0x2e, 0x24, 0x0c, 0x13, 0xfc, 0x07];

const SEED_BATCH_TRANSACTION: &[u8] = b"batch_transaction";

/// One instruction of a stored message: indexes into the message's keys (static
/// keys, then the keys its lookups load).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub account_indexes: Vec<u8>,
    pub data: Vec<u8>,
}

/// An address lookup table the message loads keys from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTableLookup {
    pub account_key: Address,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

/// `VaultTransactionMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMessage {
    pub num_signers: u8,
    pub num_writable_signers: u8,
    pub num_writable_non_signers: u8,
    pub account_keys: Vec<Address>,
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<AddressTableLookup>,
}

/// A `VaultTransaction` account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTransaction {
    pub multisig: Address,
    pub index: u64,
    /// The vault that signs when it executes.
    pub vault_index: u8,
    pub message: VaultMessage,
}

/// A `Batch` account. Its transactions execute one at a time, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Batch {
    pub multisig: Address,
    pub index: u64,
    pub vault_index: u8,
    /// Transactions in the batch, numbered from 1.
    pub size: u32,
    /// The last one executed; 0 when none has been.
    pub executed_transaction_index: u32,
}

impl Batch {
    /// The transaction a batch execute would run next, if any is left.
    pub fn next_transaction(&self) -> Option<u32> {
        self.executed_transaction_index
            .checked_add(1)
            .filter(|next| *next <= self.size)
    }
}

/// A Borsh `Vec<u8>`.
fn byte_vec(r: &mut Reader<'_>, field: &'static str) -> Result<Vec<u8>, DecodeError> {
    let len = r.vec_len(1, field)?;
    Ok(r.take(len, field)?.to_vec())
}

/// The smallest encoded instruction (program index, two empty `Vec`s) and lookup
/// (key, two empty `Vec`s): a forged count is refused before anything is allocated.
const MIN_INSTRUCTION_LEN: usize = 9;
const MIN_LOOKUP_LEN: usize = 40;

fn message(r: &mut Reader<'_>) -> Result<VaultMessage, DecodeError> {
    let num_signers = r.u8("message.num_signers")?;
    let num_writable_signers = r.u8("message.num_writable_signers")?;
    let num_writable_non_signers = r.u8("message.num_writable_non_signers")?;
    let account_keys = r.addresses("message.account_keys")?;
    let count = r.vec_len(MIN_INSTRUCTION_LEN, "message.instructions")?;
    let mut instructions = Vec::with_capacity(count);
    for _ in 0..count {
        instructions.push(CompiledInstruction {
            program_id_index: r.u8("instructions.program_id_index")?,
            account_indexes: byte_vec(r, "instructions.account_indexes")?,
            data: byte_vec(r, "instructions.data")?,
        });
    }
    let count = r.vec_len(MIN_LOOKUP_LEN, "message.address_table_lookups")?;
    let mut address_table_lookups = Vec::with_capacity(count);
    for _ in 0..count {
        address_table_lookups.push(AddressTableLookup {
            account_key: r.address("address_table_lookups.account_key")?,
            writable_indexes: byte_vec(r, "address_table_lookups.writable_indexes")?,
            readonly_indexes: byte_vec(r, "address_table_lookups.readonly_indexes")?,
        });
    }
    Ok(VaultMessage {
        num_signers,
        num_writable_signers,
        num_writable_non_signers,
        account_keys,
        instructions,
        address_table_lookups,
    })
}

/// Decodes a `VaultTransaction` account: discriminator, multisig, creator, index,
/// bump, vault index, vault bump, ephemeral signer bumps (`Vec<u8>`), message.
/// Bytes after the message are ignored.
pub fn decode_vault_transaction(data: &[u8]) -> Result<VaultTransaction, DecodeError> {
    let mut r = Reader::new(data, "VaultTransaction");
    check_discriminator(&mut r, &VAULT_TRANSACTION_DISCRIMINATOR, "VaultTransaction")?;
    let multisig = r.address("multisig")?;
    r.address("creator")?;
    let index = r.u64("index")?;
    r.u8("bump")?;
    let vault_index = r.u8("vault_index")?;
    r.u8("vault_bump")?;
    byte_vec(&mut r, "ephemeral_signer_bumps")?;
    let message = message(&mut r)?;
    Ok(VaultTransaction {
        multisig,
        index,
        vault_index,
        message,
    })
}

/// Decodes a `Batch` account: discriminator, multisig, creator, index, bump, vault
/// index, vault bump, size u32, executed transaction index u32.
pub fn decode_batch(data: &[u8]) -> Result<Batch, DecodeError> {
    let mut r = Reader::new(data, "Batch");
    check_discriminator(&mut r, &BATCH_DISCRIMINATOR, "Batch")?;
    let multisig = r.address("multisig")?;
    r.address("creator")?;
    let index = r.u64("index")?;
    r.u8("bump")?;
    let vault_index = r.u8("vault_index")?;
    r.u8("vault_bump")?;
    let size = r.u32("size")?;
    let executed_transaction_index = r.u32("executed_transaction_index")?;
    Ok(Batch {
        multisig,
        index,
        vault_index,
        size,
        executed_transaction_index,
    })
}

/// Decodes a `VaultBatchTransaction` account's message: discriminator, bump,
/// ephemeral signer bumps (`Vec<u8>`), message.
pub fn decode_batch_transaction(data: &[u8]) -> Result<VaultMessage, DecodeError> {
    let mut r = Reader::new(data, "VaultBatchTransaction");
    check_discriminator(
        &mut r,
        &VAULT_BATCH_TRANSACTION_DISCRIMINATOR,
        "VaultBatchTransaction",
    )?;
    r.u8("bump")?;
    byte_vec(&mut r, "ephemeral_signer_bumps")?;
    message(&mut r)
}

/// The PDA of transaction `transaction_index` (from 1) of the batch at
/// `batch_index`: seeds `multisig`, the multisig, `transaction`, the batch index as
/// u64 little-endian, `batch_transaction`, the transaction index as u32
/// little-endian.
pub fn batch_transaction_address(
    multisig: &Address,
    batch_index: u64,
    transaction_index: u32,
) -> Result<Address, PdaError> {
    find_program_address(
        &[
            SEED_PREFIX,
            multisig.as_bytes(),
            SEED_TRANSACTION,
            &batch_index.to_le_bytes(),
            SEED_BATCH_TRANSACTION,
            &transaction_index.to_le_bytes(),
        ],
        &PROGRAM_ID,
    )
    .map(|(address, _)| address)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "tests index known-length data")]

    use super::*;
    use crate::bytes::Reason;

    fn vec_u8(d: &mut Vec<u8>, bytes: &[u8]) {
        d.extend(u32::try_from(bytes.len()).unwrap().to_le_bytes());
        d.extend(bytes);
    }

    /// A message with two keys, one instruction and one lookup.
    fn message_bytes() -> Vec<u8> {
        let mut d = vec![1, 1, 0];
        d.extend(2u32.to_le_bytes());
        d.extend([1; 32]);
        d.extend([2; 32]);
        d.extend(1u32.to_le_bytes());
        d.push(1);
        vec_u8(&mut d, &[0, 2]);
        vec_u8(&mut d, &[3, 0, 0, 0]);
        d.extend(1u32.to_le_bytes());
        d.extend([9; 32]);
        vec_u8(&mut d, &[4]);
        vec_u8(&mut d, &[]);
        d
    }

    fn expected_message() -> VaultMessage {
        VaultMessage {
            num_signers: 1,
            num_writable_signers: 1,
            num_writable_non_signers: 0,
            account_keys: vec![Address::new([1; 32]), Address::new([2; 32])],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indexes: vec![0, 2],
                data: vec![3, 0, 0, 0],
            }],
            address_table_lookups: vec![AddressTableLookup {
                account_key: Address::new([9; 32]),
                writable_indexes: vec![4],
                readonly_indexes: vec![],
            }],
        }
    }

    fn vault_transaction_bytes() -> Vec<u8> {
        let mut d = VAULT_TRANSACTION_DISCRIMINATOR.to_vec();
        d.extend([7; 32]);
        d.extend([8; 32]);
        d.extend(42u64.to_le_bytes());
        d.extend([254, 3, 250]);
        vec_u8(&mut d, &[251, 252]);
        d.extend(message_bytes());
        d
    }

    #[test]
    fn the_batch_transaction_discriminator_is_sha256_of_its_name() {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(b"account:VaultBatchTransaction");
        assert_eq!(
            digest.get(..8),
            Some(VAULT_BATCH_TRANSACTION_DISCRIMINATOR.as_slice())
        );
    }

    #[test]
    fn decodes_a_vault_transaction_and_its_message() {
        let mut d = vault_transaction_bytes();
        let expected = VaultTransaction {
            multisig: Address::new([7; 32]),
            index: 42,
            vault_index: 3,
            message: expected_message(),
        };
        assert_eq!(decode_vault_transaction(&d), Ok(expected.clone()));
        d.extend([0; 16]);
        assert_eq!(decode_vault_transaction(&d), Ok(expected), "trailing bytes");
    }

    #[test]
    fn every_truncation_of_a_vault_transaction_is_refused() {
        let d = vault_transaction_bytes();
        for end in 0..d.len() {
            let e = decode_vault_transaction(&d[..end]).unwrap_err();
            assert_eq!(e.reason, Reason::TooShort, "at {end}: {e}");
        }
    }

    #[test]
    fn a_forged_instruction_count_is_refused() {
        let mut d = VAULT_TRANSACTION_DISCRIMINATOR.to_vec();
        d.extend([0; 75]);
        vec_u8(&mut d, &[]);
        d.extend([0, 0, 0]);
        d.extend(0u32.to_le_bytes());
        d.extend(u32::MAX.to_le_bytes());
        assert_eq!(
            decode_vault_transaction(&d).unwrap_err().field,
            "message.instructions"
        );
    }

    #[test]
    fn decodes_a_batch_and_its_transactions() {
        let mut d = BATCH_DISCRIMINATOR.to_vec();
        d.extend([7; 32]);
        d.extend([8; 32]);
        d.extend(42u64.to_le_bytes());
        d.extend([254, 1, 250]);
        d.extend(3u32.to_le_bytes());
        d.extend(1u32.to_le_bytes());
        let batch = decode_batch(&d).unwrap();
        assert_eq!(
            batch,
            Batch {
                multisig: Address::new([7; 32]),
                index: 42,
                vault_index: 1,
                size: 3,
                executed_transaction_index: 1
            }
        );
        assert_eq!(batch.next_transaction(), Some(2));
        let done = Batch {
            executed_transaction_index: 3,
            ..batch
        };
        assert_eq!(done.next_transaction(), None);

        let mut t = VAULT_BATCH_TRANSACTION_DISCRIMINATOR.to_vec();
        t.push(255);
        vec_u8(&mut t, &[]);
        t.extend(message_bytes());
        assert_eq!(decode_batch_transaction(&t), Ok(expected_message()));
        assert_eq!(
            decode_batch_transaction(&vault_transaction_bytes())
                .unwrap_err()
                .reason,
            Reason::WrongType
        );
    }

    #[test]
    fn batch_transaction_pda_extends_the_transaction_seeds() {
        let multisig = Address::new([9; 32]);
        let (expected, _) = find_program_address(
            &[
                b"multisig",
                multisig.as_bytes(),
                b"transaction",
                &5u64.to_le_bytes(),
                b"batch_transaction",
                &2u32.to_le_bytes(),
            ],
            &PROGRAM_ID,
        )
        .unwrap();
        assert_eq!(batch_transaction_address(&multisig, 5, 2), Ok(expected));
    }
}
