//! Program derived addresses and the ed25519 on-curve check. Pure; no I/O.
//!
//! The rules are the Solana runtime's (`create_program_address` and
//! `find_program_address`): at most 16 seeds, each at most 32 bytes; the address is
//! sha256(seeds, program id, "ProgramDerivedAddress") and must not be a point on the
//! ed25519 curve, so no private key can exist for it.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

use crate::read::codec::Address;

/// The most seeds an address may have, the bump seed included.
pub const MAX_SEEDS: usize = 16;
/// The longest a single seed may be, in bytes.
pub const MAX_SEED_LEN: usize = 32;

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// Why no program address could be made from the seeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdaError {
    /// More than `MAX_SEEDS` seeds (counting the bump), or one longer than `MAX_SEED_LEN`.
    BadSeeds,
    /// The hash is a point on the curve, so it is not a program address.
    OnCurve,
    /// No bump from 255 down to 1 gave an address off the curve.
    NoBump,
}

impl std::fmt::Display for PdaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSeeds => write!(
                f,
                "at most {MAX_SEEDS} seeds of at most {MAX_SEED_LEN} bytes each"
            ),
            Self::OnCurve => f.write_str("the seeds give a point on the ed25519 curve"),
            Self::NoBump => f.write_str("no bump seed gives a program address"),
        }
    }
}

impl std::error::Error for PdaError {}

/// True if the 32 bytes decompress to a point on the ed25519 curve, which is what a
/// public key is. A program address is never on the curve.
pub fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// The program address for exactly these seeds (the caller includes any bump).
pub fn create_program_address(seeds: &[&[u8]], program_id: &Address) -> Result<Address, PdaError> {
    if seeds.len() > MAX_SEEDS || seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
        return Err(PdaError::BadSeeds);
    }
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(program_id.as_bytes());
    hasher.update(PDA_MARKER);
    let hash: [u8; 32] = hasher.finalize().into();
    if is_on_curve(&hash) {
        return Err(PdaError::OnCurve);
    }
    Ok(Address::new(hash))
}

/// The canonical program address for `seeds`: the first bump seed, counting down from
/// 255, that gives an address off the curve. Returns the address and its bump.
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<(Address, u8), PdaError> {
    // The bump is one more seed.
    if seeds.len() >= MAX_SEEDS || seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
        return Err(PdaError::BadSeeds);
    }
    for bump in bump_seeds() {
        let bump_seed = [bump];
        let mut with_bump: Vec<&[u8]> = seeds.to_vec();
        with_bump.push(&bump_seed);
        match create_program_address(&with_bump, program_id) {
            Ok(address) => return Ok((address, bump)),
            Err(PdaError::OnCurve) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(PdaError::NoBump)
}

/// The bump seeds tried, in order: 255 down to 1, as the runtime's
/// `try_find_program_address` does. Bump 0 is never tried.
fn bump_seeds() -> impl Iterator<Item = u8> {
    (1..=u8::MAX).rev()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Squads v4 multisig program, the same id on mainnet and devnet.
    const SQUADS_V4: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

    fn vault(multisig: &str, index: u8) -> (Address, u8) {
        let multisig: Address = multisig.parse().unwrap();
        let program: Address = SQUADS_V4.parse().unwrap();
        find_program_address(
            &[b"multisig", multisig.as_bytes(), b"vault", &[index]],
            &program,
        )
        .unwrap()
    }

    /// Expected values are the output of `getVaultPda({ multisigPda, index })` from
    /// Squads' own TypeScript SDK, `@sqds/multisig` 2.1.4 (npm), which derives seeds
    /// `["multisig", multisigPda, "vault", u8(index)]` under the program id above.
    /// The values were cross-checked with `solana find-program-derived-address`.
    /// Squads publishes no table of vault addresses, so the multisig inputs are the
    /// ones Squads publishes in its own repositories:
    /// - `D3oQ6QxSYk6aKUsmBTa9BghFQvbRi7kxP6h95NSdjjXz`, the multisig account fixture
    ///   in `Squads-Protocol/v4` at `tests/fixtures/pre-rent-collector/multisig-account.json`;
    /// - `Aumm6P4VT4RcZUspSBRRkTYt2RFCWVfUhci23LrFNfZC`, the example `multisig-pda` in
    ///   the README of `Squads-Protocol/squads-v4-program-upgrade`.
    ///
    /// Index 255 needs a second bump (254), so the off-curve loop is exercised.
    #[test]
    fn derives_squads_v4_vault_addresses() {
        let cases = [
            (
                "D3oQ6QxSYk6aKUsmBTa9BghFQvbRi7kxP6h95NSdjjXz",
                0,
                "E8PUL1CcCvw7zHhjwt3jk3jhPXVEGpQeSjieDmJb6buR",
                255,
            ),
            (
                "D3oQ6QxSYk6aKUsmBTa9BghFQvbRi7kxP6h95NSdjjXz",
                1,
                "F7Qi4T4XD5PvmxEnvt3XPgHt1LsEUa4pbJ1x3Gxfw2Lb",
                255,
            ),
            (
                "Aumm6P4VT4RcZUspSBRRkTYt2RFCWVfUhci23LrFNfZC",
                0,
                "29fDzkuGkAV1xhpr45TdbpQw5fTbsmjH6WA5Jv87E267",
                255,
            ),
            (
                "Aumm6P4VT4RcZUspSBRRkTYt2RFCWVfUhci23LrFNfZC",
                255,
                "EjjadFpUp76Qd4QtB1prQQpR1vJkbXceGRQRSANDqPhF",
                254,
            ),
        ];
        for (multisig, index, expected, bump) in cases {
            let (address, found_bump) = vault(multisig, index);
            assert_eq!(address.to_string(), expected, "{multisig} vault {index}");
            assert_eq!(found_bump, bump, "{multisig} vault {index}");
            assert!(!is_on_curve(address.as_bytes()));
        }
    }

    #[test]
    fn a_wallet_key_is_on_the_curve_and_a_program_address_is_not() {
        // The ed25519 base point, compressed: a valid public key.
        let mut base_point = [0x66; 32];
        base_point[0] = 0x58;
        assert!(is_on_curve(&base_point));
        let (address, _) = vault("D3oQ6QxSYk6aKUsmBTa9BghFQvbRi7kxP6h95NSdjjXz", 0);
        assert!(!is_on_curve(address.as_bytes()));
        // Bump 255 for index 255 hashes to a point on the curve, so it is refused.
        let multisig: Address = "Aumm6P4VT4RcZUspSBRRkTYt2RFCWVfUhci23LrFNfZC"
            .parse()
            .unwrap();
        let program: Address = SQUADS_V4.parse().unwrap();
        assert_eq!(
            create_program_address(
                &[b"multisig", multisig.as_bytes(), b"vault", &[255], &[255]],
                &program
            ),
            Err(PdaError::OnCurve)
        );
    }

    /// The runtime's `try_find_program_address` tries 255 down to 1 and never 0.
    #[test]
    fn tries_bumps_255_down_to_1_and_never_0() {
        let bumps: Vec<u8> = bump_seeds().collect();
        assert_eq!(bumps.len(), 255);
        assert_eq!(bumps.first(), Some(&255));
        assert_eq!(bumps.last(), Some(&1));
        assert!(!bumps.contains(&0));
    }

    #[test]
    fn refuses_too_many_or_too_long_seeds() {
        let program: Address = SQUADS_V4.parse().unwrap();
        let long = [0u8; MAX_SEED_LEN + 1];
        assert_eq!(
            find_program_address(&[&long], &program),
            Err(PdaError::BadSeeds)
        );
        let many: Vec<&[u8]> = vec![b"a"; MAX_SEEDS];
        assert_eq!(
            find_program_address(&many, &program),
            Err(PdaError::BadSeeds)
        );
        assert_eq!(
            create_program_address(&vec![b"a" as &[u8]; MAX_SEEDS + 1], &program),
            Err(PdaError::BadSeeds)
        );
        let fifteen: Vec<&[u8]> = vec![b"a"; MAX_SEEDS - 1];
        assert!(find_program_address(&fifteen, &program).is_ok());
    }
}
