//! Which loader owns a program, and who may change it. Pure; no I/O.
//!
//! Layouts (`docs/how-it-works.md`, "Layouts decoded"):
//! - BPF Upgradeable Loader, bincode `UpgradeableLoaderState`: a u32 tag. The program
//!   account is tag 2 then the ProgramData address (36 bytes). The ProgramData account
//!   is tag 3, the last deploy slot (u64), then the upgrade authority as
//!   `Option<Pubkey>` (a one-byte tag): 45 bytes of header, then the ELF.
//! - BPFLoader2 and the older BPFLoader: no state. The program cannot be upgraded.
//! - Loader v4, `LoaderV4State`: slot (u64), the authority or, once finalized, the
//!   next version (32 bytes), status (u64: 0 retracted, 1 deployed, 2 finalized):
//!   48 bytes of header, then the ELF.

use crate::read::{Account, Address};

use crate::bytes::{DecodeError, Reader, Reason};

/// `BPFLoaderUpgradeab1e11111111111111111111111`.
pub const UPGRADEABLE_LOADER: Address = Address::new([
    2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61, 22,
    193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
]);
/// `BPFLoader2111111111111111111111111111111111`.
pub const BPF_LOADER_2: Address = Address::new([
    2, 168, 246, 145, 78, 136, 161, 110, 57, 90, 225, 40, 148, 143, 250, 105, 86, 147, 55, 104, 24,
    221, 71, 67, 82, 33, 243, 198, 0, 0, 0, 0,
]);
/// `BPFLoader1111111111111111111111111111111111`, the first, deprecated loader.
pub const BPF_LOADER_1: Address = Address::new([
    2, 168, 246, 145, 78, 136, 161, 107, 189, 35, 149, 133, 95, 100, 4, 217, 180, 244, 86, 183,
    130, 27, 176, 20, 87, 73, 66, 140, 0, 0, 0, 0,
]);
/// `LoaderV411111111111111111111111111111111111`.
pub const LOADER_V4: Address = Address::new([
    5, 18, 180, 17, 81, 81, 227, 122, 173, 10, 139, 197, 211, 136, 46, 123, 127, 218, 76, 243, 210,
    192, 40, 200, 207, 131, 54, 24, 0, 0, 0, 0,
]);
/// `NativeLoader1111111111111111111111111111111`, which owns the builtin programs.
pub const NATIVE_LOADER: Address = Address::new([
    5, 135, 132, 191, 20, 139, 164, 40, 47, 176, 18, 87, 72, 136, 169, 241, 83, 160, 125, 173, 247,
    101, 192, 69, 92, 154, 151, 3, 128, 0, 0, 0,
]);

/// Names used in the report for each loader. Matched by readers of the JSON.
pub mod loader_name {
    pub const UPGRADEABLE: &str = "bpf-upgradeable";
    pub const BPF_LOADER_2: &str = "bpf-loader-2";
    pub const BPF_LOADER_1: &str = "bpf-loader-1";
    pub const LOADER_V4: &str = "loader-v4";
    pub const BUILTIN: &str = "builtin";
}

const PROGRAM_TAG: u32 = 2;
const PROGRAM_DATA_TAG: u32 = 3;
/// The ProgramData header: tag, slot, option tag, authority.
pub const PROGRAM_DATA_HEADER_LEN: usize = 45;
/// The loader-v4 header before the ELF.
pub const LOADER_V4_HEADER_LEN: usize = 48;

/// A loader-v4 program's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V4Status {
    /// Not executable; the authority can deploy again.
    Retracted,
    Deployed,
    /// Immutable. The address field names the next version, not an authority.
    Finalized,
}

impl V4Status {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Retracted => "retracted",
            Self::Deployed => "deployed",
            Self::Finalized => "finalized",
        }
    }
}

/// What the program account says about how the program can change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramKind {
    /// Upgradeable: the authority is in the ProgramData account, read next.
    Upgradeable { programdata: Address },
    /// BPFLoader2 or the older BPFLoader: immutable, no authority.
    Legacy { loader: &'static str },
    /// Loader v4: the authority is in the program account. `None` once finalized.
    LoaderV4 {
        last_deploy_slot: u64,
        authority: Option<Address>,
        status: V4Status,
    },
    /// A builtin owned by the native loader. Changed only by a validator release.
    Builtin,
}

impl ProgramKind {
    pub const fn loader_name(&self) -> &'static str {
        match self {
            Self::Upgradeable { .. } => loader_name::UPGRADEABLE,
            Self::Legacy { loader } => loader,
            Self::LoaderV4 { .. } => loader_name::LOADER_V4,
            Self::Builtin => loader_name::BUILTIN,
        }
    }
}

/// Why an account is not a program this scanner can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramError {
    /// Owned by a program that is not a loader.
    NotAProgram {
        owner: Address,
    },
    /// Owned by the upgradeable loader but not a program account (a buffer or a
    /// ProgramData account).
    NotAProgramAccount {
        tag: u32,
    },
    /// Owned by a legacy loader but not executable.
    NotExecutable,
    Decode(DecodeError),
}

impl std::fmt::Display for ProgramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAProgram { owner } => {
                write!(
                    f,
                    "not a program: the account is owned by {owner}, not a loader"
                )
            }
            Self::NotAProgramAccount { tag: 3 } => f.write_str(
                "this is a ProgramData account; scan the program account that points to it",
            ),
            Self::NotAProgramAccount { tag } => write!(
                f,
                "owned by the upgradeable loader but not a program account (state tag {tag})"
            ),
            Self::NotExecutable => f.write_str("owned by a loader but not executable"),
            Self::Decode(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ProgramError {}

impl From<DecodeError> for ProgramError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// Reads the program account by its owner.
pub fn classify_program(account: &Account) -> Result<ProgramKind, ProgramError> {
    let owner = account.owner;
    if owner == UPGRADEABLE_LOADER {
        let mut r = Reader::new(&account.data, "UpgradeableLoaderState");
        let tag = r.u32("tag")?;
        if tag != PROGRAM_TAG {
            return Err(ProgramError::NotAProgramAccount { tag });
        }
        let programdata = r.address("programdata_address")?;
        Ok(ProgramKind::Upgradeable { programdata })
    } else if owner == BPF_LOADER_2 || owner == BPF_LOADER_1 {
        if !account.executable {
            return Err(ProgramError::NotExecutable);
        }
        let loader = if owner == BPF_LOADER_2 {
            loader_name::BPF_LOADER_2
        } else {
            loader_name::BPF_LOADER_1
        };
        Ok(ProgramKind::Legacy { loader })
    } else if owner == LOADER_V4 {
        decode_loader_v4(&account.data)
    } else if owner == NATIVE_LOADER {
        Ok(ProgramKind::Builtin)
    } else {
        Err(ProgramError::NotAProgram { owner })
    }
}

fn decode_loader_v4(data: &[u8]) -> Result<ProgramKind, ProgramError> {
    let mut r = Reader::new(data, "LoaderV4State");
    let last_deploy_slot = r.u64("slot")?;
    let address = r.address("authority_address_or_next_version")?;
    let at = r.pos();
    let status = match r.u64("status")? {
        0 => V4Status::Retracted,
        1 => V4Status::Deployed,
        2 => V4Status::Finalized,
        tag => {
            return Err(DecodeError {
                account: "LoaderV4State",
                field: "status",
                offset: at,
                reason: Reason::BadTag(tag),
            }
            .into());
        }
    };
    let authority = (status != V4Status::Finalized).then_some(address);
    Ok(ProgramKind::LoaderV4 {
        last_deploy_slot,
        authority,
        status,
    })
}

/// The ProgramData header of an upgradeable program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramData {
    pub last_deploy_slot: u64,
    /// `None` means the program is immutable.
    pub upgrade_authority: Option<Address>,
}

/// Decodes the ProgramData header; the ELF after it is not read.
pub fn decode_program_data(data: &[u8]) -> Result<ProgramData, DecodeError> {
    let mut r = Reader::new(data, "ProgramData");
    if r.u32("tag")? != PROGRAM_DATA_TAG {
        return Err(DecodeError {
            account: "ProgramData",
            field: "tag",
            offset: 0,
            reason: Reason::WrongType,
        });
    }
    let last_deploy_slot = r.u64("slot")?;
    let upgrade_authority = r.option_address("upgrade_authority_address")?;
    Ok(ProgramData {
        last_deploy_slot,
        upgrade_authority,
    })
}

/// `UpgradeableLoaderState` tags (bincode u32).
const UNINITIALIZED_TAG: u32 = 0;
const BUFFER_TAG: u32 = 1;

/// An upgradeable loader account's state, as far as its authority goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderState {
    Uninitialized,
    /// A buffer holding code to deploy; `None` means it can no longer be changed.
    Buffer {
        authority: Option<Address>,
    },
    Program {
        programdata: Address,
    },
    ProgramData {
        upgrade_authority: Option<Address>,
    },
}

/// Decodes the state at the start of an account the upgradeable loader owns:
/// tag 0 uninitialized; 1 buffer, then the authority as `Option<Pubkey>`; 2 program,
/// then the ProgramData address; 3 ProgramData, then the slot (u64) and the upgrade
/// authority. The code after the header is not read. Any other tag is an error.
pub fn decode_state(data: &[u8]) -> Result<LoaderState, DecodeError> {
    let mut r = Reader::new(data, "UpgradeableLoaderState");
    let at = r.pos();
    match r.u32("tag")? {
        UNINITIALIZED_TAG => Ok(LoaderState::Uninitialized),
        BUFFER_TAG => Ok(LoaderState::Buffer {
            authority: r.option_address("authority_address")?,
        }),
        PROGRAM_TAG => Ok(LoaderState::Program {
            programdata: r.address("programdata_address")?,
        }),
        PROGRAM_DATA_TAG => {
            r.u64("slot")?;
            Ok(LoaderState::ProgramData {
                upgrade_authority: r.option_address("upgrade_authority_address")?,
            })
        }
        tag => Err(DecodeError {
            account: "UpgradeableLoaderState",
            field: "tag",
            offset: at,
            reason: Reason::BadTag(u64::from(tag)),
        }),
    }
}

/// `UpgradeableLoaderInstruction` tags (bincode u32, the first four bytes of the
/// instruction data) that the stale-proposal check reads, with the accounts each
/// takes (agave `programs/bpf_loader/src/lib.rs` and `sdk` loader-v3 interface).
pub mod instruction {
    /// Accounts: ProgramData, program, buffer, spill, rent, clock, authority.
    pub const UPGRADE: u32 = 3;
    /// Accounts: buffer or ProgramData, current authority, new authority (optional).
    pub const SET_AUTHORITY: u32 = 4;
    /// Accounts: the account to close, recipient, authority, program (each after
    /// the first as the state needs).
    pub const CLOSE: u32 = 5;
    /// Accounts: buffer or ProgramData, current authority, new authority (signer).
    pub const SET_AUTHORITY_CHECKED: u32 = 7;
}

/// The instruction tag of upgradeable loader instruction data, if it has four bytes.
pub fn instruction_tag(data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(owner: Address, data: Vec<u8>, executable: bool) -> Account {
        Account {
            lamports: 1,
            owner,
            data,
            executable,
        }
    }

    #[test]
    fn loader_ids_print_as_their_names() {
        for (id, text) in [
            (
                UPGRADEABLE_LOADER,
                "BPFLoaderUpgradeab1e11111111111111111111111",
            ),
            (BPF_LOADER_2, "BPFLoader2111111111111111111111111111111111"),
            (BPF_LOADER_1, "BPFLoader1111111111111111111111111111111111"),
            (LOADER_V4, "LoaderV411111111111111111111111111111111111"),
            (NATIVE_LOADER, "NativeLoader1111111111111111111111111111111"),
        ] {
            assert_eq!(id.to_string(), text);
        }
    }

    /// Constructed: devnet has no finalized loader-v4 program to capture.
    #[test]
    fn a_finalized_loader_v4_program_has_no_authority() {
        let mut data = 7u64.to_le_bytes().to_vec();
        data.extend([9; 32]);
        data.extend(2u64.to_le_bytes());
        let kind = classify_program(&account(LOADER_V4, data.clone(), true)).unwrap();
        assert_eq!(
            kind,
            ProgramKind::LoaderV4 {
                last_deploy_slot: 7,
                authority: None,
                status: V4Status::Finalized
            }
        );
        if let Some(status) = data.get_mut(40) {
            *status = 3;
        }
        assert!(matches!(
            classify_program(&account(LOADER_V4, data, true)),
            Err(ProgramError::Decode(DecodeError {
                reason: Reason::BadTag(3),
                ..
            }))
        ));
    }

    #[test]
    fn refuses_accounts_that_are_not_programs() {
        let system = Address::new([0; 32]);
        assert_eq!(
            classify_program(&account(system, vec![], false)),
            Err(ProgramError::NotAProgram { owner: system })
        );
        let mut programdata = 3u32.to_le_bytes().to_vec();
        programdata.extend([0; 9]);
        assert_eq!(
            classify_program(&account(UPGRADEABLE_LOADER, programdata.clone(), false)),
            Err(ProgramError::NotAProgramAccount { tag: 3 })
        );
        assert_eq!(
            classify_program(&account(BPF_LOADER_2, vec![], false)),
            Err(ProgramError::NotExecutable)
        );
        assert_eq!(
            decode_program_data(&programdata),
            Ok(ProgramData {
                last_deploy_slot: 0,
                upgrade_authority: None
            })
        );
        assert_eq!(
            decode_program_data(&[2, 0, 0, 0]).unwrap_err().reason,
            Reason::WrongType
        );
    }

    #[test]
    fn decodes_each_upgradeable_loader_state() {
        let key = Address::new([4; 32]);
        let mut buffer = 1u32.to_le_bytes().to_vec();
        buffer.push(1);
        buffer.extend(key.as_bytes());
        buffer.extend([0x7f, b'E']);
        assert_eq!(
            decode_state(&buffer),
            Ok(LoaderState::Buffer {
                authority: Some(key)
            })
        );
        assert_eq!(
            decode_state(&[1, 0, 0, 0, 0]),
            Ok(LoaderState::Buffer { authority: None })
        );
        assert_eq!(decode_state(&[0; 4]), Ok(LoaderState::Uninitialized));
        let mut program = 2u32.to_le_bytes().to_vec();
        program.extend(key.as_bytes());
        assert_eq!(
            decode_state(&program),
            Ok(LoaderState::Program { programdata: key })
        );
        let mut programdata = 3u32.to_le_bytes().to_vec();
        programdata.extend(9u64.to_le_bytes());
        programdata.push(1);
        programdata.extend(key.as_bytes());
        assert_eq!(
            decode_state(&programdata),
            Ok(LoaderState::ProgramData {
                upgrade_authority: Some(key)
            })
        );
        assert_eq!(
            decode_state(&[4, 0, 0, 0]).unwrap_err().reason,
            Reason::BadTag(4)
        );
        assert_eq!(decode_state(&[]).unwrap_err().reason, Reason::TooShort);
        assert_eq!(
            decode_state(&[1, 0, 0, 0, 2]).unwrap_err().reason,
            Reason::BadTag(2)
        );
        assert_eq!(
            instruction_tag(&[3, 0, 0, 0, 9]),
            Some(instruction::UPGRADE)
        );
        assert_eq!(instruction_tag(&[3, 0, 0]), None);
    }
}
