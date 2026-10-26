//! The Squads v4 index cache: one JSON file per cluster in the cache directory
//! (`out::cache_dir`, mode 0700, refused inside any git work tree), holding the
//! multisig list and the slot it was read at. A file older than `MAX_AGE` is rebuilt;
//! a rebuild that fails falls back to the old file, and the report gives its slot
//! either way. The file is read and written only through `out::OutDir`: never through
//! a symlink, and written atomically.

use std::time::{Duration, SystemTime};

use solana_authority_scan::index::{self, VaultIndex};
use solana_authority_scan::read::{Cluster, Rpc};

use crate::out::OutDir;

/// How old a cache file may be before it is rebuilt.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

fn file_name(cluster: Cluster) -> String {
    format!("squads-v4-index-{}.json", cluster.name())
}

fn read(dir: &OutDir, cluster: Cluster, max_vault_index: u8) -> Option<(VaultIndex, bool)> {
    let name = file_name(cluster);
    let text = dir.read_file(&name).ok()??;
    let index = VaultIndex::from_cache_json(&text, cluster.name(), max_vault_index)?;
    let fresh = dir
        .path(&name)
        .ok()
        .and_then(|p| std::fs::symlink_metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < MAX_AGE);
    Some((index, fresh))
}

fn write(dir: &OutDir, index: &VaultIndex, cluster: Cluster) -> Result<(), String> {
    let text = index.to_cache_json(cluster.name()).to_string();
    dir.write(&file_name(cluster), &text)
        .map(|_| ())
        .map_err(|e| format!("cannot write the cache file: {e}"))
}

/// The index for `cluster`: from a fresh cache file, else rebuilt with
/// `getProgramAccounts` and saved, else from a stale cache file. `Err` says why no
/// index is available.
pub fn load_or_build<R: Rpc + ?Sized>(
    rpc: &R,
    cluster: Cluster,
    dir: &OutDir,
    max_vault_index: u8,
    refresh: bool,
) -> Result<VaultIndex, String> {
    let cached = read(dir, cluster, max_vault_index);
    if let Some((index, true)) = &cached
        && !refresh
    {
        return Ok(index.clone());
    }
    eprintln!(
        "{}: listing Squads v4 multisigs (getProgramAccounts) ...",
        crate::NAME
    );
    let built = rpc
        .get_program_accounts(
            &solana_authority_scan::squads::PROGRAM_ID,
            &index::multisig_list_query(),
        )
        .map(|read| {
            let multisigs = VaultIndex::multisigs_from(&read.value);
            VaultIndex::build(read.slot, &multisigs, max_vault_index)
        });
    match (built, cached) {
        (Ok(index), _) => {
            if let Err(e) = write(dir, &index, cluster) {
                eprintln!("{}: {e}; continuing without saving the index", crate::NAME);
            }
            Ok(index)
        }
        (Err(e), Some((index, _))) => {
            eprintln!(
                "{}: cannot rebuild the index ({e}); using the cached one from slot {}",
                crate::NAME,
                index.slot
            );
            Ok(index)
        }
        (Err(e), None) => Err(format!(
            "the Squads v4 multisig list (getProgramAccounts) was refused or failed: {e}"
        )),
    }
}
