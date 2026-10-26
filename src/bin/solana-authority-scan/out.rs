//! Where the scanner writes: the report directory (`--out`) and the index cache.
//!
//! A report names programs and the rules they matched, so it must not land where it
//! could be committed and published by accident. Every path is canonicalised first
//! (symlinks, `.`, `..`), then refused if it is inside a git work tree (any ancestor
//! holds `.git`). A `..` after a part that does not exist yet is refused outright.
//! Files are written atomically (a uniquely named temp file, then a rename), never
//! through a symlink.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

/// The largest file [`OutDir::read_file`] reads.
pub const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

/// A directory that has passed the checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutDir {
    root: PathBuf,
}

fn io(what: &str, path: &Path, e: std::io::Error) -> String {
    format!("cannot {what} {}: {e}", path.display())
}

/// Refuses a canonical path inside a git work tree.
pub fn check_outside_git(path: &Path) -> Result<(), String> {
    for dir in path.ancestors() {
        let git = dir.join(".git");
        if fs::symlink_metadata(&git).is_ok() {
            return Err(format!(
                "{} is inside a git work tree ({}); scan output names programs, so it is \
                 never written where it could be committed. Choose a directory outside \
                 any repository",
                path.display(),
                git.display()
            ));
        }
    }
    Ok(())
}

/// Creates `dir` and its missing parents. With `private`, each is created with mode
/// 0700 and `dir` itself is set to 0700 even if it existed.
fn make_dirs(dir: &Path, private: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        return fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let _ = private;
    fs::create_dir_all(dir)
}

/// A temp-file suffix no other write uses: the process id, a per-process counter and
/// the clock's nanoseconds.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(".tmp-{}-{n}-{nanos}", std::process::id())
}

impl OutDir {
    /// `path`, created if needed (mode 0700 with `private`). Nothing is created until
    /// the deepest existing parent has been canonicalised and the full path checked.
    pub fn create(path: &Path, private: bool) -> Result<OutDir, String> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| format!("cannot read the current directory: {e}"))?
                .join(path)
        };
        let mut existing = path.as_path();
        let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
        while fs::symlink_metadata(existing).is_err() {
            match (existing.file_name(), existing.parent()) {
                (Some(name), Some(parent)) => {
                    missing.push(name);
                    existing = parent;
                }
                _ => return Err(format!("{} is not a usable path", path.display())),
            }
        }
        if path
            .components()
            .rev()
            .take(missing.len())
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(format!(
                "{} has `..` after a directory that does not exist",
                path.display()
            ));
        }
        let mut target = fs::canonicalize(existing).map_err(|e| io("resolve", existing, e))?;
        for name in missing.iter().rev() {
            target.push(name);
        }
        check_outside_git(&target)?;
        make_dirs(&target, private).map_err(|e| io("create", &target, e))?;
        let root = fs::canonicalize(&target).map_err(|e| io("resolve", &target, e))?;
        if !root.is_dir() {
            return Err(format!("{} is not a directory", root.display()));
        }
        check_outside_git(&root)?;
        Ok(OutDir { root })
    }

    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `name` under the root: one plain file name.
    pub fn path(&self, name: &str) -> Result<PathBuf, String> {
        let rel = Path::new(name);
        let mut parts = rel.components();
        let plain = matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none();
        if !plain {
            return Err(format!("{name:?} is not a plain file name"));
        }
        Ok(self.root.join(rel))
    }

    /// The text of `name`, or `None` if it does not exist. A symlink is refused.
    pub fn read_file(&self, name: &str) -> Result<Option<String>, String> {
        let path = self.path(name)?;
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io("read", &path, e)),
        };
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a symlink; refusing to use it",
                path.display()
            ));
        }
        if meta.len() > MAX_READ_BYTES {
            return Err(format!("{} is too large", path.display()));
        }
        let mut text = String::new();
        fs::File::open(&path)
            .and_then(|f| f.take(MAX_READ_BYTES).read_to_string(&mut text))
            .map_err(|e| io("read", &path, e))?;
        Ok(Some(text))
    }

    /// Writes `name` atomically: a new temp file beside it, then a rename. A symlink
    /// at `name` is refused.
    pub fn write(&self, name: &str, text: &str) -> Result<PathBuf, String> {
        let target = self.path(name)?;
        if fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!(
                "{} is a symlink; refusing to write through it",
                target.display()
            ));
        }
        let mut tmp_name = OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(unique_suffix());
        let tmp = self.root.join(tmp_name);
        let written = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()));
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(io("write", &tmp, e));
        }
        fs::rename(&tmp, &target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            io("write", &target, e)
        })?;
        Ok(target)
    }

    /// Removes a file left by an earlier run, so the directory never holds a
    /// `candidates.json` from another scan. A symlink or a directory there is refused,
    /// not followed.
    pub fn remove_old(&self, name: &str) -> Result<bool, String> {
        let path = self.path(name)?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io("read", &path, e)),
            Ok(m) if !m.file_type().is_file() => Err(format!(
                "{} is not a regular file; refusing to remove it",
                path.display()
            )),
            Ok(_) => fs::remove_file(&path)
                .map(|()| true)
                .map_err(|e| io("remove", &path, e)),
        }
    }
}

/// The report directory (`--out`), created if needed, after the checks.
pub fn open_out(path: &Path) -> Result<OutDir, String> {
    OutDir::create(path, false)
}

/// `$XDG_CACHE_HOME/solana-authority-scan`, else `$HOME/.cache/solana-authority-scan`.
pub fn cache_path(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf, String> {
    let base = xdg
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".cache"))
        })
        .ok_or("neither XDG_CACHE_HOME nor HOME is set")?;
    Ok(base.join("solana-authority-scan"))
}

/// The index cache directory, created readable by its owner only (mode 0700).
pub fn cache_dir() -> Result<OutDir, String> {
    let path = cache_path(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))?;
    OutDir::create(&path, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test's own directory under the system temp directory, removed when the guard
    /// drops. The temp directory must not be inside a git work tree.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "solana-authority-scan-{}-{name}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let dir = fs::canonicalize(dir).unwrap();
            assert!(
                check_outside_git(&dir).is_ok(),
                "the temp directory is inside a git work tree"
            );
            Scratch(dir)
        }
    }

    impl std::ops::Deref for Scratch {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn refuses_a_directory_inside_a_git_work_tree() {
        let tmp = Scratch::new("git-tree");
        fs::create_dir_all(tmp.join("repo/.git")).unwrap();
        let error = open_out(&tmp.join("repo/reports/new")).unwrap_err();
        assert!(error.contains("git work tree"), "{error}");
        assert!(!tmp.join("repo/reports").exists(), "nothing was created");
        // A `.git` file (a linked work tree or a submodule) counts too.
        fs::create_dir_all(tmp.join("linked")).unwrap();
        fs::write(tmp.join("linked/.git"), "gitdir: /elsewhere").unwrap();
        assert!(open_out(&tmp.join("linked/out")).is_err());
    }

    #[test]
    fn refuses_this_checkout_when_it_is_a_work_tree() {
        let root = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap();
        if !root.ancestors().any(|d| d.join(".git").exists()) {
            return;
        }
        for inside in [root.clone(), root.join("src"), root.join("target/scan-out")] {
            let error = open_out(&inside).unwrap_err();
            assert!(error.contains("git work tree"), "{error}");
        }
        assert!(
            !root.join("target/scan-out").exists(),
            "nothing was created"
        );
    }

    #[test]
    fn refuses_dotdot_after_a_missing_part_and_a_path_back_into_a_tree() {
        let tmp = Scratch::new("dotdot");
        assert!(open_out(&tmp.join("missing/../x")).is_err());
        assert!(!tmp.join("missing").exists());
        fs::create_dir_all(tmp.join("repo/.git")).unwrap();
        fs::create_dir_all(tmp.join("free")).unwrap();
        let through = tmp.join("free/../repo/out");
        assert!(open_out(&through).is_err(), "{}", through.display());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_into_a_work_tree() {
        let tmp = Scratch::new("symlink");
        fs::create_dir_all(tmp.join("repo/.git")).unwrap();
        fs::create_dir_all(tmp.join("repo/src")).unwrap();
        let link = tmp.join("link");
        std::os::unix::fs::symlink(tmp.join("repo/src"), &link).unwrap();
        assert!(open_out(&link).is_err());
        assert!(open_out(&link.join("new/report")).is_err());
        assert!(!tmp.join("repo/src/new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn never_writes_through_a_symlink() {
        let tmp = Scratch::new("write-link");
        let dir = open_out(&tmp.join("out")).unwrap();
        let target = tmp.join("elsewhere.json");
        fs::write(&target, "kept").unwrap();
        std::os::unix::fs::symlink(&target, dir.root().join("authority-scan.json")).unwrap();
        assert!(dir.write("authority-scan.json", "{}").is_err());
        assert!(dir.remove_old("authority-scan.json").is_err());
        assert!(dir.read_file("authority-scan.json").is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "kept");
    }

    #[test]
    fn plain_names_only() {
        let tmp = Scratch::new("names");
        let dir = open_out(&tmp).unwrap();
        for bad in ["", "../x", "/etc/passwd", "a/b", "./x", ".."] {
            assert!(dir.path(bad).is_err(), "{bad}");
            assert!(dir.write(bad, "x").is_err(), "{bad}");
        }
    }

    #[test]
    fn writes_reads_and_removes_outside_any_work_tree() {
        let tmp = Scratch::new("outside");
        let dir = open_out(&tmp.join("a/b")).unwrap();
        assert!(dir.root().ends_with("a/b"));
        dir.write("candidates.json", "{}").unwrap();
        dir.write("candidates.json", "{\"x\":1}").unwrap();
        assert_eq!(
            dir.read_file("candidates.json").unwrap().as_deref(),
            Some("{\"x\":1}")
        );
        let names: Vec<_> = fs::read_dir(dir.root()).unwrap().collect();
        assert_eq!(names.len(), 1, "no temp file is left behind");
        assert!(dir.remove_old("candidates.json").unwrap());
        assert!(!dir.remove_old("candidates.json").unwrap());
        assert_eq!(dir.read_file("candidates.json").unwrap(), None);
    }

    #[test]
    fn the_cache_path_follows_xdg_then_home() {
        assert_eq!(
            cache_path(Some("/x".into()), Some("/h".into())).unwrap(),
            PathBuf::from("/x/solana-authority-scan")
        );
        assert_eq!(
            cache_path(Some("".into()), Some("/h".into())).unwrap(),
            PathBuf::from("/h/.cache/solana-authority-scan")
        );
        assert!(cache_path(None, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_cache_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = Scratch::new("cache");
        let path = cache_path(Some(tmp.as_os_str().to_owned()), None).unwrap();
        let dir = OutDir::create(&path.join("nested"), true).unwrap();
        for d in [dir.root().to_path_buf(), path] {
            let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", d.display());
        }
    }
}
