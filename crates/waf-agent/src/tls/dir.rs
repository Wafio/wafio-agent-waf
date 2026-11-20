//! The key directory: the certificates and keys the agent serves, and what it remembers about
//! them. Only the process that holds `tls.lock` writes in it, so a reload's successor, which runs
//! next to the process it replaces for a while, reads what that process wrote and writes nothing.
//!
//! The directory is made 0700 and must belong to the user the agent runs as; its files are 0600
//! from the moment they exist. Reads never follow a link and are capped, and a file appears under
//! its name only whole (written under a temporary name, synced, renamed).

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use wafio_control::{TempGuard, create_temp};

/// The directory of a running agent. The unit's `StateDirectory` is its parent.
pub const KEY_DIR: &str = "/var/lib/wafio-waf-agent/tls";

/// Names its holder: one writer at a time.
const LOCK_FILE: &str = "tls.lock";
/// A file with a key and a chain is a few kilobytes; nothing the agent wrote is larger.
pub const MAX_KEY_FILE: usize = 128 << 10;
/// Prefix of a file that is being written.
const TEMP_PREFIX: &str = ".tmp-";

/// Why a file could not be read.
#[derive(Debug)]
pub enum ReadError {
    Missing,
    TooLarge,
    /// A link, a directory or anything else that is not a plain file, or an I/O error.
    Other(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Missing => f.write_str("no such file"),
            ReadError::TooLarge => f.write_str("larger than the limit"),
            ReadError::Other(e) => write!(f, "{}", e.kind()),
        }
    }
}

/// The key directory, and the lock that makes its holder the one writer.
pub struct KeyDir {
    path: PathBuf,
    lock: Option<Flock<File>>,
    /// The lock could not be tried for a reason other than another holder, and that was logged:
    /// a process that keeps trying says it once.
    complained: bool,
}

impl KeyDir {
    /// Opens the directory the agent uses: `KEY_DIR`, or with the `test-tls` feature the one
    /// `WAFIO_TEST_TLS_DIR` names. The error says why the directory cannot be used.
    pub fn open_default() -> Result<KeyDir, String> {
        let path = default_path();
        KeyDir::open(&path, nix::unistd::geteuid().as_raw())
    }

    /// Makes the directory 0700 if it is missing (its parent must exist) and checks it: a real
    /// directory, not a link, owned by `uid`. Group and other bits are cleared. Takes the lock if
    /// it is free, and then clears out the files of a write that did not finish.
    pub fn open(path: &Path, uid: u32) -> Result<KeyDir, String> {
        let shown = path.display();
        match DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{shown}: cannot create ({})", e.kind())),
        }
        // Not `metadata`: a link in place of the directory is refused, not followed.
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("{shown}: cannot stat ({})", e.kind()))?;
        if !meta.is_dir() {
            return Err(format!("{shown}: not a directory"));
        }
        if meta.uid() != uid {
            return Err(format!(
                "{shown}: owned by user {}, not by user {uid}",
                meta.uid()
            ));
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & !0o077))
                .map_err(|e| {
                    format!(
                        "{shown}: cannot clear group and other access ({})",
                        e.kind()
                    )
                })?;
            tracing::info!(
                "[tls] key directory {shown}: group and other access cleared (mode was {mode:04o})"
            );
        }
        let mut dir = KeyDir {
            path: path.to_owned(),
            lock: None,
            complained: false,
        };
        dir.try_lock();
        Ok(dir)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this process is the one that writes.
    pub fn holds_lock(&self) -> bool {
        self.lock.is_some()
    }

    /// Takes the lock if no other process holds it, and then removes the temporary files of a
    /// write that did not finish. Returns whether this process holds the lock.
    pub fn try_lock(&mut self) -> bool {
        if self.lock.is_some() {
            return true;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path.join(LOCK_FILE));
        let file = match file {
            Ok(f) => f,
            Err(e) => {
                self.complain(format_args!("cannot open ({})", e.kind()));
                return false;
            }
        };
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => {
                self.lock = Some(lock);
                self.sweep_temp();
                true
            }
            Err((_, Errno::EAGAIN)) => false,
            Err((_, e)) => {
                self.complain(format_args!("{e}"));
                false
            }
        }
    }

    fn complain(&mut self, what: std::fmt::Arguments<'_>) {
        if !std::mem::replace(&mut self.complained, true) {
            tracing::info!("[tls] key directory lock: {what}");
        }
    }

    /// Lets go of the lock, so the process that takes over can write.
    pub fn release_lock(&mut self) {
        self.lock = None;
    }

    /// The file `name`, read without following a link and without more than `limit` bytes.
    pub fn read(&self, name: &str, limit: usize) -> Result<Vec<u8>, ReadError> {
        // O_NONBLOCK: opening a named pipe for reading waits for a writer, and the apply lock is
        // held. It changes nothing for a plain file, and the check below refuses anything else.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.file(name))
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => ReadError::Missing,
                _ => ReadError::Other(e),
            })?;
        let meta = file.metadata().map_err(ReadError::Other)?;
        if !meta.is_file() {
            return Err(ReadError::Other(io::Error::other("not a regular file")));
        }
        let mut data = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut data)
            .map_err(ReadError::Other)?;
        if data.len() > limit {
            return Err(ReadError::TooLarge);
        }
        Ok(data)
    }

    /// Puts `data` under `name`, whole or not at all: written to a temporary file, synced, renamed
    /// over the name, and the directory synced. The temporary file is gone on every failure.
    /// Only the holder of the lock writes.
    pub fn write(&self, name: &str, data: &[u8]) -> io::Result<()> {
        self.must_hold_lock()?;
        let (mut file, temp) = create_temp(&self.path, TEMP_PREFIX, "")?;
        let mut guard = TempGuard::new(&temp);
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, self.file(name))?;
        guard.keep();
        File::open(&self.path)?.sync_all()
    }

    /// Removes the file `name`; one that is not there is not an error. Only the holder of the lock
    /// writes.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        self.must_hold_lock()?;
        match std::fs::remove_file(self.file(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// The names of the plain files that end in `.pem`.
    pub fn pem_files(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            // `file_type` does not follow a link.
            if entry.file_type()?.is_file()
                && let Ok(name) = entry.file_name().into_string()
                && name.ends_with(".pem")
            {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    /// Removes the temporary files a write that was cut short left behind. Only the holder of the
    /// lock may, as it is the only one that can tell nobody is writing one.
    fn sweep_temp(&self) {
        let Ok(entries) = std::fs::read_dir(&self.path) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(TEMP_PREFIX)
                && entry.file_type().is_ok_and(|t| t.is_file())
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    fn must_hold_lock(&self) -> io::Result<()> {
        if self.lock.is_some() {
            Ok(())
        } else {
            Err(io::Error::other(
                "another process holds the key directory lock",
            ))
        }
    }

    /// The path of a file of the directory. Names come from the checks of `entry` and from the
    /// agent's own state; one with a separator in it would leave the directory.
    fn file(&self, name: &str) -> PathBuf {
        debug_assert!(!name.contains('/') && !name.starts_with(".."), "{name}");
        self.path.join(name)
    }
}

fn default_path() -> PathBuf {
    #[cfg(feature = "test-tls")]
    if let Some(dir) = std::env::var_os("WAFIO_TEST_TLS_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(KEY_DIR)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A scratch directory in the system temp dir, removed on drop.
    pub(crate) struct Scratch(pub PathBuf);

    impl Scratch {
        pub(crate) fn new() -> Scratch {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "wafio-key-dir-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Scratch(path)
        }

        pub(crate) fn dir(&self) -> PathBuf {
            self.0.join("tls")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn my_uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn open(s: &Scratch) -> KeyDir {
        KeyDir::open(&s.dir(), my_uid()).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_missing_directory_is_made_private_and_a_loose_one_is_closed() {
        let s = Scratch::new();
        let dir = open(&s);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&s.dir()), 0o700);
        assert!(dir.holds_lock());
        assert_eq!(mode(&s.dir().join("tls.lock")), 0o600);

        // Group and other bits of an existing directory are cleared, the owner's are kept.
        drop(dir);
        std::fs::set_permissions(s.dir(), std::fs::Permissions::from_mode(0o775)).unwrap();
        open(&s);
        assert_eq!(mode(&s.dir()), 0o700);
        std::fs::set_permissions(s.dir(), std::fs::Permissions::from_mode(0o750)).unwrap();
        open(&s);
        assert_eq!(mode(&s.dir()), 0o700);
    }

    #[test]
    fn a_directory_that_is_not_ours_or_not_a_directory_is_refused() {
        let s = Scratch::new();
        // Another owner.
        std::fs::create_dir(s.dir()).unwrap();
        let err = KeyDir::open(&s.dir(), my_uid() + 1).err().unwrap();
        assert!(err.contains("owned by user"), "{err}");

        // A link in place of the directory, even to a directory of ours.
        let real = s.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = s.0.join("link");
        symlink(&real, &link).unwrap();
        let err = KeyDir::open(&link, my_uid()).err().unwrap();
        assert!(err.contains("not a directory"), "{err}");

        // A file.
        let file = s.0.join("file");
        std::fs::write(&file, "x").unwrap();
        let err = KeyDir::open(&file, my_uid()).err().unwrap();
        assert!(
            err.contains("not a directory") || err.contains("cannot create"),
            "{err}"
        );

        // A parent that is not there is not made.
        let err = KeyDir::open(&s.0.join("missing/tls"), my_uid())
            .err()
            .unwrap();
        assert!(err.contains("cannot create"), "{err}");
    }

    #[test]
    fn only_the_process_that_holds_the_lock_writes() {
        let s = Scratch::new();
        let mut first = open(&s);
        assert!(first.holds_lock());
        first.write("a.pem", b"one").unwrap();

        // Another description of the lock file, as another process has: refused while the first
        // holds it, and it may read what the first wrote.
        let mut second = open(&s);
        assert!(!second.holds_lock() && !second.try_lock());
        assert_eq!(second.read("a.pem", 100).unwrap(), b"one");
        assert!(second.write("b.pem", b"two").is_err());
        assert!(second.remove("a.pem").is_err());
        assert_eq!(
            names(&s.dir()),
            ["a.pem", "tls.lock"],
            "the second wrote nothing"
        );

        first.release_lock();
        assert!(second.try_lock());
        second.write("b.pem", b"two").unwrap();
        assert!(first.write("c.pem", b"x").is_err(), "the first lets go");
    }

    #[test]
    fn a_write_is_whole_private_and_leaves_no_temporary_file() {
        let s = Scratch::new();
        let dir = open(&s);
        dir.write("a.pem", b"first").unwrap();
        dir.write("a.pem", b"second").unwrap();
        assert_eq!(dir.read("a.pem", 100).unwrap(), b"second");
        let mode = std::fs::metadata(s.dir().join("a.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(names(&s.dir()), ["a.pem", "tls.lock"]);

        // A write that fails leaves nothing of its own: a name that is a directory cannot be
        // renamed over.
        std::fs::create_dir(s.dir().join("b.pem")).unwrap();
        assert!(dir.write("b.pem", b"x").is_err());
        assert_eq!(names(&s.dir()), ["a.pem", "b.pem", "tls.lock"]);
        assert_eq!(
            dir.read("a.pem", 100).unwrap(),
            b"second",
            "the others are as they were"
        );
    }

    #[test]
    fn a_read_does_not_follow_a_link_and_stops_at_the_limit() {
        let s = Scratch::new();
        let dir = open(&s);
        dir.write("a.pem", b"0123456789").unwrap();
        assert_eq!(dir.read("a.pem", 10).unwrap(), b"0123456789");
        assert!(matches!(dir.read("a.pem", 9), Err(ReadError::TooLarge)));
        assert!(matches!(dir.read("none.pem", 10), Err(ReadError::Missing)));

        symlink(s.dir().join("a.pem"), s.dir().join("link.pem")).unwrap();
        assert!(matches!(
            dir.read("link.pem", 100),
            Err(ReadError::Other(_))
        ));
        std::fs::create_dir(s.dir().join("dir.pem")).unwrap();
        assert!(matches!(dir.read("dir.pem", 100), Err(ReadError::Other(_))));
        // Links and directories are not files of the agent's: they are not listed to be removed.
        assert_eq!(dir.pem_files().unwrap(), ["a.pem"]);
    }

    /// A named pipe under a file name must not hold the caller: it would wait for a writer.
    #[test]
    fn a_named_pipe_is_refused_and_does_not_block_the_read() {
        let s = Scratch::new();
        let dir = open(&s);
        let pipe = s.dir().join("pipe.pem");
        let made = std::process::Command::new("mkfifo").arg(&pipe).status();
        assert!(made.is_ok_and(|status| status.success()), "mkfifo failed");
        assert!(matches!(
            dir.read("pipe.pem", 100),
            Err(ReadError::Other(_))
        ));
        assert_eq!(dir.pem_files().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn the_holder_clears_out_the_files_of_a_cut_short_write_and_only_the_holder() {
        let s = Scratch::new();
        let first = open(&s);
        let left = s.dir().join(".tmp-123456");
        std::fs::write(&left, "half").unwrap();
        // The second does not hold the lock: a write may be under way, so it leaves the file.
        let mut second = open(&s);
        assert!(left.exists());
        drop(first);
        assert!(second.try_lock());
        assert!(!left.exists());
    }
}
