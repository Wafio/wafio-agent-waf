//! What is checked before a library is loaded. Loading runs the code of the file, so the checks decide who can make the
//! agent run code. They are, in this order:
//!
//! 1. the path is absolute: nothing is searched in `LD_LIBRARY_PATH` or the working directory;
//! 2. every directory above the file, as the path is written and as it resolves, is owned by root and not writable by
//!    group or others (a test trust relaxes the mode of all but the directory the file sits in);
//! 3. the file, opened without following a link, is a regular file owned by root and not writable by group or others;
//! 4. the file `<path>.sha256` next to it, which the installer writes, passes the same two checks of the file and starts with
//!    the SHA-256 of the library in hex, and the bytes of the library hash to it;
//! 5. the file is an ELF shared object whose segments and section headers lie inside the file. A file cut short would
//!    hash right if its checksum was made after the cut, and the dynamic loader would then die of SIGBUS in it.
//!
//! The library is then loaded through the descriptor that was checked (`/proc/self/fd/N`), so a file replaced after the
//! checks is not the one that runs.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::LoadError;

/// Who may own the files that are loaded.
#[derive(Clone, Copy, Debug)]
pub struct Trust {
    extra_owner: Option<u32>,
    /// Whether the directories above the one the file sits in must also be closed to group and others.
    strict_ancestors: bool,
}

impl Trust {
    /// Root only. What an agent under systemd uses.
    pub const fn root_only() -> Trust {
        Trust {
            extra_owner: None,
            strict_ancestors: true,
        }
    }

    /// Root, or the user the process runs as, and no mode check above the directory of the file: for tests that
    /// cannot be root and run under a home directory.
    #[cfg(feature = "test-owner")]
    pub fn root_or_current_user() -> Trust {
        // SAFETY: geteuid has no arguments and cannot fail.
        Trust {
            extra_owner: Some(unsafe { libc::geteuid() }),
            strict_ancestors: false,
        }
    }

    fn accepts(self, uid: u32) -> bool {
        uid == 0 || self.extra_owner == Some(uid)
    }
}

/// A library that passed the checks, open for reading.
pub struct Verified {
    pub file: File,
    pub path: PathBuf,
}

impl Verified {
    /// The path through which the checked file, and no other, can be loaded.
    pub fn load_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
}

fn io(path: &Path, what: &'static str, err: std::io::Error) -> LoadError {
    if err.kind() == std::io::ErrorKind::NotFound && what != "read" {
        return LoadError::Missing(path.to_path_buf());
    }
    LoadError::Io {
        path: path.to_path_buf(),
        what,
        err,
    }
}

fn check_dir(dir: &Path, trust: Trust, strict: bool) -> Result<(), LoadError> {
    let m = fs::metadata(dir).map_err(|e| io(dir, "inspect", e))?;
    if !m.is_dir() {
        return Err(LoadError::NotRegularFile(dir.to_path_buf()));
    }
    if !trust.accepts(m.uid()) {
        return Err(LoadError::WrongOwner {
            path: dir.to_path_buf(),
            uid: m.uid(),
        });
    }
    if strict && m.mode() & 0o022 != 0 {
        return Err(LoadError::Writable {
            path: dir.to_path_buf(),
            mode: m.mode(),
        });
    }
    Ok(())
}

fn open_checked(path: &Path, trust: Trust) -> Result<File, LoadError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| io(path, "open", e))?;
    let m = file.metadata().map_err(|e| io(path, "inspect", e))?;
    if !m.is_file() {
        return Err(LoadError::NotRegularFile(path.to_path_buf()));
    }
    if !trust.accepts(m.uid()) {
        return Err(LoadError::WrongOwner {
            path: path.to_path_buf(),
            uid: m.uid(),
        });
    }
    if m.mode() & 0o022 != 0 {
        return Err(LoadError::Writable {
            path: path.to_path_buf(),
            mode: m.mode(),
        });
    }
    Ok(file)
}

fn sha256_hex(file: &mut File) -> std::io::Result<String> {
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const ELF_HEADER: usize = 64;
const PROGRAM_HEADER: usize = 56;

/// Whether every segment the dynamic loader maps, and the section headers, are inside the file.
fn check_elf_extent(file: &File, path: &Path) -> Result<(), LoadError> {
    let bad = |why: &str| LoadError::Open {
        path: path.to_path_buf(),
        reason: why.to_string(),
    };
    let len = file.metadata().map_err(|e| io(path, "inspect", e))?.len();
    let mut h = [0u8; ELF_HEADER];
    file.read_exact_at(&mut h, 0)
        .map_err(|_| bad("the file is shorter than an ELF header"))?;
    if &h[..4] != b"\x7fELF" || h[4] != 2 || h[5] != 1 {
        return Err(bad("the file is not a 64-bit little-endian ELF file"));
    }
    let u16_at = |o: usize| u64::from(u16::from_le_bytes([h[o], h[o + 1]]));
    let u64_at =
        |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("eight bytes"));
    let (phoff, shoff) = (u64_at(&h, 32), u64_at(&h, 40));
    let (phentsize, phnum, shentsize, shnum) = (u16_at(54), u16_at(56), u16_at(58), u16_at(60));
    let end_of = |off: u64, size: u64| off.checked_add(size).filter(|e| *e <= len);
    let cut = || bad("the file is cut short: a part the loader maps lies beyond its end");
    if phentsize != PROGRAM_HEADER as u64 || end_of(phoff, phnum * phentsize).is_none() {
        return Err(cut());
    }
    for i in 0..phnum {
        let mut ph = [0u8; PROGRAM_HEADER];
        file.read_exact_at(&mut ph, phoff + i * PROGRAM_HEADER as u64)
            .map_err(|_| cut())?;
        let kind = u32::from_le_bytes(ph[..4].try_into().expect("four bytes"));
        if (kind == PT_LOAD || kind == PT_DYNAMIC)
            && end_of(u64_at(&ph, 8), u64_at(&ph, 32)).is_none()
        {
            return Err(cut());
        }
    }
    if shnum > 0 && end_of(shoff, shnum * shentsize).is_none() {
        return Err(cut());
    }
    Ok(())
}

/// The file the installer writes the checksum to.
pub fn checksum_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".sha256");
    PathBuf::from(s)
}

/// Runs the checks of the module on `path`.
pub fn verify(path: &Path, trust: Trust) -> Result<Verified, LoadError> {
    if !path.is_absolute() {
        return Err(LoadError::NotAbsolute(path.to_path_buf()));
    }
    let canonical = fs::canonicalize(path).map_err(|e| io(path, "resolve", e))?;
    for chain in [path, canonical.as_path()] {
        for (i, dir) in chain.ancestors().skip(1).enumerate() {
            check_dir(dir, trust, i == 0 || trust.strict_ancestors)?;
        }
    }
    let mut file = open_checked(&canonical, trust)?;

    let sum_path = checksum_path(path);
    let mut sum_file = match open_checked(&sum_path, trust) {
        Err(LoadError::Missing(p)) => return Err(LoadError::NoChecksum(p)),
        other => other?,
    };
    let mut text = String::new();
    // A checksum line is 64 hex digits, a blank and a name; a few hundred bytes are more than enough.
    (&mut sum_file)
        .take(4096)
        .read_to_string(&mut text)
        .map_err(|e| io(&sum_path, "read", e))?;
    let expected = text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(LoadError::BadChecksumFile(sum_path));
    }
    let actual = sha256_hex(&mut file).map_err(|e| io(&canonical, "read", e))?;
    if actual != expected {
        return Err(LoadError::ChecksumMismatch {
            path: canonical,
            expected,
            actual,
        });
    }
    check_elf_extent(&file, &canonical)?;
    Ok(Verified {
        file,
        path: canonical,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A directory under the temp dir that is removed at the end of the test.
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Dir {
            let p = std::env::temp_dir().join(format!("wafio-loader-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            Dir(p)
        }
        fn file(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let p = self.0.join(name);
            fs::File::create(&p).unwrap().write_all(bytes).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
            p
        }
        /// The library, its checksum file and nothing else.
        fn library(&self, bytes: &[u8]) -> PathBuf {
            let lib = self.file("libx.so", bytes, 0o644);
            let mut hash = Sha256::new();
            hash.update(bytes);
            let hex: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
            self.file(
                "libx.so.sha256",
                format!("{hex}  libx.so\n").as_bytes(),
                0o644,
            );
            lib
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The owner of what the test creates is the owner the trust accepts.
    fn me(dir: &Dir) -> Trust {
        let uid = fs::metadata(&dir.0).unwrap().uid();
        Trust {
            extra_owner: Some(uid),
            strict_ancestors: false,
        }
    }

    #[test]
    fn a_path_that_is_not_absolute_is_not_searched_for() {
        let e = verify(Path::new("libx.so"), Trust::root_only())
            .err()
            .unwrap();
        assert!(matches!(e, LoadError::NotAbsolute(_)), "{e}");
    }

    #[test]
    fn a_missing_library_is_reported_as_missing() {
        let d = Dir::new("missing");
        let e = verify(&d.0.join("libx.so"), me(&d)).err().unwrap();
        assert!(e.is_missing(), "{e}");
    }

    #[test]
    fn a_file_that_root_does_not_own_is_refused() {
        let d = Dir::new("owner");
        let lib = d.library(&tiny_elf());
        // Owned by the user running the test, and so not by root; a test run as root hands the file to nobody.
        if fs::metadata(&lib).unwrap().uid() == 0 {
            std::os::unix::fs::chown(&lib, Some(65534), None).unwrap();
        }
        let e = verify(&lib, Trust::root_only()).err().unwrap();
        assert!(
            matches!(e, LoadError::WrongOwner { .. } | LoadError::Writable { .. }),
            "{e}"
        );
        assert!(verify(&lib, me(&d)).is_ok() || fs::metadata(&lib).unwrap().uid() == 65534);
    }

    #[test]
    fn a_file_writable_by_group_or_others_is_refused() {
        for mode in [0o664, 0o646, 0o666, 0o622] {
            let d = Dir::new("mode");
            let lib = d.library(b"abc");
            fs::set_permissions(&lib, fs::Permissions::from_mode(mode)).unwrap();
            let e = verify(&lib, me(&d)).err().unwrap();
            assert!(matches!(e, LoadError::Writable { .. }), "{mode:o}: {e}");
        }
    }

    #[test]
    fn a_directory_writable_by_group_or_others_is_refused() {
        let d = Dir::new("dir");
        let lib = d.library(b"abc");
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o775)).unwrap();
        let e = verify(&lib, me(&d)).err().unwrap();
        assert!(
            matches!(e, LoadError::Writable { ref path, .. } if *path == d.0),
            "{e}"
        );
    }

    #[test]
    fn something_that_is_not_a_regular_file_is_refused() {
        let d = Dir::new("kind");
        fs::create_dir(d.0.join("libx.so")).unwrap();
        let e = verify(&d.0.join("libx.so"), me(&d)).err().unwrap();
        assert!(
            matches!(e, LoadError::NotRegularFile(_) | LoadError::Io { .. }),
            "{e}"
        );
    }

    #[test]
    fn the_checksum_file_must_be_there_well_formed_and_right() {
        let d = Dir::new("sum");
        let lib = d.file("libx.so", b"abc", 0o644);
        assert!(matches!(
            verify(&lib, me(&d)).err().unwrap(),
            LoadError::NoChecksum(_)
        ));
        d.file("libx.so.sha256", b"not a hash\n", 0o644);
        assert!(matches!(
            verify(&lib, me(&d)).err().unwrap(),
            LoadError::BadChecksumFile(_)
        ));
        d.file("libx.so.sha256", format!("{:064}\n", 7).as_bytes(), 0o644);
        assert!(matches!(
            verify(&lib, me(&d)).err().unwrap(),
            LoadError::ChecksumMismatch { .. }
        ));
        // sha256("abc")
        d.file(
            "libx.so.sha256",
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  libx.so\n",
            0o644,
        );
        // The checks of the file are done; what is left is that it is not an ELF file.
        let e = verify(&lib, me(&d)).err().unwrap();
        assert!(
            matches!(e, LoadError::Open { .. })
                && e.to_string().contains("shorter than an ELF header"),
            "{e}"
        );
    }

    /// The 64 bytes of an ELF header with one program header at 64.
    fn elf_header() -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        h[32..40].copy_from_slice(&64u64.to_le_bytes());
        h[54..56].copy_from_slice(&56u16.to_le_bytes());
        h[56..58].copy_from_slice(&1u16.to_le_bytes());
        h
    }

    fn program_header(offset: u64, filesz: u64) -> Vec<u8> {
        let mut p = vec![0u8; 56];
        p[..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        p[8..16].copy_from_slice(&offset.to_le_bytes());
        p[32..40].copy_from_slice(&filesz.to_le_bytes());
        p
    }

    /// An ELF file of 120 bytes that holds its one segment: enough for the checks of the loader, not to run.
    fn tiny_elf() -> Vec<u8> {
        let mut whole = elf_header();
        whole.extend(program_header(0, 120));
        whole.resize(120, 0);
        whole
    }

    #[test]
    fn a_segment_that_runs_past_the_end_of_the_file_is_a_cut_file() {
        let d = Dir::new("elf");
        let whole = tiny_elf();
        let lib = d.library(&whole);
        assert!(
            verify(&lib, me(&d)).is_ok(),
            "a file that holds its segments passes"
        );
        let cut = &whole[..100];
        let lib = d.library(cut);
        let e = verify(&lib, me(&d)).err().unwrap();
        assert!(
            matches!(e, LoadError::Open { .. }) && e.to_string().contains("cut short"),
            "{e}"
        );
        let lib = d.library(&whole[..40]);
        let e = verify(&lib, me(&d)).err().unwrap();
        assert!(e.to_string().contains("shorter than an ELF header"), "{e}");
    }

    #[test]
    fn a_checksum_file_that_others_can_write_is_refused() {
        let d = Dir::new("sumperm");
        let lib = d.library(b"abc");
        fs::set_permissions(checksum_path(&lib), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            verify(&lib, me(&d)).err().unwrap(),
            LoadError::Writable { .. }
        ));
    }

    #[test]
    fn a_truncated_library_does_not_match_the_checksum_of_the_whole_one() {
        let d = Dir::new("cut");
        let lib = d.library(b"0123456789abcdef");
        fs::File::create(&lib)
            .unwrap()
            .write_all(b"01234567")
            .unwrap();
        assert!(matches!(
            verify(&lib, me(&d)).err().unwrap(),
            LoadError::ChecksumMismatch { .. }
        ));
    }

    #[test]
    fn a_link_to_a_library_is_followed_and_the_target_checked() {
        let d = Dir::new("link");
        let lib = d.library(&tiny_elf());
        let link = d.0.join("liblink.so");
        std::os::unix::fs::symlink(&lib, &link).unwrap();
        d.file(
            "liblink.so.sha256",
            &fs::read(checksum_path(&lib)).unwrap(),
            0o644,
        );
        let v = verify(&link, me(&d)).unwrap();
        assert_eq!(v.path, fs::canonicalize(&lib).unwrap());
        fs::set_permissions(&lib, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            verify(&link, me(&d)).err().unwrap(),
            LoadError::Writable { .. }
        ));
    }

    #[test]
    fn the_name_of_the_checksum_file_is_the_name_of_the_library_and_sha256() {
        assert_eq!(
            checksum_path(Path::new("/a/libx.so")),
            PathBuf::from("/a/libx.so.sha256")
        );
    }
}
