//! The per-agent secret behind challenge cookies and tokens when a project has no `secret_key`.
//! Kept in the state directory so a restart or a SIGUSR2 successor accepts what the predecessor
//! issued; without a usable state directory it lives for one process.
//!
//! The file is `<state-dir>/challenge-secret`: 64 hex chars, mode 0600, the directory 0700. It is
//! opened without following a symlink and judged on the opened descriptor (no check-then-open
//! race): a symlink, a file that is not a regular file, or one readable by group or other is not
//! trusted and never overwritten, and the secret is then random for this process only.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

use wafio_agent_pages::crypto::{fill_random_bytes, hex_decode, hex_encode};
use wafio_bytetext::strings::trim_whitespace;

const FILE: &str = "challenge-secret";
const THIS_PROCESS_ONLY: &str = "cookies are valid for this process only";

/// A random secret; panics when the OS CSPRNG is unreadable.
fn random_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    fill_random_bytes(&mut s).expect("challenge: crypto/rand unavailable");
    s
}

/// 64 hex chars around optional whitespace.
fn parse_secret(raw: &[u8]) -> Option<[u8; 32]> {
    let h = trim_whitespace(raw);
    if h.len() != 64 {
        return None;
    }
    hex_decode(h).ok()?.try_into().ok()
}

/// A path error text: `<op> <path>: <errno text>` (the OS error text starts lower case:
/// "too many levels of symbolic links").
fn path_error(op: &str, path: &Path, e: &std::io::Error) -> String {
    let text = e.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
    let mut c = text.chars();
    let lower: String = c
        .next()
        .map(|f| f.to_lowercase().chain(c).collect())
        .unwrap_or_default();
    format!("{op} {}: {lower}", path.display())
}

/// The mode text of a unix `st_mode`: "-rw-r--r--", "drwx------", "urwxr-xr-x".
// `mode_t` is u16 on macOS, so the casts stay for a dev build there.
#[allow(clippy::unnecessary_cast)]
fn mode_text(st_mode: u32) -> String {
    let (fmt, mut s) = (st_mode & libc::S_IFMT as u32, String::new());
    for (ty, ch) in [
        (libc::S_IFDIR, 'd'),
        (libc::S_IFLNK, 'L'),
        (libc::S_IFBLK, 'D'),
        (libc::S_IFCHR, 'D'),
        (libc::S_IFIFO, 'p'),
        (libc::S_IFSOCK, 'S'),
    ] {
        if fmt == ty as u32 {
            s.push(ch);
        }
    }
    for (bit, ch) in [(libc::S_ISUID, 'u'), (libc::S_ISGID, 'g')] {
        if st_mode & bit as u32 != 0 {
            s.push(ch);
        }
    }
    if fmt == libc::S_IFCHR as u32 {
        s.push('c');
    }
    if st_mode & libc::S_ISVTX as u32 != 0 {
        s.push('t');
    }
    if s.is_empty() {
        s.push('-');
    }
    for (i, ch) in "rwxrwxrwx".chars().enumerate() {
        s.push(if st_mode & (1 << (8 - i)) != 0 {
            ch
        } else {
            '-'
        });
    }
    s
}

enum State {
    Ok([u8; 32]),
    /// Absent or not (yet) valid content: create it.
    Missing,
    /// Present but not ours to use or replace.
    Untrusted,
}

/// Opens `path` without following a symlink and judges the opened
/// descriptor: a regular file with no group/other bits.
fn read_secret(path: &Path) -> State {
    let mut f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return State::Missing,
        Err(e) => {
            tracing::info!(
                "[wafio-waf-agent] challenge secret file {} refused ({}); {THIS_PROCESS_ONLY}",
                path.display(),
                path_error("open", path, &e)
            );
            return State::Untrusted;
        }
    };
    let Ok(md) = f.metadata() else {
        return State::Untrusted;
    };
    if !md.file_type().is_file() || md.mode() & 0o077 != 0 {
        tracing::info!(
            "[wafio-waf-agent] challenge secret file {} refused (not a regular file or mode {} has group/other bits); {THIS_PROCESS_ONLY}",
            path.display(),
            mode_text(md.mode())
        );
        return State::Untrusted;
    }
    let mut raw = Vec::new();
    if (&mut f).take(256).read_to_end(&mut raw).is_err() {
        return State::Missing;
    }
    parse_secret(&raw).map_or(State::Missing, State::Ok)
}

/// The secret in `<state_dir>/challenge-secret`, created on first use (the directory 0700, the
/// file 0600, synced). A SIGUSR2 successor racing the creation sees "exists" and re-reads; a
/// half-written or corrupt file is removed on the fifth attempt. A random per-process one when
/// there is no state directory or the file cannot be trusted.
pub fn load_or_create(state_dir: &str) -> [u8; 32] {
    if state_dir.is_empty() {
        return random_secret();
    }
    let path = Path::new(state_dir).join(FILE);
    // Runs before the bundle cache creates the directory.
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state_dir)
    {
        tracing::info!(
            "[wafio-waf-agent] challenge secret dir {state_dir} unusable ({}); {THIS_PROCESS_ONLY}",
            path_error("mkdir", Path::new(state_dir), &e)
        );
        return random_secret();
    }
    for attempt in 0..6 {
        match read_secret(&path) {
            State::Ok(s) => return s,
            State::Untrusted => return random_secret(),
            State::Missing => {}
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                let s = random_secret();
                if write_synced(&mut f, &s).is_ok() {
                    return s;
                }
                // Never leave a half-written file.
                let _ = std::fs::remove_file(&path);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                if attempt == 4 {
                    // Trusted file, corrupt for 80 ms: not a racing writer.
                    let _ = std::fs::remove_file(&path);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                tracing::info!(
                    "[wafio-waf-agent] challenge secret file {} unusable ({}); {THIS_PROCESS_ONLY}",
                    path.display(),
                    path_error("open", &path, &e)
                );
                return random_secret();
            }
        }
    }
    tracing::info!(
        "[wafio-waf-agent] challenge secret file {} unusable (no stable content); {THIS_PROCESS_ONLY}",
        path.display()
    );
    random_secret()
}

fn write_synced(f: &mut File, secret: &[u8; 32]) -> std::io::Result<()> {
    f.write_all(&hex_encode(secret))?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    const GOOD_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn tmp(name: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "wafio-chkey-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn dir(name: &str) -> String {
        tmp(name).to_string_lossy().into_owned()
    }

    fn good() -> [u8; 32] {
        parse_secret(GOOD_HEX.as_bytes()).unwrap()
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_a_0600_file_with_64_hex_and_is_stable() {
        let d = dir("reuse");
        let a = load_or_create(&d);
        assert_ne!(a, [0u8; 32]);
        let p = Path::new(&d).join(FILE);
        let raw = std::fs::read(&p).unwrap();
        assert!(
            raw.len() == 64
                && raw
                    .iter()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(mode_of(&p), 0o600);
        assert_eq!(
            load_or_create(&d),
            a,
            "a restart or successor reads the same secret"
        );
        assert_ne!(load_or_create(&dir("other")), a);
    }

    #[test]
    fn trims_whitespace() {
        let d = dir("trim");
        let s = load_or_create(&d);
        let p = Path::new(&d).join(FILE);
        let raw = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, format!("\n  {raw} \n")).unwrap();
        assert_eq!(load_or_create(&d), s, "whitespace changed the secret");
    }

    #[test]
    fn corrupt_file_is_replaced() {
        let d = dir("corrupt");
        let p = Path::new(&d).join(FILE);
        std::fs::write(&p, b"garbage").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let a = load_or_create(&d);
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(raw.len(), 64, "corrupt file kept: {raw:?}");
        assert_eq!(load_or_create(&d), a, "the replacement sticks");
    }

    #[test]
    fn empty_and_unusable_dirs_give_random_secrets() {
        assert_ne!(
            load_or_create(""),
            load_or_create(""),
            "empty dir returned a fixed secret"
        );
        // A state dir below a regular file cannot be created.
        let blocker = tmp("blocker").join("file");
        std::fs::write(&blocker, b"x").unwrap();
        let bad = blocker.join("sub").to_string_lossy().into_owned();
        assert_ne!(
            load_or_create(&bad),
            load_or_create(&bad),
            "unusable dir returned a fixed secret"
        );
    }

    #[test]
    fn creates_a_missing_state_dir_with_0700() {
        let d = tmp("mkdir").join("a/b/state");
        let ds = d.to_string_lossy().into_owned();
        let s1 = load_or_create(&ds);
        assert!(d.is_dir() && mode_of(&d) == 0o700, "mode {:o}", mode_of(&d));
        let raw = std::fs::read(d.join(FILE)).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(load_or_create(&ds), s1, "not stable after creating the dir");
    }

    /// A file that is a symlink, has group/other permission bits or is not a regular file is not
    /// trusted: the secret is random for this process and the file is left exactly as found.
    #[test]
    fn symlink_is_refused_and_left_alone() {
        let d = tmp("symlink");
        let target = tmp("elsewhere").join("target");
        std::fs::write(&target, GOOD_HEX).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = d.join(FILE);
        symlink(&target, &link).unwrap();
        let ds = d.to_string_lossy().into_owned();
        let (a, b) = (load_or_create(&ds), load_or_create(&ds));
        assert!(a != good() && b != good(), "secret read through a symlink");
        assert_ne!(a, b, "untrusted file gave a stable secret");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            GOOD_HEX,
            "target overwritten"
        );
    }

    #[test]
    fn dangling_symlink_is_not_created_through() {
        let d = tmp("dangling");
        let target = tmp("not-yet").join("secret");
        symlink(&target, d.join(FILE)).unwrap();
        load_or_create(&d.to_string_lossy());
        assert!(
            std::fs::symlink_metadata(&target).is_err(),
            "secret file created through a dangling symlink"
        );
    }

    #[test]
    fn group_or_other_readable_is_refused_and_untouched() {
        for mode in [0o644, 0o640, 0o604] {
            let d = tmp("mode");
            let p = d.join(FILE);
            std::fs::write(&p, GOOD_HEX).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap(); // beat the umask
            assert_ne!(
                load_or_create(&d.to_string_lossy()),
                good(),
                "mode {mode:o}: secret taken from an exposed file"
            );
            assert_eq!(
                std::fs::read_to_string(&p).unwrap(),
                GOOD_HEX,
                "mode {mode:o}: file rewritten"
            );
            assert_eq!(mode_of(&p), mode, "mode {mode:o}: permissions changed");
        }
    }

    #[test]
    fn a_directory_in_place_of_the_file_is_refused() {
        let d = tmp("isdir");
        let p = d.join(FILE);
        std::fs::create_dir(&p).unwrap();
        let ds = d.to_string_lossy().into_owned();
        assert_ne!(
            load_or_create(&ds),
            load_or_create(&ds),
            "directory in place of the file gave a stable secret"
        );
        assert!(p.is_dir(), "directory removed");
    }

    #[test]
    fn a_trusted_0600_file_is_read() {
        let d = tmp("trusted");
        let p = d.join(FILE);
        std::fs::write(&p, format!("{GOOD_HEX}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_or_create(&d.to_string_lossy()), good());
    }

    #[test]
    fn file_mode_text() {
        #[allow(clippy::unnecessary_cast)]
        let m = |t: libc::mode_t, perm: u32| t as u32 | perm;
        assert_eq!(mode_text(m(libc::S_IFREG, 0o644)), "-rw-r--r--");
        assert_eq!(mode_text(m(libc::S_IFDIR, 0o700)), "drwx------");
        assert_eq!(mode_text(m(libc::S_IFREG, 0o4755)), "urwxr-xr-x");
        assert_eq!(mode_text(m(libc::S_IFDIR, 0o1777)), "dtrwxrwxrwx");
        assert_eq!(mode_text(m(libc::S_IFLNK, 0o777)), "Lrwxrwxrwx");
        assert_eq!(mode_text(m(libc::S_IFCHR, 0o620)), "Dcrw--w----");
    }
}
