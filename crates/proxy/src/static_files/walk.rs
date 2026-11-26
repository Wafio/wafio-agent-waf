//! The walk from the folder's root to a file, one `openat` for each segment.
//!
//! Every directory is opened with `O_NOFOLLOW | O_DIRECTORY` from the descriptor of the one
//! before, so a link anywhere below the root, in a directory name or as the file, is not
//! followed and the walk cannot leave the root. What the last `openat` returns is `fstat`ed, and
//! only a regular file is served. This module blocks: callers run it under `spawn_blocking`.

use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;

use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;

use super::names::Target;

/// A directory, from the one before. `O_NOFOLLOW` makes a link an error, and `O_NOCTTY` keeps a
/// terminal that a name might open from becoming the process's.
const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NOCTTY);

/// The last name. `O_NONBLOCK` so that opening a FIFO that nobody writes to returns at once; the
/// `fstat` that follows says it is no regular file.
const LAST: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NOCTTY);

// The opens this thread has made, which a test reads to show that a path was refused before the
// disk was touched.
#[cfg(test)]
thread_local! {
    pub(super) static OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn count_open() {
    #[cfg(test)]
    OPENS.with(|n| n.set(n.get() + 1));
}

/// What `fstat` said of a regular file: its size and modification time in seconds, and which
/// file it is.
pub(super) struct Seen {
    pub size: u64,
    pub mtime: i64,
    pub dev: u64,
    pub ino: u64,
}

impl Seen {
    fn of(meta: &Metadata) -> Seen {
        Seen {
            size: meta.len(),
            mtime: meta.mtime(),
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

/// What the walk found.
pub(super) enum Found {
    /// A regular file, open for reading, what `fstat` said of it, and the name its type is
    /// taken from.
    File(File, Seen, Vec<u8>),
    /// A directory that has an `index.html`, asked for without the final slash.
    Slash,
    /// Nothing the folder serves: no such name, a link, a FIFO, a device, a socket, a directory
    /// without an index, or any other error of an open.
    Nothing,
}

/// The root folder, opened by its path. The path itself may hold links (a deploy's `current`);
/// everything below it may not.
pub(super) fn open_root(path: &str) -> Option<File> {
    count_open();
    let flags = OFlag::O_RDONLY
        .union(OFlag::O_DIRECTORY)
        .union(OFlag::O_CLOEXEC)
        .union(OFlag::O_NOCTTY);
    open(path, flags, Mode::empty()).ok().map(File::from)
}

fn open_at(parent: &File, name: &[u8], flags: OFlag) -> Option<File> {
    count_open();
    openat(parent, name, flags, Mode::empty())
        .ok()
        .map(File::from)
}

/// `index.html` of the directory open as `dir`, if it is a regular file.
fn index_of(dir: &File) -> Option<(File, Seen)> {
    let file = open_at(dir, b"index.html", LAST)?;
    let meta = file.metadata().ok()?;
    meta.is_file().then(|| (file, Seen::of(&meta)))
}

/// Walks `target` from `root`.
pub(super) fn find(root: &File, target: &Target<'_>) -> Found {
    let (names, directory) = (&target.segments, target.directory);
    let dirs = if directory {
        names.len()
    } else {
        names.len().saturating_sub(1)
    };
    let mut current: Option<File> = None;
    for name in &names[..dirs] {
        match open_at(current.as_ref().unwrap_or(root), name, DIRECTORY) {
            Some(dir) => current = Some(dir),
            None => return Found::Nothing,
        }
    }
    let parent = current.as_ref().unwrap_or(root);
    if directory {
        return index_of(parent).map_or(Found::Nothing, |(file, seen)| {
            Found::File(file, seen, b"index.html".to_vec())
        });
    }
    let Some(last) = names.last() else {
        return Found::Nothing;
    };
    let Some(file) = open_at(parent, last, LAST) else {
        return Found::Nothing;
    };
    let Ok(meta) = file.metadata() else {
        return Found::Nothing;
    };
    if meta.is_file() {
        Found::File(file, Seen::of(&meta), last.to_vec())
    } else if meta.is_dir() && index_of(&file).is_some() {
        Found::Slash
    } else {
        Found::Nothing
    }
}

/// Reads up to `buf.len()` bytes at `offset`, until the buffer is full or the file ends.
pub(crate) fn read_at_full(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match file.read_at(&mut buf[done..], offset + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

#[cfg(test)]
pub(super) mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::static_files::names::plan;

    /// A scratch directory that is removed when it goes out of scope.
    pub(crate) struct Scratch(pub PathBuf);

    impl Scratch {
        pub fn new(tag: &str) -> Scratch {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("wafio-static-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // The canonical path: the temporary directory itself may be a link.
            Scratch(dir.canonicalize().unwrap())
        }

        pub fn file(&self, rel: &str, content: &[u8]) -> PathBuf {
            let path = self.0.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            path
        }

        pub fn dir(&self, rel: &str) -> PathBuf {
            let path = self.0.join(rel);
            std::fs::create_dir_all(&path).unwrap();
            path
        }

        pub fn link(&self, rel: &str, target: impl AsRef<Path>) {
            let path = self.0.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            symlink(target, path).unwrap();
        }

        pub fn path(&self, rel: &str) -> String {
            self.0.join(rel).to_str().unwrap().to_owned()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn walk(root: &Path, path: &str) -> Found {
        let root = open_root(root.to_str().unwrap()).expect("the root opens");
        find(&root, &plan(path.as_bytes()).expect("a servable path"))
    }

    fn served(root: &Path, path: &str) -> Option<Vec<u8>> {
        match walk(root, path) {
            Found::File(file, seen, _) => {
                let mut buf = vec![0; seen.size as usize];
                read_at_full(&file, &mut buf, 0).unwrap();
                Some(buf)
            }
            Found::Slash | Found::Nothing => None,
        }
    }

    #[test]
    fn a_regular_file_in_a_folder_is_found_with_its_content_and_name() {
        let s = Scratch::new("regular");
        s.file("index.html", b"home");
        s.file("css/site.css", b"body{}");
        s.file("a/b/c/deep.txt", b"deep");
        assert_eq!(served(&s.0, "/css/site.css").unwrap(), b"body{}");
        assert_eq!(served(&s.0, "/a/b/c/deep.txt").unwrap(), b"deep");
        assert_eq!(served(&s.0, "/").unwrap(), b"home");
        let Found::File(_, _, name) = walk(&s.0, "/css/site.css") else {
            panic!("found")
        };
        assert_eq!(name, b"site.css");
        let Found::File(_, _, name) = walk(&s.0, "/") else {
            panic!("found")
        };
        assert_eq!(name, b"index.html");
    }

    #[test]
    fn a_directory_serves_its_index_for_a_final_slash_and_asks_for_the_slash_otherwise() {
        let s = Scratch::new("index");
        s.file("docs/index.html", b"docs");
        s.dir("empty");
        s.file("noindex/a.txt", b"a");
        assert_eq!(served(&s.0, "/docs/").unwrap(), b"docs");
        assert!(matches!(walk(&s.0, "/docs"), Found::Slash));
        // No index.html: nothing, with or without the slash. There is no listing.
        assert!(matches!(walk(&s.0, "/empty/"), Found::Nothing));
        assert!(matches!(walk(&s.0, "/empty"), Found::Nothing));
        assert!(matches!(walk(&s.0, "/noindex/"), Found::Nothing));
        assert!(matches!(walk(&s.0, "/noindex"), Found::Nothing));
        // The root has none either.
        assert!(matches!(walk(&s.0, "/"), Found::Nothing));
        // An index that is not a regular file is not one.
        let t = Scratch::new("indexlink");
        t.file("real.html", b"x");
        t.link("d/index.html", t.0.join("real.html"));
        assert!(matches!(walk(&t.0, "/d/"), Found::Nothing));
        assert!(matches!(walk(&t.0, "/d"), Found::Nothing));
        // A file asked for as a directory is nothing.
        s.file("f.txt", b"f");
        assert!(matches!(walk(&s.0, "/f.txt/"), Found::Nothing));
        assert!(matches!(walk(&s.0, "/f.txt/x"), Found::Nothing));
    }

    #[test]
    fn a_missing_name_is_nothing() {
        let s = Scratch::new("missing");
        s.file("a.txt", b"a");
        for path in ["/b.txt", "/a.txt/b", "/x/y/z.txt", "/A.TXT"] {
            assert!(matches!(walk(&s.0, path), Found::Nothing), "{path}");
        }
    }

    /// A link is never followed: not as the file, not as a directory in the path, not to a file
    /// inside the folder, above it or at an absolute path, and not when it dangles.
    #[test]
    fn a_link_is_not_followed_wherever_it_stands() {
        let s = Scratch::new("links");
        let outside = Scratch::new("outside");
        outside.file("secret.txt", b"secret");
        outside.file("dir/inner.txt", b"inner");
        s.file("public/real.txt", b"real");
        s.file("public/sub/other.txt", b"other");
        s.link("public/inside.txt", "real.txt");
        s.link("public/up.txt", outside.0.join("secret.txt"));
        s.link("public/rel-up.txt", "../../../../../../etc/os-release");
        s.link("public/abs.txt", "/etc/os-release");
        s.link("public/dir-link", outside.0.join("dir"));
        s.link("public/dir-link-inside", "sub");
        s.link("public/dangling.txt", "nowhere");
        s.link("public/loop-a", "loop-b");
        s.link("public/loop-b", "loop-a");
        let root = s.0.join("public");
        assert_eq!(served(&root, "/real.txt").unwrap(), b"real");
        for path in [
            "/inside.txt",
            "/up.txt",
            "/rel-up.txt",
            "/abs.txt",
            "/dir-link/inner.txt",
            "/dir-link-inside/other.txt",
            "/dangling.txt",
            "/loop-a",
        ] {
            assert!(matches!(walk(&root, path), Found::Nothing), "{path}");
        }
        // A link that is a directory asked for as one: nothing, even with an index behind it.
        outside.file("dir/index.html", b"index");
        assert!(matches!(walk(&root, "/dir-link/"), Found::Nothing));
        assert!(matches!(walk(&root, "/dir-link"), Found::Nothing));
    }

    /// The folder itself may be a link, a deploy's `current`, or sit below one: the walk starts
    /// from what that path opens.
    #[test]
    fn the_root_path_may_hold_links_and_the_walk_starts_from_what_it_opens() {
        let s = Scratch::new("rootlink");
        s.file("releases/1/public/index.html", b"one");
        s.file("releases/2/public/index.html", b"two");
        s.link("current", "releases/1");
        let public = s.0.join("current/public");
        assert_eq!(served(&public, "/").unwrap(), b"one");
        std::fs::remove_file(s.0.join("current")).unwrap();
        s.link("current", "releases/2");
        assert_eq!(served(&public, "/").unwrap(), b"two");
        // A final link as the root is followed too.
        s.link("site", "releases/1/public");
        assert_eq!(served(&s.0.join("site"), "/").unwrap(), b"one");
    }

    #[test]
    fn a_fifo_a_device_and_a_socket_are_nothing_and_opening_them_does_not_block() {
        let s = Scratch::new("special");
        s.file("regular.txt", b"x");
        nix::unistd::mkfifo(&s.0.join("pipe"), Mode::S_IRWXU).unwrap();
        let sock = s.path("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(walk(&s.0, "/pipe"), Found::Nothing));
        assert!(matches!(walk(&s.0, "/sock"), Found::Nothing));
        assert!(matches!(walk(&s.0, "/pipe/"), Found::Nothing));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // A device node needs root to make; a link to one is refused already, and a bind mount
        // is not made here. The fstat of every open is what says it is no regular file.
        s.link("zero", "/dev/zero");
        assert!(matches!(walk(&s.0, "/zero"), Found::Nothing));
    }

    #[test]
    fn a_directory_that_cannot_be_opened_is_nothing() {
        if std::fs::metadata("/proc/self").is_err() || nix::unistd::geteuid().is_root() {
            return; // root opens everything
        }
        let s = Scratch::new("locked");
        s.file("closed/a.txt", b"a");
        s.file("open/a.txt", b"a");
        std::fs::set_permissions(s.0.join("closed"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        assert!(matches!(walk(&s.0, "/closed/a.txt"), Found::Nothing));
        assert!(served(&s.0, "/open/a.txt").is_some());
        std::fs::set_permissions(s.0.join("closed"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    #[test]
    fn a_hard_link_looks_like_a_file_and_is_served() {
        // The documented limit: `fs.protected_hardlinks` is what keeps a user from making one to
        // a file that is not theirs.
        let s = Scratch::new("hard");
        let real = s.file("private-store/data.txt", b"data");
        std::fs::create_dir_all(s.0.join("public")).unwrap();
        std::fs::hard_link(&real, s.0.join("public/data.txt")).unwrap();
        assert_eq!(served(&s.0.join("public"), "/data.txt").unwrap(), b"data");
        assert_eq!(std::fs::metadata(&real).unwrap().nlink(), 2);
    }

    #[test]
    fn reading_at_an_offset_stops_at_the_end_of_the_file() {
        let s = Scratch::new("read");
        let path = s.file("a.txt", b"0123456789");
        let file = File::open(path).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(read_at_full(&file, &mut buf, 2).unwrap(), 4);
        assert_eq!(&buf, b"2345");
        assert_eq!(read_at_full(&file, &mut buf, 8).unwrap(), 2);
        assert_eq!(&buf[..2], b"89");
        assert_eq!(read_at_full(&file, &mut buf, 10).unwrap(), 0);
        assert_eq!(read_at_full(&file, &mut buf, 1_000).unwrap(), 0);
    }
}
