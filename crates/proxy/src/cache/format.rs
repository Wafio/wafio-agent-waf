//! The file of one stored answer, and how it is written and read.
//!
//! ```text
//! header, 64 bytes, little endian
//!    0  magic "WFC1"           4  version (1)         5  three zero bytes
//!    8  key length u32        12  primary key length u32 (a prefix of the key)
//!   16  head length u32       20  CRC-32 u32, over the header with this field zero, then key, head, body
//!   24  body length u64       32  stored at u64      40  fresh until u64 (unix seconds)
//!   48  age at storing u32    52  stale window u32   56  eight zero bytes
//! key, head, body
//! ```
//!
//! A file is written under a temporary name in `tmp/` (mode 0600, `O_NOFOLLOW`), then renamed to its
//! place, with no `fsync`: a file that a crash tore fails its length or its CRC when it is read.
//! A reader opens with `O_NOFOLLOW`, reads the whole file and checks everything; the paths it is
//! given are canonical and absolute.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::Crc;

use super::key::{FileId, hex};

pub(crate) const HEADER_LEN: usize = 64;
const MAGIC: &[u8; 4] = b"WFC1";
const VERSION: u8 = 1;
/// The longest key and head a file may hold; a longer one is not stored and not read.
pub(crate) const MAX_KEY: usize = 64 << 10;
pub(crate) const MAX_HEAD: usize = 64 << 10;
/// The largest body a file may hold, whatever the settings say: the largest `max_object_bytes`.
pub(crate) const MAX_BODY: u64 = 64 << 20;
/// The directory of the files being written.
pub(crate) const TMP_DIR: &str = "tmp";

/// What the index keeps of a file besides its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Times {
    pub stored_at: u64,
    pub fresh_until: u64,
    /// The `Age` the upstream gave the answer when it was stored.
    pub initial_age: u32,
    /// Seconds past `fresh_until` that the answer allows itself to be sent stale.
    pub stale_window: u32,
}

/// The head of an answer as stored: status line and header lines, hop-by-hop headers left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StoredHead {
    pub status: u16,
    pub http10: bool,
    pub reason: Vec<u8>,
    pub lines: Vec<(Vec<u8>, Vec<u8>)>,
}

impl StoredHead {
    /// `None` when the head is longer than a file takes or has more lines than fit a count.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.status.to_le_bytes());
        out.push(u8::from(self.http10));
        out.extend_from_slice(&u16::try_from(self.reason.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&self.reason);
        out.extend_from_slice(&u16::try_from(self.lines.len()).ok()?.to_le_bytes());
        for (name, value) in &self.lines {
            out.extend_from_slice(&u16::try_from(name.len()).ok()?.to_le_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(&u32::try_from(value.len()).ok()?.to_le_bytes());
            out.extend_from_slice(value);
            if out.len() > MAX_HEAD {
                return None;
            }
        }
        (out.len() <= MAX_HEAD).then_some(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<StoredHead> {
        let mut at = Cursor { bytes, at: 0 };
        let status = u16::from_le_bytes(at.take(2)?.try_into().ok()?);
        let http10 = at.take(1)?[0] != 0;
        let reason_len = usize::from(u16::from_le_bytes(at.take(2)?.try_into().ok()?));
        let reason = at.take(reason_len)?.to_vec();
        let count = u16::from_le_bytes(at.take(2)?.try_into().ok()?);
        let mut lines = Vec::with_capacity(usize::from(count).min(256));
        for _ in 0..count {
            let name_len = usize::from(u16::from_le_bytes(at.take(2)?.try_into().ok()?));
            let name = at.take(name_len)?.to_vec();
            let value_len = u32::from_le_bytes(at.take(4)?.try_into().ok()?);
            let value = at.take(usize::try_from(value_len).ok()?)?.to_vec();
            lines.push((name, value));
        }
        (at.at == bytes.len()).then_some(StoredHead {
            status,
            http10,
            reason,
            lines,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
}

/// What a header says of the rest of its file.
struct Layout {
    key_len: usize,
    primary_len: usize,
    head_len: usize,
    body_len: u64,
    crc: u32,
    times: Times,
}

impl Layout {
    fn parse(h: &[u8; HEADER_LEN]) -> Option<Layout> {
        let u32_at = |at: usize| u32::from_le_bytes(h[at..at + 4].try_into().expect("4 bytes"));
        let u64_at = |at: usize| u64::from_le_bytes(h[at..at + 8].try_into().expect("8 bytes"));
        if &h[..4] != MAGIC || h[4] != VERSION || h[5..8] != [0; 3] || h[56..] != [0; 8] {
            return None;
        }
        let layout = Layout {
            key_len: usize::try_from(u32_at(8)).ok()?,
            primary_len: usize::try_from(u32_at(12)).ok()?,
            head_len: usize::try_from(u32_at(16)).ok()?,
            crc: u32_at(20),
            body_len: u64_at(24),
            times: Times {
                stored_at: u64_at(32),
                fresh_until: u64_at(40),
                initial_age: u32_at(48),
                stale_window: u32_at(52),
            },
        };
        (layout.key_len <= MAX_KEY
            && layout.primary_len <= layout.key_len
            && layout.head_len <= MAX_HEAD
            && layout.body_len <= MAX_BODY)
            .then_some(layout)
    }

    /// The size of the whole file the header describes.
    fn file_len(&self) -> u64 {
        HEADER_LEN as u64 + self.key_len as u64 + self.head_len as u64 + self.body_len
    }
}

/// The size of the file for these parts.
pub(crate) fn file_len(key: &[u8], head: &[u8], body: &[u8]) -> u64 {
    (HEADER_LEN + key.len() + head.len() + body.len()) as u64
}

fn crc(header: &[u8; HEADER_LEN], rest: &[&[u8]]) -> u32 {
    let mut crc = Crc::new();
    let mut zeroed = *header;
    zeroed[20..24].fill(0);
    crc.update(&zeroed);
    for part in rest {
        crc.update(part);
    }
    crc.sum()
}

fn header(
    primary_len: usize,
    key: &[u8],
    head: &[u8],
    body: &[u8],
    times: Times,
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[4] = VERSION;
    let len32 = |n: usize| u32::try_from(n).unwrap_or(u32::MAX).to_le_bytes();
    h[8..12].copy_from_slice(&len32(key.len()));
    h[12..16].copy_from_slice(&len32(primary_len));
    h[16..20].copy_from_slice(&len32(head.len()));
    h[24..32].copy_from_slice(&(body.len() as u64).to_le_bytes());
    h[32..40].copy_from_slice(&times.stored_at.to_le_bytes());
    h[40..48].copy_from_slice(&times.fresh_until.to_le_bytes());
    h[48..52].copy_from_slice(&times.initial_age.to_le_bytes());
    h[52..56].copy_from_slice(&times.stale_window.to_le_bytes());
    let sum = crc(&h, &[key, head, body]);
    h[20..24].copy_from_slice(&sum.to_le_bytes());
    h
}

/// Why a file was not read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    /// There is no such file.
    Missing,
    /// It is not a file the agent wrote whole: a link, a size or a check sum that differs, a key
    /// that is not the one asked for. The caller deletes it.
    Corrupt,
    /// Any other error of the disk.
    Io,
}

/// A file read and checked.
#[derive(Clone, Debug)]
pub(crate) struct Loaded {
    pub times: Times,
    pub head: StoredHead,
    pub body: Vec<u8>,
    /// The size of the file.
    pub size: u64,
}

/// `O_NOFOLLOW` so a link is an error, `O_NONBLOCK` so that a FIFO does not hold the open, and the
/// `fstat` that follows refuses anything but a plain file.
fn open_plain(path: &Path) -> Result<(File, u64), ReadError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ReadError::Missing,
            _ if e.raw_os_error() == Some(nix::libc::ELOOP) => ReadError::Corrupt,
            _ => ReadError::Io,
        })?;
    let meta = file.metadata().map_err(|_| ReadError::Io)?;
    if !meta.is_file() {
        return Err(ReadError::Corrupt);
    }
    Ok((file, meta.size()))
}

fn read_header(file: &mut File, size: u64) -> Result<(Layout, [u8; HEADER_LEN]), ReadError> {
    let mut h = [0u8; HEADER_LEN];
    if size < HEADER_LEN as u64 {
        return Err(ReadError::Corrupt);
    }
    file.read_exact(&mut h).map_err(|_| ReadError::Io)?;
    let layout = Layout::parse(&h).ok_or(ReadError::Corrupt)?;
    if layout.file_len() != size {
        return Err(ReadError::Corrupt);
    }
    Ok((layout, h))
}

/// Reads the whole file: the size is `expect_size` (what the index holds), the check sum holds and
/// the key is `expect_key`.
pub(crate) fn read(path: &Path, expect_size: u64, expect_key: &[u8]) -> Result<Loaded, ReadError> {
    let (mut file, size) = open_plain(path)?;
    if size != expect_size {
        return Err(ReadError::Corrupt);
    }
    let (layout, h) = read_header(&mut file, size)?;
    let eof = |e: io::Error| match e.kind() {
        io::ErrorKind::UnexpectedEof => ReadError::Corrupt,
        _ => ReadError::Io,
    };
    let mut parts = vec![0u8; layout.key_len + layout.head_len];
    file.read_exact(&mut parts).map_err(eof)?;
    let mut body = vec![0u8; usize::try_from(layout.body_len).map_err(|_| ReadError::Corrupt)?];
    file.read_exact(&mut body).map_err(eof)?;
    let (key, head) = parts.split_at(layout.key_len);
    if crc(&h, &[key, head, &body]) != layout.crc || key != expect_key {
        return Err(ReadError::Corrupt);
    }
    let head = StoredHead::decode(head).ok_or(ReadError::Corrupt)?;
    Ok(Loaded {
        times: layout.times,
        head,
        body,
        size,
    })
}

/// What the scan of a directory needs of a file: everything but the body and the check sum of it.
pub(crate) struct Summary {
    pub times: Times,
    pub key: Vec<u8>,
    pub primary_len: usize,
    pub head: StoredHead,
    pub size: u64,
}

pub(crate) fn read_summary(path: &Path) -> Result<Summary, ReadError> {
    let (mut file, size) = open_plain(path)?;
    let (layout, _) = read_header(&mut file, size)?;
    let mut parts = vec![0u8; layout.key_len + layout.head_len];
    file.read_exact(&mut parts)
        .map_err(|_| ReadError::Corrupt)?;
    let head = StoredHead::decode(&parts[layout.key_len..]).ok_or(ReadError::Corrupt)?;
    parts.truncate(layout.key_len);
    Ok(Summary {
        times: layout.times,
        key: parts,
        primary_len: layout.primary_len,
        head,
        size,
    })
}

/// Where the file of `id` is, below the directory of its app.
pub(crate) fn path_of(app_dir: &Path, id: &FileId) -> PathBuf {
    let name = hex(id);
    app_dir.join(&name[..2]).join(name)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates `dir` (mode 0700) when it is not there.
fn make_dir(dir: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

/// Writes the answer under its name. The file is created whole in `tmp/` and renamed; every
/// failure removes what was made. Returns the size of the file.
pub(crate) fn write(
    app_dir: &Path,
    id: &FileId,
    primary_len: usize,
    key: &[u8],
    head: &[u8],
    body: &[u8],
    times: Times,
) -> io::Result<u64> {
    let name = hex(id);
    make_dir(app_dir)?;
    let tmp_dir = app_dir.join(TMP_DIR);
    make_dir(&tmp_dir)?;
    let shard = app_dir.join(&name[..2]);
    make_dir(&shard)?;
    let temp = tmp_dir.join(format!(
        "{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temp)?;
    let done = (|| {
        file.write_all(&header(primary_len, key, head, body, times))?;
        file.write_all(key)?;
        file.write_all(head)?;
        file.write_all(body)?;
        drop(file);
        std::fs::rename(&temp, shard.join(&name))
    })();
    if let Err(e) = done {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(file_len(key, head, body))
}

/// Removes the file of `id`; one that is not there is not an error.
pub(crate) fn remove(app_dir: &Path, id: &FileId) {
    let _ = std::fs::remove_file(path_of(app_dir, id));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::key::file_id;

    pub(crate) struct Scratch(pub PathBuf);

    impl Scratch {
        pub fn new() -> Scratch {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "wafio-cache-format-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir.canonicalize().unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const TIMES: Times = Times {
        stored_at: 1_700_000_000,
        fresh_until: 1_700_000_600,
        initial_age: 7,
        stale_window: 90,
    };

    fn head() -> StoredHead {
        StoredHead {
            status: 200,
            http10: false,
            reason: b"OK".to_vec(),
            lines: vec![
                (b"Content-Type".to_vec(), b"text/css".to_vec()),
                (b"Cache-Control".to_vec(), b"public, max-age=600".to_vec()),
            ],
        }
    }

    fn put(dir: &Path, key: &[u8], body: &[u8]) -> (FileId, u64) {
        let id = file_id(key, b"");
        let size = write(
            dir,
            &id,
            key.len(),
            key,
            &head().encode().unwrap(),
            body,
            TIMES,
        )
        .unwrap();
        (id, size)
    }

    #[test]
    fn a_file_reads_back_as_it_was_written() {
        let s = Scratch::new();
        let (id, size) = put(&s.0, b"the key", b"body bytes");
        let path = path_of(&s.0, &id);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);
        let loaded = read(&path, size, b"the key").unwrap();
        assert_eq!(loaded.body, b"body bytes");
        assert_eq!(loaded.times, TIMES);
        assert_eq!(loaded.head, head());
        assert_eq!(loaded.size, size);
        let summary = read_summary(&path).unwrap();
        assert_eq!(
            (summary.times, summary.key, summary.size),
            (TIMES, b"the key".to_vec(), size)
        );
        // Nothing is left in tmp/, and the file is private.
        assert_eq!(std::fs::read_dir(s.0.join("tmp")).unwrap().count(), 0);
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // An empty body is a file too.
        let (id, size) = put(&s.0, b"empty", b"");
        assert!(
            read(&path_of(&s.0, &id), size, b"empty")
                .unwrap()
                .body
                .is_empty()
        );
    }

    #[test]
    fn a_flipped_byte_anywhere_a_cut_and_a_longer_file_are_corrupt() {
        let s = Scratch::new();
        let (id, size) = put(&s.0, b"k", &[7u8; 300]);
        let path = path_of(&s.0, &id);
        let good = std::fs::read(&path).unwrap();
        for at in (0..good.len()).step_by(7).chain([good.len() - 1]) {
            let mut bad = good.clone();
            bad[at] ^= 0x01;
            std::fs::write(&path, &bad).unwrap();
            assert_eq!(
                read(&path, size, b"k").err(),
                Some(ReadError::Corrupt),
                "byte {at}"
            );
        }
        for len in [0, 10, HEADER_LEN, good.len() - 1] {
            std::fs::write(&path, &good[..len]).unwrap();
            assert_eq!(
                read(&path, size, b"k").err(),
                Some(ReadError::Corrupt),
                "cut to {len}"
            );
        }
        let mut longer = good.clone();
        longer.push(0);
        std::fs::write(&path, &longer).unwrap();
        assert_eq!(read(&path, size, b"k").err(), Some(ReadError::Corrupt));
        // A zero-filled tail of the right length (a torn write) fails the check sum.
        let mut torn = good.clone();
        torn[HEADER_LEN + 1..].fill(0);
        std::fs::write(&path, &torn).unwrap();
        assert_eq!(read(&path, size, b"k").err(), Some(ReadError::Corrupt));
        std::fs::write(&path, &good).unwrap();
        assert!(read(&path, size, b"k").is_ok());
    }

    #[test]
    fn a_file_with_another_key_or_another_size_than_asked_is_corrupt() {
        let s = Scratch::new();
        let (id, size) = put(&s.0, b"key-a", b"body");
        let path = path_of(&s.0, &id);
        // Two bodies swapped between two names: each file holds its own key, so the swap shows.
        assert_eq!(read(&path, size, b"key-b").err(), Some(ReadError::Corrupt));
        assert_eq!(
            read(&path, size + 1, b"key-a").err(),
            Some(ReadError::Corrupt)
        );
        assert_eq!(
            read(&s.0.join("nothing"), 1, b"x").err(),
            Some(ReadError::Missing)
        );
    }

    #[test]
    fn a_link_a_directory_and_a_fifo_are_not_read() {
        let s = Scratch::new();
        let (id, size) = put(&s.0, b"k", b"body");
        let path = path_of(&s.0, &id);
        let link = s.0.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read(&link, size, b"k").err(), Some(ReadError::Corrupt));
        assert_eq!(read_summary(&link).err(), Some(ReadError::Corrupt));
        assert_eq!(read(&s.0, size, b"k").err(), Some(ReadError::Corrupt));
        let fifo = s.0.join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        assert_eq!(read(&fifo, size, b"k").err(), Some(ReadError::Corrupt));
    }

    #[test]
    fn a_header_that_promises_more_than_a_file_may_hold_is_corrupt_before_anything_is_allocated() {
        let s = Scratch::new();
        let (id, size) = put(&s.0, b"k", b"body");
        let path = path_of(&s.0, &id);
        let mut bytes = std::fs::read(&path).unwrap();
        // A body length of 2^60: the size does not match and no buffer of that size is made.
        bytes[24..32].copy_from_slice(&(1u64 << 60).to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(read(&path, size, b"k").err(), Some(ReadError::Corrupt));
        assert_eq!(read_summary(&path).err(), Some(ReadError::Corrupt));
        // A version or magic that is not ours.
        let mut other = std::fs::read(path_of(&s.0, &put(&s.0, b"k2", b"b").0)).unwrap();
        other[4] = 2;
        std::fs::write(&path, &other).unwrap();
        assert_eq!(read_summary(&path).err(), Some(ReadError::Corrupt));
    }

    #[test]
    fn a_head_round_trips_and_a_cut_head_does_not_decode() {
        let encoded = head().encode().unwrap();
        assert_eq!(StoredHead::decode(&encoded), Some(head()));
        for cut in 0..encoded.len() {
            assert_eq!(StoredHead::decode(&encoded[..cut]), None, "cut at {cut}");
        }
        let mut longer = encoded.clone();
        longer.push(0);
        assert_eq!(StoredHead::decode(&longer), None);
        let big = StoredHead {
            lines: vec![(b"X".to_vec(), vec![b'a'; MAX_HEAD])],
            ..head()
        };
        assert_eq!(big.encode(), None, "a head over the limit is not stored");
    }

    #[test]
    fn a_write_that_cannot_finish_leaves_nothing_behind() {
        let s = Scratch::new();
        // The shard directory is a file: the rename fails, and the temporary file goes.
        let id = file_id(b"k", b"");
        let name = hex(&id);
        std::fs::create_dir_all(s.0.join("a")).unwrap();
        let app = s.0.join("a");
        std::fs::write(app.join(&name[..2]), b"in the way").unwrap();
        let err = write(&app, &id, 1, b"k", &head().encode().unwrap(), b"b", TIMES);
        assert!(err.is_err());
        assert_eq!(std::fs::read_dir(app.join("tmp")).unwrap().count(), 0);
    }
}
