use std::fmt;
use std::path::PathBuf;

/// Why a library was not loaded. Every message is one line and names the file.
#[derive(Debug)]
pub enum LoadError {
    /// This build cannot load shared libraries at all.
    Unsupported(&'static str),
    NotAbsolute(PathBuf),
    Missing(PathBuf),
    Io {
        path: PathBuf,
        what: &'static str,
        err: std::io::Error,
    },
    NotRegularFile(PathBuf),
    WrongOwner {
        path: PathBuf,
        uid: u32,
    },
    Writable {
        path: PathBuf,
        mode: u32,
    },
    NoChecksum(PathBuf),
    BadChecksumFile(PathBuf),
    ChecksumMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    Open {
        path: PathBuf,
        reason: String,
    },
    MissingSymbol(&'static str),
    VersionMismatch {
        path: PathBuf,
        found: u32,
        wanted: u32,
    },
    BadIdentity(String),
    InitFailed(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Unsupported(why) => f.write_str(why),
            LoadError::NotAbsolute(p) => write!(
                f,
                "{} is not an absolute path (the agent does not search for the library)",
                p.display()
            ),
            LoadError::Missing(p) => write!(f, "{} does not exist", p.display()),
            LoadError::Io { path, what, err } => {
                write!(f, "cannot {what} {}: {err}", path.display())
            }
            LoadError::NotRegularFile(p) => write!(f, "{} is not a regular file", p.display()),
            LoadError::WrongOwner { path, uid } => {
                write!(f, "{} is owned by uid {uid}, not by root", path.display())
            }
            LoadError::Writable { path, mode } => write!(
                f,
                "{} is writable by group or others (mode {:04o})",
                path.display(),
                mode & 0o7777
            ),
            LoadError::NoChecksum(p) => write!(
                f,
                "{} is missing: the installer writes the SHA-256 of the library next to it",
                p.display()
            ),
            LoadError::BadChecksumFile(p) => {
                write!(f, "{} does not start with a SHA-256 in hex", p.display())
            }
            LoadError::ChecksumMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "{} has SHA-256 {actual}, its checksum file says {expected}",
                path.display()
            ),
            LoadError::Open { path, reason } => {
                write!(f, "{} cannot be loaded: {reason}", path.display())
            }
            LoadError::MissingSymbol(name) => {
                write!(f, "the library does not export {name}")
            }
            LoadError::VersionMismatch {
                path,
                found,
                wanted,
            } => write!(
                f,
                "{} has interface version {found}, this agent knows version {wanted}",
                path.display()
            ),
            LoadError::BadIdentity(why) => write!(f, "the library describes itself badly: {why}"),
            LoadError::InitFailed(msg) => write!(f, "the library failed to start: {msg}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl LoadError {
    /// A missing file at the default path is not worth a warning.
    pub fn is_missing(&self) -> bool {
        matches!(self, LoadError::Missing(_))
    }
}
