//! Static files: an app can answer `GET` and `HEAD` for the files of one folder itself, after
//! the verdict, without a round trip to the application.
//!
//! The folder is a setting of the app (`AppSpec::static_files`), checked once when a bundle is
//! applied ([`StaticSpec::check`]: it exists, is a directory, opens, and is not one of the
//! system folders) and again on every request in one cheap form: the root is opened by its path,
//! and the `(st_dev, st_ino)` of what that opened is compared with the pair seen at apply. A
//! deploy that moves a `current` link changes the pair and is followed, after the forbidden-folder
//! check has run on what the new directory is; a link that now leads to a forbidden folder serves
//! nothing. Below the root no link is followed (`walk`), and a request path that names a hidden
//! file, a PHP file, or one of the names the host agent never sheds from its trace ring is
//! refused before any system call (`names`).
//!
//! A file of 1 MiB or less is read whole and can be compressed like an upstream answer; a bigger
//! one is sent from its open descriptor in 256 KiB reads ([`FileAnswer`], written by the route).
//!
//! Every look and every read runs on a blocking thread through the [`DiskGate`], which bounds how
//! many threads the folders may hold and how long a request waits for the disk.

mod answer;
mod gate;
mod mime;
mod names;
mod walk;

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::config::Route;
use crate::pipeline::Done;
use crate::proxy::Shared;
use crate::request::{InboundRequest, push_escaped_path, push_forward_query};
use crate::response::{OutboundResponse, http_date};
pub(crate) use answer::{Asked, asked, parse_http_date};
use answer::{Conditions, Meta, Plan};
pub(crate) use gate::{DISK_DEADLINE, DiskGate, LOOKUP_WAIT};
use walk::Found;

/// The longest browser cache time: 365 days.
pub const MAX_BROWSER_CACHE_S: i64 = 31_536_000;

/// The longest root folder, in bytes.
const ROOT_MAX_BYTES: usize = 1024;

/// Folders that are never served, and neither is one above or below one of them (the root
/// folder is above them all).
const FORBIDDEN_ROOTS: &[&str] = &[
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/boot",
    "/usr",
    "/var/lib/wafio-waf-agent",
    "/var/cache/wafio-waf",
];

/// Folders the agent's unit hides (`ProtectHome=yes`): a folder in one reads as missing there,
/// so it is refused for what it is.
const HIDDEN_BY_UNIT: &[&str] = &["/home", "/root", "/run/user"];

/// A file up to this size is read whole; a bigger one is sent from its descriptor.
const READ_WHOLE_MAX: u64 = 1 << 20;

/// How much of a big file one read takes.
pub(crate) const CHUNK: usize = 256 << 10;

pub(crate) use walk::read_at_full;

/// Why the folder is not served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCode {
    /// A setting that is not valid: the folder text, `missing` or the browser cache time.
    Invalid,
    RootMissing,
    RootNotDirectory,
    RootUnreadable,
    RootForbidden,
}

impl RefusalCode {
    /// The code of `EdgeFeatureState`.
    pub fn as_str(self) -> &'static str {
        match self {
            RefusalCode::Invalid => "invalid",
            RefusalCode::RootMissing => "root_missing",
            RefusalCode::RootNotDirectory => "root_not_directory",
            RefusalCode::RootUnreadable => "root_unreadable",
            RefusalCode::RootForbidden => "root_forbidden",
        }
    }
}

/// A refusal and what the control plane shows with it: the folder or the value, cleaned of
/// control characters and cut to 256 bytes. Never a file's content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRefusal {
    pub code: RefusalCode,
    pub detail: String,
}

impl StaticRefusal {
    /// The refusal for a folder whose disk did not answer within the time the caller allowed. The
    /// note after the folder survives the cut to 256 bytes.
    pub fn no_answer(root: &str) -> StaticRefusal {
        const NOTE: &str = " (no answer from the disk)";
        let mut detail = detail_within(root, DETAIL_MAX - NOTE.len());
        detail.push_str(NOTE);
        StaticRefusal {
            code: RefusalCode::RootUnreadable,
            detail,
        }
    }
}

/// What happens to a request whose file is not in the folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Missing {
    /// It goes to the application.
    App,
    /// It is answered `404`, and every method but `GET` and `HEAD` `405`.
    NotFound,
}

/// The folder of one app, checked. Only [`StaticSpec::check`] makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticSpec {
    root: String,
    missing: Missing,
    max_age_s: u32,
    /// `(st_dev, st_ino)` of the root as the check saw it.
    pair: (u64, u64),
    forbidden: &'static [&'static str],
}

/// `base` itself, or something below it.
fn under(path: &str, base: &str) -> bool {
    path.strip_prefix(base)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether a folder may not be served, for the path it has now: one the unit hides, or one that is
/// the root folder, a forbidden folder, below one or above one, or one with a segment on the names
/// the host agent never sheds from its trace ring. The agent opens the root by its path on every
/// request, so such a name in the path would turn each request into an event that cannot be shed.
fn root_fault(path: &str, forbidden: &[&str]) -> Option<RefusalCode> {
    if HIDDEN_BY_UNIT.iter().any(|hidden| under(path, hidden)) {
        return Some(RefusalCode::RootUnreadable);
    }
    (path == "/"
        || forbidden.iter().any(|f| under(path, f) || under(f, path))
        || path
            .split('/')
            .any(|segment| names::kept_name(segment.as_bytes())))
    .then_some(RefusalCode::RootForbidden)
}

/// A root that is an absolute path of at most 1,024 bytes with no empty, `.` or `..` segment, no
/// control character and no replacement character (what a byte that is not UTF-8 becomes). It is
/// the control plane's check; the agent is never stricter.
fn root_text_valid(root: &str) -> bool {
    root.len() <= ROOT_MAX_BYTES
        && root.starts_with('/')
        && !root
            .chars()
            .any(|c| c < ' ' || c == '\u{7f}' || c == '\u{fffd}')
        && root[1..]
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

/// The longest `detail` of a refusal, in bytes.
const DETAIL_MAX: usize = 256;

/// `text` for the control plane to show: control characters become `?`, at most `max` bytes.
fn detail_within(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text.chars() {
        let c = if c.is_control() { '?' } else { c };
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

fn detail(text: &str) -> String {
    detail_within(text, DETAIL_MAX)
}

/// Where an open directory is, as the kernel says.
fn resolved_path(dir: &File) -> Option<String> {
    std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

impl StaticSpec {
    /// Checks the settings of an app's `static_files` and the folder, and says what is wrong:
    /// `invalid` for a text or a number that is out of range (`missing` is `app`, `not_found` or
    /// empty for `app`; the browser cache time 0 to [`MAX_BROWSER_CACHE_S`]), `root_forbidden`
    /// (also for a folder with a segment such as `private` or `profile`, a name the host agent
    /// never sheds), `root_unreadable` (a folder under `/home` and the like, which the unit
    /// hides), `root_missing`, `root_not_directory`, or `root_unreadable` again for a folder that
    /// cannot be opened. The forbidden check is run on the text and on the folder the path opens.
    pub fn check(root: &str, missing: &str, max_age_s: i64) -> Result<StaticSpec, StaticRefusal> {
        StaticSpec::check_against(root, missing, max_age_s, FORBIDDEN_ROOTS)
    }

    /// [`StaticSpec::check`] with another forbidden list, which tests use to forbid a folder they
    /// can make.
    #[doc(hidden)]
    pub fn check_against(
        root: &str,
        missing: &str,
        max_age_s: i64,
        forbidden: &'static [&'static str],
    ) -> Result<StaticSpec, StaticRefusal> {
        let refuse = |code, what: &str| {
            Err(StaticRefusal {
                code,
                detail: detail(what),
            })
        };
        let missing = match missing {
            "" | "app" => Missing::App,
            "not_found" => Missing::NotFound,
            other => return refuse(RefusalCode::Invalid, other),
        };
        let Some(max_age_s) = u32::try_from(max_age_s)
            .ok()
            .filter(|n| i64::from(*n) <= MAX_BROWSER_CACHE_S)
        else {
            return refuse(RefusalCode::Invalid, &max_age_s.to_string());
        };
        if root != "/" && !root_text_valid(root) {
            return refuse(RefusalCode::Invalid, root);
        }
        if let Some(code) = root_fault(root, forbidden) {
            return refuse(code, root);
        }
        let meta = match std::fs::metadata(root) {
            Ok(meta) => meta,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return refuse(RefusalCode::RootMissing, root);
            }
            Err(_) => return refuse(RefusalCode::RootUnreadable, root),
        };
        if !meta.is_dir() {
            return refuse(RefusalCode::RootNotDirectory, root);
        }
        let Some(dir) = walk::open_root(root) else {
            return refuse(RefusalCode::RootUnreadable, root);
        };
        let (Some(resolved), Ok(opened)) = (resolved_path(&dir), dir.metadata()) else {
            return refuse(RefusalCode::RootUnreadable, root);
        };
        if let Some(code) = root_fault(&resolved, forbidden) {
            return refuse(code, &resolved);
        }
        Ok(StaticSpec {
            root: root.to_owned(),
            missing,
            max_age_s,
            pair: (opened.dev(), opened.ino()),
            forbidden,
        })
    }

    /// The folder as the bundle wrote it.
    pub fn root(&self) -> &str {
        &self.root
    }
}

/// A route's folder: the settings, and the pair of the directory the root path last opened that
/// passed the forbidden-folder check.
pub(crate) struct StaticFolder {
    app_id: String,
    spec: StaticSpec,
    pair: Mutex<(u64, u64)>,
    /// The folder's path leads to a directory that may not be served now (said once in the log
    /// each time that changes).
    refused: AtomicBool,
}

/// What the blocking part found for a request.
enum Outcome {
    /// Nothing the folder serves.
    Missing,
    /// A directory asked for without its final slash.
    Slash,
    Hit(Hit),
}

struct Hit {
    meta: Meta,
    content_type: &'static str,
    plan: Plan,
    body: Body,
}

enum Body {
    /// No body: `HEAD`, `304`, `416`.
    None,
    /// The bytes of the answer, read.
    Bytes(Vec<u8>),
    /// A file that is sent after the head.
    File(Arc<File>),
}

/// An answer whose body is read from the open file as it is sent: the head (status, headers, the
/// length it announces) and the span of the file after it.
pub(crate) struct FileAnswer {
    pub head: OutboundResponse,
    pub file: Arc<File>,
    pub offset: u64,
    pub len: u64,
}

impl StaticFolder {
    pub fn new(app_id: &str, spec: &StaticSpec) -> StaticFolder {
        StaticFolder {
            app_id: app_id.to_owned(),
            pair: Mutex::new(spec.pair),
            spec: spec.clone(),
            refused: AtomicBool::new(false),
        }
    }

    /// Whether the directory the root path opens may be served. The pair of the directory is
    /// compared with the last one that passed; when it differs (a `current` link moved) the
    /// forbidden check runs on where the descriptor leads before anything is served, and the new
    /// pair is kept when it passes.
    fn root_allowed(&self, root: &File) -> bool {
        let Ok(meta) = root.metadata() else {
            return false;
        };
        let pair = (meta.dev(), meta.ino());
        let allowed = *self.pair.lock().unwrap_or_else(PoisonError::into_inner) == pair
            || resolved_path(root).is_some_and(|path| {
                let passes = root_fault(&path, self.spec.forbidden).is_none();
                if passes {
                    *self.pair.lock().unwrap_or_else(PoisonError::into_inner) = pair;
                }
                passes
            });
        self.note(allowed);
        allowed
    }

    /// Says in the log when the folder's path starts or stops leading to a directory that may not
    /// be served, once for each change and not for each request.
    fn note(&self, allowed: bool) {
        if self.refused.load(Ordering::Relaxed) != allowed
            || self.refused.swap(!allowed, Ordering::Relaxed) != allowed
        {
            return;
        }
        let folder = detail(&self.spec.root);
        if allowed {
            tracing::info!(
                "[static] app={} folder {folder} opens a directory that may be served again",
                self.app_id
            );
        } else {
            tracing::warn!(
                "[static] app={} folder {folder} now opens a directory that may not be served: nothing is served from it",
                self.app_id
            );
        }
    }

    /// Looks `path` (the app's decoded path) up and reads what the answer needs. Blocks.
    fn lookup(&self, path: &[u8], conditions: &Conditions, head: bool) -> Outcome {
        let Some(target) = names::plan(path) else {
            return Outcome::Missing;
        };
        let Some(root) = walk::open_root(&self.spec.root) else {
            return Outcome::Missing;
        };
        if !self.root_allowed(&root) {
            return Outcome::Missing;
        }
        match walk::find(&root, &target) {
            Found::Nothing => Outcome::Missing,
            Found::Slash => Outcome::Slash,
            Found::File(file, seen, name) => {
                hit(file, &seen, &name, conditions, head).map_or(Outcome::Missing, Outcome::Hit)
            }
        }
    }
}

/// The plan for an opened file, and its bytes when the answer is small enough to read whole.
/// `None` when the file changed under the read.
fn hit(
    file: File,
    seen: &walk::Seen,
    name: &[u8],
    conditions: &Conditions,
    head: bool,
) -> Option<Hit> {
    let meta = Meta {
        size: seen.size,
        mtime: u64::try_from(seen.mtime).unwrap_or(0),
    };
    let plan = answer::plan(&meta, conditions);
    let (offset, len) = match plan {
        Plan::Whole => (0, meta.size),
        Plan::Part { start, len } => (start, len),
        Plan::NotModified | Plan::Unsatisfiable => (0, 0),
    };
    let body = if head || matches!(plan, Plan::NotModified | Plan::Unsatisfiable) {
        Body::None
    } else if len <= READ_WHOLE_MAX {
        let mut bytes = vec![0; usize::try_from(len).ok()?];
        let read = walk::read_at_full(&file, &mut bytes, offset).ok()?;
        if read != bytes.len() {
            return None;
        }
        Body::Bytes(bytes)
    } else {
        Body::File(Arc::new(file))
    };
    Some(Hit {
        meta,
        content_type: mime::content_type(name),
        plan,
        body,
    })
}

/// The request headers that decide the answer.
fn conditions(req: &InboundRequest) -> Conditions {
    Conditions {
        if_none_match: req.peek("If-None-Match").to_vec(),
        if_modified_since: req.peek("If-Modified-Since").to_vec(),
        range: req.peek("Range").to_vec(),
        if_range: req.peek("If-Range").to_vec(),
    }
}

/// The head of the answer for `hit`; the length of a body that is not in `body` is announced.
fn head_of(hit: &Hit, head: bool, max_age_s: u32) -> OutboundResponse {
    let meta = &hit.meta;
    let mut r = match hit.plan {
        Plan::NotModified => OutboundResponse::new(304),
        Plan::Unsatisfiable => {
            let mut r = OutboundResponse::new(416);
            r.set(
                b"Content-Range",
                format!("bytes */{}", meta.size).as_bytes(),
            );
            r.set(b"Accept-Ranges", b"bytes");
            return r;
        }
        Plan::Whole => OutboundResponse::new(200),
        Plan::Part { start, len } => {
            let mut r = OutboundResponse::new(206);
            let range = format!("bytes {start}-{}/{}", start + len - 1, meta.size);
            r.set(b"Content-Range", range.as_bytes());
            r
        }
    };
    r.set(b"ETag", meta.etag().as_bytes());
    r.set(b"Last-Modified", http_date(meta.mtime).as_bytes());
    if max_age_s > 0 {
        r.set(b"Cache-Control", format!("max-age={max_age_s}").as_bytes());
    }
    if r.status != 304 {
        r.assign_content_type(hit.content_type.as_bytes());
        r.set(b"X-Content-Type-Options", b"nosniff");
        r.set(b"Accept-Ranges", b"bytes");
        let len = match hit.plan {
            Plan::Part { len, .. } => len,
            _ => meta.size,
        };
        if head || matches!(hit.body, Body::File(_)) {
            r.declare_length(len);
        }
    }
    r
}

/// A plain answer of the folder: `404`, `405` or `503`, counted.
fn refusal(status: u16) -> Done {
    let mut r = OutboundResponse::error(
        status,
        match status {
            404 => "Not Found",
            503 => "Service Unavailable",
            _ => "Method Not Allowed",
        },
    );
    if status == 405 {
        r.set(b"Allow", b"GET, HEAD");
    }
    crate::metrics::count_static(status, r.body.len() as u64);
    Done::Respond(r)
}

/// `308` to the same path with a final slash, for a directory asked for without one. The
/// location is the public path, re-quoted, so no byte of the request can end the header line or
/// name another host.
fn add_slash(req: &InboundRequest) -> Done {
    let mut r = OutboundResponse::new(308);
    let mut location = Vec::with_capacity(req.forward_path.len() + req.query.len() + 2);
    push_escaped_path(&mut location, &req.forward_path);
    location.push(b'/');
    if !req.query.is_empty() {
        location.push(b'?');
        push_forward_query(&mut location, &req.query);
    }
    r.set(b"Location", &location);
    crate::metrics::count_static(308, 0);
    Done::Respond(r)
}

/// The folder's answer for `req`, or `None` when the request is the application's: a file that is
/// not there with `missing: app`, every method but `GET` and `HEAD` with it, and any request the
/// disk gate turned away or the disk did not answer (`missing: not_found` says `503` for those).
/// Runs after the verdict; a request that asks for an upgrade never gets here.
pub(crate) async fn serve(
    shared: &Shared,
    route: &Route,
    folder: &Arc<StaticFolder>,
    req: &InboundRequest,
) -> Option<Done> {
    let own = folder.spec.missing == Missing::NotFound;
    let head = req.method == b"HEAD";
    if !head && req.method != b"GET" {
        return own.then(|| refusal(405));
    }
    let path = crate::redirect::app_path(route, req).to_vec();
    let conditions = conditions(req);
    let looked = {
        let folder = folder.clone();
        shared
            .disk
            .run(LOOKUP_WAIT, move || folder.lookup(&path, &conditions, head))
            .await
    };
    let Some(outcome) = looked else {
        return own.then(|| refusal(503));
    };
    let hit = match outcome {
        Outcome::Missing => return own.then(|| refusal(404)),
        Outcome::Slash => return Some(add_slash(req)),
        Outcome::Hit(hit) => hit,
    };
    let mut response = head_of(&hit, head, folder.spec.max_age_s);
    let (offset, len) = match hit.plan {
        Plan::Part { start, len } => (start, len),
        _ => (0, hit.meta.size),
    };
    match hit.body {
        Body::File(file) => {
            crate::metrics::count_static(response.status, 0);
            Some(Done::File(Box::new(FileAnswer {
                head: response,
                file,
                offset,
                len,
            })))
        }
        Body::Bytes(bytes) => {
            response.body = bytes;
            if let (Some(spec), 200) = (&route.compression, response.status) {
                let stats = shared.edge.app(&route.app_id);
                crate::compress::apply(&stats, spec, req, &route.session, &mut response).await;
            }
            crate::metrics::count_static(response.status, response.body.len() as u64);
            Some(Done::Respond(response))
        }
        Body::None => {
            crate::metrics::count_static(response.status, 0);
            Some(Done::Respond(response))
        }
    }
}

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod tests;
