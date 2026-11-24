//! The response cache: an app can keep the answers of its application and send them again without
//! asking it, after the verdict. Two tiers, disk (`format`, `store`) and memory (`index`), both
//! evicted by a segmented LRU (`slru`); a key made of what a request is (`key`); the rules for what
//! is kept (`control`, [`decide`]); and the answer for a copy that is found (`hit`).
//!
//! Only a request the verdict allows reads or fills it: a log or monitor verdict, an upgrade, a body
//! on a `GET`, a method override and a path under a `bypass` rule go to the application as they
//! are, unread and unstored (`X-Cache: BYPASS`). The agent never keeps what is private to a visitor:
//! see [`decide`] for every case.

mod control;
mod format;
mod hit;
mod host;
mod index;
mod key;
mod slru;
mod store;

use std::sync::Arc;
use std::time::Duration;

use wafio_domain::ip_address::IpAddress;

use crate::compress::media_type;
use crate::config::Route;
use crate::proxy::Shared;
use crate::request::InboundRequest;
use crate::response::OutboundResponse;
use crate::signed_in::is_signed_in;
use crate::static_files::LOOKUP_WAIT;
use control::{CacheControl, MAX_LIFETIME_S, vary_names};
use format::{MAX_KEY, StoredHead, Times};
use index::MEMORY_COPY_MAX;
use key::{
    Bucket, FileId, PrimaryId, file_id, is_https, keyed_inputs, primary_id, primary_key,
    request_header_values, variant,
};
use store::Store;

pub use host::{CacheRefusal, CacheRefusalCode, HostFacts};
pub(crate) use store::AppCache;
pub use store::{CacheHost, CacheLimits, valid_app_id};

/// The settings of an app's cache, as the bundle brings them and after the agent has checked them.
/// The defaults and ranges are those of the dashboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheSpec {
    /// Seconds a file of a type listed in the docs is kept when the application says nothing; 0
    /// keeps none of them.
    pub default_ttl_s: u32,
    /// Seconds past its life that a stored copy is sent when the application is down.
    pub stale_if_error_s: u32,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
    pub max_object_bytes: u64,
    /// Names of cookies that mark a visitor as signed in, besides the ones the agent knows.
    pub session_cookies: Vec<String>,
    pub rules: Vec<CacheRule>,
}

/// A path rule: the longest prefix that matches a path decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheRule {
    pub prefix: String,
    /// Never keep: the request goes to the application unread and unstored.
    pub bypass: bool,
    /// Seconds to keep an answer that does not say; 1 or more for a keeping rule.
    pub ttl_s: u32,
    /// Also keep for a signed-in visitor.
    pub signed_in: bool,
}

pub const DEFAULT_TTL_S: u32 = 3600;
pub const MAX_TTL_S: u32 = 31_536_000;
pub const DEFAULT_STALE_IF_ERROR_S: u32 = 600;
pub const MAX_STALE_IF_ERROR_S: u32 = 86_400;
pub const DEFAULT_DISK_BYTES: u64 = 1 << 30;
pub const MIN_DISK_BYTES: u64 = 16 << 20;
pub const MAX_DISK_BYTES: u64 = 1 << 40;
pub const DEFAULT_MEMORY_BYTES: u64 = 32 << 20;
pub const MAX_MEMORY_BYTES: u64 = 4 << 30;
pub const DEFAULT_OBJECT_BYTES: u64 = 8 << 20;
pub const MIN_OBJECT_BYTES: u64 = 1 << 10;
pub const MAX_OBJECT_BYTES: u64 = 64 << 20;
pub const MAX_RULES: usize = 50;
pub const MAX_COOKIE_NAMES: usize = 20;

impl Default for CacheSpec {
    fn default() -> CacheSpec {
        CacheSpec {
            default_ttl_s: DEFAULT_TTL_S,
            stale_if_error_s: DEFAULT_STALE_IF_ERROR_S,
            disk_bytes: DEFAULT_DISK_BYTES,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            max_object_bytes: DEFAULT_OBJECT_BYTES,
            session_cookies: Vec::new(),
            rules: Vec::new(),
        }
    }
}

fn invalid(field: &str) -> Result<(), CacheRefusal> {
    Err(CacheRefusal {
        code: CacheRefusalCode::Invalid,
        detail: field.to_owned(),
    })
}

/// A cookie name the control plane lets through: 1 to 64 printable ASCII characters, none of them a
/// space, comma, semicolon or `=`.
fn cookie_name_ok(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|c| (0x21..0x7f).contains(&c) && !matches!(c, b',' | b';' | b'='))
}

impl CacheSpec {
    /// Checks the settings against the ranges of the control plane, which the agent is never
    /// stricter than. The refusal's detail is the name of the setting.
    pub fn check(&self) -> Result<(), CacheRefusal> {
        if self.default_ttl_s > MAX_TTL_S {
            return invalid("default_ttl_s");
        }
        if self.stale_if_error_s > MAX_STALE_IF_ERROR_S {
            return invalid("stale_if_error_s");
        }
        if !(MIN_DISK_BYTES..=MAX_DISK_BYTES).contains(&self.disk_bytes) {
            return invalid("disk_bytes");
        }
        if self.memory_bytes > MAX_MEMORY_BYTES {
            return invalid("memory_bytes");
        }
        if !(MIN_OBJECT_BYTES..=MAX_OBJECT_BYTES).contains(&self.max_object_bytes)
            || self.max_object_bytes > self.disk_bytes
        {
            return invalid("max_object_bytes");
        }
        if self.session_cookies.len() > MAX_COOKIE_NAMES
            || !self.session_cookies.iter().all(|n| cookie_name_ok(n))
        {
            return invalid("session_cookies");
        }
        if self.rules.len() > MAX_RULES {
            return invalid("rules");
        }
        for (i, rule) in self.rules.iter().enumerate() {
            let prefix_ok = rule.prefix.starts_with('/')
                && rule.prefix.len() <= 256
                && !rule.prefix.contains([' ', '?', '#'])
                && !rule.prefix.chars().any(char::is_control);
            let ttl_ok = rule.bypass || (1..=MAX_TTL_S).contains(&rule.ttl_s);
            let repeated = self.rules[..i].iter().any(|r| r.prefix == rule.prefix);
            if !prefix_ok || repeated {
                return invalid("rules.prefix");
            }
            if !ttl_ok {
                return invalid("rules.ttl_s");
            }
        }
        Ok(())
    }

    /// What the store needs of these settings.
    pub fn limits(&self, app_id: &str) -> CacheLimits {
        CacheLimits {
            app_id: app_id.to_owned(),
            disk_bytes: self.disk_bytes,
            memory_bytes: self.memory_bytes,
            stale_if_error_s: self.stale_if_error_s,
        }
    }
}

/// The settings a request reads.
pub(crate) struct Settings {
    default_ttl_s: u64,
    max_object_bytes: u64,
    /// Longest prefix first, so the first that matches is the one that decides.
    rules: Vec<CacheRule>,
}

impl Settings {
    fn new(spec: &CacheSpec) -> Settings {
        let mut rules = spec.rules.clone();
        rules.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
        Settings {
            default_ttl_s: u64::from(spec.default_ttl_s),
            max_object_bytes: spec.max_object_bytes,
            rules,
        }
    }

    fn rule_for(&self, path: &[u8]) -> Option<&CacheRule> {
        self.rules
            .iter()
            .find(|r| path.starts_with(r.prefix.as_bytes()))
    }
}

/// The cache of a route: its settings, and the store once the proxy has bound one.
pub(crate) struct RouteCache {
    pub settings: Settings,
    pub app: Option<Arc<AppCache>>,
}

impl RouteCache {
    pub fn new(spec: &CacheSpec) -> RouteCache {
        RouteCache {
            settings: Settings::new(spec),
            app: None,
        }
    }
}

/// What the cache did with a request, as `X-Cache` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Label {
    Hit,
    Miss,
    Bypass,
}

/// Sets `X-Cache` on an answer of an app that has the cache on.
pub(crate) fn tag(resp: &mut OutboundResponse, label: Label) {
    resp.set(
        b"X-Cache",
        match label {
            Label::Hit => b"HIT",
            Label::Miss => b"MISS",
            Label::Bypass => b"BYPASS",
        },
    );
}

/// What the cache makes of a request.
pub(crate) enum Plan {
    /// The app has no cache.
    Off,
    /// Not read, not stored.
    Bypass,
    /// Looked up, and stored when the answer allows it and the request does (`Ask::fillable`).
    Lookup(Box<Ask>),
}

impl Plan {
    /// The label of an answer that came from the application.
    pub fn label(&self) -> Option<Label> {
        match self {
            Plan::Off => None,
            Plan::Bypass => Some(Label::Bypass),
            Plan::Lookup(_) => Some(Label::Miss),
        }
    }

    /// Whether the answer of the application is to be offered to the store.
    pub fn fills(&self) -> bool {
        matches!(self, Plan::Lookup(ask) if ask.fillable)
    }
}

/// A request that the cache looks up.
pub(crate) struct Ask {
    primary: Vec<u8>,
    primary_id: PrimaryId,
    bucket: Bucket,
    /// The request itself allows a copy to be made of its answer: a `GET` with no `Range`, from a
    /// visitor who is not signed in (or for a path with a rule for them).
    pub fillable: bool,
    /// The request has a `Cookie`.
    cookie: bool,
    /// The lifetime of the keeping rule the path is under.
    rule_ttl: Option<u64>,
}

fn has_line(req: &InboundRequest, names: &[&[u8]]) -> bool {
    req.lines
        .iter()
        .any(|(n, _)| names.iter().any(|w| n.eq_ignore_ascii_case(w)))
}

/// A request that carries, or may carry, a body: bytes were read, a length above 0, or any
/// `Transfer-Encoding`.
fn has_body(req: &InboundRequest, body_read: bool) -> bool {
    let length = req
        .headers
        .get(&b"Content-Length"[..])
        .and_then(|v| v.first())
        .is_some_and(|v| {
            std::str::from_utf8(v.trim_ascii())
                .ok()
                .and_then(|t| t.parse::<u64>().ok())
                != Some(0)
        });
    body_read || length || has_line(req, &[b"transfer-encoding"])
}

/// The headers that make a request say it is another method.
const OVERRIDES: [&[u8]; 3] = [
    b"x-http-method-override",
    b"x-http-method",
    b"x-method-override",
];

/// Whether the peer is a proxy the route trusts to say what it was asked for.
pub(crate) fn trusts(route: &Route, peer: &IpAddress) -> bool {
    route.proxy_config.may_supply_forwarded_headers(peer)
}

pub(crate) use key::{forwarded_host_or_proto, unkeyed_input};

/// Whether the route has the cache on and the peer is not a proxy it trusts: what such a peer says
/// in the headers that are not part of the key is not sent to the application.
pub(crate) fn drops_unkeyed_inputs(route: &Route, peer: &IpAddress) -> bool {
    route.cache_active().is_some() && !trusts(route, peer)
}

/// What the cache makes of `req`, after the verdict: `action` is the verdict, `body_read` whether
/// the request had a body.
pub(crate) fn plan(
    route: &Route,
    req: &InboundRequest,
    action: &str,
    body_read: bool,
    peer: &IpAddress,
) -> Plan {
    let Some((settings, _)) = route.cache_active() else {
        return Plan::Off;
    };
    let get = req.method == b"GET";
    if action != "allow"
        || req.has_upgrade()
        || !(get || req.method == b"HEAD")
        || has_body(req, body_read)
        || has_line(req, &OVERRIDES)
        || crate::upstream::rewrites_response_body(route, &req.forward_path)
    {
        return Plan::Bypass;
    }
    // A rule is for a path as the application reads it. `;` ends a path for some servers (`..;`
    // is `..` to Tomcat), so what a rule matches there may be another path: never read or stored.
    let rule = settings.rule_for(&req.forward_path);
    if rule.is_some_and(|r| r.bypass || req.forward_path.contains(&b';')) {
        return Plan::Bypass;
    }
    let trusted = trusts(route, peer);
    let keyed = if trusted {
        match keyed_inputs(req) {
            Some(keyed) => keyed,
            None => return Plan::Bypass,
        }
    } else {
        Vec::new()
    };
    let bucket = Bucket::of(req);
    let primary = primary_key(
        is_https(req, trusted),
        &req.host,
        &req.forward_request_target,
        bucket,
        &keyed,
    );
    let signed_in = is_signed_in(req, &route.session);
    Plan::Lookup(Box::new(Ask {
        primary_id: primary_id(&primary),
        primary,
        bucket,
        fillable: get
            && req.peek("Range").is_empty()
            && (!signed_in || rule.is_some_and(|r| r.signed_in)),
        cookie: !req.cookies.is_empty(),
        rule_ttl: rule.map(|r| u64::from(r.ttl_s)),
    }))
}

/// Why an answer was not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotKept {
    Status,
    /// `Set-Cookie`, `private`, `no-store` or `no-cache`.
    Private,
    /// A `Cache-Control` that cannot be read.
    Control,
    Vary,
    TooLarge,
    Encoding,
    NoLifetime,
    /// The request had cookies and nothing says the answer is the same for everyone.
    Cookie,
    /// The head or the key is longer than a file takes.
    Length,
}

/// An answer ready to put on disk.
pub(crate) struct Prepared {
    id: FileId,
    primary: PrimaryId,
    key: Vec<u8>,
    primary_len: usize,
    names: Vec<Vec<u8>>,
    head: Vec<u8>,
    times: Times,
}

/// Types a file is kept by type, when the application says nothing.
fn file_type(media: &[u8]) -> bool {
    matches!(
        media,
        b"text/css" | b"text/javascript" | b"application/javascript" | b"application/wasm"
    ) || [&b"image/"[..], b"font/", b"video/", b"audio/"]
        .iter()
        .any(|p| media.starts_with(p))
}

fn digits(value: Option<&[u8]>) -> u32 {
    value
        .and_then(|v| std::str::from_utf8(v.trim_ascii()).ok())
        .and_then(|t| t.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Whether the answer to `req` may be kept, and under what key and for how long. Never kept: a
/// status other than 200, 203, 300, 301, 308, 404 and 410 (the last two only with a lifetime of
/// their own, never the default for files); `Set-Cookie`; `private`, `no-store` and `no-cache`
/// (the request's own `Cache-Control` is ignored); a `Vary` of `*`, `Cookie` or `Authorization`,
/// or of more than four names; a body over the largest object; an encoding other than the
/// request's own bucket; an answer with no lifetime (`s-maxage`, `max-age`, `Expires` minus `Date`,
/// a keeping rule's time, or the default for a file type; at most 365 days); and, for a request
/// with a cookie, an answer that is not `public`, has no `s-maxage`, is not a file type and has no
/// rule behind it. A signed-in visitor, a `Range` and a `HEAD` are refused before ([`Ask::fillable`]).
pub(crate) fn decide(
    settings: &Settings,
    ask: &Ask,
    req: &InboundRequest,
    resp: &OutboundResponse,
    now: u64,
) -> Result<Prepared, NotKept> {
    if !matches!(resp.status, 200 | 203 | 300 | 301 | 308 | 404 | 410) {
        return Err(NotKept::Status);
    }
    let lines = resp.stored_lines().ok_or(NotKept::Private)?;
    let cc = CacheControl::parse(resp.values(b"Cache-Control"));
    if cc.invalid {
        return Err(NotKept::Control);
    }
    if cc.forbids_storing() {
        return Err(NotKept::Private);
    }
    let names = vary_names(resp.values(b"Vary")).map_err(|()| NotKept::Vary)?;
    if resp.body.len() as u64 > settings.max_object_bytes {
        return Err(NotKept::TooLarge);
    }
    let encoding = resp
        .peek(b"Content-Encoding")
        .map(|e| e.trim_ascii().to_ascii_lowercase())
        .unwrap_or_default();
    if !(encoding.is_empty() || encoding == b"identity" || encoding == ask.bucket.token()) {
        return Err(NotKept::Encoding);
    }
    let media = media_type(resp.content_type());
    let own = cc.lifetime(resp.peek(b"Expires"), resp.peek(b"Date"), now);
    let by_type =
        (settings.default_ttl_s > 0 && file_type(&media) && !matches!(resp.status, 404 | 410))
            .then_some(settings.default_ttl_s);
    let lifetime = own
        .or(ask.rule_ttl)
        .or(by_type)
        .map_or(0, |n| n.min(MAX_LIFETIME_S));
    let initial_age = digits(resp.peek(b"Age"));
    let left = lifetime.saturating_sub(u64::from(initial_age));
    if left == 0 {
        return Err(NotKept::NoLifetime);
    }
    if ask.cookie
        && !(cc.public || cc.s_maxage.is_some() || file_type(&media) || ask.rule_ttl.is_some())
    {
        return Err(NotKept::Cookie);
    }
    let head = StoredHead {
        status: resp.status,
        http10: false,
        reason: resp.reason().to_vec(),
        lines,
    }
    .encode()
    .ok_or(NotKept::Length)?;
    let mut key = ask.primary.clone();
    key.extend_from_slice(&variant(&names, ask.bucket, |n| {
        request_header_values(req, n)
    }));
    if key.len() > MAX_KEY {
        return Err(NotKept::Length);
    }
    Ok(Prepared {
        id: file_id(&key, b""),
        primary: ask.primary_id,
        primary_len: ask.primary.len(),
        key,
        names,
        head,
        times: Times {
            stored_at: now,
            fresh_until: now + left,
            initial_age,
            stale_window: u32::try_from(cc.stale_window()).unwrap_or(u32::MAX),
        },
    })
}

/// The longest the answer waits for its copy to be written. The write goes on past it.
const STORE_WAIT: Duration = Duration::from_millis(500);

/// Offers the answer of the application to the store, which keeps it when [`decide`] allows. The
/// answer is sent after the copy is written, or after [`STORE_WAIT`] when the disk is slow.
pub(crate) async fn fill(
    shared: &Shared,
    route: &Route,
    ask: &Ask,
    req: &InboundRequest,
    resp: &OutboundResponse,
) -> bool {
    let Some((settings, app)) = route.cache_active() else {
        return false;
    };
    if !app.can_store() {
        return false;
    }
    let Ok(p) = decide(settings, ask, req, resp, store::now()) else {
        return false;
    };
    let size = format::file_len(&p.key, &p.head, &resp.body);
    let Some(permit) = u32::try_from(size)
        .ok()
        .and_then(|n| app.budget().clone().try_acquire_many_owned(n).ok())
    else {
        return false;
    };
    let item = Store {
        id: p.id,
        primary: p.primary,
        key: p.key,
        primary_len: p.primary_len,
        names: p.names,
        head: p.head,
        body: resp.body.clone(),
        times: p.times,
    };
    let app = app.clone();
    let job = shared.disk.run_counting(LOOKUP_WAIT, no_count, move || {
        let _permit = permit;
        app.store(item)
    });
    match tokio::time::timeout(STORE_WAIT, job).await {
        Ok(Some(Ok(()))) => true,
        Ok(Some(Err(store::Skip::Disk(e)))) => {
            tracing::debug!("[cache] a copy was not written: {e}");
            false
        }
        _ => false,
    }
}

fn no_count() {}

/// The answer for `req` from a fresh copy, `None` for a miss: no copy, one that is not fresh, one
/// whose file fails its check, or a disk that gives no slot or no answer.
pub(crate) async fn lookup(
    shared: &Shared,
    route: &Route,
    ask: &Ask,
    req: &InboundRequest,
) -> Option<OutboundResponse> {
    let (_, app) = route.cache_active()?;
    let now = store::now();
    let found = {
        let (found, fresh) = app.index().find(
            &ask.primary_id,
            &ask.primary,
            |names| variant(names, ask.bucket, |n| request_header_values(req, n)),
            now,
        )?;
        fresh.then_some(found)?
    };
    let (id, hits, size) = (found.id, found.hits, found.size);
    let (loaded, from_memory) = match found.mem.clone() {
        Some(copy) => (copy, true),
        None => {
            let permit = app
                .budget()
                .clone()
                .try_acquire_many_owned(u32::try_from(size).ok()?)
                .ok()?;
            let reader = app.clone();
            let read = shared
                .disk
                .run_counting(LOOKUP_WAIT, no_count, move || {
                    let _permit = permit;
                    reader.read(&found)
                })
                .await?;
            (Arc::new(read.ok()?), false)
        }
    };
    if loaded.times.fresh_until <= now {
        return None;
    }
    // The second hit of a small copy puts it in memory, so the third reads no disk.
    if !from_memory && hits >= 2 && loaded.size <= MEMORY_COPY_MAX {
        app.index().admit_memory(&id, loaded.clone());
    }
    Some(hit::answer(req, loaded, now))
}

/// A 2xx or 3xx answer to `POST`, `PUT`, `PATCH` or `DELETE` ends the copies of the URL, in every
/// encoding and variant. The index forgets them at once and their files are deleted before the
/// answer goes on (a deletion that is slow goes on behind it).
pub(crate) async fn drop_copies(
    shared: &Shared,
    route: &Route,
    req: &InboundRequest,
    peer: &IpAddress,
    status: u16,
) {
    let Some((_, app)) = route.cache_active() else {
        return;
    };
    if !matches!(&req.method[..], b"POST" | b"PUT" | b"PATCH" | b"DELETE")
        || !(200..400).contains(&status)
    {
        return;
    }
    let trusted = trusts(route, peer);
    let keyed = if trusted {
        match keyed_inputs(req) {
            Some(keyed) => keyed,
            None => return,
        }
    } else {
        Vec::new()
    };
    let https = is_https(req, trusted);
    let primaries: Vec<PrimaryId> = Bucket::ALL
        .iter()
        .map(|&bucket| {
            primary_id(&primary_key(
                https,
                &req.host,
                &req.forward_request_target,
                bucket,
                &keyed,
            ))
        })
        .collect();
    let gone = app.drop_primaries(&primaries);
    if gone.is_empty() {
        return;
    }
    let app = app.clone();
    let job = shared
        .disk
        .run_counting(LOOKUP_WAIT, no_count, move || app.delete_files(&gone));
    let _ = tokio::time::timeout(STORE_WAIT, job).await;
}

#[cfg(test)]
mod tests;
