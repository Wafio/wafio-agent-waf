//! The response cache: an app can keep the answers of its application and send them again without
//! asking it, after the verdict. Two tiers, disk (`format`, `store`) and memory (`index`), both
//! evicted by a segmented LRU (`slru`); a key made of what a request is (`key`); the rules for what
//! is kept (`control`, [`decide`]); the answer for a copy that is found (`hit`); the one fetch at
//! a time for a key that has no copy (`fills`); a copy that is past its life, checked again or sent
//! stale (`refresh`); and what a purge names (`purge`).
//!
//! Only a request the verdict allows reads or fills it: a log or monitor verdict, an upgrade, a body
//! on a `GET`, a method override and a path under a `bypass` rule go to the application as they
//! are, unread and unstored (`X-Cache: BYPASS`). The agent never keeps what is private to a visitor:
//! see [`decide`] for every case.

mod control;
mod fills;
mod format;
mod hit;
mod host;
mod index;
mod key;
mod purge;
mod refresh;
mod slru;
mod statics;
mod stats;
mod store;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::OwnedSemaphorePermit;
use wafio_domain::ip_address::IpAddress;

use crate::compress::media_type;
use crate::config::Route;
use crate::proxy::Shared;
use crate::request::InboundRequest;
use crate::response::OutboundResponse;
use crate::signed_in::is_signed_in;
use crate::static_files::LOOKUP_WAIT;
use control::{CacheControl, MAX_LIFETIME_S, vary_names};
use fills::{FillGuard, Turn};
use format::{Loaded, MAX_KEY, StoredHead, Times};
use index::MEMORY_COPY_MAX;
use key::{
    Bucket, FileId, PrimaryId, file_id, is_https, keyed_inputs, primary_id, primary_key,
    request_header_values, same_name, variant,
};
use stats::Count;
use store::{Skip, Store};

pub use host::{CacheRefusal, CacheRefusalCode, HostFacts};
pub(crate) use key::StaticFile;
pub use purge::PurgeScope;
pub(crate) use refresh::{NO_CONDITIONS, Validator};
pub(crate) use statics::{StaticKey, StaticMemory, static_memory};
pub use stats::{CacheCounters, CacheTotals};
pub(crate) use store::AppCache;
pub use store::{AppMetrics, CacheHost, CacheLimits, PurgeError, valid_app_id};

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

/// What the cache did with a request, as `X-Cache` says. A hit says which tier it came from, for
/// the counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Label {
    HitMemory,
    HitDisk,
    /// A copy past its life, sent because the application is allowed to be late or is down.
    Stale,
    /// The application was asked, whatever came of it.
    Miss,
    Bypass,
}

/// Sets `X-Cache` on an answer of an app that has the cache on, and counts it.
pub(crate) fn tag(route: &Route, resp: &mut OutboundResponse, label: Label) {
    resp.set(
        b"X-Cache",
        match label {
            Label::HitMemory | Label::HitDisk => b"HIT",
            Label::Stale => b"STALE",
            Label::Miss => b"MISS",
            Label::Bypass => b"BYPASS",
        },
    );
    if let Some((_, app)) = route.cache_active() {
        app.count(match label {
            Label::HitMemory => Count::HitMemory,
            Label::HitDisk => Count::HitDisk,
            Label::Stale => Count::Stale,
            Label::Miss => Count::Miss,
            Label::Bypass => Count::Bypass,
        });
    }
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
#[derive(Clone)]
pub(crate) struct Ask {
    primary: Vec<u8>,
    primary_id: PrimaryId,
    bucket: Bucket,
    /// The request itself allows a copy to be made of its answer: a `GET` with no `Range`, from a
    /// visitor who is not signed in (or for a path with a rule for them).
    pub fillable: bool,
    /// A `GET` from a visitor who is signed in, for a path no rule opens to them: its answer is
    /// not kept, and is counted as private.
    pub signed_in_get: bool,
    /// The request has a `Cookie`.
    cookie: bool,
    /// The lifetime of the keeping rule the path is under.
    rule_ttl: Option<u64>,
    /// The purge count of the app when the request came: a purge since then drops its copy.
    purge_gen: u64,
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

/// The headers that make a request say it is another method, as a CGI parameter names them: the
/// `_` spelling of a name is the same parameter as the `-` one.
const OVERRIDES: [&[u8]; 3] = [
    b"x-http-method-override",
    b"x-http-method",
    b"x-method-override",
];

fn has_override(req: &InboundRequest) -> bool {
    req.lines
        .iter()
        .any(|(n, _)| OVERRIDES.iter().any(|o| same_name(n, o)))
}

/// Whether the peer is a proxy the route trusts to say what it was asked for.
pub(crate) fn trusts(route: &Route, peer: &IpAddress) -> bool {
    route.proxy_config.may_supply_forwarded_headers(peer)
}

pub(crate) use key::{forwarded_host, forwarded_host_or_proto, unkeyed_input};

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
    let Some((settings, app)) = route.cache_active() else {
        return Plan::Off;
    };
    let get = req.method == b"GET";
    if action != "allow"
        || req.has_upgrade()
        || !(get || req.method == b"HEAD")
        || has_body(req, body_read)
        || has_override(req)
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
    let may_sign_in = !signed_in || rule.is_some_and(|r| r.signed_in);
    Plan::Lookup(Box::new(Ask {
        primary_id: primary_id(&primary),
        primary,
        bucket,
        fillable: get && req.peek("Range").is_empty() && may_sign_in,
        signed_in_get: get && !may_sign_in,
        cookie: !req.cookies.is_empty(),
        rule_ttl: rule.map(|r| u64::from(r.ttl_s)),
        purge_gen: app.purge_count(),
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

/// The longest a request waits for the files of a drop to be deleted. The deletion goes on past it.
const STORE_WAIT: Duration = Duration::from_millis(500);

/// What an answer that is not kept counts as, if the dashboard has a line for it.
fn skipped(why: NotKept) -> Option<Count> {
    match why {
        NotKept::NoLifetime => Some(Count::SkippedNoLifetime),
        NotKept::Private | NotKept::Control | NotKept::Vary | NotKept::Cookie => {
            Some(Count::SkippedPrivate)
        }
        NotKept::TooLarge => Some(Count::SkippedTooLarge),
        NotKept::Status | NotKept::Encoding | NotKept::Length => None,
    }
}

/// How long the key of an answer that is not kept is marked, so that the next requests do not
/// queue behind a fetch that will not help them: 30 seconds, or the `max-age` of an answer that
/// says it is private or not to be stored (at most ten minutes). `None` for a refusal that is
/// about the visitor, for an error of the application, which may pass, and for a `304` or `412`,
/// which answer a condition and say nothing of the page.
fn mark_seconds(why: NotKept, resp: &OutboundResponse) -> Option<u64> {
    match why {
        NotKept::Cookie => None,
        NotKept::Status if resp.status >= 500 || matches!(resp.status, 304 | 412) => None,
        NotKept::Private => {
            let cc = CacheControl::parse(resp.values(b"Cache-Control"));
            Some(match cc.max_age {
                Some(n) if n > 0 && (cc.private || cc.no_store) => n.min(fills::MARK_MAX_S),
                _ => fills::MARK_DEFAULT_S,
            })
        }
        _ => Some(fills::MARK_DEFAULT_S),
    }
}

/// Offers the answer of the application to the store, which keeps it when [`decide`] allows. An
/// answer that is not kept is counted, and marks its key so that the next requests go on without
/// waiting. The copy is written behind the visitor: the answer goes out at once, and what bounds
/// the work is the budget of bytes in flight, taken here, and the wait for a disk slot. The body
/// is shared with the answer, not copied. `guard` is the fill lock of the request: whoever waits
/// for it wakes when the copy is in, or at once when there is none.
pub(crate) fn fill(
    shared: &Shared,
    route: &Route,
    ask: &Ask,
    req: &InboundRequest,
    resp: &OutboundResponse,
    guard: Option<FillGuard>,
) {
    let Some((settings, app)) = route.cache_active() else {
        return;
    };
    let now = store::now();
    match decide(settings, ask, req, resp, now) {
        Ok(p) if app.can_store() => keep(shared, app, ask.purge_gen, p, resp.body.clone(), guard),
        Ok(_) => {}
        Err(why) => {
            if let Some(count) = skipped(why) {
                app.count(count);
            }
            // A key that is marked already stays so until its mark ends: asking again how long
            // would only move the end.
            if !app.fills().marked(&ask.primary_id, now)
                && let Some(seconds) = mark_seconds(why, resp)
            {
                app.fills().mark(ask.primary_id, seconds, now);
            }
        }
    }
}

/// Writes a prepared answer behind the request that made it, holding `guard` until it is in.
fn keep(
    shared: &Shared,
    app: &Arc<AppCache>,
    purge_gen: u64,
    p: Prepared,
    body: Bytes,
    guard: Option<FillGuard>,
) {
    let size = format::file_len(&p.key, &p.head, &body);
    let Some(permit) = u32::try_from(size)
        .ok()
        .and_then(|n| app.budget().clone().try_acquire_many_owned(n).ok())
    else {
        return;
    };
    let item = Store {
        purge_gen,
        id: p.id,
        primary: p.primary,
        key: p.key,
        primary_len: p.primary_len,
        names: p.names,
        head: p.head,
        body,
        times: p.times,
    };
    let app = app.clone();
    let storing = app.storing();
    let disk = shared.disk.clone();
    tokio::spawn(async move {
        let _storing = storing;
        let _guard = guard;
        let stored = disk
            .run_counting(LOOKUP_WAIT, no_count, move || {
                let _permit = permit;
                app.store(item)
            })
            .await;
        if let Some(Err(Skip::Disk(e))) = stored {
            tracing::debug!("[cache] a copy was not written: {e}");
        }
    });
}

fn no_count() {}

/// An answer that came in pieces is not kept, and its key is marked.
pub(crate) fn note_streamed(route: &Route, ask: &Ask) {
    if !ask.fillable {
        return;
    }
    if let Some((_, app)) = route.cache_active() {
        app.count(Count::SkippedStreamed);
        app.fills()
            .mark(ask.primary_id, fills::MARK_DEFAULT_S, store::now());
    }
}

/// The answer to a visitor who may not have a copy made of it is counted as private.
pub(crate) fn note_not_kept(route: &Route, ask: &Ask) {
    if ask.signed_in_get
        && let Some((_, app)) = route.cache_active()
    {
        app.count(Count::SkippedPrivate);
    }
}

/// What a request needs to ask the application again for a key: the connection, the route and the
/// request as the cache step saw them.
pub(crate) struct Ctx<'a> {
    pub shared: &'a Arc<Shared>,
    pub route: &'a Arc<Route>,
    pub req: &'a InboundRequest,
    pub peer: &'a IpAddress,
    pub remote: &'a str,
}

/// A copy the index named, read. The share of the budget of bytes in flight that a read from disk
/// took is held with it, so a crowd of requests for a big copy cannot hold more of them in memory
/// than the budget allows.
struct Copy {
    id: FileId,
    loaded: Arc<Loaded>,
    from_memory: bool,
    hits: u32,
    permit: Option<OwnedSemaphorePermit>,
}

/// The copy for the request, fresh or not, read from memory or disk; `None` for no copy, a file
/// that fails its check, and a disk that gives no slot or no answer.
async fn load(cx: &Ctx<'_>, ask: &Ask, now: u64) -> Option<Copy> {
    let (_, app) = cx.route.cache_active()?;
    let found = {
        let (found, _) = app.index().find(
            &ask.primary_id,
            &ask.primary,
            |names| variant(names, ask.bucket, |n| request_header_values(cx.req, n)),
            now,
        )?;
        found
    };
    let (id, hits, size) = (found.id, found.hits, found.size);
    let (loaded, from_memory, permit) = match found.mem.clone() {
        Some(copy) => (copy, true, None),
        None => {
            let permit = app
                .budget()
                .clone()
                .try_acquire_many_owned(u32::try_from(size).ok()?)
                .ok()?;
            let reader = app.clone();
            // Made here, not on a disk thread: see `static_files::LOOKUP_READ_MAX`.
            let body = Vec::with_capacity(usize::try_from(size).ok()?);
            let (read, permit) = cx
                .shared
                .disk
                .run_counting(LOOKUP_WAIT, no_count, move || {
                    (reader.read(&found, body), permit)
                })
                .await?;
            (Arc::new(read.ok()?), false, Some(permit))
        }
    };
    Some(Copy {
        id,
        loaded,
        from_memory,
        hits,
        permit,
    })
}

/// How far past its life a copy may be used. A copy whose answer says `must-revalidate`,
/// `proxy-revalidate` or `s-maxage` is never used stale unless the answer names its own
/// `stale-while-revalidate` or `stale-if-error`, and then only for what it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Windows {
    /// Seconds past its life the copy is sent at once while a fresh one is fetched.
    revalidate: u64,
    /// Seconds past its life the copy is sent when the application fails.
    error: u64,
}

impl Windows {
    /// `setting_s` is `stale_if_error_s` of the settings, for an answer that names no window.
    fn of(copy: &Loaded, setting_s: u32) -> Windows {
        let cc = CacheControl::parse(
            copy.head
                .lines
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(b"Cache-Control"))
                .map(|(_, v)| v.as_slice()),
        );
        let never = cc.must_revalidate || cc.proxy_revalidate || cc.s_maxage.is_some();
        let own = cc.stale_while_revalidate.is_some() || cc.stale_if_error.is_some();
        if never && !own {
            return Windows {
                revalidate: 0,
                error: 0,
            };
        }
        Windows {
            revalidate: cc.stale_while_revalidate.unwrap_or(0),
            error: cc
                .stale_if_error
                .unwrap_or(if never { 0 } else { u64::from(setting_s) }),
        }
    }
}

/// A copy that is past its life: kept for the application to confirm it, and for the day the
/// application fails.
pub(crate) struct Old {
    id: FileId,
    copy: Arc<Loaded>,
    windows: Windows,
    /// What to ask the application with; only a request that may fill asks.
    validator: Option<Validator>,
    _permit: Option<OwnedSemaphorePermit>,
}

/// What a request carries past the cache step to the application.
#[derive(Default)]
pub(crate) struct Pending {
    guard: Option<FillGuard>,
    old: Option<Old>,
}

impl Pending {
    /// The fill lock, to be handed to [`fill`].
    pub fn take_guard(&mut self) -> Option<FillGuard> {
        self.guard.take()
    }

    /// What the request asks the application to confirm, when there is a copy to confirm.
    pub fn validator(&self) -> Option<&Validator> {
        self.old.as_ref()?.validator.as_ref()
    }
}

/// What the cache step made of a request.
pub(crate) enum Entered {
    /// The answer, from a copy, with the label it takes.
    Answer(Box<OutboundResponse>, Label),
    /// The request goes on, to the folder of files or to the application.
    Go(Pending),
}

/// A fresh copy as the answer, which a second hit of a small one also puts in memory.
fn fresh(
    cx: &Ctx<'_>,
    app: &Arc<AppCache>,
    copy: Copy,
    now: u64,
) -> (Box<OutboundResponse>, Label) {
    // The second hit of a small copy puts it in memory, so the third reads no disk.
    if !copy.from_memory && copy.hits >= 2 && copy.loaded.size <= MEMORY_COPY_MAX {
        app.index().admit_memory(&copy.id, copy.loaded.clone());
    }
    let label = if copy.from_memory {
        Label::HitMemory
    } else {
        Label::HitDisk
    };
    (Box::new(hit::answer(cx.req, copy.loaded, now)), label)
}

/// What the lookup finds: the answer, or the copy past its life.
enum Settled {
    Answer(Box<OutboundResponse>, Label),
    Old(Option<Old>),
}

/// Looks the copy up. A fresh one answers. One past its life but within the `stale-while-revalidate`
/// of its answer is sent as `STALE` and one fetch in the background makes it fresh (`first`: only
/// the first look does that). Any other is handed back to be confirmed or replaced.
async fn settle(cx: &Ctx<'_>, ask: &Ask, app: &Arc<AppCache>, first: bool) -> Settled {
    let now = store::now();
    let Some(copy) = load(cx, ask, now).await else {
        return Settled::Old(None);
    };
    if now < copy.loaded.times.fresh_until {
        let (answer, label) = fresh(cx, app, copy, now);
        return Settled::Answer(answer, label);
    }
    let windows = Windows::of(&copy.loaded, app.stale_if_error_s());
    let late = now - copy.loaded.times.fresh_until;
    let confirmable = Validator::of(&copy.loaded);
    // A copy that can neither be confirmed nor stand in for the application is of no use, to this
    // request or to any other: it was read once and goes.
    if confirmable.is_none() && late >= windows.revalidate.max(windows.error) {
        app.forget(&copy.id, copy.loaded.size, copy.loaded.times);
        return Settled::Old(None);
    }
    let validator = confirmable.filter(|_| ask.fillable);
    let old = Old {
        id: copy.id,
        validator,
        copy: copy.loaded,
        windows,
        _permit: copy.permit,
    };
    if first && late < windows.revalidate {
        let answer = hit::answer(cx.req, old.copy.clone(), now);
        if ask.fillable
            && app.can_store()
            && let Some(guard) = app.fills().try_lead(ask.primary_id, now)
        {
            refresh::spawn(cx, ask, old, guard);
        }
        return Settled::Answer(Box::new(answer), Label::Stale);
    }
    Settled::Old(Some(old))
}

/// The cache step of a request that the verdict allows: a fresh copy is the answer, and so is one
/// within its `stale-while-revalidate`. With none, the request goes on with what it needs to ask
/// the application about a copy past its life, or to send it when the application fails. It has
/// not taken its turn for the key yet: [`take_turn`] does that once the folder of files has said
/// the request is not its own.
pub(crate) async fn enter(cx: &Ctx<'_>, ask: &Ask) -> Entered {
    let Some((_, app)) = cx.route.cache_active() else {
        return Entered::Go(Pending::default());
    };
    match settle(cx, ask, app, true).await {
        Settled::Answer(answer, label) => Entered::Answer(answer, label),
        Settled::Old(old) => Entered::Go(Pending { guard: None, old }),
    }
}

/// The turn of a request for its key, before it asks the application: the one that may fill
/// fetches, the others wait up to five seconds for it and look again, so one request at a time
/// goes to the application for a key that has no copy. A copy that came in while a request waited
/// is the answer.
pub(crate) async fn take_turn(
    cx: &Ctx<'_>,
    ask: &Ask,
    pending: &mut Pending,
) -> Option<(Box<OutboundResponse>, Label)> {
    let (_, app) = cx.route.cache_active()?;
    // Only the process that writes fetches for others: one that cannot store has nothing to give
    // those who wait.
    let lead = ask.fillable && app.can_store();
    match app.fills().turn(ask.primary_id, lead, store::now()) {
        Turn::Free => {}
        // `enter` looked a moment ago and read the copy it found: no second read.
        Turn::Lead(guard) => pending.guard = Some(guard),
        Turn::Wait(rx) => {
            fills::wait(rx).await;
            match settle(cx, ask, app, false).await {
                Settled::Answer(answer, label) => return Some((answer, label)),
                Settled::Old(old) => pending.old = old.or(pending.old.take()),
            }
        }
    }
    None
}

/// The copy as the answer when the application cannot give one: it is down or timed out, or it
/// answered 500, 502, 503 or 504, and the copy is within the window its answer allows (else the
/// setting's).
pub(crate) fn on_error(cx: &Ctx<'_>, pending: &Pending) -> Option<OutboundResponse> {
    let old = pending.old.as_ref()?;
    let now = store::now();
    (now.saturating_sub(old.copy.times.fresh_until) < old.windows.error)
        .then(|| hit::answer(cx.req, old.copy.clone(), now))
}

/// Whether an answer of the application is one that a copy may stand in for.
pub(crate) fn is_failure(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504)
}

/// The application said `304` to the question the cache asked: the copy holds. Its headers take
/// the new ones and it is kept again for as long as the new answer says. Returns the copy as it
/// now is, for [`answer_of`]; `None` when the request asked no question.
pub(crate) fn revalidated(
    cx: &Ctx<'_>,
    ask: &Ask,
    pending: &mut Pending,
    answer: &OutboundResponse,
) -> Option<Arc<Loaded>> {
    let guard = pending.take_guard();
    let old = pending.old.as_ref().filter(|o| o.validator.is_some())?;
    let (settings, app) = cx.route.cache_active()?;
    let now = store::now();
    // A cookie of the `304` is in `merged`, which `decide` then refuses: no copy is kept, and this
    // visitor still gets the cookie.
    let (head, merged) = refresh::merged(&old.copy, answer);
    let prepared = decide(settings, ask, cx.req, &merged, now);
    let times = prepared.as_ref().map_or(
        Times {
            stored_at: now,
            fresh_until: now,
            initial_age: 0,
            stale_window: 0,
        },
        |p| p.times,
    );
    let loaded = Arc::new(Loaded {
        times,
        head,
        body: old.copy.body.clone(),
        size: old.copy.size,
    });
    match prepared {
        Ok(p) if app.can_store() => keep(cx.shared, app, ask.purge_gen, p, merged.body, guard),
        Ok(_) => {}
        // The new headers say it is not to be kept: it goes, and still answers this request.
        Err(_) => {
            app.forget(&old.id, old.copy.size, old.copy.times);
        }
    }
    Some(loaded)
}

/// The visitor of a fetch asked the application with none of its own conditions. `304` when the
/// answer it got is the page the visitor holds, which is what the application would have said;
/// `None` for any other answer, one with a cookie included.
pub(crate) fn if_held(req: &InboundRequest, resp: &OutboundResponse) -> Option<OutboundResponse> {
    if resp.status != 200
        || (req.peek("If-None-Match").is_empty() && req.peek("If-Modified-Since").is_empty())
    {
        return None;
    }
    let head = StoredHead {
        status: 200,
        http10: false,
        reason: Vec::new(),
        lines: resp.stored_lines()?,
    };
    hit::not_modified_answer(req, &head)
}

/// The answer a copy gives to the request.
pub(crate) fn answer_of(cx: &Ctx<'_>, copy: Arc<Loaded>) -> OutboundResponse {
    hit::answer(cx.req, copy, store::now())
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
    let gone = app.drop_primaries(&primaries, store::now());
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
mod fuzz;
#[cfg(test)]
mod tests;
