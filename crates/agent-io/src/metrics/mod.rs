//! A small hand-written OpenMetrics text exposition: counter, gauge and histogram families,
//! label escaping and the terminating `# EOF`. The listener binds a loopback IP literal only.

mod histogram;

pub use histogram::{ANALYZE_LATENCY_BOUNDS, Histogram, micros};

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::url_parse::split_host_and_port;

/// Environment variable that enables the metrics listener.
pub const LISTEN_ADDRESS_ENV: &str = "WAFIO_METRICS_ADDR";

/// The OpenMetrics text media type.
pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// One name/value pair on a sample.
#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub name: String,
    pub value: String,
}

/// One labelled value of a vector family.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Sample {
    pub labels: Vec<Label>,
    pub value: f64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

type Collect = Box<dyn Fn() -> Vec<Sample> + Send + Sync>;

struct Family {
    name: String,
    help: String,
    kind: Kind,
    collect: Option<Collect>,
    hist: Option<Arc<Histogram>>,
}

/// Holds the families one listener exposes, written in name order.
#[derive(Default)]
pub struct Registry {
    families: Mutex<BTreeMap<String, Arc<Family>>>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry::default()
    }

    fn add(&self, f: Family) {
        if !is_valid_metric_name(&f.name) {
            panic!(
                "metrics: invalid metric name {}",
                wafio_domain::text_helpers::quote(f.name.as_bytes())
            );
        }
        if f.kind == Kind::Counter && f.name.ends_with("_total") {
            panic!("metrics: counter family names omit _total: {}", f.name);
        }
        let mut fams = self.families.lock().unwrap_or_else(|e| e.into_inner());
        if fams.contains_key(&f.name) {
            panic!("metrics: duplicate family {}", f.name);
        }
        fams.insert(f.name.clone(), Arc::new(f));
    }

    /// A monotonically increasing value; `name` omits the `_total` suffix.
    pub fn counter(&self, name: &str, help: &str, read: impl Fn() -> f64 + Send + Sync + 'static) {
        self.add(family(name, help, Kind::Counter, Some(single(read)), None));
    }

    /// A value that can go up and down.
    pub fn gauge(&self, name: &str, help: &str, read: impl Fn() -> f64 + Send + Sync + 'static) {
        self.add(family(name, help, Kind::Gauge, Some(single(read)), None));
    }

    /// A labelled counter family.
    pub fn labeled_counter(
        &self,
        name: &str,
        help: &str,
        collect: impl Fn() -> Vec<Sample> + Send + Sync + 'static,
    ) {
        self.add(family(
            name,
            help,
            Kind::Counter,
            Some(Box::new(collect)),
            None,
        ));
    }

    /// A labelled gauge family.
    pub fn labeled_gauge(
        &self,
        name: &str,
        help: &str,
        collect: impl Fn() -> Vec<Sample> + Send + Sync + 'static,
    ) {
        self.add(family(
            name,
            help,
            Kind::Gauge,
            Some(Box::new(collect)),
            None,
        ));
    }

    /// Registers `h` under `name` (name should end in `_seconds`).
    pub fn histogram(&self, name: &str, help: &str, h: Arc<Histogram>) {
        self.add(family(name, help, Kind::Histogram, None, Some(h)));
    }

    /// Every family in OpenMetrics text format.
    pub fn write(&self) -> Vec<u8> {
        let fams: Vec<Arc<Family>> = {
            let g = self.families.lock().unwrap_or_else(|e| e.into_inner());
            g.values().cloned().collect()
        };
        let mut out = String::new();
        for f in fams {
            out.push_str(&format!("# TYPE {} {}\n", f.name, f.kind.as_str()));
            if !f.help.is_empty() {
                out.push_str(&format!(
                    "# HELP {} {}\n",
                    f.name,
                    escape_help_text(&f.help)
                ));
            }
            if f.kind == Kind::Histogram {
                render_histogram(
                    &mut out,
                    &f.name,
                    f.hist.as_deref().expect("histogram family"),
                );
                continue;
            }
            let suffix = if f.kind == Kind::Counter {
                "_total"
            } else {
                ""
            };
            for s in (f.collect.as_ref().expect("collect"))() {
                out.push_str(&f.name);
                out.push_str(suffix);
                render_labels(&mut out, &s.labels);
                out.push(' ');
                out.push_str(&render_float(s.value));
                out.push('\n');
            }
        }
        out.push_str("# EOF\n");
        out.into_bytes()
    }

    /// The response to a request with
    /// `method`. Only GET and HEAD are answered.
    pub fn handle(&self, method: &str) -> Response {
        if method != "GET" && method != "HEAD" {
            return Response {
                status: 405,
                headers: vec![
                    ("Allow", "GET, HEAD".into()),
                    ("Content-Type", "text/plain; charset=utf-8".into()),
                    ("X-Content-Type-Options", "nosniff".into()),
                ],
                body: b"method not allowed\n".to_vec(),
            };
        }
        let headers = vec![
            ("Content-Type", CONTENT_TYPE.into()),
            ("Cache-Control", "no-store".into()),
        ];
        let body = if method == "HEAD" {
            Vec::new()
        } else {
            self.write()
        };
        Response {
            status: 200,
            headers,
            body,
        }
    }
}

/// An HTTP response from [`Registry::handle`] / the metrics server routes.
#[derive(Clone, Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

fn family(
    name: &str,
    help: &str,
    kind: Kind,
    collect: Option<Collect>,
    hist: Option<Arc<Histogram>>,
) -> Family {
    Family {
        name: name.into(),
        help: help.into(),
        kind,
        collect,
        hist,
    }
}

fn single(read: impl Fn() -> f64 + Send + Sync + 'static) -> Collect {
    Box::new(move || {
        vec![Sample {
            labels: Vec::new(),
            value: read(),
        }]
    })
}

fn render_histogram(out: &mut String, name: &str, h: &Histogram) {
    let (cum, count, sum) = h.snapshot();
    for (i, b) in h.bounds().iter().enumerate() {
        out.push_str(&format!(
            "{name}_bucket{{le=\"{}\"}} {}\n",
            render_float(*b),
            cum[i]
        ));
    }
    out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
    out.push_str(&format!("{name}_count {count}\n"));
    out.push_str(&format!("{name}_sum {}\n", render_float(sum)));
}

fn render_labels(out: &mut String, labels: &[Label]) {
    if labels.is_empty() {
        return;
    }
    out.push('{');
    for (i, l) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&l.name);
        out.push_str("=\"");
        out.push_str(&escape_label_value(&l.value));
        out.push('"');
    }
    out.push('}');
}

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn escape_help_text(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Shortest round-trip text of `v`, with `+Inf` / `-Inf` / `NaN`.
pub fn render_float(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        };
    }
    // Rust's `{:e}` gives the shortest round-trip digits: "d.ddde-x".
    let e = format!("{v:e}");
    let (neg, e) = match e.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, e.as_str()),
    };
    let (mant, exp) = e.split_once('e').expect("exponent");
    let exp: i32 = exp.parse().expect("exponent digits");
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let nd = digits.len() as i32;
    let dp = exp + 1; // decimal point position
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if v == 0.0 {
        out.push('0');
        return out;
    }
    // %e when exp < -4 || exp >= eprec, eprec = 6 for shortest.
    if !(-4..6).contains(&exp) {
        out.push_str(&digits[..1]);
        if nd > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        let a = exp.abs();
        if a < 10 {
            out.push('0');
        }
        out.push_str(&a.to_string());
        return out;
    }
    // %f with max(nd - dp, 0) decimals.
    if dp > 0 {
        let int_digits = dp.min(nd) as usize;
        out.push_str(&digits[..int_digits]);
        for _ in nd..dp {
            out.push('0');
        }
        if nd > dp {
            out.push('.');
            out.push_str(&digits[dp as usize..]);
        }
    } else {
        out.push_str("0.");
        for _ in dp..0 {
            out.push('0');
        }
        out.push_str(&digits);
    }
    out
}

fn is_valid_metric_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars().enumerate().all(|(i, c)| {
        c == '_' || c == ':' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
    })
}

/// Address validation failure; `not_loopback` is set when the host is not a loopback IP literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenAddressError {
    pub message: String,
    pub not_loopback: bool,
}

impl fmt::Display for ListenAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ListenAddressError {}

/// The error text for a listen address that is not a loopback IP literal.
pub const NOT_LOOPBACK_MESSAGE: &str = "must bind a loopback IP literal (127.0.0.1 or [::1])";

/// Checks that `addr` is a host:port whose host is a loopback IP literal.
pub fn check_loopback_listen_address(addr: &str) -> Result<(), ListenAddressError> {
    let quoted = wafio_domain::text_helpers::quote(addr.as_bytes());
    let host = match split_host_and_port(addr.as_bytes()) {
        Ok((h, _)) => h,
        Err(e) => {
            return Err(ListenAddressError {
                message: format!("address {quoted}: {e}"),
                not_loopback: false,
            });
        }
    };
    // No zone; IPv4-mapped IPv6 counts as its IPv4.
    let loopback = match wafio_domain::ip_address::parse_ip_address(&host) {
        Ok(a) => a.zone().is_empty() && a.without_ipv4_mapping().is_loopback(),
        Err(_) => false,
    };
    if !loopback {
        return Err(ListenAddressError {
            message: format!("address {quoted}: {NOT_LOOPBACK_MESSAGE}"),
            not_loopback: true,
        });
    }
    Ok(())
}

/// Validates `addr` and binds it.
pub async fn listen(addr: &str) -> Result<tokio::net::TcpListener, ListenAddressError> {
    if let Err(e) = check_loopback_listen_address(addr) {
        return Err(ListenAddressError {
            message: format!("{LISTEN_ADDRESS_ENV}: {}", e.message),
            not_loopback: e.not_loopback,
        });
    }
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ListenAddressError {
            message: format!("{LISTEN_ADDRESS_ENV}: listen: {e}"),
            not_loopback: false,
        })
}

/// Routing: GET /metrics only; other paths answer 404.
pub fn route(reg: &Registry, method: &str, path: &str) -> Response {
    if path != "/metrics" {
        return Response {
            status: 404,
            headers: vec![
                ("Content-Type", "text/plain; charset=utf-8".into()),
                ("X-Content-Type-Options", "nosniff".into()),
            ],
            body: b"404 page not found\n".to_vec(),
        };
    }
    reg.handle(method)
}

/// Serves `ln` in the background; dropping or calling the handle's
/// `close` stops it. One request per connection (`Connection: close`).
pub fn serve(ln: tokio::net::TcpListener, reg: Arc<Registry>) -> ServeHandle {
    let task = tokio::spawn(async move {
        loop {
            let (mut conn, _) = match ln.accept().await {
                Ok(c) => c,
                Err(e) => {
                    // net/http backs off on accept errors instead of spinning
                    tracing::warn!("metrics server: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let reg = reg.clone();
            tokio::spawn(async move {
                // ReadHeaderTimeout 5 s / WriteTimeout 30 s, as NewServer sets them.
                let head =
                    tokio::time::timeout(std::time::Duration::from_secs(5), read_head(&mut conn))
                        .await;
                let Ok(Some((method, path))) = head else {
                    return;
                };
                let resp = route(&reg, &method, &path);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    write_http_reply(&mut conn, &resp),
                )
                .await;
            });
        }
    });
    ServeHandle { task }
}

/// Stops the metrics server when closed or dropped.
pub struct ServeHandle {
    task: tokio::task::JoinHandle<()>,
}

impl ServeHandle {
    pub fn close(self) {}
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_head(conn: &mut tokio::net::TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while memchr::memmem::find(&buf, b"\r\n\r\n").is_none()
        && memchr::memmem::find(&buf, b"\n\n").is_none()
    {
        if buf.len() > 1 << 20 {
            return None;
        }
        let n = conn.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line_end = buf.iter().position(|&c| c == b'\n')?;
    let line = std::str::from_utf8(&buf[..line_end])
        .ok()?
        .trim_end_matches('\r');
    let mut parts = line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let path = target.split('?').next().unwrap_or("").to_string();
    Some((method, path))
}

async fn write_http_reply(conn: &mut tokio::net::TcpStream, r: &Response) -> std::io::Result<()> {
    let reason = match r.status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "",
    };
    let mut out = format!("HTTP/1.1 {} {reason}\r\n", r.status);
    for (k, v) in &r.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        r.body.len()
    ));
    conn.write_all(out.as_bytes()).await?;
    conn.write_all(&r.body).await?;
    conn.shutdown().await
}

#[cfg(test)]
mod tests;
