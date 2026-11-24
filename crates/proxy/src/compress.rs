//! Compression of the answers an upstream sends whole: gzip or brotli, by what the visitor's
//! `Accept-Encoding` takes. An answer that comes in pieces (no length up front) is not
//! compressed, only counted.

use std::io::Write;
use std::sync::{Arc, LazyLock};

use tokio::sync::Semaphore;

use crate::config::CompressionSpec;
use crate::decision::now_unix;
use crate::edge_stats::AppEdgeStats;
use crate::metrics::{
    COMPRESSED_BROTLI, COMPRESSED_GZIP, COMPRESSION_BYTES_IN, COMPRESSION_BYTES_OUT, SKIP_BUSY,
    SKIP_GREW, SKIP_STREAMED, SKIP_TOO_LARGE, count_compression_skipped,
};
use crate::request::InboundRequest;
use crate::response::OutboundResponse;
use crate::signed_in::{SessionNames, is_signed_in};

/// An answer over this size is not compressed.
pub(crate) const MAX_BODY: usize = 8 << 20;
/// An answer up to this size is compressed on the worker that holds it; a bigger one on a
/// blocking thread, so one big answer cannot stall the connections of its worker.
const INLINE_MAX: usize = 64 << 10;
const BROTLI_QUALITY: u32 = 4;
const BROTLI_WINDOW: u32 = 22;
const GZIP_LEVEL: u32 = 5;
/// What is read of `Accept-Encoding`: the first KiB, the first 16 tokens.
const ACCEPT_ENCODING_BYTES: usize = 1024;
const ACCEPT_ENCODING_TOKENS: usize = 16;

/// Big answers compressed at the same time: one for each core. With none free the answer goes as
/// it is.
static SLOTS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(crate::default_worker_threads()));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Gzip,
    Brotli,
}

impl Encoding {
    pub(crate) fn token(self) -> &'static [u8] {
        match self {
            Encoding::Gzip => b"gzip",
            Encoding::Brotli => b"br",
        }
    }
}

/// What the visitor takes: brotli when its weight is the highest (a tie goes to brotli) and above
/// 0, else gzip when its weight is above 0, else nothing. `*` is the weight of a coding the list
/// does not name. A weight that does not parse counts as 0.
pub(crate) fn negotiate(accept: &[u8]) -> Option<Encoding> {
    let accept = &accept[..accept.len().min(ACCEPT_ENCODING_BYTES)];
    let (mut brotli, mut gzip, mut star) = (None, None, None);
    for token in accept.split(|&c| c == b',').take(ACCEPT_ENCODING_TOKENS) {
        let mut parts = token.split(|&c| c == b';');
        let name = parts.next().unwrap_or_default().trim_ascii();
        let q = parts.find_map(weight).unwrap_or(1000);
        if name.eq_ignore_ascii_case(b"br") {
            brotli = Some(q);
        } else if name.eq_ignore_ascii_case(b"gzip") {
            gzip = Some(q);
        } else if name == b"*" {
            star = Some(q);
        }
    }
    let brotli = brotli.or(star).unwrap_or(0);
    let gzip = gzip.or(star).unwrap_or(0);
    if brotli > 0 && brotli >= gzip {
        Some(Encoding::Brotli)
    } else if gzip > 0 {
        Some(Encoding::Gzip)
    } else {
        None
    }
}

/// The weight of a `q=` parameter in thousandths (`None`: not a weight parameter). One that does
/// not parse, or whose integer part is not 0 or 1, is 0: the visitor is not asked for what it
/// did not mean.
fn weight(param: &[u8]) -> Option<u32> {
    let param = param.trim_ascii();
    let rest = match param.split_first() {
        Some((b'q' | b'Q', rest)) => rest.trim_ascii_start(),
        _ => return None,
    };
    let Some(value) = rest.strip_prefix(b"=") else {
        return Some(0);
    };
    let value = value.trim_ascii();
    let (whole, fraction) = match value.iter().position(|&c| c == b'.') {
        Some(dot) => (&value[..dot], &value[dot + 1..]),
        None => (value, &[][..]),
    };
    if fraction.len() > 3 || !fraction.iter().all(u8::is_ascii_digit) {
        return Some(0);
    }
    let thousandths = fraction
        .iter()
        .chain(b"000")
        .take(3)
        .fold(0, |n, &d| n * 10 + u32::from(d - b'0'));
    Some(match whole {
        b"0" => thousandths,
        b"1" => 1000,
        _ => 0,
    })
}

/// The media type of a `Content-Type` value: lower case, no parameters.
pub(crate) fn media_type(content_type: &[u8]) -> Vec<u8> {
    let end = content_type
        .iter()
        .position(|&c| c == b';')
        .unwrap_or(content_type.len());
    content_type[..end].trim_ascii().to_ascii_lowercase()
}

/// The types worth compressing: text, JSON, JavaScript, XML, WebAssembly, and the font formats
/// that are not compressed already. Images, audio, video, archives and PDF are not.
fn listed(media: &[u8]) -> bool {
    match media {
        b"text/event-stream" => false,
        m if m.starts_with(b"text/") => true,
        b"application/json"
        | b"application/javascript"
        | b"application/x-javascript"
        | b"application/xml"
        | b"application/wasm"
        | b"font/ttf"
        | b"font/otf"
        | b"application/vnd.ms-fontobject" => true,
        m => m.ends_with(b"+json") || m.ends_with(b"+xml"),
    }
}

/// HTML and JSON: the types that carry a visitor's own data beside text the visitor can reflect.
fn html_or_json(media: &[u8]) -> bool {
    matches!(
        media,
        b"text/html" | b"application/xhtml+xml" | b"application/json" | b"text/json"
    ) || media.ends_with(b"+json")
}

/// Whether the answer to this request can carry a body at all.
fn has_body(req: &InboundRequest, resp: &OutboundResponse) -> bool {
    req.method != b"HEAD"
        && !(100..200).contains(&resp.status)
        && !matches!(resp.status, 204 | 206 | 304)
}

/// Whether some line of the header `name` lists the token `want`.
fn lists(resp: &OutboundResponse, name: &[u8], want: &[u8]) -> bool {
    resp.values(name).any(|line| {
        line.split(|&c| c == b',')
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(want))
    })
}

/// The encoding for this answer if nothing about its size stops it: a listed type, no encoding
/// of its own, no range, no `no-transform`, not HTML or JSON for a signed-in visitor (BREACH: a
/// secret beside reflected input could be guessed from the size), and an encoding the visitor
/// takes.
fn encoding_for(
    req: &InboundRequest,
    session: &SessionNames,
    resp: &OutboundResponse,
    media: &[u8],
) -> Option<Encoding> {
    let encoded = resp.peek(b"Content-Encoding").is_some_and(|e| {
        !e.trim_ascii().is_empty() && !e.trim_ascii().eq_ignore_ascii_case(b"identity")
    });
    if encoded
        || resp.values(b"Content-Range").next().is_some()
        || lists(resp, b"Cache-Control", b"no-transform")
        || (html_or_json(media) && is_signed_in(req, session))
    {
        return None;
    }
    requested_encoding(req)
}

/// The encoding the visitor takes, from every `Accept-Encoding` line of the request.
pub(crate) fn requested_encoding(req: &InboundRequest) -> Option<Encoding> {
    let accept: Vec<u8> = req
        .lines
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"accept-encoding"))
        .map(|(_, value)| value.as_slice())
        .collect::<Vec<_>>()
        .join(&b',');
    negotiate(&accept)
}

/// `Vary: Accept-Encoding`, merged into what the answer already varies by (not into `*`).
fn add_vary(resp: &mut OutboundResponse) {
    if lists(resp, b"Vary", b"*") || lists(resp, b"Vary", b"Accept-Encoding") {
        return;
    }
    let merged = match resp.values(b"Vary").next() {
        Some(first) if !first.trim_ascii().is_empty() => [first, b", Accept-Encoding"].concat(),
        _ => b"Accept-Encoding".to_vec(),
    };
    resp.set(b"Vary", &merged);
}

fn encode(encoding: Encoding, body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len() / 3 + 64);
    match encoding {
        Encoding::Gzip => {
            let mut w = flate2::write::GzEncoder::new(out, flate2::Compression::new(GZIP_LEVEL));
            w.write_all(body).ok()?;
            w.finish().ok()
        }
        Encoding::Brotli => {
            {
                let mut w =
                    brotli::CompressorWriter::new(&mut out, 4096, BROTLI_QUALITY, BROTLI_WINDOW);
                w.write_all(body).ok()?;
            }
            Some(out)
        }
    }
}

/// Compresses `resp` when the app has compression on, the visitor takes an encoding and the
/// answer allows it, and counts what it did. An answer of a listed type at or over the smallest
/// size varies by `Accept-Encoding` whether or not it was compressed, which a CDN in front
/// needs. A request that asks for an upgrade is not touched.
pub(crate) async fn apply(
    stats: &AppEdgeStats,
    spec: &CompressionSpec,
    req: &InboundRequest,
    session: &SessionNames,
    resp: &mut OutboundResponse,
) {
    apply_with(&SLOTS, stats, spec, req, session, resp).await;
}

async fn apply_with(
    slots: &Semaphore,
    stats: &AppEdgeStats,
    spec: &CompressionSpec,
    req: &InboundRequest,
    session: &SessionNames,
    resp: &mut OutboundResponse,
) {
    let len = resp.body.len();
    let media = media_type(resp.content_type());
    if req.has_upgrade()
        || !has_body(req, resp)
        || !listed(&media)
        || len == 0
        || len < spec.min_bytes
    {
        return;
    }
    if len > MAX_BODY {
        if encoding_for(req, session, resp, &media).is_some() {
            count_compression_skipped(SKIP_TOO_LARGE);
        }
        return;
    }
    add_vary(resp);
    let Some(encoding) = encoding_for(req, session, resp, &media) else {
        return;
    };
    let packed = if len <= INLINE_MAX {
        encode(encoding, &resp.body)
    } else {
        let Ok(permit) = slots.try_acquire() else {
            count_compression_skipped(SKIP_BUSY);
            return;
        };
        let shared = Arc::new(std::mem::take(&mut resp.body));
        let job = shared.clone();
        let packed = tokio::task::spawn_blocking(move || encode(encoding, &job))
            .await
            .unwrap_or_else(|_| {
                crate::metrics::count_agent_panic();
                None
            });
        drop(permit);
        // The job is done, or gone with its panic: this is the last holder.
        resp.body = Arc::try_unwrap(shared).unwrap_or_else(|held| (*held).clone());
        packed
    };
    let Some(packed) = packed.filter(|p| p.len() < len) else {
        count_compression_skipped(SKIP_GREW);
        return;
    };
    let counter = match encoding {
        Encoding::Gzip => &COMPRESSED_GZIP,
        Encoding::Brotli => &COMPRESSED_BROTLI,
    };
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    COMPRESSION_BYTES_IN.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);
    COMPRESSION_BYTES_OUT.fetch_add(packed.len() as u64, std::sync::atomic::Ordering::Relaxed);
    stats.compressed(now_seconds(), (len - packed.len()) as u64);
    // A strong validator names these exact bytes, and the compressed form is other bytes.
    let weak = resp
        .peek(b"Etag")
        .filter(|tag| !tag.starts_with(b"W/"))
        .map(|tag| [&b"W/"[..], tag].concat());
    if let Some(weak) = weak {
        resp.set(b"Etag", &weak);
    }
    resp.del(b"Accept-Ranges");
    resp.set(b"Content-Encoding", encoding.token());
    resp.body = packed;
}

/// Counts an answer that came in pieces and would have been compressed had it come whole.
pub(crate) fn note_streamed(
    stats: &AppEdgeStats,
    req: &InboundRequest,
    session: &SessionNames,
    head: &OutboundResponse,
) {
    let media = media_type(head.content_type());
    if !req.has_upgrade()
        && has_body(req, head)
        && listed(&media)
        && encoding_for(req, session, head, &media).is_some()
    {
        stats.compression_streamed(now_seconds());
        count_compression_skipped(SKIP_STREAMED);
    }
}

fn now_seconds() -> u64 {
    u64::try_from(now_unix()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn the_visitor_gets_brotli_when_its_weight_is_highest_else_gzip_else_nothing() {
        use Encoding::{Brotli, Gzip};
        for (accept, want) in [
            ("", None),
            ("identity", None),
            ("deflate, compress", None),
            ("gzip", Some(Gzip)),
            ("br", Some(Brotli)),
            ("gzip, br", Some(Brotli)),
            ("br, gzip", Some(Brotli)),
            ("gzip, deflate, br", Some(Brotli)),
            ("GZip", Some(Gzip)),
            (" br ; q=0.9 , gzip;q=1 ", Some(Gzip)),
            ("br;q=0.9, gzip;q=0.9", Some(Brotli)),
            ("br;q=0.8, gzip;q=0.9", Some(Gzip)),
            ("br;q=0, gzip", Some(Gzip)),
            ("br, gzip;q=0", Some(Brotli)),
            ("br;q=0, gzip;q=0", None),
            ("gzip;q=0.001", Some(Gzip)),
            ("gzip;q=0.0001", None),
            ("*", Some(Brotli)),
            ("*;q=0.5, gzip;q=0.6", Some(Gzip)),
            ("*;q=0.6, gzip;q=0.5", Some(Brotli)),
            ("*;q=0, br", Some(Brotli)),
            ("*;q=0, gzip", Some(Gzip)),
            ("*;q=0", None),
            ("gzip, *;q=0", Some(Gzip)),
            // A weight that does not parse, or is not 0 or 1 before the dot, is 0.
            ("gzip;q=abc", None),
            ("gzip;q=", None),
            ("gzip;q", None),
            ("gzip;q=2", None),
            ("gzip;q=1.5, br;q=x", Some(Gzip)),
            ("gzip;q=0.5555", None),
            ("gzip;q=-1", None),
            ("gzip;level=9;q=0", None),
            ("gzip; Q=0.5", Some(Gzip)),
            ("gzip;q = 0", None),
        ] {
            assert_eq!(negotiate(accept.as_bytes()), want, "{accept:?}");
        }
    }

    #[test]
    fn only_the_first_kib_and_sixteen_tokens_of_the_header_are_read() {
        let padding = "x-".repeat(8);
        let mut tokens: Vec<String> = (0..15).map(|i| format!("{padding}{i}")).collect();
        tokens.push("deflate".into());
        let sixteen = tokens.join(", ");
        assert_eq!(negotiate(format!("{sixteen}, gzip").as_bytes()), None);
        assert_eq!(
            negotiate(format!("{}, gzip", tokens[..15].join(", ")).as_bytes()),
            Some(Encoding::Gzip)
        );
        let blanks = " ".repeat(ACCEPT_ENCODING_BYTES);
        assert_eq!(negotiate(format!("{blanks}gzip").as_bytes()), None);
        assert_eq!(
            negotiate(format!("{}gzip", " ".repeat(ACCEPT_ENCODING_BYTES - 4)).as_bytes()),
            Some(Encoding::Gzip)
        );
        // A token cut by the limit is read as far as it goes: `gzip;q=0.` is a weight of 0.
        let cut = format!("{}gzip;q=0.5", " ".repeat(ACCEPT_ENCODING_BYTES - 9));
        assert_eq!(negotiate(cut.as_bytes()), None);
        let name_cut = format!("{}gzip", " ".repeat(ACCEPT_ENCODING_BYTES - 2));
        assert_eq!(negotiate(name_cut.as_bytes()), None);
    }

    #[test]
    fn weights_are_thousandths() {
        for (param, want) in [
            ("q=1", Some(1000)),
            ("q=1.0", Some(1000)),
            ("q=1.000", Some(1000)),
            ("q=0", Some(0)),
            ("q=0.", Some(0)),
            ("q=0.5", Some(500)),
            ("q=0.05", Some(50)),
            ("q=0.123", Some(123)),
            ("q=0.1234", Some(0)),
            ("Q=0.7", Some(700)),
            (" q=0.7 ", Some(700)),
            ("q =0.7", Some(700)),
            ("q= 0.7", Some(700)),
            ("q=.5", Some(0)),
            ("q=2", Some(0)),
            ("q=1.5", Some(1000)),
            ("q=1e0", Some(0)),
            ("q=0x1", Some(0)),
            ("q", Some(0)),
            ("q:0.5", Some(0)),
            ("level=5", None),
            ("", None),
        ] {
            assert_eq!(weight(param.as_bytes()), want, "{param:?}");
        }
    }

    #[test]
    fn a_media_type_is_lower_case_without_its_parameters() {
        assert_eq!(media_type(b"Text/HTML; charset=utf-8"), b"text/html");
        assert_eq!(media_type(b"  application/json  "), b"application/json");
        assert_eq!(media_type(b"text/plain;charset=x;a=b"), b"text/plain");
        assert_eq!(media_type(b""), b"");
    }

    #[test]
    fn the_listed_types_and_the_ones_that_carry_a_visitors_data() {
        for media in [
            "text/html",
            "text/plain",
            "text/css",
            "text/csv",
            "text/xml",
            "text/javascript",
            "application/json",
            "application/javascript",
            "application/x-javascript",
            "application/xml",
            "application/wasm",
            "application/ld+json",
            "application/problem+json",
            "application/atom+xml",
            "application/xhtml+xml",
            "image/svg+xml",
            "font/ttf",
            "font/otf",
            "application/vnd.ms-fontobject",
        ] {
            assert!(listed(media.as_bytes()), "{media}");
        }
        for media in [
            "",
            "text",
            "text/event-stream",
            "image/png",
            "image/jpeg",
            "image/webp",
            "image/gif",
            "audio/mpeg",
            "video/mp4",
            "application/pdf",
            "application/zip",
            "application/gzip",
            "application/octet-stream",
            "application/x-protobuf",
            "font/woff",
            "font/woff2",
            "multipart/form-data",
        ] {
            assert!(!listed(media.as_bytes()), "{media}");
        }
        for media in [
            "text/html",
            "application/xhtml+xml",
            "application/json",
            "text/json",
            "application/hal+json",
        ] {
            assert!(html_or_json(media.as_bytes()), "{media}");
        }
        for media in [
            "text/css",
            "text/plain",
            "application/javascript",
            "image/svg+xml",
            "application/xml",
        ] {
            assert!(!html_or_json(media.as_bytes()), "{media}");
        }
    }

    fn decode(encoding: Encoding, packed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match encoding {
            Encoding::Gzip => flate2::read::GzDecoder::new(packed).read_to_end(&mut out),
            Encoding::Brotli => brotli::Decompressor::new(packed, 4096).read_to_end(&mut out),
        }
        .unwrap();
        out
    }

    #[test]
    fn what_is_encoded_decodes_to_what_went_in() {
        let mut mixed = Vec::new();
        for i in 0..4000u32 {
            mixed.extend_from_slice(
                format!("line {i} of some <b>text</b> \u{e9}\u{20ac}\n").as_bytes(),
            );
        }
        for body in [
            &b"a"[..],
            b"hello hello hello hello",
            &mixed,
            &vec![0u8; 100_000],
        ] {
            for encoding in [Encoding::Gzip, Encoding::Brotli] {
                let packed = encode(encoding, body).unwrap();
                assert_eq!(
                    decode(encoding, &packed),
                    body,
                    "{encoding:?} {}",
                    body.len()
                );
            }
        }
        let gzip = encode(Encoding::Gzip, b"x").unwrap();
        assert_eq!(&gzip[..2], &[0x1f, 0x8b], "a gzip member, not raw deflate");
    }

    fn request(head: &str) -> InboundRequest {
        InboundRequest::from_head(
            format!("GET / HTTP/1.1\r\nHost: a.test\r\nAccept-Encoding: gzip\r\n{head}\r\n")
                .as_bytes(),
        )
    }

    fn html(len: usize) -> OutboundResponse {
        OutboundResponse::with(200, "text/html", vec![b'a'; len])
    }

    /// `resp` after `apply` for `req`, with a pool of `slots` for the big ones.
    async fn run(
        spec: CompressionSpec,
        req: &InboundRequest,
        mut resp: OutboundResponse,
        slots: usize,
    ) -> (OutboundResponse, AppEdgeStats) {
        let stats = AppEdgeStats::default();
        apply_with(
            &Semaphore::new(slots),
            &stats,
            &spec,
            req,
            &SessionNames::default(),
            &mut resp,
        )
        .await;
        (resp, stats)
    }

    fn now() -> u64 {
        now_seconds()
    }

    const SPEC: CompressionSpec = CompressionSpec { min_bytes: 1024 };

    #[tokio::test]
    async fn a_compressed_answer_is_changed_in_every_place_that_names_its_bytes() {
        let mut resp = html(5000);
        resp.add(b"ETag", b"\"abc\"");
        resp.add(b"Accept-Ranges", b"bytes");
        resp.add(b"Vary", b"Cookie");
        let (resp, stats) = run(SPEC, &request(""), resp, 1).await;
        assert_eq!(resp.peek(b"Content-Encoding"), Some(&b"gzip"[..]));
        assert_eq!(resp.peek(b"Etag"), Some(&b"W/\"abc\""[..]));
        assert_eq!(resp.peek(b"Accept-Ranges"), None);
        assert_eq!(resp.peek(b"Vary"), Some(&b"Cookie, Accept-Encoding"[..]));
        assert!(resp.body.len() < 100);
        assert_eq!(decode(Encoding::Gzip, &resp.body), vec![b'a'; 5000]);
        let wire = String::from_utf8_lossy(&resp.wire(false, false, false, 0)).into_owned();
        assert!(
            wire.contains(&format!("Content-Length: {}\r\n", resp.body.len())),
            "{wire}"
        );
        let c = stats.compression_counters(now());
        assert_eq!(
            (c.responses, c.skipped_streamed, c.bytes_saved),
            (1, 0, 5000 - resp.body.len() as u64)
        );
    }

    #[tokio::test]
    async fn a_weak_validator_stays_as_it_is_and_a_strong_one_in_any_case_becomes_weak() {
        for (tag, want) in [
            (&b"W/\"abc\""[..], &b"W/\"abc\""[..]),
            (b"\"abc\"", b"W/\"abc\""),
            (b"abc", b"W/abc"),
        ] {
            let mut resp = html(5000);
            resp.add(b"etag", tag);
            let (resp, _) = run(SPEC, &request(""), resp, 1).await;
            assert_eq!(resp.peek(b"Etag"), Some(want));
        }
    }

    #[tokio::test]
    async fn an_answer_that_grew_or_did_not_shrink_is_kept_and_counted() {
        // Random-looking bytes do not compress.
        let mut noise = Vec::new();
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..4096 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            noise.push((x >> 24) as u8);
        }
        let before = crate::metrics::COMPRESSION_SKIPPED[SKIP_GREW]
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut resp = OutboundResponse::with(200, "text/plain", noise.clone());
        resp.add(b"ETag", b"\"n\"");
        let req = request("").clone();
        let (resp, stats) = run(SPEC, &req, resp, 1).await;
        // Gzip adds a header to bytes that do not shrink, so it is not kept.
        assert_eq!(resp.peek(b"Content-Encoding"), None);
        assert_eq!(resp.body, noise);
        assert_eq!(
            resp.peek(b"Etag"),
            Some(&b"\"n\""[..]),
            "its validator is untouched"
        );
        assert_eq!(stats.compression_counters(now()), Default::default());
        assert!(
            crate::metrics::COMPRESSION_SKIPPED[SKIP_GREW]
                .load(std::sync::atomic::Ordering::Relaxed)
                > before
        );
    }

    #[tokio::test]
    async fn nothing_is_compressed_for_a_status_or_method_that_has_no_body_to_send() {
        let head = InboundRequest::from_head(
            b"HEAD / HTTP/1.1\r\nHost: a.test\r\nAccept-Encoding: gzip\r\n\r\n",
        );
        let (resp, _) = run(SPEC, &head, html(5000), 1).await;
        assert_eq!(resp.peek(b"Content-Encoding"), None);
        assert_eq!(resp.peek(b"Vary"), None);
        for status in [100, 101, 103, 204, 206, 304] {
            let mut resp = html(5000);
            resp.status = status;
            let (resp, _) = run(SPEC, &request(""), resp, 1).await;
            assert_eq!(resp.peek(b"Content-Encoding"), None, "{status}");
            assert_eq!(resp.peek(b"Vary"), None, "{status}");
        }
        for status in [200, 201, 400, 404, 500, 503] {
            let mut resp = html(5000);
            resp.status = status;
            let (resp, _) = run(SPEC, &request(""), resp, 1).await;
            assert_eq!(
                resp.peek(b"Content-Encoding"),
                Some(&b"gzip"[..]),
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn a_request_that_asks_for_an_upgrade_is_not_touched() {
        let upgrade = request("Connection: Upgrade\r\nUpgrade: websocket\r\n");
        let (resp, _) = run(SPEC, &upgrade, html(5000), 1).await;
        assert_eq!(
            (resp.peek(b"Content-Encoding"), resp.peek(b"Vary")),
            (None, None)
        );
    }

    #[tokio::test]
    async fn the_header_values_that_forbid_it_are_each_checked() {
        let cases: [(&str, &[(&str, &str)]); 6] = [
            ("range", &[("Content-Range", "bytes 0-1/9")]),
            (
                "no-transform",
                &[("Cache-Control", "max-age=5, no-transform")],
            ),
            (
                "no-transform in a later line",
                &[
                    ("Cache-Control", "max-age=5"),
                    ("Cache-Control", "No-Transform"),
                ],
            ),
            ("an encoding", &[("Content-Encoding", "zstd")]),
            ("an encoding in any case", &[("Content-Encoding", "GZIP")]),
            ("a list of encodings", &[("Content-Encoding", "gzip, br")]),
        ];
        for (what, headers) in cases {
            let mut resp = html(5000);
            for (k, v) in headers {
                resp.add(k.as_bytes(), v.as_bytes());
            }
            let encoding = resp.peek(b"Content-Encoding").map(<[u8]>::to_vec);
            let (resp, _) = run(SPEC, &request(""), resp, 1).await;
            assert_eq!(
                resp.peek(b"Content-Encoding").map(<[u8]>::to_vec),
                encoding,
                "{what}"
            );
            assert_eq!(resp.body.len(), 5000, "{what}");
        }
        let mut resp = html(5000);
        resp.add(b"Cache-Control", b"max-age=5, no-transformation");
        let (resp, _) = run(SPEC, &request(""), resp, 1).await;
        assert!(
            resp.peek(b"Content-Encoding").is_some(),
            "only the whole token counts"
        );
    }

    /// The names an app gives count whether or not it has a cache: BREACH does not wait for the
    /// cache to be on.
    #[tokio::test]
    async fn the_session_cookie_names_of_the_app_count_for_a_page_that_is_not_compressed() {
        let names = SessionNames::new(["MyAuth"]);
        let compressed = |req: InboundRequest, names: SessionNames| async move {
            let mut resp = html(5000);
            apply_with(
                &Semaphore::new(1),
                &AppEdgeStats::default(),
                &SPEC,
                &req,
                &names,
                &mut resp,
            )
            .await;
            resp.peek(b"Content-Encoding").is_some()
        };
        let own = request("Cookie: myauth=token\r\n");
        assert!(
            compressed(own.clone(), SessionNames::default()).await,
            "a name the agent does not know and the app did not give is not seen"
        );
        assert!(!compressed(own, names.clone()).await);
        assert!(compressed(request("Cookie: myauth2=token\r\n"), names.clone()).await);
        assert!(!compressed(request("Cookie: PHPSESSID=1\r\n"), names.clone()).await);
        // A streamed answer is counted under the same test.
        let stats = AppEdgeStats::default();
        let head = html(0);
        note_streamed(&stats, &request("Cookie: myauth=token\r\n"), &names, &head);
        assert_eq!(stats.compression_counters(now()).skipped_streamed, 0);
        note_streamed(
            &stats,
            &request("Cookie: myauth=token\r\n"),
            &SessionNames::default(),
            &head,
        );
        assert_eq!(stats.compression_counters(now()).skipped_streamed, 1);
    }

    #[tokio::test]
    async fn a_signed_in_request_gets_neither_html_nor_json_compressed_and_the_rest_is() {
        let signed = request("Cookie: PHPSESSID=1\r\n");
        let anon = request("Cookie: theme=dark\r\n");
        for (media, plain_when_signed_in) in [
            ("text/html", true),
            ("text/html; charset=utf-8", true),
            ("TEXT/HTML", true),
            ("application/json", true),
            ("application/vnd.api+json", true),
            ("text/css", false),
            ("application/javascript", false),
            ("text/plain", false),
            ("application/xml", false),
            ("image/svg+xml", false),
        ] {
            let resp = OutboundResponse::with(200, media, vec![b'a'; 5000]);
            let (s, _) = run(SPEC, &signed, resp.clone(), 1).await;
            assert_eq!(
                s.peek(b"Content-Encoding").is_none(),
                plain_when_signed_in,
                "{media}"
            );
            assert_eq!(s.peek(b"Vary"), Some(&b"Accept-Encoding"[..]), "{media}");
            let (a, _) = run(SPEC, &anon, resp, 1).await;
            assert!(
                a.peek(b"Content-Encoding").is_some(),
                "{media}: not signed in"
            );
        }
    }

    #[tokio::test]
    async fn a_big_answer_goes_through_a_blocking_thread_and_waits_for_no_slot_it_cannot_have() {
        let body: Vec<u8> = (0..300_000u32)
            .flat_map(|i| (i % 251).to_le_bytes())
            .collect();
        let resp = OutboundResponse::with(200, "text/plain", body.clone());
        let (done, stats) = run(SPEC, &request(""), resp.clone(), 1).await;
        assert_eq!(done.peek(b"Content-Encoding"), Some(&b"gzip"[..]));
        assert_eq!(decode(Encoding::Gzip, &done.body), body);
        assert_eq!(stats.compression_counters(now()).responses, 1);

        // No slot free: the answer goes as it is, and the busy count moves.
        let before = crate::metrics::COMPRESSION_SKIPPED[SKIP_BUSY]
            .load(std::sync::atomic::Ordering::Relaxed);
        let (busy, stats) = run(SPEC, &request(""), resp.clone(), 0).await;
        assert_eq!(busy.peek(b"Content-Encoding"), None);
        assert_eq!(busy.body, body, "the body is put back");
        assert_eq!(busy.peek(b"Vary"), Some(&b"Accept-Encoding"[..]));
        assert_eq!(stats.compression_counters(now()), Default::default());
        assert!(
            crate::metrics::COMPRESSION_SKIPPED[SKIP_BUSY]
                .load(std::sync::atomic::Ordering::Relaxed)
                > before
        );

        // An answer up to the inline size needs no slot.
        let (small, _) = run(SPEC, &request(""), html(INLINE_MAX), 0).await;
        assert!(small.peek(b"Content-Encoding").is_some());
        let (over, _) = run(SPEC, &request(""), html(INLINE_MAX + 1), 0).await;
        assert!(over.peek(b"Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn the_slot_is_given_back_when_the_answer_is_done() {
        let slots = Semaphore::new(1);
        let spec = SPEC;
        for _ in 0..3 {
            let mut resp = html(INLINE_MAX + 10);
            apply_with(
                &slots,
                &AppEdgeStats::default(),
                &spec,
                &request(""),
                &SessionNames::default(),
                &mut resp,
            )
            .await;
            assert!(resp.peek(b"Content-Encoding").is_some());
            assert_eq!(slots.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn an_answer_over_the_largest_size_is_left_alone_and_counted() {
        let before = crate::metrics::COMPRESSION_SKIPPED[SKIP_TOO_LARGE]
            .load(std::sync::atomic::Ordering::Relaxed);
        let (resp, _) = run(SPEC, &request(""), html(MAX_BODY + 1), 1).await;
        assert_eq!(
            (resp.peek(b"Content-Encoding"), resp.peek(b"Vary")),
            (None, None)
        );
        let after = crate::metrics::COMPRESSION_SKIPPED[SKIP_TOO_LARGE]
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(after > before);
        // The visitor takes no encoding, so there is nothing to count.
        let plain = InboundRequest::from_head(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n");
        let (resp, _) = run(SPEC, &plain, html(MAX_BODY + 1), 1).await;
        assert!(resp.peek(b"Content-Encoding").is_none());
        // At the limit it is compressed.
        let (resp, _) = run(SPEC, &request(""), html(MAX_BODY), 1).await;
        assert!(resp.peek(b"Content-Encoding").is_some());
    }

    #[tokio::test]
    async fn vary_follows_the_answer_whether_or_not_the_visitor_takes_an_encoding() {
        let plain = InboundRequest::from_head(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n");
        let (resp, _) = run(SPEC, &plain, html(5000), 1).await;
        assert_eq!(resp.peek(b"Content-Encoding"), None);
        assert_eq!(resp.peek(b"Vary"), Some(&b"Accept-Encoding"[..]));
        for (before, want) in [
            (&b""[..], &b"Accept-Encoding"[..]),
            (b"Origin", b"Origin, Accept-Encoding"),
            (b"Origin, Accept-Encoding", b"Origin, Accept-Encoding"),
            (b"accept-encoding", b"accept-encoding"),
            (b"*", b"*"),
            (b"Origin, *", b"Origin, *"),
        ] {
            let mut resp = html(5000);
            if !before.is_empty() {
                resp.add(b"Vary", before);
            }
            let (resp, _) = run(SPEC, &plain, resp, 1).await;
            assert_eq!(resp.peek(b"Vary"), Some(want), "{before:?}");
        }
        // A second Vary line that has it is enough.
        let mut resp = html(5000);
        resp.add(b"Vary", b"Origin");
        resp.add(b"Vary", b"Accept-Encoding");
        let (resp, _) = run(SPEC, &plain, resp, 1).await;
        assert_eq!(resp.peek(b"Vary"), Some(&b"Origin"[..]));
        assert_eq!(resp.values(b"Vary").count(), 2);
    }

    #[test]
    fn a_streamed_answer_is_counted_only_when_it_would_have_been_compressed() {
        let stats = AppEdgeStats::default();
        let count = |req: &InboundRequest, head: OutboundResponse| {
            note_streamed(&stats, req, &SessionNames::default(), &head);
            stats.compression_counters(now()).skipped_streamed
        };
        let taking = request("");
        let not_taking = InboundRequest::from_head(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n");
        assert_eq!(
            count(&taking, OutboundResponse::with(200, "text/html", "")),
            1
        );
        assert_eq!(
            count(&taking, OutboundResponse::with(200, "text/css", "")),
            2
        );
        assert_eq!(
            count(&not_taking, OutboundResponse::with(200, "text/html", "")),
            2
        );
        assert_eq!(
            count(&taking, OutboundResponse::with(200, "image/png", "")),
            2
        );
        assert_eq!(
            count(
                &taking,
                OutboundResponse::with(200, "text/event-stream", "")
            ),
            2
        );
        let mut encoded = OutboundResponse::with(200, "text/html", "");
        encoded.add(b"Content-Encoding", b"gzip");
        assert_eq!(count(&taking, encoded), 2);
        assert_eq!(
            count(
                &request("Cookie: sessionid=1\r\n"),
                OutboundResponse::with(200, "text/html", "")
            ),
            2
        );
        assert_eq!(
            count(
                &request("Cookie: sessionid=1\r\n"),
                OutboundResponse::with(200, "text/css", "")
            ),
            3
        );
        let upgrade = request("Upgrade: websocket\r\n");
        assert_eq!(
            count(&upgrade, OutboundResponse::with(200, "text/html", "")),
            3
        );
    }
}
