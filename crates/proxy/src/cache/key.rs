//! The key of a stored answer. The primary key is what a request is: scheme, host, the exact
//! request target the upstream gets, the encoding bucket and the few headers of a trusted proxy
//! that change what the upstream says. The variant adds the values of the headers the stored answer
//! varies by. The SHA-256 of both names the file; the file keeps the whole key, so a name that
//! matches another key's is not taken for it.

use sha2::{Digest, Sha256};

use crate::request::InboundRequest;

pub(crate) type FileId = [u8; 32];
pub(crate) type PrimaryId = [u8; 32];

/// The headers of a trusted proxy that are keyed together may hold this many bytes, names and
/// values, or the request is not cached.
pub(crate) const KEYED_INPUT_MAX: usize = 256;

/// The encoding a visitor takes, as far as the cache tells copies apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bucket {
    Identity,
    Gzip,
    Brotli,
}

impl Bucket {
    /// The bucket of a visitor. `brotli` says the agent can make brotli itself: with it off, a
    /// visitor who takes gzip is in the gzip bucket whatever else its list holds, which an
    /// application that has no brotli can answer in.
    pub fn of(req: &InboundRequest, brotli: bool) -> Bucket {
        match crate::compress::requested_encoding(req, brotli) {
            Some(crate::compress::Encoding::Brotli) => Bucket::Brotli,
            Some(crate::compress::Encoding::Gzip) => Bucket::Gzip,
            None => Bucket::Identity,
        }
    }

    fn byte(self) -> u8 {
        match self {
            Bucket::Identity => 0,
            Bucket::Gzip => 1,
            Bucket::Brotli => 2,
        }
    }

    /// The `Accept-Encoding` value that stands for the bucket in a variant.
    pub fn token(self) -> &'static [u8] {
        match self {
            Bucket::Identity => b"identity",
            Bucket::Gzip => b"gzip",
            Bucket::Brotli => b"br",
        }
    }

    pub const ALL: [Bucket; 3] = [Bucket::Identity, Bucket::Gzip, Bucket::Brotli];
}

/// `name` with `_` as `-` and lower case, the way a name of an unkeyed input is compared (a CGI
/// parameter makes both spellings one).
pub(crate) fn normalized(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|&c| {
            if c == b'_' {
                b'-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Whether `name` is `want` once it is read as a CGI parameter: lower case, `_` as `-`. `want` is
/// written that way. Nothing is allocated, as this runs on every header of every request that the
/// cache does not answer.
pub(crate) fn same_name(name: &[u8], want: &[u8]) -> bool {
    name.len() == want.len()
        && name.iter().zip(want).all(|(&c, &w)| {
            (if c == b'_' {
                b'-'
            } else {
                c.to_ascii_lowercase()
            }) == w
        })
}

/// What follows `prefix` in `name`, when `name` starts with it (compared as [`same_name`] does).
fn after_name_prefix<'a>(name: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let (head, rest) = name.split_at_checked(prefix.len())?;
    same_name(head, prefix).then_some(rest)
}

/// Whether a request header is one the application may answer differently for and the key does not
/// hold: the forwarding headers other than the three the agent writes itself, and the headers a
/// front-end uses to say what it was asked for. An untrusted peer's are not sent to the
/// application; a trusted proxy's are part of the key.
pub(crate) fn unkeyed_input(name: &[u8]) -> bool {
    if let Some(rest) = after_name_prefix(name, b"x-forwarded-") {
        return ![&b"for"[..], b"host", b"proto"]
            .iter()
            .any(|own| same_name(rest, own));
    }
    after_name_prefix(name, b"x-original-").is_some()
        || [
            &b"x-host"[..],
            b"x-rewrite-url",
            b"forwarded",
            b"front-end-https",
            b"x-url-scheme",
        ]
        .iter()
        .any(|n| same_name(name, n))
}

/// `X-Forwarded-Host`, in any spelling a CGI parameter folds into it.
pub(crate) fn forwarded_host(name: &[u8]) -> bool {
    same_name(name, b"x-forwarded-host")
}

/// `X-Forwarded-Proto`, in any spelling a CGI parameter folds into it.
pub(crate) fn forwarded_proto(name: &[u8]) -> bool {
    same_name(name, b"x-forwarded-proto")
}

/// `X-Forwarded-Host` and `X-Forwarded-Proto`, which the agent writes itself where it can.
pub(crate) fn forwarded_host_or_proto(name: &[u8]) -> bool {
    forwarded_host(name) || forwarded_proto(name)
}

/// Whether the first value of the request's `X-Forwarded-Proto` is `https`.
pub(crate) fn forwarded_https(req: &InboundRequest) -> bool {
    req.peek("X-Forwarded-Proto")
        .split(|&c| c == b',')
        .next()
        .is_some_and(|first| first.trim_ascii().eq_ignore_ascii_case(b"https"))
}

/// The scheme of the request: HTTPS when the agent ended TLS, else when `X-Forwarded-Proto` says
/// `https`, else HTTP. The word of any peer counts: with no proxy trusted, the application still
/// learns from a front proxy that the visitor came over TLS, and a spoofed value only chooses one
/// of the two keys that a real one chooses too.
pub(crate) fn is_https(req: &InboundRequest) -> bool {
    req.tls.is_some() || forwarded_https(req)
}

/// What the application is told in `X-Forwarded-Proto`: `https` when the agent ended TLS, a
/// trusted proxy's first line as it wrote it (the key holds it), else the scheme the key reads,
/// with `None` for HTTP.
pub(crate) fn forwarded_scheme(req: &InboundRequest, trusted: bool) -> Option<&[u8]> {
    let said = req.peek("X-Forwarded-Proto");
    if req.tls.is_some() {
        Some(b"https")
    } else if trusted && !said.is_empty() {
        Some(said)
    } else {
        forwarded_https(req).then_some(&b"https"[..])
    }
}

/// `host` without a port that is the scheme's own.
pub(crate) fn host_without_default_port(host: &[u8], https: bool) -> &[u8] {
    let port: &[u8] = if https { b":443" } else { b":80" };
    match host.strip_suffix(port) {
        // `[::1]:80` loses its port, `::80` (an IPv6 name) does not.
        Some(rest) if !rest.contains(&b':') || rest.ends_with(b"]") => rest,
        _ => host,
    }
}

/// The values of the unkeyed inputs of a trusted proxy and of its `X-Forwarded-Proto`, which goes
/// on as it wrote it, by name then arrival; `None` when they hold more than [`KEYED_INPUT_MAX`]
/// bytes.
pub(crate) fn keyed_inputs(req: &InboundRequest) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut found: Vec<(Vec<u8>, Vec<u8>)> = req
        .lines
        .iter()
        .filter(|(name, _)| unkeyed_input(name) || forwarded_proto(name))
        .map(|(name, value)| (normalized(name), value.clone()))
        .collect();
    let total: usize = found.iter().map(|(n, v)| n.len() + v.len()).sum();
    if total > KEYED_INPUT_MAX {
        return None;
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Some(found)
}

fn push_u16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u16::try_from(bytes.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn push_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The primary key. Every part carries its length, so two keys that differ in where a part ends
/// differ in bytes.
pub(crate) fn primary_key(
    https: bool,
    host: &[u8],
    target: &[u8],
    bucket: Bucket,
    keyed: &[(Vec<u8>, Vec<u8>)],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(host.len() + target.len() + 32);
    key.extend_from_slice(b"P1");
    key.push(u8::from(https));
    push_u16(&mut key, host_without_default_port(host, https));
    push_u32(&mut key, target);
    key.push(bucket.byte());
    key.push(u8::try_from(keyed.len()).unwrap_or(u8::MAX));
    for (name, value) in keyed {
        push_u16(&mut key, name);
        push_u16(&mut key, value);
    }
    key
}

/// The variant: for each name the answer varies by, the values of that request header, joined
/// with a comma. `Accept-Encoding` is the bucket. `value_of` reads a request header by its lower
/// case name.
pub(crate) fn variant(
    names: &[Vec<u8>],
    bucket: Bucket,
    value_of: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for name in names {
        push_u16(&mut out, name);
        if name == b"accept-encoding" {
            push_u32(&mut out, bucket.token());
        } else {
            push_u32(&mut out, &value_of(name));
        }
    }
    out
}

/// The values of every line of the request header `name` (lower case), joined with a comma. The
/// four headers the request keeps apart are read from where it keeps them.
pub(crate) fn request_header_values(req: &InboundRequest, name: &[u8]) -> Vec<u8> {
    let single: Option<&[u8]> = match name {
        b"host" => Some(&req.host_header_value),
        b"content-type" => Some(&req.content_type),
        b"user-agent" => Some(&req.user_agent),
        _ => None,
    };
    if let Some(value) = single {
        return value.to_vec();
    }
    let mut out = Vec::new();
    for (line, value) in &req.lines {
        if line.eq_ignore_ascii_case(name) {
            if !out.is_empty() {
                out.extend_from_slice(b", ");
            }
            out.extend_from_slice(value);
        }
    }
    out
}

/// The scheme (true for HTTPS), host and target a primary key holds. `None` for bytes that are not
/// one this agent made.
pub(crate) fn parse_primary(primary: &[u8]) -> Option<(bool, &[u8], &[u8])> {
    let rest = primary.strip_prefix(b"P1")?;
    let (&https, rest) = rest.split_first()?;
    let host_len = usize::from(u16::from_le_bytes(rest.get(..2)?.try_into().ok()?));
    let rest = &rest[2..];
    let host = rest.get(..host_len)?;
    let rest = &rest[host_len..];
    let target_len = usize::try_from(u32::from_le_bytes(rest.get(..4)?.try_into().ok()?)).ok()?;
    let target = rest.get(4..)?.get(..target_len)?;
    Some((https != 0, host, target))
}

/// A static file as the memory tier tells it apart: its path, and what `fstat` says of it.
pub(crate) struct StaticFile<'a> {
    pub path: &'a [u8],
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: u64,
}

/// The key of the answer of a static file in memory: the file, the encoding the visitor takes,
/// whether they are signed in (compression leaves pages alone for them) and `shape`, the settings
/// that make the answer (browser cache time, smallest compressed size).
pub(crate) fn static_key(
    file: &StaticFile<'_>,
    bucket: Bucket,
    signed_in: bool,
    shape: &[u8],
) -> FileId {
    let mut hash = Sha256::new();
    hash.update(b"S1");
    hash.update((file.path.len() as u64).to_le_bytes());
    hash.update(file.path);
    for n in [file.dev, file.ino, file.size, file.mtime] {
        hash.update(n.to_le_bytes());
    }
    hash.update([bucket.byte(), u8::from(signed_in)]);
    hash.update(shape);
    hash.finalize().into()
}

pub(crate) fn primary_id(primary: &[u8]) -> PrimaryId {
    Sha256::digest(primary).into()
}

pub(crate) fn file_id(primary: &[u8], variant: &[u8]) -> FileId {
    let mut hash = Sha256::new();
    hash.update(primary);
    hash.update(variant);
    hash.finalize().into()
}

pub(crate) fn hex(id: &[u8; 32]) -> String {
    use std::fmt::Write;
    id.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The 32 bytes a file name of 64 lower case hex digits stands for.
pub(crate) fn from_hex(name: &str) -> Option<[u8; 32]> {
    let name = name.as_bytes();
    if name.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in name.chunks(2).enumerate() {
        out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(head: &str) -> InboundRequest {
        InboundRequest::from_head(
            format!("GET /a?b=1 HTTP/1.1\r\nHost: App.Test:80\r\n{head}\r\n").as_bytes(),
        )
    }

    #[test]
    fn the_names_of_the_unkeyed_inputs_in_every_spelling() {
        for name in [
            "X-Forwarded-Port",
            "x-forwarded-scheme",
            "X_Forwarded_Server",
            "X-Forwarded-",
            "X-Original-URL",
            "x-original-host",
            "X-Host",
            "X-Rewrite-URL",
            "Forwarded",
            "Front-End-Https",
            "X-Url-Scheme",
        ] {
            assert!(unkeyed_input(name.as_bytes()), "{name}");
        }
        for name in [
            "X-Forwarded-For",
            "x-forwarded-host",
            "X-Forwarded-Proto",
            "X_Forwarded_For",
            "Host",
            "Accept",
            "X-Real-IP",
            "X-Hostname",
            "Forwarded-For",
        ] {
            assert!(!unkeyed_input(name.as_bytes()), "{name}");
        }
    }

    #[test]
    fn a_name_is_compared_as_a_cgi_parameter_names_it_without_allocating() {
        assert!(same_name(b"X_Forwarded-HOST", b"x-forwarded-host"));
        assert!(same_name(b"", b""));
        assert!(!same_name(b"x-forwarded-hos", b"x-forwarded-host"));
        assert!(!same_name(b"x-forwarded-hostt", b"x-forwarded-host"));
        assert!(!same_name(b"x.forwarded.host", b"x-forwarded-host"));
        assert!(!same_name(
            "x-forwarded-h\u{f6}st".as_bytes(),
            b"x-forwarded-host"
        ));
        assert_eq!(
            after_name_prefix(b"X_Original_Url", b"x-original-"),
            Some(&b"Url"[..])
        );
        assert_eq!(
            after_name_prefix(b"x-original-", b"x-original-"),
            Some(&b""[..])
        );
        assert_eq!(after_name_prefix(b"x-orig", b"x-original-"), None);
        assert_eq!(after_name_prefix(b"y-original-url", b"x-original-"), None);
    }

    #[test]
    fn the_host_and_proto_the_agent_writes_are_named_in_every_spelling_a_cgi_parameter_folds() {
        for name in [
            "X-Forwarded-Host",
            "x-forwarded-host",
            "X_Forwarded_Host",
            "X_FORWARDED_HOST",
            "X-Forwarded_Host",
        ] {
            assert!(forwarded_host(name.as_bytes()), "{name}");
            assert!(forwarded_host_or_proto(name.as_bytes()), "{name}");
        }
        for name in [
            "X-Forwarded-Proto",
            "x_forwarded_proto",
            "X_Forwarded_PROTO",
        ] {
            assert!(!forwarded_host(name.as_bytes()), "{name}");
            assert!(forwarded_proto(name.as_bytes()), "{name}");
            assert!(forwarded_host_or_proto(name.as_bytes()), "{name}");
        }
        for name in [
            "X-Forwarded-For",
            "X-Forwarded-Hosts",
            "X-Forwarded-Port",
            "X-Host",
            "Host",
            "",
        ] {
            assert!(!forwarded_host_or_proto(name.as_bytes()), "{name}");
            assert!(!forwarded_proto(name.as_bytes()), "{name}");
        }
    }

    #[test]
    fn the_scheme_is_tls_then_the_first_forwarded_proto_that_says_https_then_http() {
        assert!(!is_https(&request("")));
        let said = request("X-Forwarded-Proto: HTTPS, http\r\n");
        assert!(is_https(&said) && forwarded_https(&said));
        assert!(!is_https(&request("X-Forwarded-Proto: http, https\r\n")));
        assert!(!is_https(&request("X-Forwarded-Proto: ftp\r\n")));
        assert!(!is_https(&request("X-Forwarded-Proto: \r\n")));
        let mut tls = request("X-Forwarded-Proto: http\r\n");
        tls.tls = Some(std::sync::Arc::new(crate::request::TlsClient {
            server_name: "app.test".into(),
            ja4: None,
        }));
        assert!(is_https(&tls), "TLS ended here, whatever a header says");
        assert!(!forwarded_https(&tls));
    }

    #[test]
    fn a_port_that_is_the_schemes_own_is_not_part_of_the_host() {
        assert_eq!(
            host_without_default_port(b"app.test:80", false),
            b"app.test"
        );
        assert_eq!(
            host_without_default_port(b"app.test:80", true),
            b"app.test:80"
        );
        assert_eq!(
            host_without_default_port(b"app.test:443", true),
            b"app.test"
        );
        assert_eq!(
            host_without_default_port(b"app.test:8080", false),
            b"app.test:8080"
        );
        assert_eq!(host_without_default_port(b"[::1]:80", false), b"[::1]");
        assert_eq!(host_without_default_port(b"[::1]", false), b"[::1]");
        assert_eq!(host_without_default_port(b"::80", false), b"::80");
    }

    #[test]
    fn two_requests_share_a_key_only_when_every_part_is_the_same() {
        let key = |https, host: &[u8], target: &[u8], bucket, keyed: &[(Vec<u8>, Vec<u8>)]| {
            primary_key(https, host, target, bucket, keyed)
        };
        let base = key(false, b"a.test", b"/x?a=1&b=2", Bucket::Identity, &[]);
        assert_eq!(
            base,
            key(false, b"a.test:80", b"/x?a=1&b=2", Bucket::Identity, &[])
        );
        // The query is not sorted or re-encoded: these are four keys.
        for other in [
            key(false, b"a.test", b"/x?b=2&a=1", Bucket::Identity, &[]),
            key(false, b"a.test", b"/x?a=1&b=2", Bucket::Gzip, &[]),
            key(true, b"a.test", b"/x?a=1&b=2", Bucket::Identity, &[]),
            key(false, b"b.test", b"/x?a=1&b=2", Bucket::Identity, &[]),
            key(false, b"a.test", b"/x?%61=1&b=2", Bucket::Identity, &[]),
            key(
                false,
                b"a.test",
                b"/x?a=1&b=2",
                Bucket::Identity,
                &[(b"x-forwarded-port".to_vec(), b"8443".to_vec())],
            ),
        ] {
            assert_ne!(base, other);
        }
        // A part that ends in another place is another key even with the same bytes in all.
        assert_ne!(
            key(false, b"a", b"bc", Bucket::Identity, &[]),
            key(false, b"ab", b"c", Bucket::Identity, &[])
        );
        assert_ne!(primary_id(&base), primary_id(b"other"));
    }

    #[test]
    fn the_variant_holds_the_values_of_the_varying_headers_and_the_bucket_for_the_encoding() {
        let req =
            request("Accept-Language: id\r\nAccept-Language: en\r\nAccept-Encoding: gzip, br\r\n");
        let names: Vec<Vec<u8>> = vec![b"accept-encoding".to_vec(), b"accept-language".to_vec()];
        let v = |bucket| variant(&names, bucket, |name| request_header_values(&req, name));
        assert_ne!(v(Bucket::Gzip), v(Bucket::Brotli));
        assert_eq!(v(Bucket::Gzip), v(Bucket::Gzip));
        let by_value = |lang: &str| {
            let other = request(&format!("Accept-Language: {lang}\r\n"));
            variant(&names, Bucket::Gzip, |name| {
                request_header_values(&other, name)
            })
        };
        assert_ne!(by_value("id"), by_value("en"));
        assert_eq!(
            variant(&[], Bucket::Gzip, |_| unreachable!()),
            Vec::<u8>::new()
        );
        assert_eq!(
            request_header_values(&req, b"accept-language"),
            b"id, en".to_vec()
        );
        assert_eq!(
            request_header_values(&req, b"host"),
            b"App.Test:80".to_vec()
        );
        assert_eq!(request_header_values(&req, b"missing"), Vec::<u8>::new());
    }

    #[test]
    fn the_inputs_of_a_trusted_proxy_are_keyed_in_order_and_bounded() {
        let req = request(
            "X-Forwarded-Port: 8443\r\nX-Original-URL: /a\r\nAccept: x\r\nX-Forwarded-For: 1.2.3.4\r\n",
        );
        let keyed = keyed_inputs(&req).unwrap();
        assert_eq!(
            keyed,
            vec![
                (b"x-forwarded-port".to_vec(), b"8443".to_vec()),
                (b"x-original-url".to_vec(), b"/a".to_vec()),
            ]
        );
        assert_eq!(keyed_inputs(&request("")).unwrap(), Vec::new());
        let fat = request(&format!("X-Original-URL: {}\r\n", "a".repeat(300)));
        assert!(keyed_inputs(&fat).is_none());
        let fits = request(&format!("X-Original-URL: {}\r\n", "a".repeat(200)));
        assert!(keyed_inputs(&fits).is_some());
    }

    #[test]
    fn a_primary_key_gives_back_its_scheme_host_and_target() {
        let key = primary_key(
            true,
            b"a.test:443",
            b"/x?a=1",
            Bucket::Gzip,
            &[(b"x-forwarded-port".to_vec(), b"8443".to_vec())],
        );
        assert_eq!(
            parse_primary(&key),
            Some((true, &b"a.test"[..], &b"/x?a=1"[..]))
        );
        let plain = primary_key(false, b"a.test:8080", b"/", Bucket::Identity, &[]);
        assert_eq!(
            parse_primary(&plain),
            Some((false, &b"a.test:8080"[..], &b"/"[..]))
        );
        // A key that is cut anywhere, or is not one of ours, never panics and names nothing wrong.
        for n in 0..key.len() {
            if let Some((_, host, target)) = parse_primary(&key[..n]) {
                assert_eq!((host, target), (&b"a.test"[..], &b"/x?a=1"[..]));
            }
        }
        for bad in [&b""[..], b"P", b"P1", b"P2\x00\x00\x00", b"P1\x00\xff\xff"] {
            assert!(parse_primary(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn the_key_of_a_static_answer_changes_with_the_file_the_encoding_and_the_settings() {
        let file = |ino, size, mtime| StaticFile {
            path: b"/a.css",
            dev: 1,
            ino,
            size,
            mtime,
        };
        let base = static_key(&file(5, 10, 100), Bucket::Gzip, false, b"s");
        assert_eq!(
            base,
            static_key(&file(5, 10, 100), Bucket::Gzip, false, b"s")
        );
        for other in [
            static_key(&file(6, 10, 100), Bucket::Gzip, false, b"s"),
            static_key(&file(5, 11, 100), Bucket::Gzip, false, b"s"),
            static_key(&file(5, 10, 101), Bucket::Gzip, false, b"s"),
            static_key(&file(5, 10, 100), Bucket::Brotli, false, b"s"),
            static_key(&file(5, 10, 100), Bucket::Gzip, true, b"s"),
            static_key(&file(5, 10, 100), Bucket::Gzip, false, b"t"),
            static_key(
                &StaticFile {
                    path: b"/b.css",
                    ..file(5, 10, 100)
                },
                Bucket::Gzip,
                false,
                b"s",
            ),
            static_key(
                &StaticFile {
                    dev: 2,
                    ..file(5, 10, 100)
                },
                Bucket::Gzip,
                false,
                b"s",
            ),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn a_file_name_is_the_hash_in_hex_and_reads_back() {
        let id = file_id(b"p", b"v");
        let name = hex(&id);
        assert_eq!(name.len(), 64);
        assert_eq!(from_hex(&name), Some(id));
        assert_ne!(id, file_id(b"p", b"w"));
        assert_eq!(from_hex(&name.to_uppercase()), None, "lower case only");
        assert_eq!(from_hex(&name[..63]), None);
        assert_eq!(from_hex(&format!("{}g", &name[..63])), None);
    }
}
