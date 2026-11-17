//! URL parsing as far as the engines read the result (scheme, opaque, host, path, raw query,
//! fragment). Userinfo is validated, not kept. Query unescaping and query parsing are in
//! [`crate::url`].

use crate::net::parse_ip_address;
use crate::strings::{contains, count, cut, find};
use std::borrow::Cow;

/// Parsing rejected the input; no error text is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UrlParseError;

impl std::fmt::Display for UrlParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid URL")
    }
}

impl std::error::Error for UrlParseError {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EscapeMode {
    Path,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn hex_digit_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

fn needs_escaping(c: u8, mode: EscapeMode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if (mode == EscapeMode::Host || mode == EscapeMode::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            EscapeMode::Path => return c == b'?',
            EscapeMode::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            EscapeMode::QueryComponent => return true,
            EscapeMode::Fragment => return false,
            _ => {}
        },
        _ => {}
    }
    if mode == EscapeMode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

/// To be deduplicated with the url module.
pub fn unescape(s: &[u8], mode: EscapeMode) -> Result<Cow<'_, [u8]>, ()> {
    let mut n = 0;
    let mut has_plus = false;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                n += 1;
                if i + 2 >= s.len() || !is_hex_digit(s[i + 1]) || !is_hex_digit(s[i + 2]) {
                    return Err(());
                }
                if mode == EscapeMode::Host
                    && hex_digit_value(s[i + 1]) < 8
                    && &s[i..i + 3] != b"%25"
                {
                    return Err(());
                }
                if mode == EscapeMode::Zone {
                    let v = hex_digit_value(s[i + 1]) << 4 | hex_digit_value(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && v != b' ' && needs_escaping(v, EscapeMode::Host) {
                        return Err(());
                    }
                }
                i += 3;
            }
            b'+' => {
                has_plus = mode == EscapeMode::QueryComponent;
                i += 1;
            }
            c => {
                if (mode == EscapeMode::Host || mode == EscapeMode::Zone)
                    && c < 0x80
                    && needs_escaping(c, mode)
                {
                    return Err(());
                }
                i += 1;
            }
        }
    }
    if n == 0 && !has_plus {
        return Ok(Cow::Borrowed(s));
    }
    let plus = if mode == EscapeMode::QueryComponent {
        b' '
    } else {
        b'+'
    };
    let mut t = Vec::with_capacity(s.len() - 2 * n);
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                t.push(hex_digit_value(s[i + 1]) << 4 | hex_digit_value(s[i + 2]));
                i += 3;
            }
            b'+' => {
                t.push(plus);
                i += 1;
            }
            c => {
                t.push(c);
                i += 1;
            }
        }
    }
    Ok(Cow::Owned(t))
}

/// The parts of a URL the engines read (no userinfo, no raw path).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Url {
    pub scheme: Vec<u8>,
    pub opaque: Vec<u8>,
    pub host: Vec<u8>,
    pub path: Vec<u8>,
    pub raw_query: Vec<u8>,
    pub fragment: Vec<u8>,
}

impl Url {
    pub fn hostname(&self) -> &[u8] {
        split_host_and_port(&self.host).0
    }

    /// The query with its errors dropped, as (key, values) in first-seen key order, so callers
    /// that stop at the first hit get a deterministic one (`crate::url::parse_query` returns
    /// sorted keys instead).
    pub fn query(&self) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
        let query = self.raw_query.as_slice();
        let mut m: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
        if count(query, b"&") + 1 > crate::url::DEFAULT_MAX_QUERY_PARAMS {
            return m;
        }
        let mut q = query;
        while !q.is_empty() {
            let (key, rest, _) = cut(q, b"&");
            q = rest;
            if contains(key, b";") || key.is_empty() {
                continue;
            }
            let (k, v, _) = cut(key, b"=");
            let (Ok(k), Ok(v)) = (
                crate::url::unescape_query_component(k),
                crate::url::unescape_query_component(v),
            ) else {
                continue;
            };
            match m.iter_mut().find(|(ek, _)| *ek == k) {
                Some((_, vals)) => vals.push(v),
                None => m.push((k, vec![v])),
            }
        }
        m
    }
}

fn split_host_and_port(host_port: &[u8]) -> (&[u8], &[u8]) {
    let mut host = host_port;
    let mut port: &[u8] = &[];
    if let Some(colon) = host.iter().rposition(|&c| c == b':')
        && is_valid_port_suffix(&host[colon..])
    {
        port = &host[colon + 1..];
        host = &host[..colon];
    }
    if host.len() >= 2 && host[0] == b'[' && host[host.len() - 1] == b']' {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

fn is_valid_port_suffix(port: &[u8]) -> bool {
    if port.is_empty() {
        return true;
    }
    port[0] == b':' && port[1..].iter().all(u8::is_ascii_digit)
}

fn split_scheme(raw: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    for (i, &c) in raw.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok((&[], raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err(());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok((&[], raw)),
        }
    }
    Ok((&[], raw))
}

fn is_valid_userinfo(s: &[u8]) -> bool {
    s.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

fn host_from_authority(scheme: &[u8], authority: &[u8]) -> Result<Vec<u8>, ()> {
    let i = authority.iter().rposition(|&c| c == b'@');
    let host = match i {
        None => unescape_host(scheme, authority)?,
        Some(i) => unescape_host(scheme, &authority[i + 1..])?,
    };
    let Some(i) = i else { return Ok(host) };
    let userinfo = &authority[..i];
    if !is_valid_userinfo(userinfo) {
        return Err(());
    }
    match cut(userinfo, b":") {
        (u, _, false) => {
            unescape(u, EscapeMode::UserPassword)?;
        }
        (u, p, true) => {
            unescape(u, EscapeMode::UserPassword)?;
            unescape(p, EscapeMode::UserPassword)?;
        }
    }
    Ok(host)
}

fn unescape_host(scheme: &[u8], host: &[u8]) -> Result<Vec<u8>, ()> {
    let open = host.iter().rposition(|&c| c == b'[');
    if let Some(ob) = open {
        if ob > 0 {
            return Err(());
        }
        let Some(cb) = host.iter().rposition(|&c| c == b']') else {
            return Err(());
        };
        let colon_port = &host[cb + 1..];
        if !is_valid_port_suffix(colon_port) {
            return Err(());
        }
        let unescaped_port = unescape(colon_port, EscapeMode::Host)?;
        let hostname = &host[1..cb];
        let unescaped_host: Vec<u8> = match find(hostname, b"%25") {
            Some(z) => {
                let mut h = unescape(&hostname[..z], EscapeMode::Host)?.into_owned();
                h.extend_from_slice(&unescape(&hostname[z..], EscapeMode::Zone)?);
                h
            }
            None => unescape(hostname, EscapeMode::Host)?.into_owned(),
        };
        let addr = parse_ip_address(&unescaped_host).map_err(|_| ())?;
        if addr.is_ipv4 {
            return Err(());
        }
        let mut out = b"[".to_vec();
        out.extend_from_slice(&unescaped_host);
        out.push(b']');
        out.extend_from_slice(&unescaped_port);
        return Ok(out);
    } else if let Some(mut i) = host.iter().position(|&c| c == b':') {
        let last = host.iter().rposition(|&c| c == b':').unwrap_or(i);
        // http and https keep the first colon; other schemes use the last one.
        if last != i && !(scheme == b"http" || scheme == b"https") {
            i = last;
        }
        if !is_valid_port_suffix(&host[i..]) {
            return Err(());
        }
    }
    Ok(unescape(host, EscapeMode::Host)?.into_owned())
}

/// Err when the input is not a valid URL.
pub fn parse(raw: &[u8]) -> Result<Url, UrlParseError> {
    parse_fragment(raw).map_err(|()| UrlParseError)
}

fn parse_fragment(raw: &[u8]) -> Result<Url, ()> {
    let (u, frag, has_frag) = cut(raw, b"#");
    let mut url = parse_no_fragment(u)?;
    if has_frag && !frag.is_empty() {
        url.fragment = unescape(frag, EscapeMode::Fragment)?.into_owned();
    }
    Ok(url)
}

/// Parses the part before the fragment.
fn parse_no_fragment(raw: &[u8]) -> Result<Url, ()> {
    if raw.iter().any(|&b| b < b' ' || b == 0x7f) {
        return Err(());
    }
    let mut url = Url::default();
    if raw == b"*" {
        url.path = b"*".to_vec();
        return Ok(url);
    }
    let (scheme, mut rest) = split_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    if rest.ends_with(b"?") && count(rest, b"?") == 1 {
        rest = &rest[..rest.len() - 1];
    } else {
        let (r, q, _) = cut(rest, b"?");
        rest = r;
        url.raw_query = q.to_vec();
    }
    if !rest.starts_with(b"/") {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_vec();
            return Ok(url);
        }
        let (segment, _, _) = cut(rest, b"/");
        if contains(segment, b":") {
            return Err(());
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
        let mut authority = &rest[2..];
        rest = &[];
        if let Some(i) = authority.iter().position(|&c| c == b'/') {
            rest = &authority[i..];
            authority = &authority[..i];
        }
        url.host = host_from_authority(&url.scheme, authority)?;
    }
    url.path = unescape(rest, EscapeMode::Path)?.into_owned();
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_keeps_first_seen_order() {
        let u = parse(b"/p?b=1&a=2&b=3&c=%zz&d=4;x&e").unwrap();
        assert_eq!(
            u.query(),
            vec![
                (b"b".to_vec(), vec![b"1".to_vec(), b"3".to_vec()]),
                (b"a".to_vec(), vec![b"2".to_vec()]),
                (b"e".to_vec(), vec![Vec::new()])
            ]
        );
    }

    #[test]
    fn parse_matches_reference() {
        let u = parse(b"http://user@127.0.0.1:8080/x?a=1#f").unwrap();
        assert_eq!(u.hostname(), b"127.0.0.1");
        assert_eq!(u.raw_query, b"a=1");
        assert_eq!(u.fragment, b"f");
        assert!(parse(b"http://a b/").is_err());
        assert!(parse(b"http://[::1]:80/").is_ok());
        assert!(parse(b"http://a:1:2/").is_err());
        assert!(parse(b"x:1/a").is_ok()); // opaque
        assert!(parse(b"a:b/c").is_ok());
        assert!(parse(b"/a:b").is_ok());
        assert!(parse(b"ab:c").is_ok());
        assert!(parse(b"1a:b").is_err()); // first segment with colon, no scheme
        assert!(parse(b"http://%41/").is_err());
        assert!(parse(b"http://\xc3\xa9/").is_ok());
        assert_eq!(parse(b"HTTP://h/p%41").unwrap().path, b"/pA");
        assert_eq!(parse(b"mailto:a@b").unwrap().opaque, b"a@b");
        assert_eq!(parse(b"*").unwrap().path, b"*");
    }
}
